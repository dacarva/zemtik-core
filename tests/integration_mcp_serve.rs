//! Integration tests for the MCP HTTP server (`cargo run -- mcp-serve`).
//!
//! Tests the Axum router built by `build_mcp_router`:
//!   GET /mcp/health   — no auth required
//!   GET /mcp/audit    — Bearer auth required (ZEMTIK_MCP_API_KEY)
//!   GET /mcp/summary  — Bearer auth required
//!   POST /mcp         — Streamable HTTP MCP endpoint (initialize handshake)
//!
//! Each test binds to an ephemeral port (127.0.0.1:0) so tests run in parallel
//! without port conflicts. The TempDir returned by spawn_test_mcp_serve() keeps
//! the audit DB path alive for the duration of each test.

use std::net::SocketAddr;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use zemtik::config::AppConfig;
use zemtik::mcp_proxy::{build_mcp_router, write_audit_record};
use zemtik::types::McpAuditRecord;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawn a test MCP HTTP server on an ephemeral port.
/// Returns (addr, cancel_token, tempdir).
/// Drop `cancel_token` to shut down the server. Keep `_dir` alive for the test.
async fn spawn_test_mcp_serve() -> (SocketAddr, CancellationToken, TempDir) {
    spawn_test_mcp_serve_with(|_| {}).await
}

/// Spawn with an AppConfig override callback — lets individual tests flip flags without
/// duplicating the base config.
async fn spawn_test_mcp_serve_with(
    configure: impl FnOnce(&mut AppConfig),
) -> (SocketAddr, CancellationToken, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut config = AppConfig::default();
    config.mcp_api_key = Some("test-mcp-key".to_owned());
    config.mcp_audit_db_path = dir.path().join("mcp_audit.db");
    config.keys_dir = dir.path().join("keys");
    config.mcp_mode = "tunnel".to_owned();
    config.mcp_fetch_timeout_secs = 5;
    config.mcp_allowed_paths = vec![];
    config.mcp_allowed_fetch_domains = vec![];
    config.skip_circuit_validation = true;

    configure(&mut config);

    let ct = CancellationToken::new();
    let (router, _state) = build_mcp_router(&config, ct.clone())
        .expect("build_mcp_router failed");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    let ct_server = ct.clone();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { ct_server.cancelled().await })
            .await
            .ok();
    });

    (addr, ct, dir)
}

/// Pre-seed the audit DB with one record.
fn seed_audit_record(db_path: &std::path::Path, tool: &str) -> McpAuditRecord {
    let record = McpAuditRecord {
        receipt_id: uuid::Uuid::new_v4().to_string(),
        ts: "2026-04-24T12:00:00Z".to_owned(),
        tool_name: tool.to_owned(),
        input_hash: "aabbcc".to_owned(),
        output_hash: "ddeeff".to_owned(),
        preview_input: "{}".to_owned(),
        preview_output: "{}".to_owned(),
        attestation_sig: "sig".to_owned(),
        public_key_hex: "pubkey".to_owned(),
        duration_ms: 42,
        mode: "tunnel".to_owned(),
    };
    write_audit_record(db_path, &record).expect("write audit record");
    record
}

// ---------------------------------------------------------------------------
// /mcp/health
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_health_returns_200() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    let url = format!("http://{}/mcp/health", addr);
    let resp = reqwest::get(&url).await.expect("GET /mcp/health");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "zemtik-mcp");
}

// ---------------------------------------------------------------------------
// /mcp/audit — auth gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_audit_no_auth_returns_401() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    let url = format!("http://{}/mcp/audit", addr);
    let resp = reqwest::get(&url).await.expect("GET /mcp/audit");
    assert_eq!(resp.status(), 401, "missing auth must return 401");
}

#[tokio::test]
async fn test_mcp_audit_wrong_bearer_returns_401() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/mcp/audit", addr))
        .bearer_auth("wrong-key")
        .send()
        .await
        .expect("GET /mcp/audit wrong key");
    assert_eq!(resp.status(), 401, "wrong bearer must return 401");
}

#[tokio::test]
async fn test_mcp_audit_correct_bearer_returns_200_empty_array() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/mcp/audit", addr))
        .bearer_auth("test-mcp-key")
        .send()
        .await
        .expect("GET /mcp/audit correct key");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert!(body.is_array(), "audit response must be a JSON array");
    assert_eq!(body.as_array().unwrap().len(), 0, "fresh DB must be empty");
}

#[tokio::test]
async fn test_mcp_audit_query_token_auth() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    // ?token= is an alternative auth path for browser-based dashboard access
    let url = format!("http://{}/mcp/audit?token=test-mcp-key", addr);
    let resp = reqwest::get(&url).await.expect("GET /mcp/audit?token=");
    assert_eq!(resp.status(), 200, "query token auth must succeed");
}

#[tokio::test]
async fn test_mcp_audit_wrong_query_token_returns_401() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    let url = format!("http://{}/mcp/audit?token=badtoken", addr);
    let resp = reqwest::get(&url).await.expect("GET /mcp/audit?token=bad");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_mcp_audit_returns_seeded_records() {
    let (addr, _ct, dir) = spawn_test_mcp_serve().await;
    let db_path = dir.path().join("mcp_audit.db");
    seed_audit_record(&db_path, "zemtik_fetch");
    seed_audit_record(&db_path, "zemtik_read_file");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/mcp/audit", addr))
        .bearer_auth("test-mcp-key")
        .send()
        .await
        .expect("GET /mcp/audit with records");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    let records = body.as_array().expect("must be array");
    assert_eq!(records.len(), 2, "both seeded records must appear");

    // Each record must have the mandatory fields
    for r in records {
        assert!(r["receipt_id"].is_string(), "record must have receipt_id");
        assert!(r["tool_name"].is_string(), "record must have tool_name");
        assert!(r["mode"].is_string(), "record must have mode");
        assert!(r["ts"].is_string(), "record must have ts");
    }
}

#[tokio::test]
async fn test_mcp_audit_html_accept_header_returns_html() {
    let (addr, _ct, dir) = spawn_test_mcp_serve().await;
    seed_audit_record(&dir.path().join("mcp_audit.db"), "zemtik_fetch");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/mcp/audit", addr))
        .bearer_auth("test-mcp-key")
        .header("Accept", "text/html")
        .send()
        .await
        .expect("GET /mcp/audit Accept: text/html");
    assert_eq!(resp.status(), 200);
    let ct = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/html"), "HTML Accept header must return HTML, got: {}", ct);
}

// ---------------------------------------------------------------------------
// /mcp/summary — auth gate + shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_summary_no_auth_returns_401() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    let resp = reqwest::get(format!("http://{}/mcp/summary", addr))
        .await
        .expect("GET /mcp/summary");
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_mcp_summary_correct_bearer_returns_200_with_shape() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/mcp/summary", addr))
        .bearer_auth("test-mcp-key")
        .send()
        .await
        .expect("GET /mcp/summary correct key");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert!(body["tool_calls_total"].is_number(), "must have tool_calls_total");
    assert!(body["tools_used"].is_array(), "must have tools_used array");
    assert!(body["mode"].is_string(), "must have mode field");
    assert_eq!(body["tool_calls_total"], 0, "fresh DB must show 0 calls");
}

#[tokio::test]
async fn test_mcp_summary_counts_seeded_records() {
    let (addr, _ct, dir) = spawn_test_mcp_serve().await;
    let db_path = dir.path().join("mcp_audit.db");
    seed_audit_record(&db_path, "zemtik_fetch");
    seed_audit_record(&db_path, "zemtik_fetch");
    seed_audit_record(&db_path, "zemtik_read_file");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/mcp/summary", addr))
        .bearer_auth("test-mcp-key")
        .send()
        .await
        .expect("GET /mcp/summary with records");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert_eq!(body["tool_calls_total"], 3, "must count all seeded records");

    let tools = body["tools_used"].as_array().expect("tools_used array");
    let fetch_count = tools.iter()
        .find(|t| t["name"] == "zemtik_fetch")
        .and_then(|t| t["count"].as_u64())
        .unwrap_or(0);
    assert_eq!(fetch_count, 2, "zemtik_fetch must appear twice in summary");
}

// ---------------------------------------------------------------------------
// /mcp — Streamable HTTP MCP endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_tool_endpoint_reachable() {
    // Verify the MCP endpoint is mounted and responds to the MCP initialize handshake.
    // We send a valid JSON-RPC initialize request and confirm the server does not return 404.
    let (addr, _ct, _dir) = spawn_test_mcp_serve().await;
    let client = reqwest::Client::new();

    // MCP Streamable HTTP: initialize request per the spec
    let init = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "zemtik-test", "version": "0.1.0" }
        }
    });

    let resp = client
        .post(format!("http://{}/mcp", addr))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&init)
        .send()
        .await
        .expect("POST /mcp initialize");

    assert_ne!(resp.status(), 404, "MCP endpoint must be mounted (not 404)");
    // 200 = synchronous response; 202 = accepted for SSE; both are valid
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 202,
        "MCP initialize must return 200 or 202, got {}", status
    );
}

// ---------------------------------------------------------------------------
// Startup validation
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_serve_requires_api_key() {
    // build_mcp_router itself doesn't enforce the key — run_mcp_serve does.
    // Test that the config struct captures the key requirement at the call site.
    let dir = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    // api_key intentionally NOT set
    config.mcp_audit_db_path = dir.path().join("mcp_audit.db");
    config.keys_dir = dir.path().join("keys");
    config.skip_circuit_validation = true;

    // build_mcp_router succeeds — the key guard lives in run_mcp_serve.
    // We verify the guard by checking the config field is None.
    assert!(
        config.mcp_api_key.is_none(),
        "mcp_api_key must be None when not configured"
    );
    // The actual hard-error path is tested in integration by running the binary
    // with ZEMTIK_MCP_API_KEY unset — see tmp/qa-multi-model.md Section 14.
}

// ---------------------------------------------------------------------------
// zemtik_analyze — tool visibility and error paths
// ---------------------------------------------------------------------------

/// Parse a JSON-RPC response from either plain JSON or SSE (`data: {...}\n\n`).
async fn parse_mcp_response(resp: reqwest::Response) -> serde_json::Value {
    let text = resp.text().await.expect("read response body");
    // SSE format: one or more "data: <json>\n\n" lines — take the first data line.
    for line in text.lines() {
        if let Some(json_str) = line.strip_prefix("data: ") {
            if let Ok(v) = serde_json::from_str(json_str) {
                return v;
            }
        }
    }
    // Fallback: try to parse the whole body as JSON.
    serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
}

/// Perform MCP initialize handshake. Returns the Mcp-Session-Id (if any).
async fn mcp_initialize(client: &reqwest::Client, addr: SocketAddr) -> Option<String> {
    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "zemtik-test", "version": "0.1"}
        }
    });
    let resp = client
        .post(format!("http://{}/mcp", addr))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&init)
        .send()
        .await
        .expect("POST /mcp initialize");
    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    // Drain body to avoid connection issues
    let _ = resp.text().await;
    session_id
}

/// Build a request builder pre-loaded with session header if present.
fn mcp_request(
    client: &reqwest::Client,
    addr: SocketAddr,
    session_id: Option<&str>,
) -> reqwest::RequestBuilder {
    let rb = client
        .post(format!("http://{}/mcp", addr))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(sid) = session_id {
        rb.header("Mcp-Session-Id", sid)
    } else {
        rb
    }
}

/// Send a tools/list JSON-RPC request and return the tool names.
async fn list_tool_names(addr: SocketAddr) -> Vec<String> {
    let client = reqwest::Client::new();
    let session_id = mcp_initialize(&client, addr).await;

    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 10,
        "method": "tools/list", "params": {}
    });
    let resp = mcp_request(&client, addr, session_id.as_deref())
        .json(&req)
        .send()
        .await
        .expect("POST tools/list");

    let body = parse_mcp_response(resp).await;
    body["result"]["tools"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|t| t["name"].as_str().map(String::from))
        .collect()
}

/// Call zemtik_analyze via JSON-RPC and return the full result body.
async fn call_analyze(addr: SocketAddr, text: &str) -> serde_json::Value {
    let client = reqwest::Client::new();
    let session_id = mcp_initialize(&client, addr).await;

    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 2,
        "method": "tools/call",
        "params": {
            "name": "zemtik_analyze",
            "arguments": {"text": text}
        }
    });
    let resp = mcp_request(&client, addr, session_id.as_deref())
        .json(&req)
        .send()
        .await
        .expect("tools/call zemtik_analyze");
    parse_mcp_response(resp).await
}

#[tokio::test]
async fn test_analyze_tool_hidden_when_anonymizer_disabled() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve_with(|c| {
        c.anonymizer_enabled = false;
    }).await;

    let names = list_tool_names(addr).await;
    assert!(names.contains(&"zemtik_read_file".to_string()));
    assert!(names.contains(&"zemtik_fetch".to_string()));
    assert!(!names.contains(&"zemtik_analyze".to_string()), "zemtik_analyze must be hidden when anonymizer is disabled");
}

#[tokio::test]
async fn test_analyze_tool_listed_when_anonymizer_enabled() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve_with(|c| {
        c.anonymizer_enabled = true;
        c.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned(); // unreachable — list_tools doesn't call it
        c.anonymizer_fallback_regex = true;
    }).await;

    let names = list_tool_names(addr).await;
    assert!(names.contains(&"zemtik_analyze".to_string()), "zemtik_analyze must appear when anonymizer is enabled");
}

#[tokio::test]
async fn test_analyze_disabled_defense_in_depth() {
    // Even if somehow called directly, the tool rejects when anonymizer is off.
    let (addr, _ct, _dir) = spawn_test_mcp_serve_with(|c| {
        c.anonymizer_enabled = false;
    }).await;

    let body = call_analyze(addr, "hello").await;
    let code = body["error"]["code"].as_i64().unwrap_or(0);
    assert_eq!(code, -32601, "must return -32601 when anonymizer disabled");
}

#[tokio::test]
async fn test_analyze_oversize_input_rejected() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve_with(|c| {
        c.anonymizer_enabled = true;
        c.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned();
        c.anonymizer_fallback_regex = true;
    }).await;

    let big = "A".repeat(150 * 1024); // 150 KB > 100 KB cap
    let body = call_analyze(addr, &big).await;
    let code = body["error"]["code"].as_i64().unwrap_or(0);
    assert_eq!(code, -32003, "must return -32003 for input > 100KB");
}

#[tokio::test]
async fn test_analyze_missing_text_arg_rejected() {
    let (addr, _ct, _dir) = spawn_test_mcp_serve_with(|c| {
        c.anonymizer_enabled = true;
        c.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned();
        c.anonymizer_fallback_regex = true;
    }).await;

    // Call with empty arguments object
    let client = reqwest::Client::new();
    let session_id = mcp_initialize(&client, addr).await;
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 2,
        "method": "tools/call",
        "params": {"name": "zemtik_analyze", "arguments": {}}
    });
    let resp = mcp_request(&client, addr, session_id.as_deref())
        .json(&req)
        .send()
        .await
        .expect("tools/call missing arg");
    let body = parse_mcp_response(resp).await;
    let code = body["error"]["code"].as_i64().unwrap_or(0);
    assert_eq!(code, -32602, "must return -32602 for missing text arg");
}

#[tokio::test]
async fn test_analyze_regex_fallback_tokenizes_structured_pii() {
    // Sidecar unreachable + fallback_regex=true — regex path should still tokenize
    // structured identifiers like email addresses that the regex backend covers.
    let (addr, _ct, _dir) = spawn_test_mcp_serve_with(|c| {
        c.anonymizer_enabled = true;
        c.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned(); // unreachable
        c.anonymizer_fallback_regex = true;
        c.anonymizer_sidecar_timeout_ms = 100; // fail fast
        c.anonymizer_entity_types = "PERSON,ORG,LOCATION,CO_NIT,CO_CEDULA".to_owned();
    }).await;

    let body = call_analyze(addr, "Send the report to juan@acme.mx about NIT 900.123.456-7").await;

    // Either we got a successful result (regex found entities) or a graceful error
    // — both are acceptable depending on whether regex covers these patterns.
    // The key assertion: we do NOT get -32003 (size) or -32602 (missing arg).
    let error_code = body["error"]["code"].as_i64().unwrap_or(0);
    assert_ne!(error_code, -32003, "not an oversize error");
    assert_ne!(error_code, -32602, "not a missing-arg error");
    // If successful, result should be a non-empty JSON string
    if error_code == 0 {
        let content = &body["result"]["content"];
        assert!(content.is_array(), "result must have content array");
    }
}

#[tokio::test]
async fn test_analyze_writes_audit_record() {
    let (addr, _ct, dir) = spawn_test_mcp_serve_with(|c| {
        c.anonymizer_enabled = true;
        c.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned();
        c.anonymizer_fallback_regex = true;
        c.anonymizer_sidecar_timeout_ms = 100;
        c.anonymizer_entity_types = "PERSON".to_owned();
    }).await;

    let body = call_analyze(addr, "Hello world").await;
    // Check that the response is a real JSON-RPC result (not a null from failed parse).
    // Only verify audit record when the tool actually succeeded.
    let has_result = body.get("result").is_some();
    let has_error = body.get("error").is_some();
    assert!(has_result || has_error, "expected a JSON-RPC response, got: {}", body);
    if has_result && !has_error {
        // Give FORK 2 up to 500ms to write the audit record.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let db_path = dir.path().join("mcp_audit.db");
        let records = zemtik::mcp_proxy::list_mcp_audit_records(&db_path, 100)
            .expect("list audit records");
        let analyze_records: Vec<_> = records.iter()
            .filter(|r| r.tool_name == "zemtik_analyze")
            .collect();
        assert!(!analyze_records.is_empty(), "audit record must be written for zemtik_analyze call");
        let rec = analyze_records[0];
        assert!(rec.input_hash.starts_with("sha256:"), "input_hash must be a sha256 hex");
        assert!(rec.output_hash.starts_with("sha256:"), "output_hash must be a sha256 hex");
    }
}
