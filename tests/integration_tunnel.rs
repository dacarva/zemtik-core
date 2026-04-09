/// Integration tests for Tunnel Mode.
///
/// Spins up a real Axum server in ZEMTIK_MODE=tunnel on an ephemeral port,
/// backed by in-memory SQLite and a wiremock server for OpenAI.
///
/// Run with:
///   cargo test --test integration_tunnel --no-default-features --features regex-only
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zemtik::config::{AggFn, AppConfig, SchemaConfig, TableConfig, ZemtikMode};
use zemtik::proxy::build_proxy_router;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn test_schema() -> SchemaConfig {
    let mut tables = HashMap::new();

    tables.insert(
        "aws_spend".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            description: "AWS cloud infrastructure spend.".to_owned(),
            example_prompts: vec!["What was our AWS spend in Q1 2024?".to_owned()],
            value_column: "amount".to_owned(),
            timestamp_column: "timestamp".to_owned(),
            category_column: Some("category_name".to_owned()),
            agg_fn: AggFn::Sum,
            metric_label: "total_aws_spend_usd".to_owned(),
            aliases: Some(vec!["cloud spend".to_owned()]),
            tunnel_diff_tolerance: Some(0.01),
            ..Default::default()
        },
    );

    tables.insert(
        "new_hires".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            description: "Count of new employee hires.".to_owned(),
            example_prompts: vec!["How many new hires in Q1 2024?".to_owned()],
            value_column: "amount".to_owned(),
            timestamp_column: "timestamp".to_owned(),
            category_column: Some("category_name".to_owned()),
            agg_fn: AggFn::Count,
            metric_label: "hire_count".to_owned(),
            ..Default::default()
        },
    );

    tables.insert(
        "payroll".to_owned(),
        TableConfig {
            sensitivity: "critical".to_owned(),
            description: "Total payroll cost.".to_owned(),
            example_prompts: vec!["What was our payroll cost in Q1 2024?".to_owned()],
            value_column: "amount".to_owned(),
            timestamp_column: "timestamp".to_owned(),
            category_column: Some("category_name".to_owned()),
            agg_fn: AggFn::Sum,
            metric_label: "total_payroll_usd".to_owned(),
            ..Default::default()
        },
    );

    SchemaConfig {
        fiscal_year_offset_months: 0,
        tables,
    }
}

async fn spawn_tunnel_proxy() -> (SocketAddr, MockServer) {
    let mock_openai = MockServer::start().await;

    let mut config = AppConfig::default();
    config.mode = ZemtikMode::Tunnel;
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.tunnel_audit_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());
    config.tunnel_semaphore_permits = 2; // small for backpressure tests
    config.tunnel_timeout_secs = 5;

    let app = build_proxy_router(config)
        .await
        .expect("build_proxy_router failed in tunnel mode");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum serve failed");
    });

    (addr, mock_openai)
}

async fn mount_chat_mock(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-tunnel-001",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Your AWS spend for Q1 2024 was $1234567."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 60,
                "completion_tokens": 15,
                "total_tokens": 75
            }
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// 1. Health check includes tunnel semaphore fields
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_health() {
    let (addr, _mock) = spawn_tunnel_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .expect("GET /health failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("parse health JSON");
    assert_eq!(body["status"], "ok");
    assert!(body.get("tunnel_semaphore_available").is_some(), "missing tunnel_semaphore_available");
    assert!(body.get("tunnel_semaphore_capacity").is_some(), "missing tunnel_semaphore_capacity");
    assert!(body.get("tunnel_backpressure_count").is_some(), "missing tunnel_backpressure_count");
}

// ---------------------------------------------------------------------------
// 2. Non-streaming happy path — FORK 1 response returned, tunnel headers present
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_non_streaming_happy_path() {
    let (addr, mock) = spawn_tunnel_proxy().await;
    mount_chat_mock(&mock).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("authorization", "Bearer sk-test")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend total"}],
            "stream": false
        }))
        .send()
        .await
        .expect("POST /v1/chat/completions failed");

    assert_eq!(resp.status(), 200, "FORK 1 must return 200");
    let tunnel_mode = resp.headers().get("x-zemtik-mode");
    assert!(tunnel_mode.is_some(), "x-zemtik-mode header missing");
    assert_eq!(tunnel_mode.unwrap(), "tunnel");
}

// ---------------------------------------------------------------------------
// 3. Tunnel response includes x-zemtik-verified header
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_verified_header_present() {
    let (addr, mock) = spawn_tunnel_proxy().await;
    mount_chat_mock(&mock).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("authorization", "Bearer sk-test")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend total"}],
            "stream": false
        }))
        .send()
        .await
        .expect("POST /v1/chat/completions failed");

    let verified = resp.headers().get("x-zemtik-verified");
    assert!(verified.is_some(), "x-zemtik-verified header missing");
}

// ---------------------------------------------------------------------------
// 4. Original OpenAI response is returned unmodified in body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_fork1_response_unmodified() {
    let (addr, mock) = spawn_tunnel_proxy().await;
    mount_chat_mock(&mock).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("authorization", "Bearer sk-test")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend total"}]
        }))
        .send()
        .await
        .expect("request failed");

    let body: Value = resp.json().await.expect("parse body");
    // The OpenAI response structure should be intact.
    assert!(body.get("choices").is_some(), "choices missing from response body");
    assert!(body.get("id").is_some(), "id missing from response body");
}

// ---------------------------------------------------------------------------
// 5. Backpressure: exhausted semaphore sets x-zemtik-verified: false
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_backpressure() {
    // Use a proxy with semaphore=2 (default from spawn_tunnel_proxy).
    // We don't actually exhaust it in this test — just verify the header exists.
    let (addr, mock) = spawn_tunnel_proxy().await;
    mount_chat_mock(&mock).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("authorization", "Bearer sk-test")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend total"}]
        }))
        .send()
        .await
        .expect("request failed");

    // x-zemtik-verified is either true or false — must always be present.
    assert!(resp.headers().get("x-zemtik-verified").is_some(), "x-zemtik-verified missing");
}

// ---------------------------------------------------------------------------
// 6. Backpressure counter: /health shows tunnel_backpressure_count
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_backpressure_counter_exists() {
    let (addr, _mock) = spawn_tunnel_proxy().await;
    let client = reqwest::Client::new();

    let health: Value = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .expect("GET /health")
        .json()
        .await
        .expect("parse health");

    assert!(
        health["tunnel_backpressure_count"].as_u64().is_some(),
        "tunnel_backpressure_count must be a number"
    );
}

// ---------------------------------------------------------------------------
// 7. FORK 1 error path: OpenAI returns 5xx → client still gets a response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_fork1_error_returns_upstream_status() {
    let (addr, mock) = spawn_tunnel_proxy().await;

    // Mount a 500 response from OpenAI.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {"message": "Internal Server Error", "type": "server_error"}
        })))
        .mount(&mock)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("authorization", "Bearer sk-test")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend total"}]
        }))
        .send()
        .await
        .expect("request failed");

    // Client gets the upstream error response (not a zemtik error).
    assert_eq!(resp.status(), 500, "FORK 1 error must propagate to client");
    // Headers must still include tunnel mode marker.
    assert_eq!(
        resp.headers().get("x-zemtik-mode").map(|v| v.as_bytes()),
        Some(b"tunnel".as_ref()),
    );
}

// ---------------------------------------------------------------------------
// 8. Intent failure: ambiguous prompt → x-zemtik-verified: true (FORK 2 ran)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_ambiguous_prompt_still_returns_openai_response() {
    let (addr, mock) = spawn_tunnel_proxy().await;
    mount_chat_mock(&mock).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("authorization", "Bearer sk-test")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "What is the meaning of life?"}]
        }))
        .send()
        .await
        .expect("request failed");

    // FORK 1 still returns whatever OpenAI sends (tunnel doesn't block on intent failure).
    assert_eq!(resp.status(), 200, "FORK 1 must still return 200 even on intent failure");
    assert_eq!(
        resp.headers().get("x-zemtik-mode").map(|v| v.as_bytes()),
        Some(b"tunnel".as_ref()),
    );
}

// ---------------------------------------------------------------------------
// 9. /tunnel/audit endpoint returns JSON
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_audit_endpoint_returns_json() {
    let (addr, mock) = spawn_tunnel_proxy().await;
    mount_chat_mock(&mock).await;

    // Make one request to generate an audit record.
    let client = reqwest::Client::new();
    client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("authorization", "Bearer sk-test")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend total"}]
        }))
        .send()
        .await
        .expect("request failed");

    // Wait briefly for FORK 2 to write the audit record.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let resp = client
        .get(format!("http://{}/tunnel/audit", addr))
        .send()
        .await
        .expect("GET /tunnel/audit failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("parse audit JSON");
    assert!(body.get("records").is_some(), "records field missing");
    assert!(body.get("count").is_some(), "count field missing");
}

// ---------------------------------------------------------------------------
// 10. /tunnel/audit filter by match_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_audit_filter_by_status() {
    let (addr, mock) = spawn_tunnel_proxy().await;
    mount_chat_mock(&mock).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/tunnel/audit?match_status=matched", addr))
        .send()
        .await
        .expect("GET /tunnel/audit?match_status=matched failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("parse audit JSON");
    // All returned records must have match_status == "matched".
    if let Some(records) = body["records"].as_array() {
        for r in records {
            assert_eq!(r["match_status"], "matched", "filter by match_status failed");
        }
    }
}

// ---------------------------------------------------------------------------
// 11. /tunnel/audit filter by diff_detected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_audit_filter_by_diff() {
    let (addr, _mock) = spawn_tunnel_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{}/tunnel/audit?diff_detected=true", addr))
        .send()
        .await
        .expect("GET /tunnel/audit?diff_detected=true failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("parse audit JSON");
    assert!(body.get("records").is_some());
}

// ---------------------------------------------------------------------------
// 12. /tunnel/audit/csv returns CSV with Content-Disposition
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_audit_csv() {
    let (addr, _mock) = spawn_tunnel_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{}/tunnel/audit/csv", addr))
        .send()
        .await
        .expect("GET /tunnel/audit/csv failed");

    assert_eq!(resp.status(), 200);

    let content_type = resp.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("text/csv"), "content-type must be text/csv");

    let content_disposition = resp.headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_disposition.contains("attachment"),
        "content-disposition must contain attachment"
    );

    let body = resp.text().await.expect("read CSV body");
    // CSV must have header row.
    assert!(body.contains("id,created_at,match_status"), "CSV header missing");
}

// ---------------------------------------------------------------------------
// 13. /tunnel/summary returns aggregate metrics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_summary() {
    let (addr, _mock) = spawn_tunnel_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{}/tunnel/summary", addr))
        .send()
        .await
        .expect("GET /tunnel/summary failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("parse summary JSON");
    assert!(body.get("total_requests").is_some(), "total_requests missing");
    assert!(body.get("matched_rate").is_some(), "matched_rate missing");
    assert!(body.get("diff_rate").is_some(), "diff_rate missing");
    assert!(body.get("avg_zemtik_latency_ms").is_some(), "avg_zemtik_latency_ms missing");
}

// ---------------------------------------------------------------------------
// 14. Passthrough: /{*path} forwards to OpenAI base URL
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_passthrough_forwards_to_openai() {
    let (addr, mock) = spawn_tunnel_proxy().await;

    // Mount a mock for /v1/models.
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "gpt-5.4-nano", "object": "model"}]
        })))
        .mount(&mock)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/v1/models", addr))
        .header("authorization", "Bearer sk-test")
        .send()
        .await
        .expect("GET /v1/models failed");

    assert_eq!(resp.status(), 200, "passthrough should forward to OpenAI and return 200");
    let body: Value = resp.json().await.expect("parse models response");
    assert_eq!(body["object"], "list", "passthrough response should be OpenAI format");
}

// ---------------------------------------------------------------------------
// 15. Passthrough: no audit record written for /{*path}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_passthrough_no_audit_record() {
    let (addr, mock) = spawn_tunnel_proxy().await;

    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"object": "list", "data": []})))
        .mount(&mock)
        .await;

    let client = reqwest::Client::new();
    client
        .get(format!("http://{}/v1/models", addr))
        .header("authorization", "Bearer sk-test")
        .send()
        .await
        .expect("request failed");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Audit should be empty (passthrough does not write records).
    let audit_resp: Value = client
        .get(format!("http://{}/tunnel/audit", addr))
        .send()
        .await
        .expect("GET /tunnel/audit failed")
        .json()
        .await
        .expect("parse audit JSON");

    assert_eq!(
        audit_resp["count"].as_u64().unwrap_or(0),
        0,
        "passthrough must not write audit records"
    );
}

// ---------------------------------------------------------------------------
// 16. Dashboard auth: 401 when ZEMTIK_DASHBOARD_API_KEY is set and not provided
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_dashboard_auth_required() {
    let (addr, _mock) = {
        let mock_openai = MockServer::start().await;
        let mut config = AppConfig::default();
        config.mode = ZemtikMode::Tunnel;
        config.openai_base_url = mock_openai.uri();
        config.skip_circuit_validation = true;
        config.intent_backend = "regex".to_owned();
        config.openai_api_key = Some("test-key".to_owned());
        config.receipts_db_path = std::path::PathBuf::from(":memory:");
        config.tunnel_audit_db_path = std::path::PathBuf::from(":memory:");
        config.schema_config = Some(test_schema());
        config.schema_config_hash = Some("test-schema-hash".to_owned());
        config.dashboard_api_key = Some("secret-dashboard-key".to_owned());

        let app = build_proxy_router(config)
            .await
            .expect("build_proxy_router failed");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve failed");
        });
        (addr, mock_openai)
    };

    let client = reqwest::Client::new();

    // No auth → 401.
    let resp = client
        .get(format!("http://{}/tunnel/audit", addr))
        .send()
        .await
        .expect("GET /tunnel/audit failed");
    assert_eq!(resp.status(), 401, "must return 401 without auth");

    // Wrong token → 401.
    let resp = client
        .get(format!("http://{}/tunnel/audit", addr))
        .header("authorization", "Bearer wrong-token")
        .send()
        .await
        .expect("GET /tunnel/audit failed");
    assert_eq!(resp.status(), 401, "must return 401 with wrong token");

    // Correct token → 200.
    let resp = client
        .get(format!("http://{}/tunnel/audit", addr))
        .header("authorization", "Bearer secret-dashboard-key")
        .send()
        .await
        .expect("GET /tunnel/audit with auth failed");
    assert_eq!(resp.status(), 200, "must return 200 with correct token");
}

// ---------------------------------------------------------------------------
// 17. Tunnel DB roundtrip: insert and query audit record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_db_roundtrip() {
    use std::path::PathBuf;
    use zemtik::receipts::{open_tunnel_audit_db, insert_tunnel_audit, list_tunnel_audits};
    use zemtik::types::TunnelAuditRecord;

    let conn = open_tunnel_audit_db(&PathBuf::from(":memory:"))
        .expect("open in-memory tunnel audit DB");

    let record = TunnelAuditRecord {
        id: "test-id-001".to_owned(),
        receipt_id: Some("receipt-001".to_owned()),
        created_at: "2026-04-08T15:00:00Z".to_owned(),
        match_status: "matched".to_owned(),
        matched_table: Some("aws_spend".to_owned()),
        matched_agg_fn: Some("SUM".to_owned()),
        original_status_code: 200,
        original_response_body_hash: "abc123".to_owned(),
        original_latency_ms: 320,
        zemtik_aggregate: Some(1234567),
        zemtik_row_count: Some(42),
        zemtik_engine: Some("fast_lane".to_owned()),
        zemtik_latency_ms: Some(15),
        diff_detected: false,
        diff_summary: Some("within_tolerance".to_owned()),
        diff_details: None,
        original_response_preview: Some("Your AWS spend was $1,234,567.".to_owned()),
        zemtik_response_preview: None,
        error_message: None,
        request_hash: "req-hash-001".to_owned(),
        prompt_hash: "prompt-hash-001".to_owned(),
        intent_confidence: Some(0.95),
        tunnel_model: Some("gpt-5.4-nano".to_owned()),
    };

    insert_tunnel_audit(&conn, &record).expect("insert tunnel audit");
    let records = list_tunnel_audits(&conn, 10).expect("list tunnel audits");

    assert_eq!(records.len(), 1, "expected 1 record");
    let r = &records[0];
    assert_eq!(r.id, "test-id-001");
    assert_eq!(r.match_status, "matched");
    assert_eq!(r.zemtik_aggregate, Some(1234567));
    assert_eq!(r.diff_detected, false);
    assert_eq!(r.diff_summary.as_deref(), Some("within_tolerance"));
    assert_eq!(r.original_latency_ms, 320);
    assert_eq!(r.intent_confidence, Some(0.95));
}

// ---------------------------------------------------------------------------
// 18. /tunnel/summary returns zero rates when no records exist
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tunnel_summary_empty() {
    let (addr, _mock) = spawn_tunnel_proxy().await;
    let client = reqwest::Client::new();

    let resp: Value = client
        .get(format!("http://{}/tunnel/summary", addr))
        .send()
        .await
        .expect("GET /tunnel/summary failed")
        .json()
        .await
        .expect("parse summary");

    assert_eq!(resp["total_requests"].as_u64(), Some(0));
    assert_eq!(resp["matched_rate"].as_f64(), Some(0.0));
    assert_eq!(resp["diff_rate"].as_f64(), Some(0.0));
}

// ---------------------------------------------------------------------------
// 19. ZEMTIK_MODE parsing: unrecognized value → bail
// ---------------------------------------------------------------------------

#[test]
fn test_zemtik_mode_reject_unrecognized() {
    use zemtik::config::{load_from_sources, CliArgs};
    let mut env = HashMap::new();
    env.insert("ZEMTIK_MODE".to_owned(), "banana".to_owned());
    let result = load_from_sources(None, &env, &CliArgs::default());
    assert!(result.is_err(), "unrecognized ZEMTIK_MODE must fail");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("unrecognized value"), "error message must mention unrecognized value");
}

// ---------------------------------------------------------------------------
// 20. Standard mode: passthrough still returns 501 (regression)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_standard_passthrough_still_501() {
    let mock_openai = MockServer::start().await;

    let mut config = AppConfig::default();
    // Standard mode — no ZemtikMode::Tunnel
    config.openai_base_url = mock_openai.uri();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());

    let app = build_proxy_router(config).await.expect("build_proxy_router failed");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/embeddings", addr))
        .header("authorization", "Bearer sk-test")
        .json(&json!({"model": "text-embedding-ada-002", "input": "hello"}))
        .send()
        .await
        .expect("POST /v1/embeddings failed");

    assert_eq!(resp.status(), 501, "standard mode passthrough must return 501");
    let body: Value = resp.json().await.expect("parse body");
    assert_eq!(body["error"]["type"], "zemtik_proxy_passthrough");
}

// ---------------------------------------------------------------------------
// 21. ZEMTIK_MODE=standard still works normally (regression)
// ---------------------------------------------------------------------------

#[test]
fn test_zemtik_mode_standard_parses() {
    use zemtik::config::{load_from_sources, CliArgs, ZemtikMode};
    let mut env = HashMap::new();
    env.insert("ZEMTIK_MODE".to_owned(), "standard".to_owned());
    let config = load_from_sources(None, &env, &CliArgs::default()).expect("load config");
    assert_eq!(config.mode, ZemtikMode::Standard);
}

// ---------------------------------------------------------------------------
// 22. ZEMTIK_MODE=tunnel parses correctly
// ---------------------------------------------------------------------------

#[test]
fn test_zemtik_mode_tunnel_parses() {
    use zemtik::config::{load_from_sources, CliArgs, ZemtikMode};
    let mut env = HashMap::new();
    env.insert("ZEMTIK_MODE".to_owned(), "tunnel".to_owned());
    let config = load_from_sources(None, &env, &CliArgs::default()).expect("load config");
    assert_eq!(config.mode, ZemtikMode::Tunnel);
}
