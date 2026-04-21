/// Integration tests for the Zemtik proxy.
///
/// These tests spin up a real Axum server on an ephemeral port, backed by in-memory SQLite,
/// and a wiremock server standing in for OpenAI. They test the full request/response cycle
/// without requiring nargo, bb, or the ONNX embedding model.
///
/// Run with:
///   cargo test --test integration_proxy --no-default-features --features regex-only
use std::collections::HashMap;
use std::net::SocketAddr;

use serde_json::{json, Value};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zemtik::config::{AggFn, AppConfig, SchemaConfig, TableConfig};
use zemtik::proxy::build_proxy_router;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal in-memory SchemaConfig with three test tables:
/// - `aws_spend`   (low sensitivity, SUM)  — FastLane
/// - `new_hires`   (low sensitivity, COUNT) — FastLane
/// - `payroll`     (critical, SUM)          — ZK SlowLane (skipped in non-ZK tests)
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

/// Spin up a zemtik proxy on an ephemeral port with in-memory SQLite and a wiremock
/// OpenAI server. Returns `(proxy_addr, mock_openai_server)`.
///
/// The mock_openai_server must be kept alive for the duration of the test.
async fn spawn_test_proxy() -> (SocketAddr, MockServer) {
    let mock_openai = MockServer::start().await;

    let mut config = AppConfig::default();
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    // Use in-memory receipts DB so parallel test instances don't contend on ~/.zemtik/receipts.db
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    // Inline schema — no file dependency
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());

    let app = build_proxy_router(config)
        .await
        .expect("build_proxy_router failed");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum serve failed");
    });

    (addr, mock_openai)
}

/// Mount a mock OpenAI chat completions endpoint that returns a valid response.
async fn mount_openai_chat_mock(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-test-001",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Your AWS spend was within budget for Q1 2024."
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
// Tests
// ---------------------------------------------------------------------------

/// GET /health returns 200 with a status field.
#[tokio::test]
async fn health_returns_200() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .expect("health request failed");

    assert_eq!(resp.status(), 200, "expected 200 from /health");
    let body: Value = resp.json().await.expect("health response not JSON");
    assert!(
        body.get("status").is_some(),
        "health response missing 'status' field: {body}"
    );
}

/// POST /v1/chat/completions with a low-sensitivity SUM table:
/// - HTTP 200
/// - x-zemtik-engine: fast_lane
/// - evidence.attestation_hash is non-null
/// - evidence.proof_hash is null (FastLane produces no ZK proof)
/// - evidence.data_exfiltrated == 0
#[tokio::test]
async fn fast_lane_sum_roundtrip() {
    let (addr, mock_openai) = spawn_test_proxy().await;
    mount_openai_chat_mock(&mock_openai).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend total"}]
        }))
        .send()
        .await
        .expect("POST /v1/chat/completions failed");

    assert_eq!(resp.status(), 200, "expected 200 for FastLane SUM");

    let engine = resp
        .headers()
        .get("x-zemtik-engine")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert_eq!(engine, "fast_lane", "expected x-zemtik-engine: fast_lane");

    let body: Value = resp.json().await.expect("response not JSON");
    let evidence = &body["evidence"];
    assert!(
        !evidence.is_null(),
        "response missing 'evidence' field: {body}"
    );
    assert!(
        !evidence["attestation_hash"].is_null(),
        "FastLane evidence.attestation_hash must be non-null"
    );
    assert!(
        evidence["proof_hash"].is_null(),
        "FastLane evidence.proof_hash must be null (no ZK proof)"
    );
    assert_eq!(
        evidence["data_exfiltrated"], 0,
        "evidence.data_exfiltrated must be 0"
    );
}

/// POST /v1/chat/completions with a low-sensitivity COUNT table:
/// - HTTP 200
/// - x-zemtik-engine: fast_lane
#[tokio::test]
async fn fast_lane_count_roundtrip() {
    let (addr, mock_openai) = spawn_test_proxy().await;
    mount_openai_chat_mock(&mock_openai).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 new_hires count"}]
        }))
        .send()
        .await
        .expect("POST /v1/chat/completions failed");

    assert_eq!(resp.status(), 200, "expected 200 for FastLane COUNT");

    let engine = resp
        .headers()
        .get("x-zemtik-engine")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert_eq!(engine, "fast_lane", "expected x-zemtik-engine: fast_lane");
}

/// POST /v1/embeddings returns 501 (passthrough — only /v1/chat/completions is intercepted).
#[tokio::test]
async fn passthrough_returns_501() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/embeddings", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({"model": "text-embedding-3-small", "input": "hello"}))
        .send()
        .await
        .expect("POST /v1/embeddings failed");

    assert_eq!(resp.status(), 501, "expected 501 for passthrough route");

    let body: Value = resp.json().await.expect("response not JSON");
    assert_eq!(
        body["error"]["type"], "zemtik_proxy_passthrough",
        "unexpected error type: {body}"
    );
}

/// POST with empty user content returns 400.
#[tokio::test]
async fn empty_prompt_returns_400() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": ""}]
        }))
        .send()
        .await
        .expect("POST with empty prompt failed");

    assert_eq!(resp.status(), 400, "expected 400 for empty prompt");
}

/// POST with a prompt that matches no known table returns 400 (intent rejection).
#[tokio::test]
async fn ambiguous_prompt_returns_400() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "tell me a joke"}]
        }))
        .send()
        .await
        .expect("POST with ambiguous prompt failed");

    assert_eq!(
        resp.status(),
        400,
        "expected 400 (intent rejection) for prompt with no matching table"
    );

    let body: Value = resp.json().await.expect("response not JSON");
    assert_eq!(
        body["error"]["type"], "zemtik_intent_error",
        "unexpected error type: {body}"
    );
    assert_eq!(
        body["error"]["code"], "NoTableIdentified",
        "expected error.code == NoTableIdentified: {body}"
    );
    assert!(
        body["error"]["hint"].is_string(),
        "error.hint must be present: {body}"
    );
}

/// FastLane engine: proof_hash is null and attestation_hash is non-null.
/// Explicitly tests the FastLane/ZK distinction in evidence fields.
#[tokio::test]
async fn fast_lane_evidence_fields_are_correct() {
    let (addr, mock_openai) = spawn_test_proxy().await;
    mount_openai_chat_mock(&mock_openai).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend"}]
        }))
        .send()
        .await
        .expect("request failed");

    let body: Value = resp.json().await.expect("response not JSON");
    let evidence = &body["evidence"];

    // Presence checks
    assert!(
        !evidence["receipt_id"].is_null(),
        "evidence.receipt_id must be present"
    );
    assert!(
        !evidence["timestamp"].is_null(),
        "evidence.timestamp must be present"
    );
    assert_eq!(
        evidence["engine_used"], "fast_lane",
        "evidence.engine_used must be 'fast_lane'"
    );
    assert_eq!(
        evidence["privacy_model"], "architectural_isolation",
        "evidence.privacy_model must be 'architectural_isolation'"
    );

    // FastLane: attestation present, proof absent
    assert!(
        !evidence["attestation_hash"].is_null(),
        "FastLane must have attestation_hash"
    );
    assert!(
        evidence["proof_hash"].is_null(),
        "FastLane must NOT have proof_hash"
    );

    // Evidence Pack v3 fields
    assert_eq!(
        evidence["evidence_version"], 3,
        "evidence_version must be 3 (v3)"
    );
    assert!(
        evidence["human_summary"].is_string() && !evidence["human_summary"].as_str().unwrap_or("").is_empty(),
        "evidence.human_summary must be a non-empty string, got: {:?}",
        evidence["human_summary"]
    );
    assert!(
        evidence["checks_performed"].is_array() && !evidence["checks_performed"].as_array().unwrap().is_empty(),
        "evidence.checks_performed must be a non-empty array, got: {:?}",
        evidence["checks_performed"]
    );
}

/// stream:true in standard mode → HTTP 400 with StreamingNotSupported code.
#[tokio::test]
async fn streaming_guard_returns_400_in_standard_mode() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "stream": true,
            "messages": [{"role": "user", "content": "Q1 2024 aws_spend"}]
        }))
        .send()
        .await
        .expect("streaming request failed");

    assert_eq!(resp.status(), 400, "stream:true must return 400 in standard mode");

    let body: Value = resp.json().await.expect("response not JSON");
    assert_eq!(
        body["error"]["code"], "StreamingNotSupported",
        "expected error.code == StreamingNotSupported: {body}"
    );
    assert_eq!(
        body["error"]["type"], "zemtik_config_error",
        "expected error.type == zemtik_config_error: {body}"
    );
    assert!(body["error"]["hint"].is_string(), "error.hint must be present: {body}");
}

/// /health response must include schema_validation field.
#[tokio::test]
async fn health_includes_schema_validation_field() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .expect("health request failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("health response not JSON");
    assert!(
        body.get("schema_validation").is_some(),
        "/health must include schema_validation field: {body}"
    );
    let sv = &body["schema_validation"];
    assert!(sv["status"].is_string(), "schema_validation.status must be a string: {body}");
    assert!(sv["skipped"].is_boolean(), "schema_validation.skipped must be bool: {body}");
}

/// startup_validation_skipped_when_env_set: ZEMTIK_SKIP_DB_VALIDATION=1
/// → /health schema_validation.status == "skipped".
/// Uses #[serial] because std::env::set_var/remove_var is not safe under parallel test execution.
#[tokio::test]
#[serial_test::serial]
async fn startup_validation_skipped_when_env_set() {
    std::env::set_var("ZEMTIK_SKIP_DB_VALIDATION", "1");
    let (addr, _mock) = spawn_test_proxy().await;
    std::env::remove_var("ZEMTIK_SKIP_DB_VALIDATION");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .expect("health request failed");

    let body: Value = resp.json().await.expect("health response not JSON");
    assert_eq!(
        body["schema_validation"]["status"], "skipped",
        "schema_validation.status must be 'skipped' when ZEMTIK_SKIP_DB_VALIDATION=1: {body}"
    );
    assert_eq!(
        body["schema_validation"]["skipped"], true,
        "schema_validation.skipped must be true: {body}"
    );
}

/// structured_error_has_code_hint_doc_url: ambiguous prompt → 400 with code/hint/doc_url.
#[tokio::test]
async fn structured_error_has_code_hint_doc_url() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "summarize my emails from last week"}]
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.expect("response not JSON");
    let err = &body["error"];
    assert!(err["code"].is_string(), "error.code must be present: {body}");
    assert!(err["hint"].is_string(), "error.hint must be present: {body}");
    assert!(err["doc_url"].is_string(), "error.doc_url must be present: {body}");
}

// ---------------------------------------------------------------------------
// Rewriter helpers
// ---------------------------------------------------------------------------

/// Spin up a zemtik proxy with ZEMTIK_QUERY_REWRITER=1 enabled.
/// Both the main OpenAI completion and the rewriter LLM share the same mock server.
///
/// Rewriter calls are distinguished from main completion calls by the presence of
/// "AVAILABLE TABLES" in the request body (injected by the hardened rewriter prompt).
async fn spawn_test_proxy_with_rewriter() -> (SocketAddr, MockServer) {
    let mock_openai = MockServer::start().await;

    let mut config = AppConfig::default();
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());

    // Enable the hybrid rewriter.
    config.query_rewriter_enabled = true;
    config.query_rewriter_model = "gpt-5.4-nano".to_owned();
    config.query_rewriter_context_turns = 6;
    config.query_rewriter_scan_messages = 5;
    config.query_rewriter_timeout_secs = 10;
    config.query_rewriter_max_context_tokens = 2000;

    let app = build_proxy_router(config)
        .await
        .expect("build_proxy_router failed");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum serve failed");
    });

    (addr, mock_openai)
}

// ---------------------------------------------------------------------------
// Multi-turn integration tests
// ---------------------------------------------------------------------------

/// Deterministic time-pivot: a two-turn conversation where the follow-up provides
/// only a time expression ("How about Q2 2024?"). deterministic_resolve must carry
/// the `aws_spend` table from the prior turn and apply the new time range.
///
/// Expected: HTTP 200, `rewrite_method: "deterministic"` in the evidence envelope.
/// The mock OpenAI server is called exactly once (main completion), never by the rewriter.
#[tokio::test]
async fn multi_turn_deterministic_time_pivot_integration() {
    let (addr, mock_openai) = spawn_test_proxy_with_rewriter().await;

    // Main completion mock — matches requests that do NOT contain "AVAILABLE TABLES"
    // (i.e. the normal chat completion, not the rewriter LLM call).
    // The rewriter does NOT call OpenAI for the deterministic path, so this mock
    // should be hit exactly once (for the follow-up that resolves deterministically).
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-deterministic-test",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{"index": 0, "message": {"role": "assistant",
                "content": "AWS spend in Q2 2024 was within budget."}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 12, "total_tokens": 62}
        })))
        .mount(&mock_openai)
        .await;

    let client = reqwest::Client::new();

    // Turn 1: explicit table + time — succeeds directly (no rewriter involved).
    let resp1 = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "aws_spend in Q1 2024"}]
        }))
        .send()
        .await
        .expect("turn-1 request failed");
    assert_eq!(resp1.status(), 200, "turn-1 must succeed: {}", resp1.status());

    // Turn 2: follow-up with only a time expression — intent extraction fails on its own,
    // but deterministic_resolve carries `aws_spend` from the prior turn and applies Q2 2024.
    let resp2 = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [
                {"role": "user",    "content": "aws_spend in Q1 2024"},
                {"role": "assistant","content": "AWS spend in Q1 2024 was $12,345."},
                {"role": "user",    "content": "How about Q2 2024?"}
            ]
        }))
        .send()
        .await
        .expect("turn-2 request failed");

    assert_eq!(resp2.status(), 200, "turn-2 must succeed via deterministic rewriter");

    let body: Value = resp2.json().await.expect("turn-2 body not JSON");

    // The evidence envelope is injected as body["evidence"] (see build_fast_lane_response).
    let rewrite_method = body
        .get("evidence")
        .and_then(|ev| ev.get("rewrite_method"))
        .and_then(|m| m.as_str());

    assert_eq!(
        rewrite_method,
        Some("deterministic"),
        "expected rewrite_method: deterministic in evidence envelope, body: {body}"
    );
}

/// LLM rewrite path: a three-turn conversation where the prior user message has a
/// table keyword but NO explicit time (rejected by Fix-0 in deterministic_resolve),
/// and the follow-up adds only a time expression ("For Q1 2024 specifically").
///
/// deterministic_resolve rejects the prior (no explicit time) and returns None,
/// so the LLM rewriter fires. The mock LLM returns a self-contained query naming
/// both table and time; intent extraction then succeeds.
///
/// The mock distinguishes rewriter calls from main completions by checking for
/// "AVAILABLE TABLES" in the request body (present only in the rewriter system prompt).
///
/// Expected: HTTP 200, `rewrite_method: "llm"` in the evidence envelope.
#[tokio::test]
async fn multi_turn_llm_table_switch_integration() {
    let (addr, mock_openai) = spawn_test_proxy_with_rewriter().await;

    // Rewriter LLM mock: request body contains "AVAILABLE TABLES" (injected by
    // the hardened rewriter prompt). Returns a self-contained aws_spend query so
    // that intent extraction succeeds on a FastLane (low-sensitivity) table.
    //
    // Pattern: body_string_contains("AVAILABLE TABLES") identifies rewriter calls.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_string_contains("AVAILABLE TABLES"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-rewriter-call",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{"index": 0, "message": {"role": "assistant",
                "content": "What was aws_spend in Q1 2024?"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 80, "completion_tokens": 9, "total_tokens": 89}
        })))
        .mount(&mock_openai)
        .await;

    // Main completion mock: all other POST requests (no "AVAILABLE TABLES" in body).
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-main-completion",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{"index": 0, "message": {"role": "assistant",
                "content": "AWS spend in Q1 2024 was $12,345."}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 60, "completion_tokens": 10, "total_tokens": 70}
        })))
        .mount(&mock_openai)
        .await;

    let client = reqwest::Client::new();

    // The conversation to send: prior user message has aws_spend but NO explicit
    // time — Fix-0 rejects it in deterministic_resolve because
    // parse_time_range_explicit returns Ok(None) for "How is our aws_spend doing?".
    // The follow-up "For Q1 2024 specifically" has explicit time but no table name.
    //
    // Flow: intent fails on "For Q1 2024 specifically" (no table) →
    //   deterministic_resolve scans prior → prior has no explicit time → None →
    //   LLM fires → "What was aws_spend in Q1 2024?" → intent succeeds → FastLane.
    let resp3 = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [
                {"role": "user",    "content": "How is our aws_spend doing in general?"},
                {"role": "assistant","content": "I need a time period to answer that."},
                {"role": "user",    "content": "For Q1 2024 specifically"}
            ]
        }))
        .send()
        .await
        .expect("turn-3 failed");

    assert_eq!(resp3.status(), 200, "turn-3 must succeed via LLM rewriter");

    let body: Value = resp3.json().await.expect("turn-3 body not JSON");
    let rewrite_method = body
        .get("evidence")
        .and_then(|ev| ev.get("rewrite_method"))
        .and_then(|m| m.as_str());

    assert_eq!(
        rewrite_method,
        Some("llm"),
        "expected rewrite_method: llm in evidence envelope, body: {body}"
    );
}

// ---------------------------------------------------------------------------
// GeneralLane helpers
// ---------------------------------------------------------------------------

/// Spin up a zemtik proxy with ZEMTIK_GENERAL_PASSTHROUGH=1.
/// `max_rpm=0` means unlimited (default behavior).
async fn spawn_test_proxy_with_general_passthrough(max_rpm: u32) -> (SocketAddr, MockServer) {
    let mock_openai = MockServer::start().await;

    let mut config = AppConfig::default();
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());

    config.general_passthrough_enabled = true;
    config.general_max_rpm = max_rpm;

    let app = build_proxy_router(config)
        .await
        .expect("build_proxy_router failed");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum serve failed");
    });

    (addr, mock_openai)
}

// ---------------------------------------------------------------------------
// GeneralLane integration tests
// ---------------------------------------------------------------------------

/// Regression: when ZEMTIK_GENERAL_PASSTHROUGH is unset, a non-data prompt still
/// returns 400 NoTableIdentified — existing behavior unchanged.
#[tokio::test]
async fn general_passthrough_disabled_returns_400_no_table() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Can you explain machine learning?"}]
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "NoTableIdentified");
}

/// GeneralLane happy path: a non-data prompt with ZEMTIK_GENERAL_PASSTHROUGH=1 returns
/// 200 with a zemtik_meta body field, X-Zemtik-Engine header, and X-Zemtik-Meta header.
#[tokio::test]
async fn general_passthrough_enabled_forwards_non_data_query() {
    let (addr, mock_openai) = spawn_test_proxy_with_general_passthrough(0).await;
    mount_openai_chat_mock(&mock_openai).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Can you explain machine learning to me?"}]
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200, "GeneralLane must return 200");

    // X-Zemtik-Engine header present.
    assert_eq!(
        resp.headers().get("x-zemtik-engine").and_then(|v| v.to_str().ok()),
        Some("general_lane"),
        "X-Zemtik-Engine must be general_lane"
    );

    // X-Zemtik-Meta header present.
    assert!(
        resp.headers().contains_key("x-zemtik-meta"),
        "X-Zemtik-Meta header must be present"
    );

    let body: Value = resp.json().await.expect("body not JSON");

    // zemtik_meta injected into body.
    let meta = &body["zemtik_meta"];
    assert_eq!(meta["engine_used"], "general_lane");
    assert_eq!(meta["zk_coverage"], "none");
    assert_eq!(meta["reason"], "no_table_match");
    assert!(
        meta["receipt_id"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "receipt_id must be a non-empty string"
    );

    // Original OpenAI response fields preserved.
    assert!(body["choices"].is_array(), "choices must be present");
}

/// GeneralLane must not intercept data queries — FastLane handles them normally
/// and X-Zemtik-Engine returns fast_lane.
#[tokio::test]
async fn general_passthrough_does_not_affect_data_queries() {
    let (addr, mock_openai) = spawn_test_proxy_with_general_passthrough(0).await;
    mount_openai_chat_mock(&mock_openai).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "What was the total aws_spend in Q1 2024?"}]
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200, "data query must still return 200");
    assert_eq!(
        resp.headers().get("x-zemtik-engine").and_then(|v| v.to_str().ok()),
        Some("fast_lane"),
        "data query must route via FastLane"
    );
}

/// Streaming guard still returns 400 when ZEMTIK_GENERAL_PASSTHROUGH is NOT set.
/// Regression for the existing streaming_guard_returns_400_in_standard_mode test.
#[tokio::test]
async fn streaming_still_400_without_general_passthrough() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "stream": true,
            "messages": [{"role": "user", "content": "What was Q1 2024 aws_spend?"}]
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "StreamingNotSupported");
}

/// When ZEMTIK_GENERAL_PASSTHROUGH=1 and stream:true is sent with a data query
/// (intent succeeds → data lane), it must still return 400 StreamingNotSupported.
#[tokio::test]
async fn general_passthrough_blocks_streaming_for_data_queries() {
    let (addr, _mock) = spawn_test_proxy_with_general_passthrough(0).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "stream": true,
            "messages": [{"role": "user", "content": "What was Q1 2024 aws_spend?"}]
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "StreamingNotSupported");
}

/// FastLane responses now include X-Zemtik-Engine: fast_lane header.
#[tokio::test]
async fn fast_lane_has_x_zemtik_engine_header() {
    let (addr, mock_openai) = spawn_test_proxy().await;
    mount_openai_chat_mock(&mock_openai).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Total aws_spend Q1 2024"}]
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-zemtik-engine").and_then(|v| v.to_str().ok()),
        Some("fast_lane"),
        "FastLane must set X-Zemtik-Engine: fast_lane"
    );
}

/// /health response includes general_queries_today and intent_failures_today counters.
#[tokio::test]
async fn health_includes_general_lane_counters() {
    let (addr, _mock) = spawn_test_proxy().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .expect("health request failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("general_queries_today").is_some(),
        "health must include general_queries_today, body: {body}"
    );
    assert!(
        body.get("intent_failures_today").is_some(),
        "health must include intent_failures_today, body: {body}"
    );
}

/// GeneralLane rate limiter: with max_rpm=1, the second rapid request returns 429.
#[tokio::test]
async fn general_lane_rpm_budget_exceeded() {
    let (addr, mock_openai) = spawn_test_proxy_with_general_passthrough(1).await;
    mount_openai_chat_mock(&mock_openai).await;
    let client = reqwest::Client::new();

    let general_body = json!({
        "model": "gpt-5.4-nano",
        "messages": [{"role": "user", "content": "Explain cloud computing to me."}]
    });

    // First request — should be allowed (under limit).
    let resp1 = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&general_body)
        .send()
        .await
        .expect("request 1 failed");
    assert_eq!(resp1.status(), 200, "first request must be allowed");

    // Second request — same window, over limit.
    let resp2 = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&general_body)
        .send()
        .await
        .expect("request 2 failed");
    assert_eq!(resp2.status(), 429, "second request must be rate-limited");
    let body2: Value = resp2.json().await.unwrap();
    assert_eq!(body2["code"], "GeneralLaneBudgetExceeded");
}

// ---------------------------------------------------------------------------
// Anonymizer integration tests
// ---------------------------------------------------------------------------

/// Spawn a proxy with anonymizer disabled (default). Helper for anonymizer tests.
async fn spawn_test_proxy_anonymizer_disabled() -> (SocketAddr, MockServer) {
    spawn_test_proxy().await
}

/// Spawn a proxy with anonymizer enabled but no sidecar + fallback_regex=true.
/// Sidecar addr points to a non-existent port so gRPC will fail; regex picks up IDs.
async fn spawn_test_proxy_anonymizer_regex_fallback() -> (SocketAddr, MockServer) {
    let mock_openai = MockServer::start().await;

    let mut config = AppConfig::default();
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());
    config.general_passthrough_enabled = true;
    // Anonymizer enabled with a dead sidecar + fallback
    config.anonymizer_enabled = true;
    config.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned(); // dead port
    config.anonymizer_fallback_regex = true;
    config.anonymizer_entity_types = "EMAIL_ADDRESS,CO_CEDULA".to_owned();

    let app = build_proxy_router(config).await.expect("build failed");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, mock_openai)
}

/// Spawn a proxy with anonymizer enabled but fallback=false and dead sidecar → 503.
async fn spawn_test_proxy_anonymizer_fail_closed() -> (SocketAddr, MockServer) {
    let mock_openai = MockServer::start().await;

    let mut config = AppConfig::default();
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());
    config.general_passthrough_enabled = true;
    config.anonymizer_enabled = true;
    config.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned(); // dead port
    config.anonymizer_fallback_regex = false;

    let app = build_proxy_router(config).await.expect("build failed");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, mock_openai)
}

/// When anonymizer is disabled, the proxy starts and responds to /health normally.
#[tokio::test]
async fn anonymizer_disabled_is_noop() {
    let (addr, _mock_openai) = spawn_test_proxy_anonymizer_disabled().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "proxy with anonymizer disabled must be healthy");
}

/// Streaming + anonymizer enabled → 415.
#[tokio::test]
async fn anonymizer_streaming_returns_415() {
    let (addr, _mock_openai) = spawn_test_proxy_anonymizer_regex_fallback().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "stream": true,
            "messages": [{"role": "user", "content": "Hola"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 415);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "anonymizer_streaming_unsupported");
}

/// Sidecar down + fallback=false → 503 with SidecarUnreachable code.
#[tokio::test]
async fn anonymizer_sidecar_down_fail_closed_503() {
    let (addr, _mock) = spawn_test_proxy_anonymizer_fail_closed().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Cédula 79.123.456"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "anonymizer_unavailable");
    assert_eq!(body["error"]["code"], "SidecarUnreachable");
}

/// Sidecar down + fallback_regex=true: regex tokenizes email; request proceeds.
#[tokio::test]
async fn anonymizer_sidecar_down_fallback_regex_proceeds() {
    let (addr, mock_openai) = spawn_test_proxy_anonymizer_regex_fallback().await;
    // Mount mock that echoes back what it received so we can inspect outgoing body
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-anon-001",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Procesado."}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25}
        })))
        .mount(&mock_openai)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Contacto: usuario@empresa.com"}]
        }))
        .send()
        .await
        .unwrap();
    // Regex fallback succeeded → 200
    assert_eq!(resp.status(), 200);
}

/// /v1/anonymize/preview endpoint: returns anonymized messages + token list.
#[tokio::test]
async fn anonymizer_preview_endpoint_returns_tokens() {
    let (addr, _mock) = spawn_test_proxy_anonymizer_regex_fallback().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/anonymize/preview", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "messages": [{"role": "user", "content": "email: test@example.com"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("anonymized_messages").is_some(), "must have anonymized_messages: {body}");
    let tokens = body["tokens"].as_array().expect("tokens must be an array");
    let originals = body["originals"].as_array().expect("originals must be an array");
    let entity_types = body["entity_types"].as_array().expect("entity_types must be an array");
    assert_eq!(originals.len(), tokens.len(), "originals.len() must equal tokens.len()");
    assert_eq!(entity_types.len(), tokens.len(), "entity_types.len() must equal tokens.len()");
    for orig in originals {
        assert!(!orig.as_str().unwrap_or("").is_empty(), "each original must be non-empty");
    }
}

/// Anonymizer disabled: POST /v1/anonymize/preview must return 400.
#[tokio::test]
async fn anonymizer_preview_endpoint_disabled_returns_400() {
    let (addr, _mock) = spawn_test_proxy_anonymizer_disabled().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{}/v1/anonymize/preview", addr))
        .header("Authorization", "Bearer test-key")
        .json(&serde_json::json!({
            "messages": [{"role": "user", "content": "test@example.com"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "preview endpoint must return 400 when anonymizer is disabled");
}

/// debug_preview=true but sidecar not used (regex fallback): outgoing_preview must NOT be emitted
/// to avoid exposing PII not covered by the regex-only fallback (e.g. PERSON, ORG, LOCATION).
#[tokio::test]
async fn anonymizer_debug_preview_not_emitted_on_regex_fallback() {
    let mock_openai = MockServer::start().await;

    let mut config = AppConfig::default();
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());
    config.general_passthrough_enabled = true;
    config.anonymizer_enabled = true;
    config.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned(); // dead → regex fallback
    config.anonymizer_fallback_regex = true;
    config.anonymizer_entity_types = "EMAIL_ADDRESS".to_owned();
    config.anonymizer_debug_preview = true;

    mount_openai_chat_mock(&mock_openai).await;

    let app = build_proxy_router(config).await.expect("build failed");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&serde_json::json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "email: alice@example.com"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let preview = body
        .pointer("/zemtik_meta/anonymizer/outgoing_preview");
    assert!(preview.is_none(), "outgoing_preview must NOT be emitted when sidecar was not used (regex fallback) \
        — partial anonymization could expose PII not in entity_types: {body}");
}

/// Tunnel mode: anonymizer is a no-op even when enabled (FORK 2 must see original text).
#[tokio::test]
async fn anonymizer_tunnel_mode_skip() {
    use zemtik::config::ZemtikMode;
    let mock_openai = MockServer::start().await;
    mount_openai_chat_mock(&mock_openai).await;

    let mut config = AppConfig::default();
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(test_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());
    // Tunnel mode
    config.mode = ZemtikMode::Tunnel;
    config.tunnel_api_key = Some("tunnel-key".to_owned());
    // Anonymizer is enabled but must be skipped in tunnel mode
    config.anonymizer_enabled = true;
    config.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned(); // would 503 if called
    config.anonymizer_fallback_regex = false;

    let app = build_proxy_router(config).await.expect("build failed");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer tunnel-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Texto con cédula 79.123.456"}]
        }))
        .send()
        .await
        .unwrap();
    // Tunnel mode passes through; anonymizer is skipped in tunnel mode.
    assert_eq!(resp.status(), 200, "tunnel mode must pass through successfully, skipping anonymizer");
}
