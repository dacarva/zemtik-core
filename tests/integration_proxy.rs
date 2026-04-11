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
use wiremock::matchers::{method, path};
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
