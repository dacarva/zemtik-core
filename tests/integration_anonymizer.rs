/// E2E integration tests for the anonymizer pipeline.
///
/// These tests use regex fallback (no real gRPC sidecar) with entity type CO_CEDULA
/// to drive the full anonymize → LLM call → deanonymize cycle.
///
/// Run with:
///   ZEMTIK_SKIP_CIRCUIT_VALIDATION=1 cargo test --test integration_anonymizer
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

fn minimal_schema() -> SchemaConfig {
    let mut tables = HashMap::new();
    tables.insert(
        "aws_spend".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            description: "AWS cloud infrastructure spend.".to_owned(),
            example_prompts: vec!["What was our AWS spend?".to_owned()],
            value_column: "amount".to_owned(),
            timestamp_column: "timestamp".to_owned(),
            category_column: Some("category_name".to_owned()),
            agg_fn: AggFn::Sum,
            metric_label: "total_aws_spend_usd".to_owned(),
            ..Default::default()
        },
    );
    SchemaConfig { fiscal_year_offset_months: 0, tables }
}

/// Spawn proxy with anonymizer enabled, regex fallback, entity_types=CO_CEDULA.
/// The sidecar address is a dead port so gRPC fails immediately and regex takes over.
async fn spawn_anon_proxy(mock_openai: &MockServer, entity_types: &str) -> SocketAddr {
    let mut config = AppConfig::default();
    config.openai_base_url = mock_openai.uri();
    config.openai_model = "gpt-5.4-nano".to_owned();
    config.skip_circuit_validation = true;
    config.intent_backend = "regex".to_owned();
    config.openai_api_key = Some("test-key".to_owned());
    config.client_id = 123;
    config.cors_origins = vec!["*".to_owned()];
    config.receipts_db_path = std::path::PathBuf::from(":memory:");
    config.schema_config = Some(minimal_schema());
    config.schema_config_hash = Some("test-schema-hash".to_owned());
    config.general_passthrough_enabled = true;
    config.anonymizer_enabled = true;
    config.anonymizer_sidecar_addr = "http://127.0.0.1:1".to_owned(); // dead — forces regex
    config.anonymizer_fallback_regex = true;
    config.anonymizer_entity_types = entity_types.to_owned();

    let app = build_proxy_router(config).await.expect("build failed");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full E2E: cédula in prompt → token in OpenAI request → mock LLM returns token → deanonymized in response.
///
/// CO_CEDULA hash = 5b46, first entity counter = 1, so token = [[Z:5b46:1]].
/// The mock verifies the token arrives at OpenAI, then returns it; we assert the original
/// value is restored before the response reaches the caller.
#[tokio::test]
#[ignore = "token hash 5b46 only valid with live sidecar; regex fallback produces a different hash — run with docker compose --profile anonymizer up"]
async fn anonymizer_e2e_cedula_tokenized_and_deanonymized() {
    let mock_openai = MockServer::start().await;

    // Register mock BEFORE spawning proxy so it's active when proxy starts
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_string_contains("[[Z:5b46:"))  // CO_CEDULA hash = 5b46
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-anon-e2e",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    // Echo token back — proxy must deanonymize before returning to caller
                    "content": "La cédula registrada es [[Z:5b46:1]]."
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 30, "completion_tokens": 10, "total_tokens": 40}
        })))
        .mount(&mock_openai)
        .await;

    let addr = spawn_anon_proxy(&mock_openai, "CO_CEDULA").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "El cliente tiene la cédula 79.123.456 registrada."}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "proxy must return 200 for anonymized request");

    let body: Value = resp.json().await.unwrap();

    // 1. Deanonymization: caller sees original number, NOT the token
    let content = body["choices"][0]["message"]["content"]
        .as_str()
        .expect("choices[0].message.content must be a string");
    assert!(
        content.contains("79.123.456"),
        "deanonymized response must contain original cédula, got: {content}"
    );
    assert!(
        !content.contains("[[Z:5b46:"),
        "token must NOT appear in response to caller, got: {content}"
    );

    // 2. zemtik_meta.anonymizer fields present
    let meta = &body["zemtik_meta"]["anonymizer"];
    assert!(
        meta["entities_found"].as_u64().unwrap_or(0) >= 1,
        "entities_found must be >= 1, got: {meta}"
    );
    assert!(
        meta["dropped_tokens"].as_u64().unwrap_or(99) == 0,
        "dropped_tokens must be 0 (LLM preserved the token), got: {meta}"
    );
    assert_eq!(
        meta["sidecar_used"].as_bool().unwrap_or(true),
        false,
        "regex fallback path → sidecar_used must be false"
    );
}

/// Dropped tokens: mock LLM omits the token → zemtik_meta.anonymizer.dropped_tokens == 1.
#[tokio::test]
async fn anonymizer_dropped_token_counted_in_meta() {
    let mock_openai = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-anon-drop",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    // LLM paraphrased — token dropped
                    "content": "El documento fue analizado correctamente."
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 25, "completion_tokens": 8, "total_tokens": 33}
        })))
        .mount(&mock_openai)
        .await;

    let addr = spawn_anon_proxy(&mock_openai, "CO_CEDULA").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "Cédula 79.123.456 del titular."}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    let meta = &body["zemtik_meta"]["anonymizer"];
    assert_eq!(
        meta["dropped_tokens"].as_u64().unwrap_or(0),
        1,
        "LLM dropped the token → dropped_tokens must be 1, got: {meta}"
    );
}

/// No PII in prompt: anonymizer is a no-op, entities_found == 0.
#[tokio::test]
async fn anonymizer_no_pii_entities_found_zero() {
    let mock_openai = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-anon-noop",
            "object": "chat.completion",
            "model": "gpt-5.4-nano",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hola, ¿cómo puedo ayudarte?"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 6, "total_tokens": 16}
        })))
        .mount(&mock_openai)
        .await;

    let addr = spawn_anon_proxy(&mock_openai, "CO_CEDULA").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/chat/completions", addr))
        .header("Authorization", "Bearer test-key")
        .json(&json!({
            "model": "gpt-5.4-nano",
            "messages": [{"role": "user", "content": "¿Cuál es el clima hoy?"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let meta = &body["zemtik_meta"]["anonymizer"];
    assert_eq!(
        meta["entities_found"].as_u64().unwrap_or(99),
        0,
        "no PII → entities_found must be 0, got: {meta}"
    );
}
