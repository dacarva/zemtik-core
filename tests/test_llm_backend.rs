/// Integration-style tests for the LlmBackend trait impls.
/// Unit tests for private helpers (merge_consecutive_same_role, translate_to_anthropic)
/// live in src/llm_backend.rs inline tests (they require private access).
use std::sync::Arc;

use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zemtik::llm_backend::{AnthropicBackend, GeminiBackend, LlmBackend, OpenAiBackend};

fn make_openai_backend(base_url: &str) -> OpenAiBackend {
    OpenAiBackend::new(reqwest::Client::new(), base_url.to_owned())
}

fn make_anthropic_backend(base_url: &str) -> AnthropicBackend {
    AnthropicBackend::new(
        reqwest::Client::new(),
        "test-key".to_owned(),
        "claude-sonnet-4-6".to_owned(),
        base_url.to_owned(),
    )
}

fn make_gemini_backend(base_url: &str) -> GeminiBackend {
    GeminiBackend::new(
        reqwest::Client::new(),
        "gemini-test-key".to_owned(),
        "gemini-2.5-flash".to_owned(),
        base_url.to_owned(),
    )
}

#[test]
fn openai_backend_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OpenAiBackend>();
}

#[test]
fn anthropic_backend_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AnthropicBackend>();
}

#[test]
fn gemini_backend_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GeminiBackend>();
}

#[test]
fn backend_trait_objects_are_dyn_safe() {
    // Confirms LlmBackend is object-safe — all impls can be stored as Arc<dyn LlmBackend>.
    let _a: Arc<dyn LlmBackend> = Arc::new(make_openai_backend("http://localhost:9999"));
    let _b: Arc<dyn LlmBackend> = Arc::new(make_anthropic_backend("http://localhost:9999"));
    let _c: Arc<dyn LlmBackend> = Arc::new(make_gemini_backend("http://localhost:9999/v1beta/openai"));
}

#[tokio::test]
async fn test_gemini_backend_uses_operator_key_not_client_key() {
    // INVARIANT: GeminiBackend sends ZEMTIK_GEMINI_API_KEY as Bearer, never the client token.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1beta/openai/chat/completions"))
        .and(header("authorization", "Bearer gemini-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": "gemini-2.5-flash",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "pong"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let backend = GeminiBackend::new(
        reqwest::Client::new(),
        "gemini-test-key".to_owned(),
        "gemini-2.5-flash".to_owned(),
        format!("{}/v1beta/openai", server.uri()),
    );
    let body = json!({"messages": [{"role": "user", "content": "ping"}]});
    // Pass a different client_key — it must NOT be used for the outbound request.
    let (status, resp) = backend.complete(&body, "client-key-should-be-ignored").await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(resp["choices"][0]["message"]["content"], "pong");
}

#[tokio::test]
async fn test_gemini_backend_model_override() {
    // Non-gemini- prefix model → substituted with ZEMTIK_GEMINI_MODEL.
    // gemini-* prefix → passed through as-is.
    let server = MockServer::start().await;
    // First request: model=gpt-5.4-nano → expect gemini-2.5-flash in outbound body
    Mock::given(method("POST"))
        .and(path("/v1beta/openai/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "model": "gemini-2.5-flash",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6}
        })))
        .mount(&server)
        .await;

    let backend = GeminiBackend::new(
        reqwest::Client::new(),
        "test-key".to_owned(),
        "gemini-2.5-flash".to_owned(),
        format!("{}/v1beta/openai", server.uri()),
    );

    // Non-gemini model → override
    let body = json!({"model": "gpt-5.4-nano", "messages": [{"role": "user", "content": "hi"}]});
    let (status, resp) = backend.complete(&body, "").await.unwrap();
    assert_eq!(status, 200);
    // Response should have _zemtik_resolved_model set to the substituted model
    assert_eq!(resp["_zemtik_resolved_model"], "gemini-2.5-flash");
}

#[tokio::test]
async fn test_gemini_error_response_shape() {
    // Non-2xx from Gemini → pass through status + body verbatim without panicking.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1beta/openai/chat/completions"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": {"type": "rate_limit_exceeded", "message": "Too many requests"}
        })))
        .mount(&server)
        .await;

    let backend = GeminiBackend::new(
        reqwest::Client::new(),
        "test-key".to_owned(),
        "gemini-2.5-flash".to_owned(),
        format!("{}/v1beta/openai", server.uri()),
    );
    let body = json!({"messages": [{"role": "user", "content": "hi"}]});
    let (status, resp) = backend.complete(&body, "").await.unwrap();
    assert_eq!(status, 429);
    assert_eq!(resp["error"]["type"], "rate_limit_exceeded");
}
