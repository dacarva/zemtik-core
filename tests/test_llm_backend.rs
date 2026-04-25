/// Integration-style tests for the LlmBackend trait impls.
/// Unit tests for private helpers (merge_consecutive_same_role, translate_to_anthropic)
/// live in src/llm_backend.rs inline tests (they require private access).
use zemtik::llm_backend::{AnthropicBackend, LlmBackend, OpenAiBackend};

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
fn backend_trait_objects_are_dyn_safe() {
    // Confirms LlmBackend is object-safe — both impls can be stored as Arc<dyn LlmBackend>.
    use std::sync::Arc;
    let _a: Arc<dyn LlmBackend> = Arc::new(make_openai_backend("http://localhost:9999"));
    let _b: Arc<dyn LlmBackend> = Arc::new(make_anthropic_backend("http://localhost:9999"));
}
