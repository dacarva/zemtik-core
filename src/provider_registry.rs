use std::sync::Arc;

use anyhow::bail;

use crate::config::AppConfig;
use crate::llm_backend::{AnthropicBackend, GeminiBackend, LlmBackend, OpenAiBackend};

/// Startup-time factory. Builds the correct `LlmBackend` from config.
/// Returns `Err` for unknown providers or missing required keys.
pub struct ProviderRegistry;

impl ProviderRegistry {
    pub fn build(
        config: &AppConfig,
        client: reqwest::Client,
    ) -> anyhow::Result<Arc<dyn LlmBackend>> {
        match config.llm_provider.as_str() {
            "openai" => Ok(Arc::new(OpenAiBackend::new(
                client,
                config.openai_base_url.clone(),
            ))),
            "anthropic" => {
                let api_key = config
                    .anthropic_api_key
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("ZEMTIK_ANTHROPIC_API_KEY is required when llm_provider=anthropic"))?;
                Ok(Arc::new(AnthropicBackend::new(
                    client,
                    api_key,
                    config.anthropic_model.clone(),
                    config.anthropic_base_url.clone(),
                )))
            }
            "gemini" => {
                let api_key = config
                    .gemini_api_key
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("ZEMTIK_GEMINI_API_KEY is required when llm_provider=gemini"))?;
                Ok(Arc::new(GeminiBackend::new(
                    client,
                    api_key,
                    config.gemini_model.clone(),
                    config.gemini_base_url.clone(),
                )))
            }
            other => bail!(
                "llm_provider {:?} is not supported; accepted values: openai, anthropic, gemini",
                other
            ),
        }
    }
}
