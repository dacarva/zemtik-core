use zemtik::config::AppConfig;
use zemtik::provider_registry::ProviderRegistry;

fn base_config() -> AppConfig {
    AppConfig::default()
}

#[test]
fn test_registry_known_providers() {
    let client = reqwest::Client::new();

    let mut config = base_config();
    config.llm_provider = "openai".to_owned();
    assert!(ProviderRegistry::build(&config, client.clone()).is_ok());

    config.llm_provider = "anthropic".to_owned();
    config.anthropic_api_key = Some("sk-ant-test".to_owned());
    assert!(ProviderRegistry::build(&config, client.clone()).is_ok());

    config.llm_provider = "gemini".to_owned();
    config.gemini_api_key = Some("AIza-test".to_owned());
    assert!(ProviderRegistry::build(&config, client).is_ok());
}

#[test]
fn test_registry_unknown_provider_error() {
    let client = reqwest::Client::new();
    let mut config = base_config();
    config.llm_provider = "gemni".to_owned(); // typo
    let err = ProviderRegistry::build(&config, client).err().expect("expected error");
    let msg = err.to_string();
    assert!(msg.contains("gemni"), "error should name the bad value: {msg}");
    assert!(
        msg.contains("openai") && msg.contains("anthropic") && msg.contains("gemini"),
        "error should list valid values: {msg}"
    );
}
