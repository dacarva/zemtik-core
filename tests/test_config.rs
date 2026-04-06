use std::collections::HashMap;
use std::path::PathBuf;

use zemtik::config::{load_from_sources, validate_schema_config, AppConfig, CliArgs, Command, SchemaConfig, TableConfig};

fn default_cli() -> CliArgs {
    CliArgs::default()
}

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn defaults_when_yaml_missing() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert_eq!(config.proxy_port, 4000);
    assert!(config.circuit_dir.to_string_lossy().contains(".zemtik"));
    assert!(config.runs_dir.to_string_lossy().contains(".zemtik"));
    assert!(config.keys_dir.to_string_lossy().contains(".zemtik"));
}

#[test]
fn yaml_fields_loaded() {
    let yaml = "proxy_port: 9000\n";
    let config = load_from_sources(Some(yaml), &HashMap::new(), &default_cli()).unwrap();
    assert_eq!(config.proxy_port, 9000);
}

#[test]
fn env_var_overrides_yaml() {
    let yaml = "proxy_port: 9000\n";
    let mut env = HashMap::new();
    env.insert("ZEMTIK_PROXY_PORT".to_owned(), "8080".to_owned());
    let config = load_from_sources(Some(yaml), &env, &default_cli()).unwrap();
    assert_eq!(config.proxy_port, 8080);
}

#[test]
fn cli_flag_overrides_env() {
    let mut env = HashMap::new();
    env.insert("ZEMTIK_CIRCUIT_DIR".to_owned(), "/env".to_owned());
    let cli = CliArgs {
        command: Command::Pipeline,
        port: None,
        circuit_dir: Some(PathBuf::from("/cli")),
    };
    let config = load_from_sources(None, &env, &cli).unwrap();
    assert_eq!(config.circuit_dir, PathBuf::from("/cli"));
}

#[test]
fn malformed_yaml_returns_error() {
    let result =
        load_from_sources(Some("proxy_port: [invalid"), &HashMap::new(), &default_cli());
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// validate_schema_config tests (Phase 1 / Phase 3)
// ---------------------------------------------------------------------------

fn make_table(sensitivity: &str) -> TableConfig {
    TableConfig {
        sensitivity: sensitivity.to_owned(),
        ..Default::default()
    }
}

fn make_full_table(sensitivity: &str) -> TableConfig {
    TableConfig {
        sensitivity: sensitivity.to_owned(),
        description: "Test description.".to_owned(),
        example_prompts: vec!["Example prompt".to_owned()],
        ..Default::default()
    }
}

#[test]
fn validate_basic_schema_passes() {
    let mut tables = HashMap::new();
    tables.insert("aws_spend".to_owned(), make_table("low"));
    tables.insert("payroll".to_owned(), make_table("critical"));
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    assert!(validate_schema_config(&schema, false).is_ok());
}

#[test]
fn validate_missing_description_fails_when_required() {
    let mut tables = HashMap::new();
    tables.insert(
        "payroll".to_owned(),
        TableConfig {
            sensitivity: "critical".to_owned(),
            description: "".to_owned(),  // empty — invalid
            example_prompts: vec!["test".to_owned()],
            ..Default::default()
        },
    );
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    let result = validate_schema_config(&schema, true);
    assert!(result.is_err(), "missing description should fail when require_embed_fields=true");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("description"), "error should mention description");
}

#[test]
fn validate_missing_example_prompts_fails_when_required() {
    let mut tables = HashMap::new();
    tables.insert(
        "aws_spend".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            description: "AWS costs.".to_owned(),
            example_prompts: vec![],  // empty — invalid
            ..Default::default()
        },
    );
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    let result = validate_schema_config(&schema, true);
    assert!(result.is_err(), "empty example_prompts should fail when require_embed_fields=true");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("example_prompts"), "error should mention example_prompts");
}

#[test]
fn validate_full_embed_fields_passes() {
    let mut tables = HashMap::new();
    tables.insert("aws_spend".to_owned(), make_full_table("low"));
    tables.insert("payroll".to_owned(), make_full_table("critical"));
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    assert!(validate_schema_config(&schema, true).is_ok());
}

#[test]
fn embed_fields_not_required_when_flag_false() {
    // Tables without description/example_prompts should pass when flag=false
    let mut tables = HashMap::new();
    tables.insert("aws_spend".to_owned(), make_table("low"));
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    assert!(validate_schema_config(&schema, false).is_ok());
}

#[test]
fn intent_threshold_env_var() {
    let mut env = HashMap::new();
    env.insert("ZEMTIK_INTENT_THRESHOLD".to_owned(), "0.80".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert!((config.intent_confidence_threshold - 0.80).abs() < 0.001);
}

#[test]
fn intent_backend_env_var() {
    let mut env = HashMap::new();
    env.insert("ZEMTIK_INTENT_BACKEND".to_owned(), "regex".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert_eq!(config.intent_backend, "regex");
}

#[test]
fn default_intent_confidence_threshold() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert!((config.intent_confidence_threshold - 0.65).abs() < 0.001);
}

#[test]
fn client_id_env_var() {
    let mut env = HashMap::new();
    env.insert("ZEMTIK_CLIENT_ID".to_owned(), "999".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert_eq!(config.client_id, 999);
}

#[test]
fn client_id_default_is_123() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert_eq!(config.client_id, 123);
}

#[test]
fn supabase_url_and_key_env_vars() {
    let mut env = HashMap::new();
    env.insert("SUPABASE_URL".to_owned(), "https://proj.supabase.co".to_owned());
    env.insert("SUPABASE_SERVICE_KEY".to_owned(), "secret-key".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert_eq!(config.supabase_url.as_deref(), Some("https://proj.supabase.co"));
    assert_eq!(config.supabase_service_key.as_deref(), Some("secret-key"));
}

#[test]
fn cors_origins_comma_split() {
    let mut env = HashMap::new();
    env.insert("ZEMTIK_CORS_ORIGINS".to_owned(), "http://app.example.com,https://app.example.com".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert_eq!(config.cors_origins, vec!["http://app.example.com", "https://app.example.com"]);
}

#[test]
fn cors_origins_wildcard() {
    let mut env = HashMap::new();
    env.insert("ZEMTIK_CORS_ORIGINS".to_owned(), "*".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert_eq!(config.cors_origins, vec!["*"]);
}

#[test]
fn cors_origins_empty_env_preserves_default() {
    let mut env = HashMap::new();
    env.insert("ZEMTIK_CORS_ORIGINS".to_owned(), "".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert_eq!(config.cors_origins, vec!["http://localhost:4000"]);
}

#[test]
fn bind_addr_from_env_zemtik_bind_addr() {
    let mut env = HashMap::new();
    env.insert("ZEMTIK_BIND_ADDR".to_owned(), "0.0.0.0:8080".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert_eq!(config.bind_addr, "0.0.0.0:8080");
}

#[test]
fn bind_addr_default_uses_proxy_port() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert_eq!(config.bind_addr, "127.0.0.1:4000");
}

#[test]
fn bind_addr_follows_proxy_port_env() {
    let mut env_map = HashMap::new();
    env_map.insert("ZEMTIK_PROXY_PORT".to_owned(), "9999".to_owned());
    let config = load_from_sources(None, &env_map, &default_cli()).unwrap();
    assert_eq!(config.bind_addr, "127.0.0.1:9999");
}

#[test]
fn bind_addr_from_proxy_port_yaml() {
    let yaml = "proxy_port: 8080\n";
    let config = load_from_sources(Some(yaml), &env(&[]), &default_cli()).unwrap();
    assert_eq!(config.bind_addr, "127.0.0.1:8080");
}

#[test]
fn bind_addr_env_wins_over_yaml_proxy_port() {
    let yaml = "proxy_port: 8080\n";
    let config = load_from_sources(Some(yaml), &env(&[("ZEMTIK_BIND_ADDR", "0.0.0.0:4000")]), &default_cli()).unwrap();
    assert_eq!(config.bind_addr, "0.0.0.0:4000");
}

#[test]
fn cors_origins_trims_whitespace() {
    let config = load_from_sources(None, &env(&[("ZEMTIK_CORS_ORIGINS", " http://a.com , http://b.com ")]), &default_cli()).unwrap();
    assert_eq!(config.cors_origins, vec!["http://a.com", "http://b.com"]);
}

#[test]
fn cors_origins_default() {
    let config = load_from_sources(None, &env(&[]), &default_cli()).unwrap();
    assert_eq!(config.cors_origins, vec!["http://localhost:4000"]);
}

#[test]
fn client_id_invalid_env_returns_err() {
    let result = load_from_sources(None, &env(&[("ZEMTIK_CLIENT_ID", "not_a_number")]), &default_cli());
    assert!(result.is_err());
}

#[test]
fn table_config_with_client_id_deserializes() {
    let json = r#"{"sensitivity":"critical","description":"test","example_prompts":["foo"],"client_id":1001}"#;
    let tc: TableConfig = serde_json::from_str(json).unwrap();
    assert_eq!(tc.client_id, Some(1001i64));
}

#[test]
fn table_config_without_client_id_is_none() {
    let json = r#"{"sensitivity":"critical","description":"test","example_prompts":["foo"]}"#;
    let tc: TableConfig = serde_json::from_str(json).unwrap();
    assert_eq!(tc.client_id, None);
}

#[test]
fn effective_client_id_uses_table_override() {
    let table_client_id: Option<i64> = Some(1001);
    let global_client_id: i64 = 123;
    let effective = table_client_id.unwrap_or(global_client_id);
    assert_eq!(effective, 1001);
}

#[test]
fn effective_client_id_falls_back_to_global() {
    let table_client_id: Option<i64> = None;
    let global_client_id: i64 = 123;
    let effective = table_client_id.unwrap_or(global_client_id);
    assert_eq!(effective, 123);
}
