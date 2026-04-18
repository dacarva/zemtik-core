use std::collections::HashMap;
use std::path::PathBuf;

use zemtik::config::{load_from_sources, validate_schema_config, AggFn, AppConfig, CliArgs, Command, SchemaConfig, TableConfig};

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

// ---------------------------------------------------------------------------
// Universal FastLane engine — new TableConfig fields (v0.7.0)
// ---------------------------------------------------------------------------

#[test]
fn table_config_new_fields_deserialize() {
    let json = r#"{
        "sensitivity": "low",
        "physical_table": "employees",
        "value_column": "employee_id",
        "timestamp_column": "hire_date",
        "category_column": "department",
        "agg_fn": "COUNT",
        "metric_label": "new_hires",
        "skip_client_id_filter": true
    }"#;
    let tc: TableConfig = serde_json::from_str(json).expect("deserialize should succeed");
    assert_eq!(tc.physical_table.as_deref(), Some("employees"));
    assert_eq!(tc.value_column, "employee_id");
    assert_eq!(tc.timestamp_column, "hire_date");
    assert_eq!(tc.category_column.as_deref(), Some("department"));
    assert_eq!(tc.agg_fn, AggFn::Count);
    assert_eq!(tc.metric_label, "new_hires");
    assert!(tc.skip_client_id_filter);
}

#[test]
fn table_config_defaults_applied() {
    let json = r#"{"sensitivity": "low"}"#;
    let tc: TableConfig = serde_json::from_str(json).expect("deserialize should succeed");
    assert_eq!(tc.value_column, "amount");
    assert_eq!(tc.timestamp_column, "timestamp");
    assert_eq!(tc.metric_label, "total_spend_usd");
    assert_eq!(tc.agg_fn, AggFn::Sum);
    assert!(!tc.skip_client_id_filter);
    assert!(tc.physical_table.is_none());
    assert!(tc.category_column.is_none());
}

#[test]
fn validate_rejects_invalid_value_column() {
    let mut tables = HashMap::new();
    tables.insert(
        "bad_table".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            value_column: "amount; DROP TABLE".to_owned(),
            ..Default::default()
        },
    );
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    let result = validate_schema_config(&schema, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("value_column"));
}

#[test]
fn validate_rejects_invalid_physical_table() {
    let mut tables = HashMap::new();
    tables.insert(
        "bad_table".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            physical_table: Some("foo bar".to_owned()), // space not allowed
            ..Default::default()
        },
    );
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    let result = validate_schema_config(&schema, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("physical_table"));
}

#[test]
fn resolved_table_falls_back_to_key() {
    let tc = TableConfig { sensitivity: "low".to_owned(), ..Default::default() };
    assert_eq!(tc.resolved_table("aws_spend"), "aws_spend");
}

#[test]
fn resolved_table_uses_override() {
    let tc = TableConfig {
        sensitivity: "low".to_owned(),
        physical_table: Some("transactions".to_owned()),
        ..Default::default()
    };
    assert_eq!(tc.resolved_table("aws_spend"), "transactions");
}

#[test]
fn validate_allows_count_with_critical_sensitivity() {
    // COUNT+critical is valid since Universal ZK Engine sprint — routes to ZK SlowLane circuit
    let mut tables = HashMap::new();
    tables.insert(
        "headcount_table".to_owned(),
        TableConfig {
            sensitivity: "critical".to_owned(),
            agg_fn: AggFn::Count,
            ..Default::default()
        },
    );
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    let result = validate_schema_config(&schema, false);
    assert!(result.is_ok(), "COUNT+critical should be valid: {:?}", result.err());
}

#[test]
fn table_config_skip_client_id_filter_defaults_false() {
    let json = r#"{"sensitivity": "low"}"#;
    let tc: TableConfig = serde_json::from_str(json).expect("deserialize");
    assert!(!tc.skip_client_id_filter);
}

#[test]
fn table_config_agg_fn_lowercase_rejected() {
    let json = r#"{"sensitivity": "low", "agg_fn": "sum"}"#;
    let result: Result<TableConfig, _> = serde_json::from_str(json);
    assert!(result.is_err(), "lowercase 'sum' should be rejected — uppercase required");
}

// Regression: ISSUE-001 — FastLane used Supabase path even when DB_BACKEND=sqlite
// Found by /qa on 2026-04-06
// Report: .gstack/qa-reports/qa-report-zemtik-proxy-2026-04-06.md
#[test]
fn use_supabase_fast_lane_false_when_db_backend_sqlite_despite_credentials() {
    let mut env = HashMap::new();
    env.insert("DB_BACKEND".to_owned(), "sqlite".to_owned());
    env.insert("SUPABASE_URL".to_owned(), "https://proj.supabase.co".to_owned());
    env.insert("SUPABASE_SERVICE_KEY".to_owned(), "secret-key".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert!(
        !config.use_supabase_fast_lane(),
        "DB_BACKEND=sqlite must prevent Supabase FastLane even when credentials are present"
    );
}

#[test]
fn use_supabase_fast_lane_true_only_when_db_backend_supabase_and_creds_set() {
    let mut env = HashMap::new();
    env.insert("DB_BACKEND".to_owned(), "supabase".to_owned());
    env.insert("SUPABASE_URL".to_owned(), "https://proj.supabase.co".to_owned());
    env.insert("SUPABASE_SERVICE_KEY".to_owned(), "secret-key".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert!(
        config.use_supabase_fast_lane(),
        "DB_BACKEND=supabase with both credentials should enable Supabase FastLane"
    );
}

#[test]
fn use_supabase_fast_lane_false_when_missing_service_key() {
    let mut env = HashMap::new();
    env.insert("DB_BACKEND".to_owned(), "supabase".to_owned());
    env.insert("SUPABASE_URL".to_owned(), "https://proj.supabase.co".to_owned());
    let config = load_from_sources(None, &env, &default_cli()).unwrap();
    assert!(
        !config.use_supabase_fast_lane(),
        "DB_BACKEND=supabase without service key must not activate Supabase FastLane"
    );
}

#[test]
fn test_validate_rejects_reserved_dummy_key() {
    let mut tables = HashMap::new();
    tables.insert(
        "__zemtik_dummy__".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            ..Default::default()
        },
    );
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    let result = validate_schema_config(&schema, false);
    assert!(result.is_err(), "table key '__zemtik_dummy__' should be rejected as reserved");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("reserved"),
        "error message should mention 'reserved', got: {}",
        err
    );
}

// --- GeneralLane config tests ---

#[test]
fn general_passthrough_enabled_by_env() {
    let config = load_from_sources(None, &env(&[("ZEMTIK_GENERAL_PASSTHROUGH", "1")]), &default_cli()).unwrap();
    assert!(config.general_passthrough_enabled);
}

#[test]
fn general_passthrough_enabled_by_true() {
    let config = load_from_sources(None, &env(&[("ZEMTIK_GENERAL_PASSTHROUGH", "true")]), &default_cli()).unwrap();
    assert!(config.general_passthrough_enabled);
}

#[test]
fn general_passthrough_disabled_by_default() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert!(!config.general_passthrough_enabled);
}

#[test]
fn general_passthrough_invalid_value_returns_error() {
    let result = load_from_sources(None, &env(&[("ZEMTIK_GENERAL_PASSTHROUGH", "maybe")]), &default_cli());
    assert!(result.is_err(), "invalid value should return Err");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("ZEMTIK_GENERAL_PASSTHROUGH"), "error should mention the env var");
}

#[test]
fn general_max_rpm_set_by_env() {
    let config = load_from_sources(None, &env(&[("ZEMTIK_GENERAL_MAX_RPM", "60")]), &default_cli()).unwrap();
    assert_eq!(config.general_max_rpm, 60);
}

#[test]
fn general_max_rpm_default_is_zero() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert_eq!(config.general_max_rpm, 0, "default should be 0 (unlimited)");
}

#[test]
fn general_max_rpm_over_limit_returns_error() {
    let result = load_from_sources(None, &env(&[("ZEMTIK_GENERAL_MAX_RPM", "1000001")]), &default_cli());
    assert!(result.is_err(), "value over 1,000,000 should return Err");
}

#[test]
fn general_max_rpm_non_numeric_returns_error() {
    let result = load_from_sources(None, &env(&[("ZEMTIK_GENERAL_MAX_RPM", "fast")]), &default_cli());
    assert!(result.is_err(), "non-numeric value should return Err");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("ZEMTIK_GENERAL_MAX_RPM"), "error should mention the env var");
}

// ─── AnonymizerConfig env var parsing ────────────────────────────────────────

#[test]
fn anonymizer_disabled_by_default() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert!(!config.anonymizer_enabled, "anonymizer must be disabled by default");
}

#[test]
fn anonymizer_enabled_via_env() {
    let config = load_from_sources(None, &env(&[("ZEMTIK_ANONYMIZER_ENABLED", "true")]), &default_cli()).unwrap();
    assert!(config.anonymizer_enabled);
}

#[test]
fn anonymizer_fallback_regex_default_true() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert!(config.anonymizer_fallback_regex, "fallback_regex must default to true");
}

#[test]
fn anonymizer_fallback_regex_disabled_via_env() {
    let config = load_from_sources(None, &env(&[("ZEMTIK_ANONYMIZER_FALLBACK_REGEX", "false")]), &default_cli()).unwrap();
    assert!(!config.anonymizer_fallback_regex);
}

#[test]
fn anonymizer_entity_types_parsed_from_env() {
    let config = load_from_sources(
        None,
        &env(&[("ZEMTIK_ANONYMIZER_ENTITY_TYPES", "PERSON,EMAIL_ADDRESS")]),
        &default_cli(),
    ).unwrap();
    assert!(config.anonymizer_entity_types.contains(&"PERSON".to_string()));
    assert!(config.anonymizer_entity_types.contains(&"EMAIL_ADDRESS".to_string()));
}

#[test]
fn anonymizer_debug_preview_default_false() {
    let config = load_from_sources(None, &HashMap::new(), &default_cli()).unwrap();
    assert!(!config.anonymizer_debug_preview, "debug_preview must default to false");
}

#[test]
fn anonymizer_debug_preview_enabled_via_env() {
    let config = load_from_sources(None, &env(&[("ZEMTIK_ANONYMIZER_DEBUG_PREVIEW", "1")]), &default_cli()).unwrap();
    assert!(config.anonymizer_debug_preview);
}
