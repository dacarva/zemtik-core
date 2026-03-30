use std::collections::HashMap;
use std::path::PathBuf;

use zemtik::config::{load_from_sources, AppConfig, CliArgs, Command};

fn default_cli() -> CliArgs {
    CliArgs::default()
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
