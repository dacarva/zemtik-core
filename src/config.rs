use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Expand a leading `~` to the home directory so users can write `~/foo` in
/// config.yaml and env vars.  Paths that don't start with `~` are unchanged.
fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        home.join(rest)
    } else if s == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"))
    } else {
        PathBuf::from(s)
    }
}

// ---------------------------------------------------------------------------
// SchemaConfig — table sensitivity configuration for the routing engine
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct SchemaConfig {
    #[serde(default)]
    pub fiscal_year_offset_months: i64,
    pub tables: HashMap<String, TableConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TableConfig {
    pub sensitivity: String,
    pub aliases: Option<Vec<String>>,
}

/// Load a schema_config.json file. Returns `(config, sha256_hex_of_file_bytes)`.
pub fn load_schema_config(path: &Path) -> anyhow::Result<(SchemaConfig, String)> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read schema_config at {}", path.display()))?;
    let hash = hex::encode(Sha256::digest(&bytes));
    let config: SchemaConfig =
        serde_json::from_slice(&bytes).context("parse schema_config.json")?;
    Ok((config, hash))
}

/// Validate a SchemaConfig — called at proxy startup. Returns Err with a
/// human-readable message on the first validation failure.
pub fn validate_schema_config(config: &SchemaConfig) -> anyhow::Result<()> {
    for (key, tc) in &config.tables {
        if key.is_empty() {
            anyhow::bail!("schema_config: table key must not be empty");
        }
        if tc.sensitivity != "critical" && tc.sensitivity != "low" {
            anyhow::bail!(
                "schema_config: table '{}' has invalid sensitivity '{}' (must be 'critical' or 'low')",
                key, tc.sensitivity
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AppConfig
// ---------------------------------------------------------------------------

/// Application-wide configuration resolved from defaults → YAML → env vars → CLI flags.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub proxy_port: u16,
    pub openai_api_key: Option<String>,
    pub circuit_dir: PathBuf,
    pub runs_dir: PathBuf,
    pub keys_dir: PathBuf,
    pub db_path: PathBuf,
    pub receipts_db_path: PathBuf,
    pub receipts_dir: PathBuf,
    /// Path to schema_config.json. Default: ~/.zemtik/schema_config.json.
    #[serde(skip)]
    pub schema_config_path: PathBuf,
    /// Loaded SchemaConfig (None if file absent — fatal in proxy mode).
    #[serde(skip)]
    pub schema_config: Option<SchemaConfig>,
    /// SHA-256 of schema_config.json bytes (set at load time).
    #[serde(skip)]
    pub schema_config_hash: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let base = home.join(".zemtik");
        AppConfig {
            proxy_port: 4000,
            openai_api_key: None,
            circuit_dir: base.join("circuit"),
            runs_dir: base.join("runs"),
            keys_dir: base.join("keys"),
            db_path: base.join("zemtik.db"),
            receipts_db_path: base.join("receipts.db"),
            receipts_dir: base.join("receipts"),
            schema_config_path: base.join("schema_config.json"),
            schema_config: None,
            schema_config_hash: None,
        }
    }
}

pub enum Command {
    Proxy,
    Verify(PathBuf),
    List,
    Pipeline,
}

/// Parsed CLI arguments.
pub struct CliArgs {
    pub command: Command,
    pub port: Option<u16>,
    pub circuit_dir: Option<PathBuf>,
}

impl Default for CliArgs {
    fn default() -> Self {
        CliArgs {
            command: Command::Pipeline,
            port: None,
            circuit_dir: None,
        }
    }
}

/// Build a config from a YAML string (optional), env map, and CLI args.
/// Priority: defaults < YAML < env < CLI.
pub fn load_from_sources(
    yaml: Option<&str>,
    env: &HashMap<String, String>,
    cli: &CliArgs,
) -> anyhow::Result<AppConfig> {
    // Layer 1: defaults
    let mut config = AppConfig::default();

    // Layer 2: YAML — serde fills missing fields from Default; expand ~ in paths
    if let Some(yaml_str) = yaml {
        config = serde_yaml::from_str(yaml_str).context("parse config YAML")?;
        config.circuit_dir = expand_tilde(&config.circuit_dir.to_string_lossy());
        config.runs_dir = expand_tilde(&config.runs_dir.to_string_lossy());
        config.keys_dir = expand_tilde(&config.keys_dir.to_string_lossy());
        config.db_path = expand_tilde(&config.db_path.to_string_lossy());
        config.receipts_db_path = expand_tilde(&config.receipts_db_path.to_string_lossy());
        config.receipts_dir = expand_tilde(&config.receipts_dir.to_string_lossy());
    }

    // Layer 3: env vars
    if let Some(v) = env.get("ZEMTIK_PROXY_PORT") {
        config.proxy_port = v.parse().context("parse ZEMTIK_PROXY_PORT")?;
    }
    if let Some(v) = env.get("ZEMTIK_CIRCUIT_DIR") {
        config.circuit_dir = expand_tilde(v);
    }
    if let Some(v) = env.get("ZEMTIK_RUNS_DIR") {
        config.runs_dir = expand_tilde(v);
    }
    if let Some(v) = env.get("ZEMTIK_KEYS_DIR") {
        config.keys_dir = expand_tilde(v);
    }
    if let Some(v) = env.get("ZEMTIK_DB_PATH") {
        config.db_path = expand_tilde(v);
    }
    if let Some(v) = env.get("ZEMTIK_RECEIPTS_DB_PATH") {
        config.receipts_db_path = expand_tilde(v);
    }
    if let Some(v) = env.get("ZEMTIK_RECEIPTS_DIR") {
        config.receipts_dir = expand_tilde(v);
    }
    if let Some(v) = env.get("OPENAI_API_KEY") {
        config.openai_api_key = Some(v.clone());
    }

    // Layer 4: CLI flags
    if let Some(port) = cli.port {
        config.proxy_port = port;
    }
    if let Some(ref dir) = cli.circuit_dir {
        config.circuit_dir = dir.clone();
    }

    // Load schema_config if present (absent is allowed; proxy mode enforces it later).
    if config.schema_config_path.exists() {
        let (sc, hash) = load_schema_config(&config.schema_config_path)?;
        config.schema_config = Some(sc);
        config.schema_config_hash = Some(hash);
    }

    Ok(config)
}

impl AppConfig {
    /// Load config from `~/.zemtik/config.yaml` (if present), real env vars, and CLI args.
    pub fn load(cli: &CliArgs) -> anyhow::Result<AppConfig> {
        let home = dirs::home_dir().context("could not resolve home directory")?;
        let config_path = home.join(".zemtik").join("config.yaml");
        let yaml = if config_path.exists() {
            Some(
                std::fs::read_to_string(&config_path)
                    .with_context(|| format!("read {}", config_path.display()))?,
            )
        } else {
            None
        };
        let env: HashMap<String, String> = std::env::vars().collect();
        load_from_sources(yaml.as_deref(), &env, cli)
    }
}
