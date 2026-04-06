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

/// Aggregation function for FastLane queries. Uppercase required in JSON: "SUM" or "COUNT".
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum AggFn {
    #[default]
    Sum,
    Count,
}

impl AggFn {
    pub fn as_str(&self) -> &'static str {
        match self {
            AggFn::Sum => "SUM",
            AggFn::Count => "COUNT",
        }
    }
}

fn default_value_column() -> String { "amount".to_owned() }
fn default_timestamp_column() -> String { "timestamp".to_owned() }
fn default_metric_label() -> String { "total_spend_usd".to_owned() }

/// Returns true if `s` is a safe SQL/JSON identifier: non-empty, ASCII alphanumeric
/// or underscore only, max 63 chars. Column/table names from schema_config are
/// server-controlled, but this defends against misconfiguration.
fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && s.len() <= 63
}

#[derive(Debug, Deserialize, Clone)]
pub struct TableConfig {
    pub sensitivity: String,
    pub aliases: Option<Vec<String>>,
    /// One-sentence description of what this table contains (used for embedding index).
    #[serde(default)]
    pub description: String,
    /// Example natural-language prompts that should match this table.
    #[serde(default)]
    pub example_prompts: Vec<String>,
    /// Per-table client_id override. When set, takes precedence over the global
    /// ZEMTIK_CLIENT_ID. Useful for multi-client deployments where each table
    /// belongs to a different end client.
    #[serde(default)]
    pub client_id: Option<i64>,

    // --- FastLane engine fields (all optional, backward-compatible) ---

    /// Physical table name in the DB. None → falls back to the schema_config key.
    /// NOTE: physical_table override only applies to the Supabase path.
    /// The in-memory SQLite ledger always uses the 'transactions' table.
    #[serde(default)]
    pub physical_table: Option<String>,

    /// Column to aggregate (SUM) or count non-nulls from (COUNT).
    /// Defaults to "amount". For COUNT tables, use a non-nullable column (PK or equivalent).
    #[serde(default = "default_value_column")]
    pub value_column: String,

    /// Column for Unix-seconds timestamp filtering. Defaults to "timestamp".
    #[serde(default = "default_timestamp_column")]
    pub timestamp_column: String,

    /// Column for category filtering within the physical table.
    /// None → no category filter (aggregate entire table).
    #[serde(default)]
    pub category_column: Option<String>,

    /// Aggregation function: "SUM" (default) or "COUNT". Uppercase required.
    #[serde(default)]
    pub agg_fn: AggFn,

    /// Label for the aggregate metric in the OpenAI payload. Defaults to "total_spend_usd".
    /// Must match [a-zA-Z0-9_] — used as a JSON field value for the LLM.
    #[serde(default = "default_metric_label")]
    pub metric_label: String,

    /// When true, omit the client_id filter from Supabase queries.
    /// Use for tables without a client_id column (e.g., single-tenant HR tables).
    /// WARNING: setting this on a multi-tenant table exposes all tenants' data.
    #[serde(default)]
    pub skip_client_id_filter: bool,
}

impl Default for TableConfig {
    fn default() -> Self {
        TableConfig {
            sensitivity: String::new(),
            aliases: None,
            description: String::new(),
            example_prompts: Vec::new(),
            client_id: None,
            physical_table: None,
            value_column: default_value_column(),
            timestamp_column: default_timestamp_column(),
            category_column: None,
            agg_fn: AggFn::Sum,
            metric_label: default_metric_label(),
            skip_client_id_filter: false,
        }
    }
}

impl TableConfig {
    /// Returns the physical table name: physical_table override if set, otherwise the schema key.
    pub fn resolved_table<'a>(&'a self, key: &'a str) -> &'a str {
        self.physical_table.as_deref().unwrap_or(key)
    }
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
///
/// When `require_embed_fields` is true, also validates that each table has a
/// non-empty `description` and at least one `example_prompts` entry (required
/// for the embedding index).
pub fn validate_schema_config(config: &SchemaConfig, require_embed_fields: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        (0..=11).contains(&config.fiscal_year_offset_months),
        "schema_config: fiscal_year_offset_months must be 0–11, got {}",
        config.fiscal_year_offset_months
    );
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
        if require_embed_fields {
            if tc.description.is_empty() {
                anyhow::bail!(
                    "schema_config: table '{}': description is required for embedding backend",
                    key
                );
            }
            if tc.example_prompts.is_empty() {
                anyhow::bail!(
                    "schema_config: table '{}': example_prompts must be non-empty for embedding backend",
                    key
                );
            }
        }

        // Validate identifier safety for FastLane engine fields
        if !is_safe_identifier(&tc.value_column) {
            anyhow::bail!(
                "schema_config: table '{}': invalid value_column '{}'  \
                 (must match [a-zA-Z0-9_], max 63 chars)",
                key, tc.value_column
            );
        }
        if !is_safe_identifier(&tc.timestamp_column) {
            anyhow::bail!(
                "schema_config: table '{}': invalid timestamp_column '{}' \
                 (must match [a-zA-Z0-9_], max 63 chars)",
                key, tc.timestamp_column
            );
        }
        if let Some(ref cat_col) = tc.category_column {
            if !is_safe_identifier(cat_col) {
                anyhow::bail!(
                    "schema_config: table '{}': invalid category_column '{}' \
                     (must match [a-zA-Z0-9_], max 63 chars)",
                    key, cat_col
                );
            }
        }
        if let Some(ref phys) = tc.physical_table {
            if !is_safe_identifier(phys) {
                anyhow::bail!(
                    "schema_config: table '{}': invalid physical_table '{}' \
                     (must match [a-zA-Z0-9_], max 63 chars)",
                    key, phys
                );
            }
        }
        if !is_safe_identifier(&tc.metric_label) {
            anyhow::bail!(
                "schema_config: table '{}': invalid metric_label '{}' \
                 (must match [a-zA-Z0-9_], max 63 chars)",
                key, tc.metric_label
            );
        }

        // COUNT + critical is not supported: the ZK circuit only handles SUM of BN254 field elements.
        if tc.agg_fn == AggFn::Count && tc.sensitivity == "critical" {
            anyhow::bail!(
                "schema_config: table '{}': COUNT aggregation with sensitivity=critical is not \
                 supported. The ZK circuit only handles SUM. Use sensitivity=low for COUNT tables \
                 (FastLane-attested only) or use SUM with sensitivity=critical.",
                key
            );
        }

        // Warn (non-blocking) if physical_table override is used outside Supabase.
        // SQLite always queries the 'transactions' table; physical_table only works on Supabase.
        if tc.physical_table.is_some()
            && std::env::var("DB_BACKEND").unwrap_or_default() != "supabase"
        {
            eprintln!(
                "[WARN] schema_config: table '{}': physical_table override is Supabase-only — \
                 SQLite always uses 'transactions'. Requests to this table will fail at runtime \
                 if the physical table name differs.",
                key
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
    /// Bind address for the proxy server. Default: "127.0.0.1:4000".
    /// Env: ZEMTIK_BIND_ADDR. Backward compat: if absent, constructed from proxy_port.
    #[serde(skip)]
    pub bind_addr: String,
    /// Allowed CORS origins. Default: ["http://localhost:4000"].
    /// Env: ZEMTIK_CORS_ORIGINS (comma-separated). Use "*" for wildcard.
    #[serde(skip)]
    pub cors_origins: Vec<String>,
    pub openai_api_key: Option<String>,
    pub circuit_dir: PathBuf,
    pub runs_dir: PathBuf,
    pub keys_dir: PathBuf,
    pub db_path: PathBuf,
    pub receipts_db_path: PathBuf,
    pub receipts_dir: PathBuf,
    /// Directory for cached ONNX embedding models. Default: ~/.zemtik/models.
    pub models_dir: PathBuf,
    /// Cosine similarity threshold below which intent is rejected. Default: 0.65.
    pub intent_confidence_threshold: f32,
    /// Intent backend to use: "embed" (default) or "regex" (forced regex fallback).
    pub intent_backend: String,
    /// Path to schema_config.json. Default: ~/.zemtik/schema_config.json.
    #[serde(skip)]
    pub schema_config_path: PathBuf,
    /// Loaded SchemaConfig (None if file absent — fatal in proxy mode).
    #[serde(skip)]
    pub schema_config: Option<SchemaConfig>,
    /// SHA-256 of schema_config.json bytes (set at load time).
    #[serde(skip)]
    pub schema_config_hash: Option<String>,
    /// Client ID for DB filtering. Default: 123. Env: ZEMTIK_CLIENT_ID.
    #[serde(skip)]
    pub client_id: i64,
    /// Supabase project URL. Env: SUPABASE_URL.
    #[serde(skip)]
    pub supabase_url: Option<String>,
    /// Supabase service role key. Env: SUPABASE_SERVICE_KEY.
    #[serde(skip)]
    pub supabase_service_key: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let base = home.join(".zemtik");
        AppConfig {
            proxy_port: 4000,
            bind_addr: "127.0.0.1:4000".to_owned(),
            cors_origins: vec!["http://localhost:4000".to_owned()],
            openai_api_key: None,
            circuit_dir: base.join("circuit"),
            runs_dir: base.join("runs"),
            keys_dir: base.join("keys"),
            db_path: base.join("zemtik.db"),
            receipts_db_path: base.join("receipts.db"),
            receipts_dir: base.join("receipts"),
            models_dir: base.join("models"),
            intent_confidence_threshold: 0.65,
            intent_backend: "embed".to_owned(),
            schema_config_path: base.join("schema_config.json"),
            schema_config: None,
            schema_config_hash: None,
            client_id: 123,
            supabase_url: None,
            supabase_service_key: None,
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
    if let Some(v) = env.get("ZEMTIK_MODELS_DIR") {
        config.models_dir = expand_tilde(v);
    }
    if let Some(v) = env.get("ZEMTIK_INTENT_THRESHOLD") {
        let t: f32 = v.parse().context("parse ZEMTIK_INTENT_THRESHOLD")?;
        anyhow::ensure!(
            (0.01..=1.0).contains(&t),
            "ZEMTIK_INTENT_THRESHOLD must be in [0.01, 1.0], got {}",
            t
        );
        config.intent_confidence_threshold = t;
    }
    if let Some(v) = env.get("ZEMTIK_INTENT_BACKEND") {
        config.intent_backend = v.clone();
    }
    if let Some(v) = env.get("OPENAI_API_KEY") {
        config.openai_api_key = Some(v.clone());
    }
    if let Some(v) = env.get("ZEMTIK_CLIENT_ID") {
        config.client_id = v.trim().parse::<i64>().context("parse ZEMTIK_CLIENT_ID")?;
    }
    if let Some(v) = env.get("SUPABASE_URL") {
        config.supabase_url = Some(v.clone());
    }
    if let Some(v) = env.get("SUPABASE_SERVICE_KEY") {
        config.supabase_service_key = Some(v.clone());
    }
    if let Some(v) = env.get("ZEMTIK_CORS_ORIGINS") {
        let parsed: Vec<String> = v
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if !parsed.is_empty() {
            config.cors_origins = parsed;
        }
    }

    // Layer 4: CLI flags
    if let Some(port) = cli.port {
        config.proxy_port = port;
    }
    if let Some(ref dir) = cli.circuit_dir {
        config.circuit_dir = dir.clone();
    }

    // Resolve bind_addr after all layers are applied:
    // Priority: ZEMTIK_BIND_ADDR > proxy_port (YAML/env/CLI) > default "127.0.0.1:4000"
    if let Some(v) = env.get("ZEMTIK_BIND_ADDR") {
        config.bind_addr = v.trim().to_owned();
    } else {
        config.bind_addr = format!("127.0.0.1:{}", config.proxy_port);
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
