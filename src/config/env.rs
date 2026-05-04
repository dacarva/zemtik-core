use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;

use super::{expand_tilde, load_schema_config, SchemaConfig};

// ---------------------------------------------------------------------------
// ZemtikMode — standard proxy or transparent tunnel mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ZemtikMode {
    #[default]
    Standard,
    Tunnel,
}

// ---------------------------------------------------------------------------
// AppConfig
// ---------------------------------------------------------------------------

/// Application-wide configuration resolved from defaults → YAML → env vars → CLI flags.
///
/// Marked `#[non_exhaustive]` so new fields added in future versions are
/// non-breaking changes for downstream crates that construct this via
/// [`load_from_sources`] or [`AppConfig::default`].
#[non_exhaustive]
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
    /// Max prompt length (chars) for which the substring gate is trusted.
    /// Prompts longer than this skip the gate and go to the margin check.
    /// Default: 300. Env: ZEMTIK_INTENT_SUBSTRING_GATE_MAX_CHARS.
    pub intent_substring_gate_max_chars: usize,
    /// Max prompt length (chars) used as embedding-backend input.
    /// Default: 250. Env: ZEMTIK_INTENT_EMBED_PROMPT_MAX_CHARS.
    pub intent_embed_prompt_max_chars: usize,
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
    /// Resolved DB backend ("sqlite" or "supabase"). Populated from DB_BACKEND env var.
    #[serde(skip)]
    pub db_backend: String,
    /// OpenAI base URL for outbound requests. Default: "https://api.openai.com".
    /// Env: ZEMTIK_OPENAI_BASE_URL. Override in tests to point at a mock server.
    #[serde(skip)]
    pub openai_base_url: String,
    /// OpenAI model identifier. Default: "gpt-5.4-nano". Env: ZEMTIK_OPENAI_MODEL.
    #[serde(skip)]
    pub openai_model: String,
    /// Skip circuit directory validation at proxy startup. Default: false.
    /// Env: ZEMTIK_SKIP_CIRCUIT_VALIDATION=1. Set in integration tests and Docker (no nargo/bb).
    #[serde(skip)]
    pub skip_circuit_validation: bool,

    // --- Tunnel mode fields ---

    /// Operating mode: Standard (default) or Tunnel.
    /// Env: ZEMTIK_MODE=standard|tunnel
    #[serde(skip)]
    pub mode: ZemtikMode,
    /// Separate API key for zemtik's verification calls in tunnel mode.
    /// Env: ZEMTIK_TUNNEL_API_KEY. Falls back to OPENAI_API_KEY if unset (warns at startup).
    #[serde(skip)]
    pub tunnel_api_key: Option<String>,
    /// Model for zemtik's verification OpenAI calls. Falls back to openai_model if unset.
    /// Env: ZEMTIK_TUNNEL_MODEL
    #[serde(skip)]
    pub tunnel_model: Option<String>,
    /// Max seconds for FORK 2 background pipeline. Default: 180 (covers nargo+bb).
    /// Env: ZEMTIK_TUNNEL_TIMEOUT_SECS
    #[serde(skip)]
    pub tunnel_timeout_secs: u64,
    /// Max concurrent FORK 2 background tasks. Default: 50.
    /// Env: ZEMTIK_TUNNEL_SEMAPHORE_PERMITS
    #[serde(skip)]
    pub tunnel_semaphore_permits: usize,
    /// Bearer token required for /tunnel/audit and /tunnel/audit/csv.
    /// Env: ZEMTIK_DASHBOARD_API_KEY. Warns at startup if unset in tunnel mode.
    #[serde(skip)]
    pub dashboard_api_key: Option<String>,
    /// Path to tunnel audit SQLite DB. Default: ~/.zemtik/tunnel_audit.db.
    /// Env: ZEMTIK_TUNNEL_AUDIT_DB_PATH
    #[serde(skip)]
    pub tunnel_audit_db_path: PathBuf,
    /// When true, store a 500-char plaintext preview of original OpenAI responses in the audit DB.
    /// Default: false — previews are omitted in production to avoid persisting customer LLM output.
    /// Env: ZEMTIK_TUNNEL_DEBUG_PREVIEWS=1
    #[serde(skip)]
    pub tunnel_debug_previews: bool,

    // --- Query rewriter fields ---

    /// Enable hybrid query rewriter (deterministic + LLM fallback). Default: false.
    /// Env: ZEMTIK_QUERY_REWRITER=1|true
    #[serde(skip)]
    pub query_rewriter_enabled: bool,
    /// Model for LLM rewrite calls. Default: "gpt-5.4-nano".
    /// Env: ZEMTIK_QUERY_REWRITER_MODEL
    #[serde(skip)]
    pub query_rewriter_model: String,
    /// Prior turns included in the LLM rewriter context. Default: 6.
    /// Env: ZEMTIK_QUERY_REWRITER_TURNS
    #[serde(skip)]
    pub query_rewriter_context_turns: usize,
    /// Max prior user messages scanned by deterministic_resolve. Default: 5.
    /// Env: ZEMTIK_QUERY_REWRITER_SCAN_MESSAGES
    #[serde(skip)]
    pub query_rewriter_scan_messages: usize,
    /// Per-request timeout for LLM rewrite call (seconds). Default: 10.
    /// Env: ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS
    #[serde(skip)]
    pub query_rewriter_timeout_secs: u64,
    /// Token budget for LLM context (estimated as chars/4). Default: 2000.
    /// Env: ZEMTIK_QUERY_REWRITER_MAX_CONTEXT_TOKENS
    #[serde(skip)]
    pub query_rewriter_max_context_tokens: usize,

    // --- MCP attestation server fields (v0.10.0+) ---

    /// Bind address for the MCP HTTP server. Default: "127.0.0.1:4001".
    /// Env: ZEMTIK_MCP_BIND_ADDR. Used only in mcp-serve (SSE) mode.
    pub mcp_bind_addr: String,
    /// Bearer API key for /mcp/audit and /mcp/summary. Hard startup error in mcp-serve mode if unset.
    /// Env: ZEMTIK_MCP_API_KEY.
    pub mcp_api_key: Option<String>,
    /// MCP operating mode. Default: "tunnel". Env: ZEMTIK_MCP_MODE=tunnel|governed.
    pub mcp_mode: String,
    /// Path to mcp_audit.db SQLite database. Default: ~/.zemtik/mcp_audit.db.
    /// Env: ZEMTIK_MCP_AUDIT_DB_PATH.
    pub mcp_audit_db_path: PathBuf,
    /// HTTP fetch timeout seconds for zemtik_fetch tool. Default: 30.
    /// Env: ZEMTIK_MCP_FETCH_TIMEOUT_SECS.
    pub mcp_fetch_timeout_secs: u64,
    /// Comma-separated glob-style path allowlist for zemtik_read_file.
    /// Empty = allow-all in STDIO mode, deny-all in SSE mode (operator must set explicitly).
    /// Env: ZEMTIK_MCP_ALLOWED_PATHS.
    pub mcp_allowed_paths: Vec<String>,
    /// Comma-separated domain allowlist for zemtik_fetch.
    /// Empty = allow-all in STDIO mode, deny-all in SSE mode.
    /// Env: ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS.
    pub mcp_allowed_fetch_domains: Vec<String>,
    /// Path to mcp_tools.json for dynamic tool registration. None = use builtin tools only.
    /// Env: ZEMTIK_MCP_TOOLS_PATH.
    pub mcp_tools_path: Option<PathBuf>,

    // --- General Passthrough fields (v0.11.0+) ---

    /// Enable General Passthrough lane. Default: false.
    /// When enabled, non-data queries that fail intent extraction are forwarded to OpenAI
    /// with a receipt and zemtik_meta block instead of returning 400 NoTableIdentified.
    /// Env: ZEMTIK_GENERAL_PASSTHROUGH=1|true
    #[serde(skip)]
    pub general_passthrough_enabled: bool,
    /// Max requests per minute for the General Passthrough lane. Default: 0 (unlimited).
    /// Sliding 60-second window, per-instance. 429 GeneralLaneBudgetExceeded on breach.
    /// Env: ZEMTIK_GENERAL_MAX_RPM
    #[serde(skip)]
    pub general_max_rpm: u32,
    /// Optional public base URL for this deployment (e.g. "https://zemtik.example.com").
    /// When set, adds a `verify_url` hint to `zemtik_meta` blocks pointing to the receipt audit endpoint.
    /// No startup error if unset — the hint is omitted silently.
    /// Env: ZEMTIK_PUBLIC_URL
    pub public_url: Option<String>,

    // --- Anonymizer fields (v0.14.0+) ---

    /// Enable the PII anonymizer pre-router hook. Default: false.
    /// Env: ZEMTIK_ANONYMIZER_ENABLED=1|true
    #[serde(skip)]
    pub anonymizer_enabled: bool,
    /// gRPC address of the Python anonymizer sidecar. Default: "http://localhost:50051".
    /// Env: ZEMTIK_ANONYMIZER_SIDECAR_ADDR
    pub anonymizer_sidecar_addr: String,
    /// Timeout in milliseconds for each gRPC anonymize call. Default: 1500.
    /// Env: ZEMTIK_ANONYMIZER_SIDECAR_TIMEOUT_MS
    pub anonymizer_sidecar_timeout_ms: u64,
    /// Fall back to regex-only (LATAM IDs) when the sidecar is unavailable. Default: true.
    /// When false, sidecar unavailability returns HTTP 503 (fail-closed).
    /// Env: ZEMTIK_ANONYMIZER_FALLBACK_REGEX=1|true
    #[serde(skip)]
    pub anonymizer_fallback_regex: bool,
    /// Comma-separated list of entity types to detect.
    /// Default: 21-type set (excludes PHONE_NUMBER and EMAIL_ADDRESS from the 23-type hash table).
    /// Full list: see entity_hashes.rs (23 types).
    /// Env: ZEMTIK_ANONYMIZER_ENTITY_TYPES
    pub anonymizer_entity_types: String,
    /// Expose outgoing_preview (first 200 chars of anonymized text) in zemtik_meta. Default: false.
    /// Never enable in production — the preview contains sanitized prompt text.
    /// Env: ZEMTIK_ANONYMIZER_DEBUG_PREVIEW=1|true
    #[serde(skip)]
    pub anonymizer_debug_preview: bool,
    /// Vault TTL in seconds. Entries older than this are evicted by the background task. Default: 300.
    /// Env: ZEMTIK_ANONYMIZER_VAULT_TTL_SECS
    pub anonymizer_vault_ttl_secs: u64,
    /// Enable anonymizer hook for MCP tool results. Default: false.
    /// Env: ZEMTIK_MCP_ANONYMIZER_ENABLED=1|true
    #[serde(skip)]
    pub mcp_anonymizer_enabled: bool,
    /// Dedicated bearer key for /v1/anonymize/preview. When set, takes precedence over
    /// openai_api_key for that endpoint. If unset, falls back to openai_api_key (legacy).
    /// Env: ZEMTIK_ANONYMIZER_PREVIEW_KEY
    pub anonymizer_preview_key: Option<String>,

    // --- Multi-model LLM backend (v0.16.0+) ---

    /// Active LLM provider. Default: "openai". Env: ZEMTIK_LLM_PROVIDER=openai|anthropic|gemini.
    pub llm_provider: String,
    /// Anthropic API key (operator-configured, server-side). Env: ZEMTIK_ANTHROPIC_API_KEY.
    /// Hard startup error when ZEMTIK_LLM_PROVIDER=anthropic and this is unset.
    pub anthropic_api_key: Option<String>,
    /// Claude model identifier. Default: "claude-sonnet-4-6". Env: ZEMTIK_ANTHROPIC_MODEL.
    pub anthropic_model: String,
    /// Anthropic API base URL. Default: "https://api.anthropic.com". Env: ZEMTIK_ANTHROPIC_BASE_URL.
    /// Override in tests to point at a mock server.
    // TODO: If per-request provider override (x-zemtik-provider header) ever ships in v2,
    // this URL selection becomes user-controlled and requires ssrf_block_reason + ssrf_dns_guard
    // treatment (matching zemtik_fetch in mcp_proxy.rs).
    pub anthropic_base_url: String,
    /// Gemini API key (operator-configured, server-side). Env: ZEMTIK_GEMINI_API_KEY.
    /// Hard startup error when ZEMTIK_LLM_PROVIDER=gemini and this is unset.
    pub gemini_api_key: Option<String>,
    /// Gemini model identifier. Default: "gemini-2.5-flash". Env: ZEMTIK_GEMINI_MODEL.
    pub gemini_model: String,
    /// Gemini OpenAI-compat base URL. Default: Gemini OpenAI-compat endpoint.
    /// Env: ZEMTIK_GEMINI_BASE_URL. Override in tests to point at a mock server.
    pub gemini_base_url: String,
    /// Proxy bearer key for inbound requests when provider=anthropic or gemini.
    /// Required hard startup error when ZEMTIK_LLM_PROVIDER=anthropic or gemini. Env: ZEMTIK_PROXY_API_KEY.
    /// Also gates GET /v1/models when set.
    pub proxy_api_key: Option<String>,
}

impl AppConfig {
    /// Returns true only when DB_BACKEND=supabase AND both credentials are present.
    /// Having credentials alone does not activate the Supabase FastLane path —
    /// the operator must explicitly opt in via DB_BACKEND=supabase.
    pub fn use_supabase_fast_lane(&self) -> bool {
        self.db_backend == "supabase"
            && self.supabase_url.is_some()
            && self.supabase_service_key.is_some()
    }
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
            intent_substring_gate_max_chars: 300,
            intent_embed_prompt_max_chars: 250,
            schema_config_path: base.join("schema_config.json"),
            schema_config: None,
            schema_config_hash: None,
            client_id: 123,
            supabase_url: None,
            supabase_service_key: None,
            db_backend: "sqlite".to_owned(),
            openai_base_url: "https://api.openai.com".to_owned(),
            openai_model: "gpt-5.4-nano".to_owned(),
            skip_circuit_validation: false,
            mode: ZemtikMode::Standard,
            tunnel_api_key: None,
            tunnel_model: None,
            tunnel_timeout_secs: 180,
            tunnel_semaphore_permits: 50,
            dashboard_api_key: None,
            tunnel_audit_db_path: base.join("tunnel_audit.db"),
            tunnel_debug_previews: false,
            query_rewriter_enabled: false,
            query_rewriter_model: "gpt-5.4-nano".to_owned(),
            query_rewriter_context_turns: 6,
            query_rewriter_scan_messages: 5,
            query_rewriter_timeout_secs: 10,
            query_rewriter_max_context_tokens: 2000,
            mcp_bind_addr: "127.0.0.1:4001".to_owned(),
            mcp_api_key: None,
            mcp_mode: "tunnel".to_owned(),
            mcp_audit_db_path: base.join("mcp_audit.db"),
            mcp_fetch_timeout_secs: 30,
            mcp_allowed_paths: vec![],
            mcp_allowed_fetch_domains: vec![],
            mcp_tools_path: None,
            general_passthrough_enabled: false,
            general_max_rpm: 0,
            public_url: None,
            anonymizer_enabled: false,
            anonymizer_sidecar_addr: "http://localhost:50051".to_owned(),
            anonymizer_sidecar_timeout_ms: 1500,
            anonymizer_fallback_regex: true,
            anonymizer_entity_types: "PERSON,ORG,LOCATION,CO_NIT,CO_CEDULA,AR_DNI,CL_RUT,BR_CPF,BR_CNPJ,MX_CURP,MX_RFC,ES_NIF,IBAN_CODE,DATE_TIME,MONEY,EC_RUC,PE_RUC,BO_NIT,UY_CI,VE_CI,PASSPORT".to_owned(),
            anonymizer_debug_preview: false,
            anonymizer_vault_ttl_secs: 300,
            mcp_anonymizer_enabled: false,
            anonymizer_preview_key: None,
            llm_provider: "openai".to_owned(),
            anthropic_api_key: None,
            anthropic_model: "claude-sonnet-4-6".to_owned(),
            anthropic_base_url: "https://api.anthropic.com".to_owned(),
            gemini_api_key: None,
            gemini_model: "gemini-2.5-flash".to_owned(),
            gemini_base_url: "https://generativelanguage.googleapis.com/v1beta/openai".to_owned(),
            proxy_api_key: None,
        }
    }
}

// ---------------------------------------------------------------------------
// RewriterConfig — built from AppConfig when ZEMTIK_QUERY_REWRITER=1
// ---------------------------------------------------------------------------

/// Configuration for the hybrid query rewriter (deterministic + LLM fallback).
/// Built from `AppConfig` at proxy startup when `query_rewriter_enabled` is true.
#[derive(Debug, Clone)]
pub struct RewriterConfig {
    /// OpenAI base URL (reuses ZEMTIK_OPENAI_BASE_URL).
    pub base_url: String,
    /// Model for LLM rewrite calls. Default: "gpt-5.4-nano".
    pub model: String,
    /// API key for LLM rewrite calls (reuses OPENAI_API_KEY).
    pub api_key: String,
    /// Number of prior turns to include in the LLM prompt context.
    pub context_window_turns: usize,
    /// Max prior user messages scanned by `deterministic_resolve`.
    pub max_scan_messages: usize,
    /// Per-request timeout for the LLM rewrite call (seconds).
    pub timeout_secs: u64,
    /// Token budget for LLM context (estimated as chars/4).
    pub max_context_tokens: usize,
}

pub enum Command {
    Proxy,
    Verify(PathBuf),
    List,
    ListTunnel,
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
        // MCP path fields can also be set in YAML — expand ~ for them too.
        config.mcp_audit_db_path = expand_tilde(&config.mcp_audit_db_path.to_string_lossy());
        if let Some(ref p) = config.mcp_tools_path.clone() {
            config.mcp_tools_path = Some(expand_tilde(&p.to_string_lossy()));
        }
        // Normalize mcp_api_key from YAML: treat blank as absent.
        if let Some(ref k) = config.mcp_api_key.clone() {
            if k.trim().is_empty() {
                config.mcp_api_key = None;
            }
        }
        // Normalize public_url from YAML: trim whitespace and trailing slashes (same as env path).
        if let Some(url) = config.public_url.take() {
            let normalized = url.trim().trim_end_matches('/').to_owned();
            if !normalized.is_empty() {
                config.public_url = Some(normalized);
            }
        }
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
    if let Some(v) = env.get("ZEMTIK_INTENT_SUBSTRING_GATE_MAX_CHARS") {
        let n: usize = v.trim().parse().context("parse ZEMTIK_INTENT_SUBSTRING_GATE_MAX_CHARS")?;
        anyhow::ensure!(n > 0, "ZEMTIK_INTENT_SUBSTRING_GATE_MAX_CHARS must be > 0, got {}", n);
        config.intent_substring_gate_max_chars = n;
    }
    if let Some(v) = env.get("ZEMTIK_INTENT_EMBED_PROMPT_MAX_CHARS") {
        let n: usize = v.trim().parse().context("parse ZEMTIK_INTENT_EMBED_PROMPT_MAX_CHARS")?;
        anyhow::ensure!(n > 0, "ZEMTIK_INTENT_EMBED_PROMPT_MAX_CHARS must be > 0, got {}", n);
        config.intent_embed_prompt_max_chars = n;
    }
    if let Some(v) = env.get("OPENAI_API_KEY") {
        config.openai_api_key = Some(v.clone());
    }
    if let Some(v) = env.get("ZEMTIK_CLIENT_ID") {
        config.client_id = v.trim().parse::<i64>().context("parse ZEMTIK_CLIENT_ID")?;
    }
    if let Some(v) = env.get("DB_BACKEND") {
        config.db_backend = v.trim().to_lowercase();
    }
    if let Some(v) = env.get("SUPABASE_URL") {
        config.supabase_url = Some(v.clone());
    }
    if let Some(v) = env.get("SUPABASE_SERVICE_KEY") {
        config.supabase_service_key = Some(v.clone());
    }
    if let Some(v) = env.get("ZEMTIK_RECEIPTS_DB_PATH") {
        config.receipts_db_path = expand_tilde(v.trim());
    }
    if let Some(v) = env.get("ZEMTIK_OPENAI_BASE_URL") {
        config.openai_base_url = v.trim().to_owned();
    }
    if let Some(v) = env.get("ZEMTIK_OPENAI_MODEL") {
        config.openai_model = v.trim().to_owned();
    }
    // Rewriter model inherits the main model unless explicitly overridden.
    // Applied after ZEMTIK_OPENAI_MODEL so the inheritance is resolved in one pass.
    if env.get("ZEMTIK_QUERY_REWRITER_MODEL").is_none() {
        config.query_rewriter_model = config.openai_model.clone();
    }
    if let Some(v) = env.get("ZEMTIK_SKIP_CIRCUIT_VALIDATION") {
        let s = v.trim();
        config.skip_circuit_validation = match s {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => anyhow::bail!(
                "ZEMTIK_SKIP_CIRCUIT_VALIDATION: unrecognized value {:?}; accepted: 0, 1, true, false",
                other
            ),
        };
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

    // Tunnel mode env vars
    if let Some(v) = env.get("ZEMTIK_MODE") {
        let s = v.trim().to_lowercase();
        config.mode = match s.as_str() {
            "standard" => ZemtikMode::Standard,
            "tunnel" => ZemtikMode::Tunnel,
            other => anyhow::bail!(
                "ZEMTIK_MODE: unrecognized value {:?}; accepted: standard, tunnel",
                other
            ),
        };
    }
    if let Some(v) = env.get("ZEMTIK_TUNNEL_API_KEY") {
        config.tunnel_api_key = Some(v.trim().to_owned());
    }
    if let Some(v) = env.get("ZEMTIK_TUNNEL_MODEL") {
        config.tunnel_model = Some(v.trim().to_owned());
    }
    if let Some(v) = env.get("ZEMTIK_TUNNEL_TIMEOUT_SECS") {
        let secs = v.trim().parse::<u64>().context("parse ZEMTIK_TUNNEL_TIMEOUT_SECS")?;
        anyhow::ensure!(secs >= 10, "ZEMTIK_TUNNEL_TIMEOUT_SECS must be >= 10 (got {})", secs);
        config.tunnel_timeout_secs = secs;
    }
    if let Some(v) = env.get("ZEMTIK_TUNNEL_SEMAPHORE_PERMITS") {
        let permits = v.trim().parse::<usize>().context("parse ZEMTIK_TUNNEL_SEMAPHORE_PERMITS")?;
        anyhow::ensure!(permits >= 1, "ZEMTIK_TUNNEL_SEMAPHORE_PERMITS must be >= 1 (got {})", permits);
        config.tunnel_semaphore_permits = permits;
    }
    if let Some(v) = env.get("ZEMTIK_DASHBOARD_API_KEY") {
        config.dashboard_api_key = Some(v.trim().to_owned());
    }
    if let Some(v) = env.get("ZEMTIK_TUNNEL_DEBUG_PREVIEWS") {
        let s = v.trim();
        config.tunnel_debug_previews = match s {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => anyhow::bail!(
                "ZEMTIK_TUNNEL_DEBUG_PREVIEWS: unrecognized value {:?}; accepted: 0, 1, true, false",
                other
            ),
        };
    }
    if let Some(v) = env.get("ZEMTIK_TUNNEL_AUDIT_DB_PATH") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            let expanded = if let Some(rest) = trimmed.strip_prefix("~/") {
                let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
                home.join(rest)
            } else {
                PathBuf::from(trimmed)
            };
            config.tunnel_audit_db_path = expanded;
        }
    }

    // Query rewriter env vars
    if let Some(v) = env.get("ZEMTIK_QUERY_REWRITER") {
        let s = v.trim();
        config.query_rewriter_enabled = match s {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => anyhow::bail!(
                "ZEMTIK_QUERY_REWRITER: unrecognized value {:?}; accepted: 0, 1, true, false",
                other
            ),
        };
    }
    if let Some(v) = env.get("ZEMTIK_QUERY_REWRITER_MODEL") {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            config.query_rewriter_model = trimmed;
        }
    }
    if let Some(v) = env.get("ZEMTIK_QUERY_REWRITER_TURNS") {
        let n = v.trim().parse::<usize>().context("parse ZEMTIK_QUERY_REWRITER_TURNS")?;
        if n == 0 {
            anyhow::bail!("ZEMTIK_QUERY_REWRITER_TURNS must be a positive integer (got 0)");
        }
        config.query_rewriter_context_turns = n;
    }
    if let Some(v) = env.get("ZEMTIK_QUERY_REWRITER_SCAN_MESSAGES") {
        let n = v.trim().parse::<usize>().context("parse ZEMTIK_QUERY_REWRITER_SCAN_MESSAGES")?;
        if n == 0 {
            anyhow::bail!("ZEMTIK_QUERY_REWRITER_SCAN_MESSAGES must be a positive integer (got 0)");
        }
        config.query_rewriter_scan_messages = n;
    }
    if let Some(v) = env.get("ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS") {
        let n = v.trim().parse::<u64>().context("parse ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS")?;
        if n == 0 {
            anyhow::bail!("ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS must be a positive integer (got 0)");
        }
        config.query_rewriter_timeout_secs = n;
    }
    if let Some(v) = env.get("ZEMTIK_QUERY_REWRITER_MAX_CONTEXT_TOKENS") {
        let n = v.trim().parse::<usize>().context("parse ZEMTIK_QUERY_REWRITER_MAX_CONTEXT_TOKENS")?;
        if n == 0 {
            anyhow::bail!("ZEMTIK_QUERY_REWRITER_MAX_CONTEXT_TOKENS must be a positive integer (got 0)");
        }
        config.query_rewriter_max_context_tokens = n;
    }

    // MCP attestation server env vars
    if let Some(v) = env.get("ZEMTIK_MCP_BIND_ADDR") {
        config.mcp_bind_addr = v.trim().to_owned();
    }
    if let Some(v) = env.get("ZEMTIK_MCP_API_KEY") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.mcp_api_key = Some(trimmed.to_owned());
        }
    }
    if let Some(v) = env.get("ZEMTIK_MCP_MODE") {
        let s = v.trim().to_lowercase();
        match s.as_str() {
            "tunnel" | "governed" => config.mcp_mode = s,
            other => anyhow::bail!(
                "ZEMTIK_MCP_MODE: unrecognized value {:?}; accepted: tunnel, governed",
                other
            ),
        }
    }
    if let Some(v) = env.get("ZEMTIK_MCP_TRANSPORT") {
        let s = v.trim().to_lowercase();
        if s == "sse" {
            anyhow::bail!(
                "ZEMTIK_MCP_TRANSPORT=sse is deprecated (sunset 2026-04-01). \
                 Use ZEMTIK_MCP_TRANSPORT=http for Streamable HTTP transport."
            );
        }
    }
    if let Some(v) = env.get("ZEMTIK_MCP_AUDIT_DB_PATH") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.mcp_audit_db_path = expand_tilde(trimmed);
        }
    }
    if let Some(v) = env.get("ZEMTIK_MCP_FETCH_TIMEOUT_SECS") {
        let n = v.trim().parse::<u64>().context("parse ZEMTIK_MCP_FETCH_TIMEOUT_SECS")?;
        anyhow::ensure!(n >= 1, "ZEMTIK_MCP_FETCH_TIMEOUT_SECS must be >= 1 (got {})", n);
        config.mcp_fetch_timeout_secs = n;
    }
    if let Some(v) = env.get("ZEMTIK_MCP_ALLOWED_PATHS") {
        config.mcp_allowed_paths = v
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(v) = env.get("ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS") {
        config.mcp_allowed_fetch_domains = v
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(v) = env.get("ZEMTIK_MCP_TOOLS_PATH") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.mcp_tools_path = Some(expand_tilde(trimmed));
        }
    }

    // General Passthrough env vars
    if let Some(v) = env.get("ZEMTIK_GENERAL_PASSTHROUGH") {
        let s = v.trim();
        config.general_passthrough_enabled = match s {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => anyhow::bail!(
                "ZEMTIK_GENERAL_PASSTHROUGH: unrecognized value {:?}; accepted: 0, 1, true, false",
                other
            ),
        };
    }
    if let Some(v) = env.get("ZEMTIK_GENERAL_MAX_RPM") {
        let n = v.trim().parse::<u32>().with_context(|| {
            format!("ZEMTIK_GENERAL_MAX_RPM: invalid value {:?}; must be a non-negative integer", v.trim())
        })?;
        if n > 1_000_000 {
            anyhow::bail!(
                "ZEMTIK_GENERAL_MAX_RPM: value {} exceeds maximum of 1,000,000",
                n
            );
        }
        config.general_max_rpm = n;
    }
    if let Some(v) = env.get("ZEMTIK_PUBLIC_URL") {
        let url = v.trim().trim_end_matches('/').to_owned();
        if !url.is_empty() {
            config.public_url = Some(url);
        }
    }

    // Anonymizer env vars
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_ENABLED") {
        let s = v.trim();
        config.anonymizer_enabled = match s {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => anyhow::bail!(
                "ZEMTIK_ANONYMIZER_ENABLED: unrecognized value {:?}; accepted: 0, 1, true, false",
                other
            ),
        };
    }
    // Deprecated alias — accepted for backwards compatibility with integrators using the old name.
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_SIDECAR_URL") {
        eprintln!("[WARN] ZEMTIK_ANONYMIZER_SIDECAR_URL is deprecated; use ZEMTIK_ANONYMIZER_SIDECAR_ADDR");
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            config.anonymizer_sidecar_addr = trimmed;
        }
    }
    // Canonical key overrides the alias if both are set.
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_SIDECAR_ADDR") {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            config.anonymizer_sidecar_addr = trimmed;
        }
    }
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_SIDECAR_TIMEOUT_MS") {
        let n = v.trim().parse::<u64>().context("parse ZEMTIK_ANONYMIZER_SIDECAR_TIMEOUT_MS")?;
        anyhow::ensure!(n >= 1, "ZEMTIK_ANONYMIZER_SIDECAR_TIMEOUT_MS must be >= 1 (got {})", n);
        config.anonymizer_sidecar_timeout_ms = n;
    }
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_FALLBACK_REGEX") {
        let s = v.trim();
        config.anonymizer_fallback_regex = match s {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => anyhow::bail!(
                "ZEMTIK_ANONYMIZER_FALLBACK_REGEX: unrecognized value {:?}; accepted: 0, 1, true, false",
                other
            ),
        };
    }
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_ENTITY_TYPES") {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            config.anonymizer_entity_types = trimmed;
        }
    }
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_DEBUG_PREVIEW") {
        let s = v.trim();
        config.anonymizer_debug_preview = match s {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => anyhow::bail!(
                "ZEMTIK_ANONYMIZER_DEBUG_PREVIEW: unrecognized value {:?}; accepted: 0, 1, true, false",
                other
            ),
        };
    }
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_VAULT_TTL_SECS") {
        let n = v.trim().parse::<u64>().context("parse ZEMTIK_ANONYMIZER_VAULT_TTL_SECS")?;
        anyhow::ensure!(n >= 1, "ZEMTIK_ANONYMIZER_VAULT_TTL_SECS must be >= 1 (got {})", n);
        config.anonymizer_vault_ttl_secs = n;
    }
    if let Some(v) = env.get("ZEMTIK_ANONYMIZER_PREVIEW_KEY") {
        let trimmed = v.trim().to_owned();
        if !trimmed.is_empty() {
            config.anonymizer_preview_key = Some(trimmed);
        }
    }
    if let Some(v) = env.get("ZEMTIK_MCP_ANONYMIZER_ENABLED") {
        let s = v.trim();
        config.mcp_anonymizer_enabled = match s {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => anyhow::bail!(
                "ZEMTIK_MCP_ANONYMIZER_ENABLED: unrecognized value {:?}; accepted: 0, 1, true, false",
                other
            ),
        };
    }

    // Multi-model LLM backend env vars (v0.16.0+)
    if let Some(v) = env.get("ZEMTIK_LLM_PROVIDER") {
        let s = v.trim().to_lowercase();
        match s.as_str() {
            "openai" | "anthropic" | "gemini" => config.llm_provider = s,
            other => anyhow::bail!(
                "ZEMTIK_LLM_PROVIDER: unrecognized value {:?}; accepted: openai, anthropic, gemini",
                other
            ),
        }
    }
    if let Some(v) = env.get("ZEMTIK_ANTHROPIC_API_KEY") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.anthropic_api_key = Some(trimmed.to_owned());
        }
    }
    if let Some(v) = env.get("ZEMTIK_ANTHROPIC_MODEL") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.anthropic_model = trimmed.to_owned();
        }
    }
    if let Some(v) = env.get("ZEMTIK_ANTHROPIC_BASE_URL") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.anthropic_base_url = trimmed.to_owned();
        }
    }
    if let Some(v) = env.get("ZEMTIK_GEMINI_API_KEY") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.gemini_api_key = Some(trimmed.to_owned());
        }
    }
    if let Some(v) = env.get("ZEMTIK_GEMINI_MODEL") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.gemini_model = trimmed.to_owned();
        }
    }
    if let Some(v) = env.get("ZEMTIK_GEMINI_BASE_URL") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.gemini_base_url = trimmed.to_owned();
        }
    }
    if let Some(v) = env.get("ZEMTIK_PROXY_API_KEY") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            config.proxy_api_key = Some(trimmed.to_owned());
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

    // Post-merge normalization: reject whitespace-only secrets and invalid provider values
    // that may arrive from YAML (serde deserializes freely; env-layer validates its own inputs).
    config.llm_provider = config.llm_provider.trim().to_lowercase();
    match config.llm_provider.as_str() {
        "openai" | "anthropic" | "gemini" => {}
        other => anyhow::bail!(
            "llm_provider: unrecognized value {:?}; accepted: openai, anthropic, gemini",
            other
        ),
    }
    if let Some(ref k) = config.proxy_api_key.clone() {
        if k.trim().is_empty() {
            config.proxy_api_key = None;
        }
    }
    if let Some(ref k) = config.mcp_api_key.clone() {
        if k.trim().is_empty() {
            config.mcp_api_key = None;
        }
    }
    if let Some(url) = config.public_url.take() {
        let normalized = url.trim().trim_end_matches('/').to_owned();
        if !normalized.is_empty() {
            config.public_url = Some(normalized);
        }
    }

    // Post-layer validation: Anthropic requires both API key and proxy auth key.
    if config.llm_provider == "anthropic" {
        anyhow::ensure!(
            config.anthropic_api_key.as_deref().map(|k| !k.is_empty()).unwrap_or(false),
            "ZEMTIK_ANTHROPIC_API_KEY is required when ZEMTIK_LLM_PROVIDER=anthropic"
        );
        anyhow::ensure!(
            config.proxy_api_key.as_deref().map(|k| !k.is_empty()).unwrap_or(false),
            "ZEMTIK_PROXY_API_KEY is required when ZEMTIK_LLM_PROVIDER=anthropic"
        );
    }

    // Post-layer validation: catch zero/invalid values that the YAML layer can set
    anyhow::ensure!(
        config.intent_substring_gate_max_chars > 0,
        "intent_substring_gate_max_chars must be > 0, got {} (check config YAML or ZEMTIK_INTENT_SUBSTRING_GATE_MAX_CHARS)",
        config.intent_substring_gate_max_chars
    );
    anyhow::ensure!(
        config.intent_embed_prompt_max_chars > 0,
        "intent_embed_prompt_max_chars must be > 0, got {} (check config YAML or ZEMTIK_INTENT_EMBED_PROMPT_MAX_CHARS)",
        config.intent_embed_prompt_max_chars
    );

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
