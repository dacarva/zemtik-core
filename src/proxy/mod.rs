use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use constant_time_eq::constant_time_eq;
use crate::config::{AggFn, AppConfig, RewriterConfig, ZemtikMode};
use crate::intent::{IntentBackend, IntentError};
use crate::llm_backend::{AnthropicBackend, LlmBackend, OpenAiBackend};
use crate::types::{
    AuditRecord, EngineResult, EvidencePack, FastLaneResult, IntentResult, MessageContent,
    OpenAiRequestLog, OpenAiResponseLog, QueryParams, RequestedMode, RewriteMethod, Route,
    SchemaValidationResult, SignatureData, TokenUsage, ZemtikErrorCode,
};
use crate::{audit, bundle, db, engine_fast, evidence, intent, intent_embed, keys, prover, receipts, rewriter, router};
use crate::anonymizer::{AnonymizerGrpcClient, VaultStore, Vault, new_vault_store, build_channel, check_sidecar_health, SidecarHealth};

mod ui;
use ui::{render_verify_page, render_receipts_list, render_not_found};

pub(crate) struct ProxyState {
    pub(crate) http_client: reqwest::Client,
    /// Per-aggregation-type locks for ZK pipeline executions.
    /// Each mini-circuit uses its own directory, so SUM and COUNT can run concurrently.
    /// Two requests hitting the same aggregation type still contend on Prover.toml.
    pub(crate) pipeline_locks: HashMap<AggFn, tokio::sync::Mutex<()>>,
    /// Lock held across BOTH SUM and COUNT pipeline runs for AVG queries.
    /// Ensures both proofs operate on the same 500 transactions.
    pub(crate) avg_pipeline_lock: tokio::sync::Mutex<()>,
    /// File-based receipts DB, shared across requests.
    /// WARNING: std::sync::MutexGuard<Connection> must NEVER be held across an .await point.
    /// Lock inside spawn_blocking or in a synchronous scope that drops before any .await.
    pub(crate) receipts_db: std::sync::Mutex<Connection>,
    /// Separate in-memory ledger DB for FastLane reads (avoids contention with receipts_db).
    /// WARNING: std::sync::MutexGuard<Connection> must NEVER be held across an .await point.
    pub(crate) ledger_db: std::sync::Mutex<Connection>,
    /// Application configuration (ports, paths).
    pub(crate) config: Arc<AppConfig>,
    /// Bank signing key bytes (loaded once at startup, passed into spawn_blocking).
    pub(crate) signing_key_bytes: Vec<u8>,
    /// SHA-256 of schema_config.json bytes (empty string when schema absent).
    pub(crate) schema_config_hash: String,
    /// Intent matching backend — static after startup, no lock needed.
    pub(crate) intent_backend: Arc<dyn IntentBackend>,
    /// Provider-abstracted LLM backend. OpenAiBackend or AnthropicBackend.
    /// Constructed once at startup from ZEMTIK_LLM_PROVIDER.
    pub(crate) llm_backend: Arc<dyn LlmBackend>,
    /// Base URL for the query rewriter's OpenAI calls. Always points at OpenAI regardless
    /// of ZEMTIK_LLM_PROVIDER — the rewriter is OpenAI-only in v1.
    /// Renamed from openai_base_url in ProxyState (AppConfig.openai_base_url unchanged).
    pub(crate) rewriter_base_url: String,
    /// Semaphore for bounding concurrent FORK 2 background tasks (tunnel mode only).
    pub(crate) tunnel_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    /// Separate SQLite connection for tunnel audit records (tunnel mode only).
    /// WARNING: Never hold MutexGuard across .await.
    pub(crate) tunnel_audit_db: Option<std::sync::Mutex<Connection>>,
    /// Count of requests where FORK 2 was skipped due to semaphore exhaustion.
    pub(crate) backpressure_count: std::sync::atomic::AtomicU64,
    /// Schema validation result from startup. Exposed via /health.
    pub(crate) schema_validation: Arc<SchemaValidationResult>,
    /// Query rewriter configuration. None when ZEMTIK_QUERY_REWRITER is off (default).
    pub(crate) rewriter_config: Option<Arc<RewriterConfig>>,
    /// Whether ZEMTIK_GENERAL_PASSTHROUGH is enabled. Copied from config at startup.
    pub(crate) general_passthrough_enabled: bool,
    /// Sliding-window rate limiter for GeneralLane. None when general_max_rpm == 0 (unlimited).
    pub(crate) general_rate_limiter: Option<Arc<std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>>>,
    /// Max requests/minute for GeneralLane (0 = unlimited).
    pub(crate) general_max_rpm: u32,
    /// ed25519 manifest signing public key, hex-encoded. Derived from bank_sk at startup.
    /// Served on GET /public-key. Stable across restarts as long as bank_sk is unchanged.
    pub(crate) ed25519_manifest_pub_hex: String,
    /// SHA-256(raw ed25519 verifying key bytes) — key fingerprint added to every receipt.
    pub(crate) manifest_key_id: String,
    /// BabyJubJub public key components, precomputed at startup for GET /public-key.
    /// Avoids per-request scalar multiplication (expensive) on the /public-key hot path.
    pub(crate) bjj_pub_x: String,
    pub(crate) bjj_pub_y: String,
    /// Optional public base URL for this deployment (e.g. "https://zemtik.example.com").
    /// When set, zemtik_meta blocks include a verify_url hint.
    #[allow(dead_code)]
    pub(crate) public_url: Option<String>,
    /// Session-scoped vault store. std::sync::Mutex — never hold guard across .await.
    pub(crate) vault_store: VaultStore,
    /// Lazy gRPC client for the anonymizer sidecar. Clone per request (tonic client is cheap to clone).
    /// None when ZEMTIK_ANONYMIZER_ENABLED=false.
    pub(crate) anonymizer_client: Option<AnonymizerGrpcClient>,
}

// Results returned from the blocking ZK pipeline (includes optional bundle).
pub(crate) struct ZkPipelineResult {
    pub(crate) txns_len: usize,
    pub(crate) batch_count: usize,
    pub(crate) aggregate: u64,
    pub(crate) proof_status: &'static str,
    pub(crate) circuit_execution_secs: f32,
    pub(crate) first_sig: SignatureData,
    pub(crate) proof_hex: Option<String>,
    pub(crate) vk_hex: Option<String>,
    pub(crate) fully_verifiable: bool,
    pub(crate) bundle_result: Option<bundle::BundleResult>,
    /// SHA-256 of the ZK payload JSON sent to the LLM (Rust-layer commitment).
    /// None when fully_verifiable=false — no bundle artifact exists to match against.
    pub(crate) outgoing_prompt_hash: Option<String>,
    /// Number of real (non-dummy padding) rows included in the proof.
    pub(crate) actual_row_count: usize,
}

/// Build the Axum router with all state wired up. Extracted from `run_proxy()` so
/// integration tests can spin up a server on an ephemeral port without binding to a
/// real address or requiring nargo/bb on PATH.
pub async fn build_proxy_router(config: AppConfig) -> anyhow::Result<Router> {
    // Fail fast: schema_config.json is required for proxy mode routing.
    if config.schema_config.is_none() {
        anyhow::bail!(
            "schema_config required for proxy mode. \
             schema_config.json not found at {}. \
             Copy schema_config.example.json to ~/.zemtik/schema_config.json \
             and configure your table sensitivities. \
             Fix: mount your config with -v /path/to/schema_config.json:/etc/zemtik/schema_config.json",
            config.schema_config_path.display()
        );
    }

    // Validate sensitivity values
    crate::config::validate_schema_config(config.schema_config.as_ref().unwrap(), false)
        .context("validate schema_config")?;

    // Circuit validation — skipped when skip_circuit_validation=true (Docker / tests without nargo/bb).
    if !config.skip_circuit_validation {
        prover::validate_circuit_dir(&config.circuit_dir).context("circuit directory validation")?;
    }

    // D8: hard startup error — rewriter calls OpenAI internally; incompatible with Anthropic
    if config.query_rewriter_enabled && config.llm_provider == "anthropic" {
        anyhow::bail!(
            "ZEMTIK_QUERY_REWRITER=1 is incompatible with ZEMTIK_LLM_PROVIDER=anthropic. \
             The rewriter calls OpenAI internally. \
             To use Anthropic: set ZEMTIK_QUERY_REWRITER=0. \
             To keep the rewriter: set ZEMTIK_LLM_PROVIDER=openai."
        );
    }

    // S1: hard startup error — Anthropic path requires both API key and proxy auth key
    if config.llm_provider == "anthropic" {
        if config.anthropic_api_key.as_deref().map(|k| k.is_empty()).unwrap_or(true) {
            anyhow::bail!(
                "ZEMTIK_ANTHROPIC_API_KEY is required when ZEMTIK_LLM_PROVIDER=anthropic."
            );
        }
        if config.proxy_api_key.as_deref().map(|k| k.is_empty()).unwrap_or(true) {
            anyhow::bail!(
                "ZEMTIK_PROXY_API_KEY is required when ZEMTIK_LLM_PROVIDER=anthropic.\n\
                 When Anthropic is the backend, Zemtik uses a server-side API key for all outbound\n\
                 Claude calls. Any client that reaches :4000 would otherwise get free API calls\n\
                 billed to your Anthropic account.\n\
                 Set ZEMTIK_PROXY_API_KEY to a strong bearer token and send it from your client\n\
                 as 'Authorization: Bearer <ZEMTIK_PROXY_API_KEY>'."
            );
        }
    }

    let schema_config_hash = config.schema_config_hash.clone().unwrap_or_default();
    let schema = config.schema_config.clone().unwrap();
    let rewriter_base_url = config.openai_base_url.clone();

    // Build intent backend. Use EmbeddingBackend unless ZEMTIK_INTENT_BACKEND=regex
    // or the feature is disabled. Falls back to RegexBackend on model load failure.
    let intent_backend: Arc<dyn IntentBackend> = {
        let use_embed = config.intent_backend.to_lowercase() != "regex";
        let backend: Box<dyn IntentBackend> = if use_embed {
            // Validate embed fields before attempting model load
            if let Err(e) = crate::config::validate_schema_config(&schema, true) {
                eprintln!(
                    "[INTENT] WARN: schema missing embed fields ({}). Falling back to regex backend.",
                    e
                );
                let mut b = Box::new(intent::RegexBackend::new());
                b.index_schema(&schema);
                b as Box<dyn IntentBackend>
            } else {
                match intent_embed::try_new_embedding_backend(&config.models_dir, config.intent_embed_prompt_max_chars) {
                    Some(mut b) => {
                        b.index_schema(&schema);
                        b
                    }
                    None => {
                        // Fallback already logged by try_new_embedding_backend
                        let mut b = Box::new(intent::RegexBackend::new());
                        b.index_schema(&schema);
                        b as Box<dyn IntentBackend>
                    }
                }
            }
        } else {
            println!("[INTENT] Using regex intent backend (ZEMTIK_INTENT_BACKEND=regex)");
            let mut b = Box::new(intent::RegexBackend::new());
            b.index_schema(&schema);
            b as Box<dyn IntentBackend>
        };
        Arc::from(backend)
    };

    let config = Arc::new(config);

    let receipts_conn =
        receipts::open_receipts_db(&config.receipts_db_path).context("open receipts DB")?;

    // Initialize ledger DB (in-memory, seeded) for FastLane reads.
    let ledger_conn = db::init_ledger_sqlite().context("init ledger DB for FastLane")?;

    // Load (or generate) the bank signing key once at startup.
    let signing_key = keys::load_or_generate_key(&config.keys_dir)
        .context("load or generate signing key")?;
    let signing_key_bytes = signing_key.key.to_vec();

    // Derive ed25519 manifest signing key and compute key fingerprint.
    let (ed25519_manifest_pub_hex, manifest_key_id) = {
        let seed: [u8; 32] = signing_key_bytes.as_slice().try_into()
            .context("bank_sk must be exactly 32 bytes")?;
        let (_, verifying_key) = keys::derive_manifest_signing_keypair(&seed)
            .context("derive manifest signing keypair at startup")?;
        let pub_hex = hex::encode(verifying_key.as_bytes());
        // Fingerprint: SHA-256 of the raw 32-byte public key (not the hex string).
        // Standard practice: auditors independently compute fingerprint from raw key bytes.
        let key_id = hex::encode(sha2::Sha256::digest(verifying_key.as_bytes()));
        (pub_hex, key_id)
    };

    // Precompute BabyJubJub public key at startup to avoid per-request scalar multiplication
    // on the GET /public-key endpoint.
    let (bjj_pub_x, bjj_pub_y) = match babyjubjub_rs::PrivateKey::import(signing_key_bytes.clone()) {
        Ok(sk) => {
            let pk = sk.public();
            (pk.x.to_string(), pk.y.to_string())
        }
        Err(e) => {
            anyhow::bail!("[STARTUP] Failed to derive BabyJubJub public key: {}", e);
        }
    };

    let mut pipeline_locks = HashMap::new();
    pipeline_locks.insert(AggFn::Sum, tokio::sync::Mutex::new(()));
    pipeline_locks.insert(AggFn::Count, tokio::sync::Mutex::new(()));

    // Initialize tunnel-mode-specific fields.
    let (tunnel_semaphore, tunnel_audit_db) = if config.mode == ZemtikMode::Tunnel {
        let sem = Arc::new(tokio::sync::Semaphore::new(config.tunnel_semaphore_permits));
        let audit_conn = receipts::open_tunnel_audit_db(&config.tunnel_audit_db_path)
            .context("open tunnel audit DB")?;
        (Some(sem), Some(std::sync::Mutex::new(audit_conn)))
    } else {
        (None, None)
    };

    // Run startup schema validation (Postgres only; SQLite and skipped modes return immediately).
    let schema_validation = Arc::new(
        crate::startup::run_startup_validation(&config, &schema).await
    );

    // Build rewriter config if enabled — skip entirely in tunnel mode (no-op there).
    // Avoids startup failure when ZEMTIK_QUERY_REWRITER=1 is set alongside
    // ZEMTIK_MODE=tunnel without a corresponding OPENAI_API_KEY.
    let rewriter_config: Option<Arc<RewriterConfig>> = if config.query_rewriter_enabled
        && config.mode != ZemtikMode::Tunnel
    {
        let api_key = config.openai_api_key.clone()
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            .unwrap_or_default();
        if api_key.is_empty() {
            anyhow::bail!(
                "ZEMTIK_QUERY_REWRITER=1 requires OPENAI_API_KEY to be set. \
                 The LLM rewrite fallback cannot authenticate without it."
            );
        }
        Some(Arc::new(RewriterConfig {
            base_url: rewriter_base_url.clone(),
            model: config.query_rewriter_model.clone(),
            api_key,
            context_window_turns: config.query_rewriter_context_turns,
            max_scan_messages: config.query_rewriter_scan_messages,
            timeout_secs: config.query_rewriter_timeout_secs,
            max_context_tokens: config.query_rewriter_max_context_tokens,
        }))
    } else {
        None
    };

    let general_rate_limiter = if config.general_max_rpm > 0 {
        Some(Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::<std::time::Instant>::new(),
        )))
    } else {
        None
    };

    // Build provider-specific LLM backend (constructed once at startup)
    let llm_backend: Arc<dyn LlmBackend> = {
        let http_client = reqwest::Client::new();
        if config.llm_provider == "anthropic" {
            // config validation (load_from_sources) guarantees anthropic_api_key is Some and non-empty.
            let api_key = config.anthropic_api_key.clone().unwrap_or_default();
            Arc::new(AnthropicBackend::new(
                http_client,
                api_key,
                config.anthropic_model.clone(),
                config.anthropic_base_url.clone(),
            )) as Arc<dyn LlmBackend>
        } else {
            Arc::new(OpenAiBackend::new(
                http_client,
                config.openai_base_url.clone(),
            )) as Arc<dyn LlmBackend>
        }
    };

    let state = Arc::new(ProxyState {
        http_client: reqwest::Client::new(),
        pipeline_locks,
        avg_pipeline_lock: tokio::sync::Mutex::new(()),
        receipts_db: std::sync::Mutex::new(receipts_conn),
        ledger_db: std::sync::Mutex::new(ledger_conn),
        config: Arc::clone(&config),
        signing_key_bytes,
        schema_config_hash,
        intent_backend,
        llm_backend,
        rewriter_base_url,
        tunnel_semaphore,
        tunnel_audit_db,
        backpressure_count: std::sync::atomic::AtomicU64::new(0),
        schema_validation,
        rewriter_config,
        general_passthrough_enabled: config.general_passthrough_enabled,
        general_rate_limiter,
        general_max_rpm: config.general_max_rpm,
        ed25519_manifest_pub_hex,
        manifest_key_id,
        bjj_pub_x,
        bjj_pub_y,
        public_url: config.public_url.clone(),
        vault_store: new_vault_store(),
        anonymizer_client: if config.anonymizer_enabled {
            Some(AnonymizerGrpcClient::new(
                build_channel(&config.anonymizer_sidecar_addr)
                    .context("build anonymizer gRPC channel")?
            ))
        } else {
            None
        },
    });

    // Spawn background vault TTL eviction task (runs every 60s, evicts entries > TTL).
    if config.anonymizer_enabled {
        let vault_store = Arc::clone(&state.vault_store);
        let ttl_secs = config.anonymizer_vault_ttl_secs;
        tokio::spawn(async move {
            let ttl = std::time::Duration::from_secs(ttl_secs);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let mut store = vault_store.lock().unwrap();
                store.retain(|_, (_, ts)| ts.elapsed() < ttl);
            }
        });

        // Startup sidecar health ping — surfaces misconfigurations before the first request
        // and warms the tonic lazy connection so the first real request doesn't fall back to regex.
        let addr = config.anonymizer_sidecar_addr.clone();
        let channel = build_channel(&addr).context("build anonymizer gRPC channel for startup ping")?;
        let ping_start = std::time::Instant::now();
        let health = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            check_sidecar_health(channel),
        )
        .await
        .unwrap_or(SidecarHealth::Unreachable);
        match health {
            SidecarHealth::Serving => println!(
                "[ANON] Sidecar OK at {} ({}ms)",
                addr,
                ping_start.elapsed().as_millis()
            ),
            _ => eprintln!(
                "[ANON] WARNING: Sidecar unreachable at {} — first request will fall back to regex \
                 (or 503 if ZEMTIK_ANONYMIZER_FALLBACK_REGEX=false). \
                 Start the sidecar with: docker run --rm -p 50051:50051 zemtik-sidecar",
                addr
            ),
        }
    }

    // If any configured origin is "*", use the wildcard policy.
    // Mixing "*" with specific origins (e.g. "*, https://app") is unsupported —
    // the "*" takes precedence so callers don't get surprising no-CORS responses.
    let exposed_headers: Vec<axum::http::HeaderName> = vec![
        axum::http::HeaderName::from_static("x-zemtik-engine"),
        axum::http::HeaderName::from_static("x-zemtik-meta"),
        axum::http::HeaderName::from_static("x-zemtik-receipt-id"),
        axum::http::HeaderName::from_static("x-zemtik-bundle-id"),
        axum::http::HeaderName::from_static("x-zemtik-verify-url"),
    ];
    let cors = if config.cors_origins.iter().any(|o| o == "*") {
        CorsLayer::new()
            .allow_origin(tower_http::cors::Any)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
            .expose_headers(exposed_headers)
    } else {
        let origins: Vec<HeaderValue> = config
            .cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
            .expose_headers(exposed_headers)
    };

    let app = match config.mode {
        ZemtikMode::Standard => Router::new()
            .route("/health", get(handle_health))
            .route("/public-key", get(handle_public_key))
            .route("/v1/chat/completions", post(handle_chat_completions))
            .route("/v1/models", get(handle_models))
            .route("/v1/anonymize/preview", post(handle_anonymize_preview))
            .route("/receipts", get(handle_receipts_list))
            .route("/verify/{id}", get(handle_verify))
            .route("/{*path}", any(handle_passthrough)),
        ZemtikMode::Tunnel => Router::new()
            .route("/health", get(handle_health))
            .route("/public-key", get(handle_public_key))
            .route("/v1/chat/completions", post(crate::tunnel::handle_tunnel))
            .route("/v1/models", any(crate::tunnel::handle_tunnel_passthrough))
            .route("/v1/anonymize/preview", post(handle_anonymize_preview))
            .route("/tunnel/audit", get(crate::tunnel::handle_audit))
            .route("/tunnel/audit/csv", get(crate::tunnel::handle_audit_csv))
            .route("/tunnel/summary", get(crate::tunnel::handle_summary))
            .route("/receipts", get(handle_receipts_list))
            .route("/verify/{id}", get(handle_verify))
            .route("/{*path}", any(crate::tunnel::handle_tunnel_passthrough)),
    };
    let app = app.layer(cors).with_state(state);

    Ok(app)
}

/// Entry point for proxy mode. Starts Axum on the configured port.
pub async fn run_proxy(config: AppConfig) -> anyhow::Result<()> {
    let addr = config.bind_addr.clone();
    let is_tunnel = config.mode == ZemtikMode::Tunnel;
    let tunnel_model = config.tunnel_model.clone()
        .unwrap_or_else(|| config.openai_model.clone());
    let tunnel_permits = config.tunnel_semaphore_permits;
    let tunnel_timeout = config.tunnel_timeout_secs;
    if is_tunnel && config.tunnel_api_key.is_none() {
        anyhow::bail!(
            "ZEMTIK_TUNNEL_API_KEY is required in tunnel mode.\n\
             Zemtik's verification calls must be billed to zemtik's account, not the \
             pilot customer's.\n\
             Set ZEMTIK_TUNNEL_API_KEY to a separate OpenAI API key before starting \
             in tunnel mode."
        );
    }

    let app = build_proxy_router(config).await?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!("╔══════════════════════════════════════════════════╗");
    println!("║   Zemtik Proxy — ZK Middleware for Enterprise AI ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    if is_tunnel {
        println!("[TUNNEL MODE] Zemtik is running in transparent verification mode.");
        println!("[TUNNEL MODE] Audit records:    http://{}/tunnel/audit", addr);
        println!("[TUNNEL MODE] Summary metrics:  http://{}/tunnel/summary", addr);
        println!(
            "[TUNNEL MODE] ZEMTIK_TUNNEL_MODEL: {} | permits: {} | timeout: {}s",
            tunnel_model, tunnel_permits, tunnel_timeout
        );
        println!();
    } else {
        println!("[PROXY] Listening on http://{}", addr);
        println!(
            "[PROXY] Intercepts POST /v1/chat/completions → ZK pipeline → forwards to OpenAI"
        );
        println!(
            "[PROXY] Point your app to http://{} instead of api.openai.com",
            addr
        );
        println!(
            "[PROXY] Verify receipts at http://{}/verify/<bundle-id>",
            addr
        );
        println!();
    }

    axum::serve(listener, app).await?;
    Ok(())
}

/// Intercept /v1/chat/completions: extract intent → route → FastLane or ZK pipeline.
async fn handle_chat_completions(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<Response, ProxyError> {
    let total_start = Instant::now();

    // S1: When provider=anthropic, require an explicit Authorization bearer — do NOT fall back to
    // OPENAI_API_KEY or config.openai_api_key. The server-side Anthropic key is used for all
    // outbound calls; the incoming bearer is purely to authenticate requests to this proxy.
    // Missing key is a startup error (build_proxy_router), but we defend in-depth here.
    let api_key = if state.config.llm_provider == "anthropic" {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_owned());
        let expected = state.config.proxy_api_key.as_deref().unwrap_or("");
        let incoming = bearer.as_deref().unwrap_or("");
        if expected.is_empty() || !constant_time_eq(incoming.as_bytes(), expected.as_bytes()) {
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": {
                        "type": "auth_error",
                        "message": "Invalid or missing Authorization bearer token. \
                                    Set Authorization: Bearer <ZEMTIK_PROXY_API_KEY>."
                    }
                })),
            )
                .into_response());
        }
        incoming.to_owned()
    } else {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_owned())
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            .or_else(|| state.config.openai_api_key.clone())
            .ok_or_else(|| {
                ProxyError::Internal(anyhow::anyhow!(
                    "No Authorization header, OPENAI_API_KEY env var, or openai_api_key in config.yaml"
                ))
            })?
    };

    // ---------------------------------------------------------------------------
    // zemtik_mode: parse, validate, and strip before hashing / forwarding.
    // OpenAI rejects unknown top-level fields, so the strip must happen first.
    // ---------------------------------------------------------------------------
    let requested_mode = match body.get("zemtik_mode") {
        None => RequestedMode::Unspecified,
        Some(v) => match v.as_str() {
            Some("document") => RequestedMode::Document,
            Some("data") => RequestedMode::Data,
            Some(other) => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": {
                            "type": "invalid_zemtik_mode",
                            "message": format!(
                                "invalid zemtik_mode {:?}: expected 'document' or 'data'",
                                other
                            )
                        }
                    })),
                )
                    .into_response());
            }
            // Non-string value (true, 42, null, {}, …) — reject instead of silently ignoring.
            None => {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": {
                            "type": "invalid_zemtik_mode",
                            "message": "zemtik_mode must be a string: expected 'document' or 'data'"
                        }
                    })),
                )
                    .into_response());
            }
        },
    };
    // Strip before hashing so request_hash doesn't include this zemtik-internal field.
    if let Some(obj) = body.as_object_mut() {
        obj.remove("zemtik_mode");
    }

    let request_hash = hex::encode(Sha256::digest(
        &serde_json::to_vec(&body)
            .context("serialize request body for hashing")
            .map_err(ProxyError::Internal)?,
    ));
    let prompt_hash = hex::encode(Sha256::digest(
        &serde_json::to_vec(&body["messages"])
            .context("serialize messages for hashing")
            .map_err(ProxyError::Internal)?,
    ));

    // Extract the last user message prompt for intent parsing.
    // Handles both plain-string content and the content-parts array format
    // sent by openai-python v1.x and other modern SDKs.
    let mut prompt = body
        .get("messages")
        .and_then(|m| m.as_array())
        .and_then(|arr| {
            arr.iter()
                .rev()
                .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        })
        .and_then(|m| m.get("content"))
        .map(|c| {
            serde_json::from_value::<MessageContent>(c.clone())
                .map(|mc| mc.to_text())
                .unwrap_or_default()
        })
        .unwrap_or_default();

    // Preserve original prompt for intent extraction — the anonymizer will
    // overwrite `prompt` with the tokenized version, but intent matching must
    // run against the real text so entity names don't break embedding scores.
    let original_prompt_for_intent = prompt.clone();

    // ---------------------------------------------------------------------------
    // Anonymizer pre-router hook
    // ---------------------------------------------------------------------------
    // Invariant: skip in Tunnel mode (FORK 2 must see original text for diff).
    let is_streaming = body.get("stream").and_then(|v| v.as_bool()) == Some(true);
    let anonymizer_vault: Option<Vault>;
    let mut anonymizer_meta: Option<crate::anonymizer::AuditMeta> = None;
    let anonymizer_session_id = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| {
            s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if state.config.anonymizer_enabled
        && state.config.mode != ZemtikMode::Tunnel
    {
        // Streaming + anonymizer → 415 (buffer+re-stream deferred to phase 3)
        if is_streaming {
            return Ok((
                StatusCode::from_u16(415).unwrap(),
                Json(serde_json::json!({
                    "error": {
                        "type": "anonymizer_streaming_unsupported",
                        "message": "Streaming not supported when anonymizer is enabled. Set stream: false or disable ZEMTIK_ANONYMIZER_ENABLED."
                    }
                })),
            ).into_response());
        }

        let messages = body.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default();
        let messages_values: Vec<Value> = messages;

        let mut grpc_client = state.anonymizer_client.clone();
        let anon_result = crate::anonymizer::anonymize_conversation(
            &messages_values,
            &anonymizer_session_id,
            grpc_client.as_mut(),
            &state.config.anonymizer_entity_types,
            state.config.anonymizer_sidecar_timeout_ms,
            state.config.anonymizer_fallback_regex,
            &state.config.anonymizer_sidecar_addr,
        ).await;

        match anon_result {
            Ok((anon_messages, vault, meta)) => {
                // Mutate body.messages with anonymized content
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("messages".to_owned(), Value::Array(anon_messages.clone()));
                    // Inject system prompt as a separate message
                    if !vault.is_empty() {
                        if let Some(msgs) = obj.get_mut("messages").and_then(|m| m.as_array_mut()) {
                            msgs.push(serde_json::json!({
                                "role": "system",
                                "content": crate::anonymizer::SYSTEM_PROMPT_INJECT
                            }));
                        }
                    }
                }
                // Re-extract prompt from anonymized messages
                prompt = body
                    .get("messages")
                    .and_then(|m| m.as_array())
                    .and_then(|arr| {
                        arr.iter().rev().find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
                    })
                    .and_then(|m| m.get("content"))
                    .map(|c| serde_json::from_value::<MessageContent>(c.clone()).map(|mc| mc.to_text()).unwrap_or_default())
                    .unwrap_or_default();

                // Insert vault into store; scopeguard removes it after this request
                {
                    let mut store = state.vault_store.lock().unwrap();
                    store.insert(anonymizer_session_id.clone(), (vault.clone(), Instant::now()));
                }
                anonymizer_vault = Some(vault);

                anonymizer_meta = Some(meta);
            }
            Err(e) => {
                let (code, error_type, error_code, msg) = match &e {
                    crate::anonymizer::AnonymizerError::SidecarUnreachable { addr } => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "anonymizer_unavailable",
                        "SidecarUnreachable",
                        format!("PII sidecar unreachable at {addr}. Ensure the anonymizer service is running (docker compose up) or set ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true to use regex-only mode."),
                    ),
                    crate::anonymizer::AnonymizerError::SidecarStarting => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "anonymizer_unavailable",
                        "SidecarStarting",
                        "PII sidecar is starting. GLiNER model load takes 10-30s. Check container health (docker compose ps) and retry, or wait for the 'anonymizer' service to report 'healthy'.".to_owned(),
                    ),
                    _ => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "anonymizer_unavailable",
                        "SidecarError",
                        e.to_string(),
                    ),
                };
                return Ok((
                    code,
                    Json(serde_json::json!({
                        "error": {
                            "type": error_type,
                            "code": error_code,
                            "message": msg
                        }
                    })),
                ).into_response());
            }
        }
    } else {
        anonymizer_vault = None;
    }
    // scopeguard: remove vault entry after this request (after deanonymize, or on error/panic)
    let _vault_cleanup = {
        let store = Arc::clone(&state.vault_store);
        let sid = anonymizer_session_id.clone();
        scopeguard::guard((), move |_| {
            if let Ok(mut s) = store.lock() {
                s.remove(&sid);
            }
        })
    };

    // ---------------------------------------------------------------------------
    // zemtik_mode: document — skip intent matching, force general_lane.
    // Placed after the anonymizer block so PII is tokenized before routing.
    // Tunnel mode: field is accepted but ignored (transparent passthrough).
    // ---------------------------------------------------------------------------
    if requested_mode == RequestedMode::Document && state.config.mode != ZemtikMode::Tunnel {
        if !state.general_passthrough_enabled {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "type": "zemtik_mode_document_requires_passthrough",
                        "message": "zemtik_mode=document requires ZEMTIK_GENERAL_PASSTHROUGH=1"
                    }
                })),
            )
                .into_response());
        }
        return handle_general_lane(
            state,
            body,
            api_key,
            prompt,
            prompt_hash,
            None,
            total_start,
            anonymizer_vault,
            anonymizer_meta,
        )
        .await;
    }

    // Streaming guard (standard mode only). Tunnel mode supports stream:true via
    // forward_streaming. GeneralLane also supports streaming when
    // ZEMTIK_GENERAL_PASSTHROUGH=1 — allow stream:true through so intent extraction
    // can run; data lanes reject stream:true at their own dispatch point below.
    if state.config.mode == crate::config::ZemtikMode::Standard
        && is_streaming
        && !state.general_passthrough_enabled
    {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "type": "zemtik_config_error",
                    "code": ZemtikErrorCode::StreamingNotSupported,
                    "message": "Set stream: false in your client configuration.",
                    "hint": "The ZK pipeline must complete before any part of the response can be sent.",
                    "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/GETTING_STARTED.md#streaming"
                }
            })),
        ).into_response());
    }

    // Reject empty prompts early — an empty string silently triggers the expensive
    // ZK slow lane (intent returns NoTableIdentified → ZK fallback). Return 400 instead.
    if prompt.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "type": "zemtik_config_error",
                    "code": ZemtikErrorCode::InvalidRequest,
                    "message": "user message content is empty or unreadable",
                    "hint": "Ensure the last message has role 'user' with non-empty text content.",
                    "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/GETTING_STARTED.md"
                }
            })),
        ).into_response());
    }

    // Extract intent using SchemaConfig
    let schema = state.config.schema_config.as_ref().ok_or_else(|| {
        ProxyError::Internal(anyhow::anyhow!("schema_config not loaded"))
    })?;

    // Run intent extraction in a blocking thread — the embedding backend holds a
    // std::sync::Mutex<TextEmbedding> and ONNX inference can take tens to hundreds of ms.
    // Running this on the Tokio worker thread would starve other async tasks under load.
    let intent_result_raw = {
        let backend = Arc::clone(&state.intent_backend);
        let prompt_clone = original_prompt_for_intent.clone();
        let schema_clone = schema.clone();
        let threshold = state.config.intent_confidence_threshold;
        let gate_max_chars = state.config.intent_substring_gate_max_chars;
        tokio::task::spawn_blocking(move || {
            intent::extract_intent_with_backend(&prompt_clone, &schema_clone, backend.as_ref(), threshold, gate_max_chars)
        })
        .await
        .map_err(|e| ProxyError::Internal(anyhow::anyhow!("intent backend thread panicked: {}", e)))?
    };

    // Extract the full messages array for rewriter context (cloned before borrowing schema).
    let messages: Vec<Value> = body
        .get("messages")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();

    let intent_result = match intent_result_raw {
        Ok(r) => r,
        Err(intent_err) => {
            println!("[ROUTE] Intent rejection: {}", intent_err);

            // True when GeneralLane will handle this request — not a user-visible failure.
            // Used to suppress the intent_rejection receipt so that intent_failures_today
            // only counts queries that resulted in a 400, not queries rescued by GeneralLane.
            let divert_to_general_lane = state.general_passthrough_enabled
                && matches!(
                    intent_err,
                    IntentError::NoTableIdentified | IntentError::TimeRangeAmbiguous
                );

            // Helper: log rejection to receipts DB synchronously.
            // Called only on final failure paths so that a successful rewrite does not
            // produce a phantom rejection record alongside the success receipt.
            // Skipped when divert_to_general_lane is true — the general_lane receipt
            // already records the request, and the query was never rejected from the user's POV.
            let log_rejection = |db: &std::sync::MutexGuard<rusqlite::Connection>, msg: &str| {
                if divert_to_general_lane {
                    return;
                }
                if let Err(db_err) = receipts::insert_intent_rejection(db, &prompt, msg) {
                    eprintln!("[WARN] Failed to log intent rejection to receipts DB: {}", db_err);
                }
            };

            // Hybrid query rewriter — only fires when ZEMTIK_QUERY_REWRITER=1.
            if let Some(rw_config) = state.rewriter_config.as_ref().map(Arc::clone) {
                // ── STEP 1: deterministic_resolve ────────────────────────────────
                // KNOWN ISSUE: `messages` here is the anonymized array (PII replaced with [[Z:…]] tokens).
                // Rewriter context quality degrades when entity names are absent. Fix tracked for Phase 2.
                let det_result = {
                    let backend = Arc::clone(&state.intent_backend);
                    let messages_clone = messages.clone();
                    let schema_clone = schema.clone();
                    let threshold = state.config.intent_confidence_threshold;
                    let max_scan = rw_config.max_scan_messages;
                    let gate_max_chars = state.config.intent_substring_gate_max_chars;
                    tokio::task::spawn_blocking(move || {
                        rewriter::deterministic_resolve(
                            &messages_clone,
                            &schema_clone,
                            backend.as_ref(),
                            threshold,
                            max_scan,
                            gate_max_chars,
                        )
                    })
                    .await
                    .map_err(|e| {
                        ProxyError::Internal(anyhow::anyhow!(
                            "deterministic_resolve spawn_blocking panicked: {}", e
                        ))
                    })?
                };

                if let Some(mut resolved) = det_result {
                    // Per-table disable check (fail-secure override).
                    if let Some(tc) = schema.tables.get(&resolved.table) {
                        if tc.query_rewriting == Some(false) {
                            let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
                            log_rejection(&db_guard, "rewriting disabled for table (query_rewriting: false)");
                            return Ok(rewriting_disabled_400());
                        }
                    }
                    // Record the original failing prompt (what the user actually said).
                    // The resolved table+time are stored in the IntentResult fields themselves.
                    resolved.rewritten_query = Some(prompt.clone());
                    resolved.rewrite_method = Some(RewriteMethod::Deterministic);
                    println!("[REWRITER] Deterministic: '{}' → table='{}' [{}-{}]",
                        prompt, resolved.table, resolved.start_unix_secs, resolved.end_unix_secs);
                    let route = router::decide_route(&resolved, schema);
                    let effective_client_id: i64 = schema
                        .tables
                        .get(&resolved.table)
                        .and_then(|tc| tc.client_id)
                        .unwrap_or(state.config.client_id);
                    // Data lanes do not support streaming.
                    if is_streaming {
                        return Ok(streaming_not_supported_for_data_lane());
                    }
                    return match route {
                        Route::FastLane => handle_fast_lane(state, body, api_key, request_hash, prompt_hash, resolved, effective_client_id, total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await,
                        Route::ZkSlowLane => handle_zk_slow_lane(state, body, headers, api_key, request_hash, prompt_hash, prompt.clone(), resolved, effective_client_id, total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await,
                        Route::GeneralLane => unreachable!("decide_route never returns GeneralLane"),
                    };
                }

                // ── STEP 2: LLM rewriter (async — do NOT put inside spawn_blocking) ──
                // KNOWN ISSUE: `messages` passed here is the anonymized array. Tracked for Phase 2.
                match rewriter::rewrite_query(&messages, &prompt, schema, &rw_config, &state.http_client).await {
                    Ok(rewriter::RewriteResult::Rewritten(q)) => {
                        println!("[REWRITER] LLM: '{}' → '{}'", prompt, q);
                        // Re-run intent on the rewritten query.
                        let backend = Arc::clone(&state.intent_backend);
                        let q_clone = q.clone();
                        let schema_clone = schema.clone();
                        let threshold = state.config.intent_confidence_threshold;
                        let gate_max_chars = state.config.intent_substring_gate_max_chars;
                        let re_intent_join = tokio::task::spawn_blocking(move || {
                            intent::extract_intent_with_backend(&q_clone, &schema_clone, backend.as_ref(), threshold, gate_max_chars)
                        })
                        .await;

                        // Distinguish panic (JoinError → 500) from intent failure (→ unresolvable 400).
                        let re_intent: Option<_> = match re_intent_join {
                            Err(join_err) => {
                                return Err(ProxyError::Internal(anyhow::anyhow!(
                                    "re-intent spawn_blocking panicked after LLM rewrite: {}", join_err
                                )));
                            }
                            Ok(intent_result) => intent_result.ok(),
                        };

                        match re_intent {
                            Some(mut r) => {
                                // Per-table disable (LLM could have picked a locked table).
                                if let Some(tc) = schema.tables.get(&r.table) {
                                    if tc.query_rewriting == Some(false) {
                                        let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
                                        log_rejection(&db_guard, "rewriting disabled for table (query_rewriting: false)");
                                        return Ok(rewriting_disabled_400());
                                    }
                                }
                                r.rewritten_query = Some(q.clone());
                                r.rewrite_method = Some(RewriteMethod::LlmRewrite);
                                let route = router::decide_route(&r, schema);
                                let effective_client_id: i64 = schema
                                    .tables
                                    .get(&r.table)
                                    .and_then(|tc| tc.client_id)
                                    .unwrap_or(state.config.client_id);
                                // Rewrite succeeded — do NOT log intent_rejection.
                                // Data lanes do not support streaming.
                                if is_streaming {
                                    return Ok(streaming_not_supported_for_data_lane());
                                }
                                return match route {
                                    Route::FastLane => handle_fast_lane(state, body, api_key, request_hash, prompt_hash, r, effective_client_id, total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await,
                                    Route::ZkSlowLane => handle_zk_slow_lane(state, body, headers, api_key, request_hash, prompt_hash, prompt.clone(), r, effective_client_id, total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await,
                                    Route::GeneralLane => unreachable!("decide_route never returns GeneralLane"),
                                };
                            }
                            None => {
                                // LLM rewrote but re-intent failed — final failure.
                                {
                                    let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
                                    log_rejection(&db_guard, &intent_err.to_string());
                                } // drop db_guard before potential GeneralLane dispatch
                                if state.general_passthrough_enabled
                                    && matches!(intent_err, IntentError::NoTableIdentified | IntentError::TimeRangeAmbiguous)
                                {
                                    return handle_general_lane(state, body, api_key, prompt, prompt_hash, Some(intent_err), total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await;
                                }
                                return Ok(rewriting_failed_400("unresolvable"));
                            }
                        }
                    }
                    Ok(rewriter::RewriteResult::Unresolvable) => {
                        {
                            let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
                            log_rejection(&db_guard, &intent_err.to_string());
                        } // drop db_guard before potential GeneralLane dispatch
                        if state.general_passthrough_enabled
                            && matches!(intent_err, IntentError::NoTableIdentified | IntentError::TimeRangeAmbiguous)
                        {
                            return handle_general_lane(state, body, api_key, prompt, prompt_hash, Some(intent_err), total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await;
                        }
                        return Ok(rewriting_failed_400("unresolvable"));
                    }
                    Err(e) => {
                        // Walk the full anyhow error chain — reqwest::Error is typically
                        // wrapped by `.context()` so downcast_ref on the top level fails.
                        let is_timeout = e.chain().any(|cause| {
                            cause.downcast_ref::<reqwest::Error>()
                                .map(|re| re.is_timeout())
                                .unwrap_or(false)
                        });
                        // Log to stderr but never expose in HTTP response body.
                        eprintln!("[REWRITER] rewrite_query error (not exposed to caller): {:?}", e);
                        let hint_kind = if is_timeout {
                            format!("timeout:{}", rw_config.timeout_secs)
                        } else {
                            "unresolvable".to_owned()
                        };
                        let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
                        log_rejection(&db_guard, &intent_err.to_string());
                        // Rewriter timeout is a transient infra error — do NOT route to GeneralLane
                        // (an operator who hits a timeout wants to debug the rewriter, not silently
                        // fall back). Only Unresolvable/NoTableIdentified routes to GeneralLane.
                        return Ok(rewriting_failed_400(&hint_kind));
                    }
                }
            }

            // Rewriter disabled (or exhausted without rewriter path above) — log rejection.
            {
                let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
                log_rejection(&db_guard, &intent_err.to_string());
            }
            // Route to GeneralLane if enabled and the error is a genuine non-data query.
            if state.general_passthrough_enabled
                && matches!(intent_err, crate::intent::IntentError::NoTableIdentified | crate::intent::IntentError::TimeRangeAmbiguous)
            {
                return handle_general_lane(state, body, api_key, prompt, prompt_hash, Some(intent_err), total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await;
            }
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "type": "zemtik_intent_error",
                        "code": ZemtikErrorCode::NoTableIdentified,
                        "message": format!("Intent extraction failed: {}", intent_err),
                        "hint": "If this query references your data, add aliases to schema_config.json (see docs/HOW_TO_ADD_TABLE.md). If this is a general (non-data) query, set ZEMTIK_GENERAL_PASSTHROUGH=1 to route it through the general lane.",
                        "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/HOW_TO_ADD_TABLE.md"
                    }
                })),
            ).into_response());
        }
    };

    let route = router::decide_route(&intent_result, schema);

    // Resolve effective client_id: per-table override takes precedence over global config.
    let effective_client_id: i64 = schema
        .tables
        .get(&intent_result.table)
        .and_then(|tc| tc.client_id)
        .unwrap_or(state.config.client_id);

    // Data lanes do not support streaming (ZK pipeline must complete before response).
    // If general_passthrough is enabled and stream:true reached here via a resolved data
    // query, reject it explicitly rather than sending stream:true to the ZK/fast pipeline.
    if is_streaming {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "type": "zemtik_config_error",
                    "code": ZemtikErrorCode::StreamingNotSupported,
                    "message": "Set stream: false in your client configuration.",
                    "hint": "The ZK pipeline must complete before any part of the response can be sent.",
                    "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/GETTING_STARTED.md#streaming"
                }
            })),
        ).into_response());
    }

    match route {
        Route::FastLane => {
            handle_fast_lane(state, body, api_key, request_hash, prompt_hash, intent_result, effective_client_id, total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await
        }
        Route::ZkSlowLane => {
            handle_zk_slow_lane(state, body, headers, api_key, request_hash, prompt_hash, prompt, intent_result, effective_client_id, total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await
        }
        Route::GeneralLane => {
            // GeneralLane variant is never produced by decide_route (it only returns
            // FastLane or ZkSlowLane for successfully resolved intents). Handled defensively.
            handle_general_lane(state, body, api_key, prompt, prompt_hash, None, total_start, anonymizer_vault.clone(), anonymizer_meta.clone()).await
        }
    }
}

/// Output of the FastLane engine: computed aggregate + table config for the caller.
pub(crate) struct FastLaneEngineOutput {
    pub(crate) result: FastLaneResult,
    pub(crate) table_config: crate::config::TableConfig,
    pub(crate) metric_label: String,
}

/// Run the FastLane engine (DB aggregate → BabyJubJub attestation).
/// Extracted from handle_fast_lane so tunnel.rs can call the engine without the HTTP layer.
pub(crate) async fn run_fast_lane_engine(
    state: &Arc<ProxyState>,
    intent: &IntentResult,
    effective_client_id: i64,
) -> Result<FastLaneEngineOutput, ProxyError> {
    let category_name = intent.category_name.clone();
    let start = intent.start_unix_secs;
    let end = intent.end_unix_secs;
    let key_bytes = state.signing_key_bytes.clone();
    let client_id = effective_client_id;
    let table = intent.table.clone();

    let schema = state.config.schema_config.as_ref()
        .ok_or_else(|| ProxyError::Internal(anyhow::anyhow!("schema_config missing in FastLane")))?;
    let table_config = schema.tables.get(&table).cloned()
        .ok_or_else(|| ProxyError::Internal(anyhow::anyhow!("routing bug: table '{}' not in schema", table)))?;
    let metric_label = table_config.metric_label.clone();

    let engine_result: EngineResult = if state.config.use_supabase_fast_lane() {
        let url = state.config.supabase_url.as_ref().unwrap();
        let svc_key = state.config.supabase_service_key.as_ref().unwrap();
        let physical_table = table_config.resolved_table(&table).to_owned();
        let (aggregate, row_count) = db::query_aggregate_table(
            &state.http_client,
            url,
            svc_key,
            &physical_table,
            &table_config.value_column,
            &table_config.timestamp_column,
            table_config.category_column.as_deref(),
            &category_name,
            &table_config.agg_fn,
            client_id,
            table_config.skip_client_id_filter,
            start,
            end,
        )
        .await
        .map_err(ProxyError::Internal)?;

        let key_bytes2 = key_bytes.clone();
        let category_name2 = category_name.clone();
        let table_key2 = table.clone();
        let table_config2 = table_config.clone();
        tokio::task::spawn_blocking(move || {
            let signing_key = db::PrivateKey::import(key_bytes2)
                .map_err(|e| anyhow::anyhow!("import signing key: {}", e))?;
            Ok::<EngineResult, anyhow::Error>(
                engine_fast::attest_fast_lane(
                    &signing_key, client_id, &table_key2, &table_config2,
                    &category_name2, aggregate, row_count, start, end,
                    chrono::Utc::now().timestamp(),
                )
            )
        })
        .await
        .map_err(|e| ProxyError::Internal(anyhow::anyhow!("spawn_blocking join: {}", e)))?
        .map_err(ProxyError::Internal)?
    } else {
        let state2 = Arc::clone(state);
        let category_name_blocking = category_name.clone();
        let table_key_blocking = table.clone();
        let table_config_blocking = table_config.clone();
        tokio::task::spawn_blocking(move || {
            let guard = state2.ledger_db
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let signing_key = db::PrivateKey::import(key_bytes)
                .map_err(|e| anyhow::anyhow!("import signing key: {}", e))?;
            Ok::<EngineResult, anyhow::Error>(
                engine_fast::run_fast_lane(
                    &guard, &signing_key, client_id,
                    &table_key_blocking, table_config_blocking,
                    &category_name_blocking, start, end,
                )
            )
        })
        .await
        .map_err(|e| ProxyError::Internal(anyhow::anyhow!("spawn_blocking join: {}", e)))?
        .map_err(ProxyError::Internal)?
    };

    let fl = match engine_result {
        EngineResult::Ok(r) => r,
        EngineResult::DbError(e) => {
            return Err(ProxyError::DbError(e));
        }
        EngineResult::SignError(e) => {
            return Err(ProxyError::Internal(anyhow::anyhow!("FastLane sign error: {}", e)));
        }
    };

    // Warn when demo client_id=123 returns 0 rows and skip_client_id_filter is false.
    // Production databases often have no rows for client_id=123 (the demo default).
    // Use the parsed config value (not the raw env var) to also catch YAML-configured client_id.
    if fl.row_count == 0
        && !table_config.skip_client_id_filter
        && state.config.client_id == 123
    {
        eprintln!(
            "[PROXY] Warning: query returned 0 rows (table={}, client_id=123). \
             If this is a single-tenant setup, set skip_client_id_filter=true in schema_config.json.",
            table
        );
    }

    Ok(FastLaneEngineOutput { result: fl, table_config, metric_label })
}

/// Handle a FastLane request: DB sum → attestation → synthetic evidence response.
#[allow(clippy::too_many_arguments)]
async fn handle_fast_lane(
    state: Arc<ProxyState>,
    mut body: Value,
    api_key: String,
    request_hash: String,
    prompt_hash: String,
    intent_result: crate::types::IntentResult,
    effective_client_id: i64,
    total_start: Instant,
    vault: Option<Vault>,
    anon_meta: Option<crate::anonymizer::AuditMeta>,
) -> Result<Response, ProxyError> {
    println!(
        "[FAST] FastLane route → table='{}' start={} end={}",
        intent_result.table, intent_result.start_unix_secs, intent_result.end_unix_secs
    );

    let schema_config_hash = state.schema_config_hash.clone();
    let category_name = intent_result.category_name.clone();

    let engine_out = run_fast_lane_engine(&state, &intent_result, effective_client_id).await?;
    let fl = engine_out.result;
    let table_config = engine_out.table_config;
    let metric_label = engine_out.metric_label;

    let receipt_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();

    // Build the financial payload: fixed "aggregate" key + "metric_label" field.
    // Hash proves what financial data was transmitted to the LLM.
    let mut map = serde_json::Map::new();
    map.insert("category".to_owned(), serde_json::json!(category_name));
    map.insert("aggregate".to_owned(), serde_json::json!(fl.aggregate));
    map.insert("metric_label".to_owned(), serde_json::json!(metric_label));
    map.insert("actual_row_count".to_owned(), serde_json::json!(fl.row_count));
    map.insert("data_provenance".to_owned(), serde_json::json!("ZEMTIK_FAST_LANE_ATTESTATION"));
    map.insert("raw_data_transmitted".to_owned(), serde_json::json!(false));
    if table_config.category_column.is_none() {
        map.insert("note".to_owned(), serde_json::json!(
            "This metric aggregates the entire table and does not support category-based filtering."
        ));
    } else if fl.row_count == 0 && fl.aggregate == 0 {
        // Only emit "no rows matched" when BOTH actual_row_count and aggregate are zero.
        // Supabase path always returns actual_row_count=0 (PostgREST aggregate API limitation);
        // checking aggregate==0 avoids a false "no results" note on non-empty Supabase queries.
        map.insert("note".to_owned(), serde_json::json!("No rows matched the query criteria."));
    }
    let payload = serde_json::Value::Object(map);
    let outgoing_hash = hex::encode(Sha256::digest(
        serde_json::to_string(&payload)
            .context("serialize payload for outgoing hash")
            .map_err(ProxyError::Internal)?
            .as_bytes(),
    ));

    let (human_summary, checks_performed) = evidence::evidence_summary(
        "fast_lane",
        &intent_result.table,
        table_config.agg_fn.as_str(),
        fl.row_count,
    );
    let ev = evidence::build_evidence_pack(
        &receipt_id,
        "fast_lane",
        fl.aggregate,
        fl.row_count,
        None,
        Some(fl.attestation_hash.clone()),
        &fl.key_id,
        &schema_config_hash,
        &timestamp,
        Some(intent_result.confidence),
        Some(outgoing_hash.clone()),
        None,
        human_summary,
        checks_performed,
        state.config.llm_provider.clone(),
    );

    // Insert receipt — lock synchronously, never hold std::sync::MutexGuard across .await
    {
        let db_guard = state.receipts_db
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Err(e) = receipts::insert_receipt(
            &db_guard,
            &receipts::Receipt {
                id: receipt_id.clone(),
                bundle_path: String::new(),
                proof_status: "FAST_LANE_ATTESTED".to_owned(),
                circuit_hash: String::new(),
                bb_version: String::new(),
                prompt_hash: prompt_hash.clone(),
                request_hash: request_hash.clone(),
                created_at: timestamp.clone(),
                engine_used: "fast_lane".to_owned(),
                proof_hash: None,
                data_exfiltrated: 0,
                intent_confidence: Some(intent_result.confidence),
                outgoing_prompt_hash: Some(outgoing_hash),
                signing_version: Some(2),
                actual_row_count: None,
                rewrite_method: intent_result.rewrite_method.as_ref().map(|m| m.to_string()),
                rewritten_query: intent_result.rewritten_query.clone(),
                manifest_key_id: Some(state.manifest_key_id.clone()),
                evidence_json: match serde_json::to_string(&ev) {
                    Ok(json) => Some(json),
                    Err(e) => {
                        eprintln!("[WARN] FastLane: failed to serialize evidence_json: {}", e);
                        None
                    }
                },
                llm_provider: Some(state.config.llm_provider.clone()),
            },
        ) {
            eprintln!("[WARN] FastLane: failed to write audit receipt {}: {}", receipt_id, e);
        }
    }

    println!(
        "[FAST] aggregate={} row_count={} attestation={} ({:.2}ms)",
        fl.aggregate,
        fl.row_count,
        &fl.attestation_hash[..fl.attestation_hash.len().min(8)],
        total_start.elapsed().as_secs_f64() * 1000.0,
    );

    build_fast_lane_response(
        &mut body,
        payload,
        &state,
        &api_key,
        &receipt_id,
        &intent_result,
        &ev,
        &vault,
        &anon_meta,
    )
    .await
}

/// HTTP 400 response for `RewritingFailed` with hint based on failure kind.
/// `hint_kind`: "unresolvable" | "timeout:<N>" where N is the configured timeout in seconds.
fn rewriting_failed_400(hint_kind: &str) -> Response {
    let (message, hint, doc_url) = if hint_kind.starts_with("timeout") {
        // Do not include the configured timeout value in the response — operational
        // parameters should not be visible to callers. Log it server-side instead.
        let owned_hint =
            "Increase ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS or check LLM endpoint connectivity."
                .to_owned();
        (
            "Query rewriter timed out.".to_owned(),
            owned_hint,
            "https://github.com/dacarva/zemtik-core/blob/main/docs/CONFIGURATION.md#query-rewriting".to_owned(),
        )
    } else {
        (
            "Query rewriter could not resolve table and time range from conversation context.".to_owned(),
            "Add aliases to schema_config.json matching how users phrase this query, or use system prompt injection (Workaround B).".to_owned(),
            "https://github.com/dacarva/zemtik-core/blob/main/docs/SUPPORTED_QUERIES.md#conversation-patterns".to_owned(),
        )
    };
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": {
                "type": "zemtik_intent_error",
                "code": ZemtikErrorCode::RewritingFailed,
                "message": message,
                "hint": hint,
                "doc_url": doc_url,
            }
        })),
    )
        .into_response()
}

/// HTTP 400 response when per-table `query_rewriting: false` blocks rewriting.
fn rewriting_disabled_400() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": {
                "type": "zemtik_intent_error",
                "code": ZemtikErrorCode::RewritingFailed,
                "message": "Query rewriting is disabled for this table.",
                "hint": "Remove query_rewriting: false from this table in schema_config.json to enable rewriting.",
                "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/CONFIGURATION.md#query-rewriting",
            }
        })),
    )
        .into_response()
}

/// HTTP 400 for stream:true sent to a data lane (FastLane or ZK SlowLane).
/// Separate from the entry guard so rewriter dispatch paths can also call it.
fn streaming_not_supported_for_data_lane() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": {
                "type": "zemtik_config_error",
                "code": ZemtikErrorCode::StreamingNotSupported,
                "message": "Set stream: false in your client configuration.",
                "hint": "The ZK pipeline must complete before any part of the response can be sent.",
                "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/GETTING_STARTED.md#streaming"
            }
        })),
    )
        .into_response()
}

/// Handle a GeneralLane request: forward non-data queries to OpenAI with a receipt and
/// zemtik_meta metadata block. Supports both streaming (SSE passthrough) and non-streaming.
///
/// Called when ZEMTIK_GENERAL_PASSTHROUGH=1 and intent extraction fails to match a table.
/// `intent_err`: the original IntentError that triggered the GeneralLane route; None for
/// the rare defensive GeneralLane arm from the happy-path route match (should not occur).
#[allow(clippy::too_many_arguments)]
async fn handle_general_lane(
    state: Arc<ProxyState>,
    body: Value,
    api_key: String,
    prompt: String,
    prompt_hash: String,
    intent_err: Option<IntentError>,
    _total_start: Instant,
    vault: Option<Vault>,
    anon_meta: Option<crate::anonymizer::AuditMeta>,
) -> Result<Response, ProxyError> {
    use std::time::Duration;
    use axum::http::HeaderName;

    let receipt_id = Uuid::new_v4().to_string();

    // ── Rate limit check ────────────────────────────────────────────────────
    if let Some(ref limiter) = state.general_rate_limiter {
        let mut window = limiter.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let cutoff = now - Duration::from_secs(60);
        window.retain(|&t| t > cutoff);
        if window.len() as u32 >= state.general_max_rpm {
            // Compute Retry-After: seconds until the oldest window entry expires.
            let retry_after = window
                .front()
                .map(|oldest| {
                    let elapsed = now.duration_since(*oldest);
                    if elapsed < Duration::from_secs(60) {
                        (Duration::from_secs(60) - elapsed).as_secs() + 1
                    } else {
                        1
                    }
                })
                .unwrap_or(60);

            // Write a receipt so rate-limited requests appear in audit trail
            // and general_queries_today counts them.
            let now_str = Utc::now().to_rfc3339();
            let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = receipts::insert_receipt(&db_guard, &receipts::Receipt {
                id: receipt_id.clone(),
                bundle_path: String::new(),
                proof_status: receipts::PROOF_STATUS_GENERAL_LANE_RATE_LIMITED.to_owned(),
                circuit_hash: String::new(),
                bb_version: String::new(),
                prompt_hash: prompt_hash.clone(),
                request_hash: prompt_hash.clone(),
                created_at: now_str,
                engine_used: "general_lane".to_owned(),
                proof_hash: None,
                data_exfiltrated: 0,
                intent_confidence: None,
                outgoing_prompt_hash: None,
                signing_version: None,
                actual_row_count: None,
                rewrite_method: None,
                rewritten_query: None,
                manifest_key_id: None,
                evidence_json: None,
                llm_provider: Some(state.config.llm_provider.clone()),
            }) {
                eprintln!("[GENERAL_LANE] Warning: failed to write rate-limit receipt {}: {}", receipt_id, e);
            }
            drop(db_guard);

            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "code": "GeneralLaneBudgetExceeded",
                    "message": "General lane rate limit exceeded. Increase ZEMTIK_GENERAL_MAX_RPM or set to 0 for unlimited.",
                    "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/CONFIGURATION.md#general-passthrough-v0110"
                })),
            ).into_response();
            resp.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_str(&retry_after.to_string())
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("60")),
            );
            return Ok(resp);
        }
        window.push_back(now);
    }

    // ── reason string from intent error ────────────────────────────────────
    let reason = match &intent_err {
        Some(IntentError::NoTableIdentified) => "no_table_match",
        Some(IntentError::TimeRangeAmbiguous) => "time_range_ambiguous",
        _ => "intent_error",
    };

    // ── Write receipt BEFORE forwarding (FastLane parity) ──────────────────
    let now_str = Utc::now().to_rfc3339();
    let receipt_write_result = {
        let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
        receipts::insert_receipt(&db_guard, &receipts::Receipt {
            id: receipt_id.clone(),
            bundle_path: String::new(),
            proof_status: receipts::PROOF_STATUS_GENERAL_LANE.to_owned(),
            circuit_hash: String::new(),
            bb_version: String::new(),
            prompt_hash: prompt_hash.clone(),
            request_hash: prompt_hash.clone(),
            created_at: now_str.clone(),
            engine_used: "general_lane".to_owned(),
            proof_hash: None,
            data_exfiltrated: 0,
            intent_confidence: None,
            outgoing_prompt_hash: None,
            signing_version: None,
            actual_row_count: None,
            rewrite_method: None,
            rewritten_query: None,
            manifest_key_id: None,
            evidence_json: None,
            llm_provider: Some(state.config.llm_provider.clone()),
        })
    };
    if let Err(e) = receipt_write_result {
        eprintln!("[GENERAL_LANE] Warning: failed to write receipt {}: {}", receipt_id, e);
        // Continue — receipt failure does not block the response (FastLane parity).
    }

    let is_streaming = body.get("stream").and_then(|v| v.as_bool()) == Some(true);

    let mut zemtik_meta = serde_json::json!({
        "engine_used": "general_lane",
        "zk_coverage": "none",
        "reason": reason,
        "receipt_id": receipt_id,
    });
    let meta_header_val = urlencoding::encode(&zemtik_meta.to_string()).into_owned();

    if is_streaming {
        // Anthropic SSE uses a different event schema than OpenAI SSE.
        // Translation is deferred to a future release; return 501 so clients
        // get a clear error instead of unparseable chunks.
        if state.config.llm_provider == "anthropic" {
            return Ok((
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({
                    "error": {
                        "type": "streaming_not_supported",
                        "code": "AnthropicStreamingUnsupported",
                        "message": "Streaming is not supported with llm_provider=anthropic in this version. Set stream: false."
                    }
                })),
            ).into_response());
        }

        // ── OpenAI streaming path: SSE passthrough, metadata via header only ──
        let upstream = state
            .llm_backend
            .forward_raw(&body, &api_key)
            .await
            .map_err(|e| ProxyError::Internal(anyhow::anyhow!("GeneralLane streaming error: {}", e)))?;

        let mut resp = stream_openai_passthrough(upstream).await;
        resp.headers_mut().insert(
            HeaderName::from_static("x-zemtik-engine"),
            HeaderValue::from_static("general_lane"),
        );
        if let Ok(v) = HeaderValue::from_str(&meta_header_val) {
            resp.headers_mut().insert(HeaderName::from_static("x-zemtik-meta"), v);
        }
        return Ok(resp);
    }

    // ── Non-streaming path ──────────────────────────────────────────────────
    let (status_u16, mut resp_body) = state
        .llm_backend
        .complete(&body, &api_key)
        .await
        .map_err(|e| ProxyError::Internal(anyhow::anyhow!("GeneralLane upstream error: {}", e)))?;

    let resp_status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK);

    // Extract _zemtik_resolved_model from AnthropicBackend and inject into zemtik_meta
    if let Some(obj) = resp_body.as_object_mut() {
        if let Some(resolved) = obj.remove("_zemtik_resolved_model") {
            zemtik_meta["resolved_model"] = resolved;
        }
    }

    // Count dropped/injected tokens BEFORE deanonymize replaces [[Z:...]] tokens in resp_body.
    // After deanonymization those tokens are gone from the string, making count_dropped_tokens
    // report all vault entries as dropped even when the LLM preserved them.
    let general_lane_token_counts: (usize, usize) = vault.as_ref().map(|vlt| {
        let raw = serde_json::to_string(&resp_body).unwrap_or_default();
        (
            crate::anonymizer::count_dropped_tokens(&raw, vlt),
            crate::anonymizer::count_tokens_injected(vlt),
        )
    }).unwrap_or((0, 0));

    // Deanonymize LLM response text before returning to caller
    if let Some(ref vlt) = vault {
        if let Some(obj) = resp_body.as_object_mut() {
            if let Some(choices) = obj.get_mut("choices").and_then(|c| c.as_array_mut()) {
                for choice in choices.iter_mut() {
                    if let Some(content) = choice.pointer_mut("/message/content").and_then(|c| c.as_str().map(|s| s.to_owned())) {
                        let deanon = crate::anonymizer::deanonymize(&content, vlt);
                        choice["message"]["content"] = Value::String(deanon);
                    }
                }
            }
        }
    }

    // Augment zemtik_meta with anonymizer stats (entities, dropped tokens)
    if let Some(ref meta) = anon_meta {
        let (dropped, injected) = general_lane_token_counts;
        let mut anon_block = serde_json::json!({
            "entities_found": meta.entities_found,
            "entity_types": meta.entity_types,
            "sidecar_used": meta.sidecar_used,
            "sidecar_ms": meta.sidecar_ms,
            "dropped_tokens": dropped,
            "tokens_injected": injected,
        });
        // Only emit preview when sidecar ran — regex fallback skips PERSON/ORG/LOCATION,
        // so partial-anonymized text could expose PII not in entity_types.
        if state.config.anonymizer_debug_preview && meta.sidecar_used && !prompt.is_empty() {
            let preview: String = prompt.chars().take(200).collect();
            anon_block["outgoing_preview"] = serde_json::Value::String(preview);
        }
        zemtik_meta["anonymizer"] = anon_block;
    }

    // Persist general lane metadata to receipt so /verify page is complete.
    {
        let mut evidence = serde_json::json!({
            "engine_used": "general_lane",
            "zk_coverage": "none",
            "reason": zemtik_meta.get("reason"),
        });
        if let Some(anon) = zemtik_meta.get("anonymizer") {
            evidence["anonymizer"] = anon.clone();
        }
        if let Ok(json) = serde_json::to_string(&evidence) {
            let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = receipts::update_evidence_json(&db_guard, &receipt_id, &json) {
                eprintln!("[GENERAL_LANE] Warning: failed to update evidence_json {}: {}", receipt_id, e);
            }
        }
    }

    if let Some(obj) = resp_body.as_object_mut() {
        obj.insert("zemtik_meta".to_string(), zemtik_meta);
    }

    let final_body = serde_json::to_vec(&resp_body).unwrap_or_default();
    let mut response = Response::builder()
        .status(resp_status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(HeaderName::from_static("x-zemtik-engine"), "general_lane")
        .body(axum::body::Body::from(final_body))
        .unwrap_or_else(|_| Response::new(axum::body::Body::empty()));

    if let Ok(v) = HeaderValue::from_str(&meta_header_val) {
        response.headers_mut().insert(HeaderName::from_static("x-zemtik-meta"), v);
    }

    Ok(response)
}

/// Merge `EvidencePack` + intent summary for API clients (jq-friendly `engine` / `intent`).
/// Adds `evidence_version: 3` to enable downstream parsers to distinguish v1 (row_count,
/// single-proof), v2 (actual_row_count, AVG dual-proof), and v3 (human_summary,
/// checks_performed) response shapes.
/// When intent was rewritten, injects `rewrite_method` field into the envelope.
fn zemtik_evidence_envelope(ev: &EvidencePack, intent: &IntentResult) -> Result<Value, serde_json::Error> {
    let mut v = serde_json::to_value(ev)?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("evidence_version".to_string(), serde_json::json!(3));
        obj.insert("engine".to_string(), Value::String(ev.engine_used.clone()));
        obj.insert(
            "intent".to_string(),
            serde_json::json!({
                "table": intent.table,
                "category_name": intent.category_name,
                "start_unix_secs": intent.start_unix_secs,
                "end_unix_secs": intent.end_unix_secs,
                "confidence": intent.confidence,
            }),
        );
        if let Some(ref method) = intent.rewrite_method {
            obj.insert("rewrite_method".to_string(), serde_json::json!(method.to_string()));
        }
    }
    Ok(v)
}

/// Replace last user message with FastLane payload and forward to OpenAI.
#[allow(clippy::too_many_arguments)]
async fn build_fast_lane_response(
    body: &mut Value,
    payload: Value,
    state: &Arc<ProxyState>,
    api_key: &str,
    receipt_id: &str,
    intent: &IntentResult,
    ev: &EvidencePack,
    vault: &Option<Vault>,
    anon_meta: &Option<crate::anonymizer::AuditMeta>,
) -> Result<Response, ProxyError> {
    let message = format!(
        "Here is a cryptographically attested financial summary:\n\n{}",
        serde_json::to_string_pretty(&payload)
            .context("serialize FastLane payload")
            .map_err(ProxyError::Internal)?
    );

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        if let Some(last_user) = messages
            .iter_mut()
            .rev()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        {
            last_user["content"] = Value::String(message);
        }
    }

    let (status_u16_fl, mut resp_body) = state
        .llm_backend
        .complete(body, api_key)
        .await
        .context("forward FastLane request to LLM backend")
        .map_err(ProxyError::Internal)?;

    // Strip _zemtik_resolved_model from resp_body; inject into zemtik_meta after it exists (D7).
    // zemtik_meta is created later via entry().or_insert_with(), so save the value now.
    let fl_resolved_model = if let Some(obj) = resp_body.as_object_mut() {
        obj.remove("_zemtik_resolved_model")
    } else {
        None
    };

    let resp_status = StatusCode::from_u16(status_u16_fl).unwrap_or(StatusCode::OK);

    // Count dropped/injected tokens BEFORE deanonymize replaces them in resp_body.
    let (dropped_fast, injected_fast) = vault.as_ref().map(|vlt| {
        let raw = serde_json::to_string(&resp_body).unwrap_or_default();
        (
            crate::anonymizer::count_dropped_tokens(&raw, vlt),
            crate::anonymizer::count_tokens_injected(vlt),
        )
    }).unwrap_or((0, 0));

    // Deanonymize FastLane response before returning to caller
    if let Some(ref vlt) = vault {
        if let Some(obj) = resp_body.as_object_mut() {
            if let Some(choices) = obj.get_mut("choices").and_then(|c| c.as_array_mut()) {
                for choice in choices.iter_mut() {
                    if let Some(content) = choice.pointer("/message/content").and_then(|c| c.as_str()).map(|s| s.to_owned()) {
                        let deanon = crate::anonymizer::deanonymize(&content, vlt);
                        choice["message"]["content"] = Value::String(deanon);
                    }
                }
            }
        }
    }

    // Inject zemtik_meta.anonymizer stats into FastLane response
    if let Some(ref meta) = anon_meta {
        if let Some(obj) = resp_body.as_object_mut() {
            obj.entry("zemtik_meta").or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .map(|m| m.insert("anonymizer".to_string(), serde_json::json!({
                    "entities_found": meta.entities_found,
                    "entity_types": meta.entity_types,
                    "sidecar_used": meta.sidecar_used,
                    "sidecar_ms": meta.sidecar_ms,
                    "dropped_tokens": dropped_fast,
                    "tokens_injected": injected_fast,
                })));
        }
    }

    // Inject resolved_model into zemtik_meta for Anthropic path (D7).
    // zemtik_meta may or may not exist yet (only created above when anon_meta.is_some()).
    if let Some(resolved) = fl_resolved_model {
        if let Some(obj) = resp_body.as_object_mut() {
            obj.entry("zemtik_meta")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .map(|m| m.insert("resolved_model".to_owned(), resolved));
        }
    }

    let envelope = zemtik_evidence_envelope(ev, intent).map_err(|e| ProxyError::Internal(anyhow::Error::new(e)))?;
    if let Some(obj) = resp_body.as_object_mut() {
        obj.insert("evidence".to_string(), envelope);
    }

    let mut response = (
        resp_status,
        Json(resp_body),
    )
        .into_response();

    if let Ok(val) = HeaderValue::from_str(receipt_id) {
        response.headers_mut().insert("x-zemtik-receipt-id", val);
    }
    if let Ok(val) = HeaderValue::from_str("fast_lane") {
        response.headers_mut().insert("x-zemtik-engine", val);
    }

    Ok(response)
}

/// Handle a ZK SlowLane request (existing full ZK pipeline).
#[allow(clippy::too_many_arguments)]
async fn handle_zk_slow_lane(
    state: Arc<ProxyState>,
    mut body: Value,
    _headers: HeaderMap,
    api_key: String,
    request_hash: String,
    prompt_hash: String,
    original_prompt: String,
    intent: crate::types::IntentResult,
    effective_client_id: i64,
    total_start: Instant,
    vault: Option<Vault>,
    anon_meta: Option<crate::anonymizer::AuditMeta>,
) -> Result<Response, ProxyError> {
    println!("[ZK] ZkSlowLane route → starting ZK pipeline");
    let prompt_hash_field = compute_prompt_hash_field(&original_prompt);

    // Resolve the aggregation function for this table from schema_config.
    let agg_fn = state.config.schema_config
        .as_ref()
        .and_then(|s| s.tables.get(&intent.table))
        .map(|tc| tc.agg_fn.clone())
        .unwrap_or(AggFn::Sum);

    let zk = if agg_fn == AggFn::Avg {
        // AVG composite: hold avg_pipeline_lock + per-type locks to prevent concurrent
        // SUM/COUNT direct requests from corrupting circuit/sum/Prover.toml or
        // circuit/count/Prover.toml while AVG sub-pipelines are writing them.
        let _avg_guard = state.avg_pipeline_lock.lock().await;
        let _sum_guard = state.pipeline_locks
            .get(&AggFn::Sum)
            .expect("pipeline_locks must contain Sum")
            .lock()
            .await;
        let _count_guard = state.pipeline_locks
            .get(&AggFn::Count)
            .expect("pipeline_locks must contain Count")
            .lock()
            .await;
        run_avg_pipeline(Arc::clone(&state), request_hash.clone(), prompt_hash.clone(), prompt_hash_field.clone(), intent.clone(), effective_client_id)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ProxyError::Timeout(msg)
                } else if msg.contains("COUNT=0") {
                    ProxyError::UnprocessableEntity(msg)
                } else {
                    ProxyError::Internal(e)
                }
            })?
    } else {
        // Single agg: acquire per-type lock.
        let _pipeline_guard = state.pipeline_locks
            .get(&agg_fn)
            .expect("pipeline_locks must contain Sum and Count")
            .lock()
            .await;

        let config_clone = Arc::clone(&state.config);
        let key_bytes = state.signing_key_bytes.clone();
        let req_hash = request_hash.clone();
        let prm_hash = prompt_hash.clone();
        let prm_hash_field = prompt_hash_field.clone();
        let intent_clone = intent.clone();
        let agg_fn_clone = agg_fn.clone();

        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build local runtime")?;
            rt.block_on(run_zk_pipeline(config_clone, key_bytes, req_hash, prm_hash, prm_hash_field, intent_clone, effective_client_id, agg_fn_clone))
        })
        .await
        .context("ZK blocking task panicked")?
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("timed out") { ProxyError::Timeout(msg) } else { ProxyError::Internal(e) }
        })?
    };

    println!(
        "[ZK] Verified {} spend = ${} ({:.2}s circuit, proof: {})",
        intent.category_name, zk.aggregate, zk.circuit_execution_secs, zk.proof_status
    );

    // Insert bundle into receipts DB if generated; clear it if the insert fails
    // so we never emit headers pointing to a non-existent bundle.
    let committed_bundle: Option<&bundle::BundleResult> = if let Some(ref br) = zk.bundle_result {
        println!("[BUNDLE] Receipt: {}", br.bundle_path.display());
        println!("[BUNDLE] ID: {}", br.bundle_id);

        let db_guard = state.receipts_db
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match receipts::insert_receipt(
            &db_guard,
            &receipts::Receipt {
                id: br.bundle_id.clone(),
                bundle_path: br.bundle_path.display().to_string(),
                proof_status: zk.proof_status.to_owned(),
                circuit_hash: br.circuit_hash.clone(),
                bb_version: br.bb_version.clone(),
                prompt_hash: prompt_hash.clone(),
                request_hash: request_hash.clone(),
                created_at: Utc::now().to_rfc3339(),
                engine_used: "zk_slow_lane".to_owned(),
                proof_hash: zk.proof_hex.clone(),
                data_exfiltrated: 0,
                intent_confidence: Some(intent.confidence),
                outgoing_prompt_hash: zk.outgoing_prompt_hash.clone(),
                signing_version: Some(3),
                actual_row_count: Some(zk.actual_row_count),
                rewrite_method: intent.rewrite_method.as_ref().map(|m| m.to_string()),
                rewritten_query: intent.rewritten_query.clone(),
                manifest_key_id: Some(state.manifest_key_id.clone()),
                evidence_json: None, // Populated later via update_evidence_json once the ZK evidence pack is assembled
                llm_provider: Some(state.config.llm_provider.clone()),
            },
        ) {
            Ok(()) => Some(br),
            Err(e) => {
                eprintln!("[BUNDLE] Failed to insert receipt — discarding bundle: {}", e);
                let _ = std::fs::remove_file(&br.bundle_path);
                None
            }
        }
    } else {
        None
    };

    let target_category_hash = db::poseidon_of_string(&intent.table)
        .map(|fr| db::fr_to_decimal(&fr))
        .map_err(|e| ProxyError::Internal(anyhow::anyhow!(
            "cannot hash table key '{}' (key must be ≤93 bytes after lowercasing): {}",
            intent.table, e
        )))?;
    let params = QueryParams {
        client_id: effective_client_id,
        target_category_hash,
        category_name: intent.category_name.clone(),
        start_time: intent.start_unix_secs as u64,
        end_time: intent.end_unix_secs as u64,
    };

    let metric_label = state.config.schema_config
        .as_ref()
        .and_then(|s| s.tables.get(&intent.table))
        .map(|tc| tc.metric_label.clone())
        .unwrap_or_else(|| "result".to_owned());
    let zk_payload = {
        let mut m = serde_json::Map::new();
        m.insert("category".to_owned(), serde_json::json!(intent.category_name));
        m.insert(metric_label.clone(), serde_json::json!(zk.aggregate));
        m.insert("agg_type".to_owned(), serde_json::json!(agg_fn.as_str()));
        m.insert("data_provenance".to_owned(), serde_json::json!("ZEMTIK_VALID_ZK_PROOF"));
        m.insert("raw_data_transmitted".to_owned(), serde_json::json!(false));
        serde_json::Value::Object(m)
    };
    let zk_message = format!(
        "Here is a cryptographically verified financial summary:\n\n{}",
        serde_json::to_string_pretty(&zk_payload)
            .context("serialize ZK payload")
            .map_err(ProxyError::Internal)?
    );

    println!(
        "[ZK] Payload: {{ category: \"{}\", {}: {}, agg_type: {}, provenance: \"ZEMTIK_VALID_ZK_PROOF\" }}",
        intent.category_name, metric_label, zk.aggregate, agg_fn.as_str()
    );
    println!("[ZK] Raw rows transmitted to OpenAI: 0");

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        if let Some(last_user) = messages
            .iter_mut()
            .rev()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        {
            last_user["content"] = Value::String(zk_message.clone());
        }
    }

    let (status_u16_zk, mut resp_body) = state
        .llm_backend
        .complete(&body, &api_key)
        .await
        .context("forward to LLM backend")
        .map_err(ProxyError::Internal)?;

    // Strip internal Anthropic resolved_model field; inject into zemtik_meta later
    let zk_resolved_model = if let Some(obj) = resp_body.as_object_mut() {
        obj.remove("_zemtik_resolved_model")
    } else {
        None
    };

    let resp_status = StatusCode::from_u16(status_u16_zk).unwrap_or(StatusCode::OK);

    // Count dropped/injected tokens BEFORE deanonymize replaces them in resp_body.
    let (dropped_zk, injected_zk) = vault.as_ref().map(|vlt| {
        let raw = serde_json::to_string(&resp_body).unwrap_or_default();
        (
            crate::anonymizer::count_dropped_tokens(&raw, vlt),
            crate::anonymizer::count_tokens_injected(vlt),
        )
    }).unwrap_or((0, 0));

    // Deanonymize ZK SlowLane response before returning to caller
    if let Some(ref vlt) = vault {
        if let Some(obj) = resp_body.as_object_mut() {
            if let Some(choices) = obj.get_mut("choices").and_then(|c| c.as_array_mut()) {
                for choice in choices.iter_mut() {
                    if let Some(content) = choice.pointer("/message/content").and_then(|c| c.as_str()).map(|s| s.to_owned()) {
                        let deanon = crate::anonymizer::deanonymize(&content, vlt);
                        choice["message"]["content"] = Value::String(deanon);
                    }
                }
            }
        }
    }

    // Inject zemtik_meta.anonymizer stats into ZK SlowLane response
    if let Some(ref meta) = anon_meta {
        if let Some(obj) = resp_body.as_object_mut() {
            obj.entry("zemtik_meta").or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .map(|m| m.insert("anonymizer".to_string(), serde_json::json!({
                    "entities_found": meta.entities_found,
                    "entity_types": meta.entity_types,
                    "sidecar_used": meta.sidecar_used,
                    "sidecar_ms": meta.sidecar_ms,
                    "dropped_tokens": dropped_zk,
                    "tokens_injected": injected_zk,
                })));
        }
    }

    let receipt_id_ev = committed_bundle
        .map(|b| b.bundle_id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let timestamp_ev = Utc::now().to_rfc3339();
    let key_material = format!("{}{}", zk.first_sig.pub_key_x, zk.first_sig.pub_key_y);
    let key_id_zk = hex::encode(Sha256::digest(key_material.as_bytes()));
    let (human_summary_zk, checks_performed_zk) = evidence::evidence_summary(
        "zk_slow_lane",
        &intent.table,
        agg_fn.as_str(),
        zk.actual_row_count,
    );
    let ev_zk = evidence::build_evidence_pack(
        &receipt_id_ev,
        "zk_slow_lane",
        zk.aggregate as i64,
        zk.txns_len,
        zk.proof_hex.clone(),
        None,
        &key_id_zk,
        &state.schema_config_hash,
        &timestamp_ev,
        Some(intent.confidence),
        zk.outgoing_prompt_hash.clone(),
        Some(zk.actual_row_count),
        human_summary_zk,
        checks_performed_zk,
        state.config.llm_provider.clone(),
    );

    // Inject resolved_model into zemtik_meta for Anthropic path (D7)
    if let Some(resolved) = zk_resolved_model {
        if let Some(obj) = resp_body.as_object_mut() {
            obj.entry("zemtik_meta")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .map(|m| m.insert("resolved_model".to_owned(), resolved));
        }
    }
    let envelope = zemtik_evidence_envelope(&ev_zk, &intent).map_err(|e| ProxyError::Internal(anyhow::Error::new(e)))?;
    if let Some(obj) = resp_body.as_object_mut() {
        obj.insert("evidence".to_string(), envelope);
    }

    // Persist evidence JSON on the receipt (ZK insert happened before evidence was built)
    if committed_bundle.is_some() {
        if let Ok(json) = serde_json::to_string(&ev_zk) {
            let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = receipts::update_evidence_json(&db_guard, &receipt_id_ev, &json) {
                eprintln!("[WARN] ZK: failed to update evidence_json for {}: {}", receipt_id_ev, e);
            }
        }
    }

    let elapsed = total_start.elapsed();

    let content = resp_body
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_owned();
    let resp_model = resp_body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_owned();
    let (prompt_tokens, completion_tokens, total_tokens) = resp_body
        .get("usage")
        .map(|u| {
            (
                u.get("prompt_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                u.get("completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                u.get("total_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
            )
        })
        .unwrap_or((0, 0, 0));

    let audit_record = AuditRecord::build(
        committed_bundle.map(|b| b.bundle_id.clone()),
        zk.txns_len,
        zk.batch_count,
        db::BATCH_SIZE,
        &params,
        zk.aggregate,
        zk.proof_status.to_owned(),
        zk.circuit_execution_secs,
        &zk.first_sig,
        zk.proof_hex,
        zk.vk_hex,
        zk.fully_verifiable,
        OpenAiRequestLog {
            model: body.get("model").and_then(|m| m.as_str()).unwrap_or("").to_owned(),
            system_prompt: "[forwarded from client]".to_owned(),
            user_message: zk_message,
            max_completion_tokens: 0,
        },
        OpenAiResponseLog {
            content: content.clone(),
            model: resp_model,
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens,
            },
        },
        elapsed.as_secs_f32(),
    );

    if let Ok(audit_path) = audit::write_audit_record(&audit_record) {
        println!("[ZK] Audit record: {}", audit_path.display());
    }

    println!(
        "[ZK] Done in {:.2}s — returning OpenAI response to client",
        elapsed.as_secs_f32()
    );

    let mut response = (
        resp_status,
        Json(resp_body),
    )
        .into_response();

    // Always present — machine-readable lane signal.
    if let Ok(val) = HeaderValue::from_str("zk_slow_lane") {
        response.headers_mut().insert("x-zemtik-engine", val);
    }
    if let Some(br) = committed_bundle {
        if let Ok(val) = HeaderValue::from_str(&br.bundle_id) {
            response.headers_mut().insert("x-zemtik-bundle-id", val);
        }
        let verify_url = match state.public_url.as_deref() {
            Some(base) => format!("{}/verify/{}", base, br.bundle_id),
            None => format!("http://localhost:{}/verify/{}", state.config.proxy_port, br.bundle_id),
        };
        if let Ok(val) = HeaderValue::from_str(&verify_url) {
            response.headers_mut().insert("x-zemtik-verify-url", val);
        }
    }

    Ok(response)
}

/// Serve the /verify/:id page — server-rendered HTML receipt.
async fn handle_verify(
    State(state): State<Arc<ProxyState>>,
    Path(id): Path<String>,
) -> Result<Response, ProxyError> {
    let receipt = {
        let db_guard = state.receipts_db
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        receipts::get_receipt(&db_guard, &id).map_err(ProxyError::Internal)?
    };

    match receipt {
        None => Ok((StatusCode::NOT_FOUND, Html(render_not_found(&id))).into_response()),
        Some(r) => {
            let readable = read_public_inputs_from_bundle(&r.bundle_path);
            Ok(Html(render_verify_page(&r, readable.as_ref())).into_response())
        }
    }
}

fn read_public_inputs_from_bundle(bundle_path: &str) -> Option<serde_json::Value> {
    let file = std::fs::File::open(bundle_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let mut entry = archive.by_name("public_inputs_readable.json").ok()?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut bytes).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Serve the /receipts page — browseable HTML list of all receipts.
async fn handle_receipts_list(
    State(state): State<Arc<ProxyState>>,
) -> Result<Response, ProxyError> {
    const PAGE_SIZE: usize = 100;
    let (list, total) = {
        let db_guard = state.receipts_db
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let list = receipts::list_receipts(&db_guard, PAGE_SIZE).map_err(ProxyError::Internal)?;
        let total = receipts::count_receipts(&db_guard).map_err(ProxyError::Internal)?;
        (list, total)
    };
    Ok(Html(render_receipts_list(&list, total, PAGE_SIZE)).into_response())
}

/// Compute the BN254 Fr field element encoding of a user prompt for circuit public input #6.
///
/// Spec: SHA-256(prompt_bytes) → mask top 3 bits (AND 0x1f on byte 0) → "0x<64 hex chars>"
///
/// Masking top 3 bits guarantees the value is strictly less than the BN254 Fr modulus p
/// (p ≈ 0x30644e72... — first byte 0x30 means any value with byte[0] ≤ 0x1f is < p).
/// Using 0x3f (2 bits) is insufficient: values 0x31...–0x3f... would exceed p and be
/// silently reduced mod p by the proving backend, creating a verifier/prover mismatch.
///
/// Independent verification:
///   Python: import hashlib; h = hashlib.sha256(prompt.encode()).digest(); h = bytes([h[0]&0x1f]) + h[1:]; print("0x" + h.hex())
pub fn compute_prompt_hash_field(prompt: &str) -> String {
    let hash = Sha256::digest(prompt.as_bytes());
    let mut buf: [u8; 32] = hash.into();
    buf[0] &= 0x1f; // clear top 3 bits → guaranteed < BN254 Fr modulus
    format!("0x{}", hex::encode(buf))
}

/// RAII guard that removes a per-run work directory on drop (success or error).
struct RunDirGuard(std::path::PathBuf);
impl Drop for RunDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the full ZK pipeline (DB → sign → circuit → proof → bundle).
/// Called from within spawn_blocking so DbBackend's !Sync is not an issue.
///
/// `outgoing_prompt_hash_field` — BN254 Field encoding of SHA-256(original_user_prompt),
/// written to Prover.toml as circuit public input #6 and included in the signed manifest.
/// Format: "0x<64 hex chars>" (top 2 bits cleared for BN254 field safety).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_zk_pipeline(
    config: Arc<AppConfig>,
    key_bytes: Vec<u8>,
    request_hash: String,
    prompt_hash: String,
    outgoing_prompt_hash_field: String,
    intent: crate::types::IntentResult,
    effective_client_id: i64,
    agg_fn: AggFn,
) -> anyhow::Result<ZkPipelineResult> {
    let target_category_hash = db::poseidon_of_string(&intent.table)
        .map(|fr| db::fr_to_decimal(&fr))
        .map_err(|e| anyhow::anyhow!(
            "cannot hash table key '{}' (key must be ≤93 bytes after lowercasing): {}",
            intent.table, e
        ))?;
    let params = QueryParams {
        client_id: effective_client_id,
        target_category_hash,
        category_name: intent.category_name.clone(),
        start_time: intent.start_unix_secs as u64,
        end_time: intent.end_unix_secs as u64,
    };

    let backend = db::init_db().await.context("init DB")?;
    let batch = db::query_transactions(&backend, effective_client_id)
        .await
        .context("query transactions")?;

    let actual_row_count = batch.actual_row_count;
    let txns = batch.transactions;

    anyhow::ensure!(
        txns.len() == db::MAX_ZK_TX_COUNT,
        "Expected {} transactions after padding, got {}. This is a bug in the padding path — please report it.",
        db::MAX_ZK_TX_COUNT,
        txns.len()
    );

    let txns_len = txns.len();
    let batch_count = txns_len / db::BATCH_SIZE;
    println!("[ZK] Loaded {} transactions ({} batches, {} real rows)", txns_len, batch_count, actual_row_count);

    let signing_key_bytes_for_bundle = key_bytes.clone();
    let key = db::PrivateKey::import(key_bytes)
        .map_err(|e| anyhow::anyhow!("import signing key: {}", e))?;
    let batches = db::sign_transaction_batches(&txns, &key).context("sign batches")?;
    println!("[ZK] Signed {} batches with BabyJubJub EdDSA", batch_count);

    // Select the correct mini-circuit directory for this aggregation type.
    let circuit_dir = prover::circuit_dir_for(&agg_fn, &config.circuit_dir);

    prover::generate_batched_prover_toml(&batches, &params, &circuit_dir, &outgoing_prompt_hash_field)
        .context("write Prover.toml")?;

    let circuit_json = circuit_dir.join("target/zemtik_circuit.json");
    if !circuit_json.exists() {
        println!("[ZK] Compiling {} circuit (first run, ~30-120s)...", agg_fn.as_str());
        prover::compile_circuit(&circuit_dir).context("compile circuit")?;
    }

    println!("[ZK] Executing {} circuit (EdDSA verification + aggregation)...", agg_fn.as_str());
    let circuit_exec_start = Instant::now();
    let hex_output = prover::execute_circuit(&circuit_dir).context("execute circuit")?;
    let circuit_execution_secs = circuit_exec_start.elapsed().as_secs_f32();
    let aggregate = prover::hex_output_to_u64(&hex_output).context("parse aggregate")?;

    println!("[ZK] Generating UltraHonk proof...");
    let run_dir = prover::prepare_run_dir(&config.runs_dir, &circuit_dir)
        .context("prepare run dir")?;
    // Ensure the run directory is cleaned up regardless of success or error.
    let _run_dir_guard = RunDirGuard(run_dir.clone());

    let proof_generated = prover::generate_proof(&run_dir).context("generate proof")?;
    let proof_status = if proof_generated {
        match prover::verify_proof(&run_dir).context("verify proof")? {
            Some(true) => "VALID (ZK proof generated and verified)",
            Some(false) => anyhow::bail!("Proof verification failed"),
            None => "VERIFIED (nargo execute - circuit constraints satisfied)",
        }
    } else {
        "VERIFIED (nargo execute - all constraints including EdDSA satisfied)"
    };

    let first_sig = batches
        .into_iter()
        .next()
        .map(|(_, sig)| sig)
        .context("no signed batches produced — zero transactions matched the query")?;

    let proof_artifacts = prover::read_proof_artifacts(&run_dir).context("read proof artifacts")?;
    let fully_verifiable = proof_artifacts.is_some() && proof_generated;
    let (proof_hex, vk_hex) = match proof_artifacts {
        Some((p, v)) => (Some(p), Some(v)),
        None => (None, None),
    };

    // Generate bundle while run_dir is still present (guard cleans it up after).
    // outgoing_prompt_hash_field = SHA-256(original_user_prompt) as BN254 Field — circuit public input #6.
    let bundle_result = if fully_verifiable {
        match bundle::generate_bundle(
            &params,
            aggregate,
            proof_status,
            &first_sig,
            Some(&request_hash),
            Some(&prompt_hash),
            Some(&outgoing_prompt_hash_field),
            &run_dir,
            &circuit_dir,
            &config.receipts_dir,
            agg_fn.as_str(),
            Some(actual_row_count),
            &signing_key_bytes_for_bundle,
        ) {
            Ok(br) => Some(br),
            Err(e) => {
                eprintln!("[BUNDLE] Bundle generation failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Only commit a hash when there's an actual verifiable bundle to match against.
    let committed_hash = if fully_verifiable {
        Some(outgoing_prompt_hash_field)
    } else {
        None
    };

    Ok(ZkPipelineResult {
        txns_len,
        batch_count,
        aggregate,
        proof_status,
        circuit_execution_secs,
        first_sig,
        proof_hex,
        vk_hex,
        fully_verifiable,
        bundle_result,
        outgoing_prompt_hash: committed_hash,
        actual_row_count,
    })
}

/// Run the AVG composite pipeline: SUM proof + COUNT proof + BabyJubJub attestation.
///
/// Both proofs use the same transaction dataset (guaranteed by the avg_pipeline_lock held
/// by the caller). AVG = sum / count, attested via BabyJubJub signing.
///
/// Evidence model: "zk_composite+attestation" — numerator and denominator are each
/// independently ZK-proven; the division step is attested (not ZK-proven).
pub(crate) async fn run_avg_pipeline(
    state: Arc<ProxyState>,
    request_hash: String,
    prompt_hash: String,
    outgoing_prompt_hash_field: String,
    intent: crate::types::IntentResult,
    effective_client_id: i64,
) -> anyhow::Result<ZkPipelineResult> {
    println!("[ZK] AVG composite: running SUM pipeline...");
    let config = Arc::clone(&state.config);
    let key_bytes = state.signing_key_bytes.clone();
    let req_hash = request_hash.clone();
    let prm_hash = prompt_hash.clone();
    let prm_hash_field = outgoing_prompt_hash_field.clone();
    let intent_clone = intent.clone();

    let sum_result = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build local runtime for SUM")?;
        rt.block_on(run_zk_pipeline(config, key_bytes, req_hash, prm_hash, prm_hash_field, intent_clone, effective_client_id, AggFn::Sum))
    })
    .await
    .context("AVG/SUM blocking task panicked")??;

    println!("[ZK] AVG composite: running COUNT pipeline...");
    let config2 = Arc::clone(&state.config);
    let key_bytes2 = state.signing_key_bytes.clone();
    let req_hash2 = request_hash.clone();
    let prm_hash2 = prompt_hash.clone();
    let prm_hash_field2 = outgoing_prompt_hash_field.clone();
    let intent_clone2 = intent.clone();

    let count_result = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build local runtime for COUNT")?;
        rt.block_on(run_zk_pipeline(config2, key_bytes2, req_hash2, prm_hash2, prm_hash_field2, intent_clone2, effective_client_id, AggFn::Count))
    })
    .await
    .context("AVG/COUNT blocking task panicked")??;

    anyhow::ensure!(
        count_result.aggregate > 0,
        "AVG: no matching transactions in the queried period (COUNT=0)"
    );

    // Integer division is intentional: ZK circuits operate over finite field integers,
    // not floating-point. The truncated quotient is what the circuit commits to.
    let avg = sum_result.aggregate / count_result.aggregate;
    println!(
        "[ZK] AVG composite: sum={}, count={}, avg={}",
        sum_result.aggregate, count_result.aggregate, avg
    );

    // Return a combined ZkPipelineResult carrying the AVG as aggregate.
    // The proof_hex is the SUM proof hash (first of the two proofs).
    // The bundle_result is from the SUM pipeline (COUNT bundle stored separately).
    // TODO: composite bundle format (two proof sub-directories) is Phase 2.
    Ok(ZkPipelineResult {
        txns_len: sum_result.txns_len,
        batch_count: sum_result.batch_count,
        aggregate: avg,
        proof_status: "VALID (ZK composite: SUM+COUNT proven, AVG attested)",
        circuit_execution_secs: sum_result.circuit_execution_secs + count_result.circuit_execution_secs,
        first_sig: sum_result.first_sig,
        proof_hex: sum_result.proof_hex,
        vk_hex: sum_result.vk_hex,
        fully_verifiable: sum_result.fully_verifiable && count_result.fully_verifiable,
        bundle_result: sum_result.bundle_result,
        outgoing_prompt_hash: sum_result.outgoing_prompt_hash,
        actual_row_count: sum_result.actual_row_count,
    })
}

/// GET /v1/models — returns the configured model as an OpenAI-compatible model list.
/// Gated behind ZEMTIK_PROXY_API_KEY when set (S5). Enables SDK client discovery on init.
async fn handle_models(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // S5: require auth if proxy_api_key is configured (treat empty key as unset — always reject)
    if let Some(ref expected) = state.config.proxy_api_key {
        let incoming = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if expected.is_empty() || !constant_time_eq(incoming.as_bytes(), expected.as_bytes()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": {"type": "auth_error", "message": "Unauthorized"}
                })),
            )
                .into_response();
        }
    }

    let (model_id, owned_by) = if state.config.llm_provider == "anthropic" {
        (state.config.anthropic_model.clone(), "anthropic")
    } else {
        (state.config.openai_model.clone(), "openai")
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "object": "list",
            "data": [{
                "id": model_id,
                "object": "model",
                "owned_by": owned_by,
                "created": Utc::now().timestamp()
            }]
        })),
    )
        .into_response()
}

/// Health check endpoint. Probes Supabase connectivity when DB_BACKEND=supabase.
/// For SQLite (local dev), always returns 200 — in-memory DB is always up.
/// Mode and tunnel telemetry fields are always included regardless of DB backend.
async fn handle_health(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let backend = std::env::var("DB_BACKEND").unwrap_or_default();

    // Step 1: probe DB reachability.
    let db_ok = if backend == "supabase" {
        if let (Some(url), Some(key)) = (
            &state.config.supabase_url,
            &state.config.supabase_service_key,
        ) {
            let probe_url = format!("{}/rest/v1/", url.trim_end_matches('/'));
            // Any HTTP response (even 401/403) means reachable; only network errors count as down.
            state.http_client
                .get(&probe_url)
                .header("apikey", key.as_str())
                .header("Authorization", format!("Bearer {}", key))
                .send()
                .await
                .is_ok()
        } else {
            false
        }
    } else {
        true // SQLite in-memory is always up
    };

    // Step 2: build base body.
    let mut body = if db_ok {
        serde_json::json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")})
    } else {
        serde_json::json!({"status": "degraded", "reason": "db_unreachable"})
    };

    // Step 3: append mode + tunnel telemetry to every response (all backends).
    if let Some(obj) = body.as_object_mut() {
        let mode_str = match state.config.mode {
            crate::config::ZemtikMode::Tunnel => "tunnel",
            crate::config::ZemtikMode::Standard => "standard",
        };
        obj.insert("mode".to_string(), serde_json::json!(mode_str));
        if let Some(ref sem) = state.tunnel_semaphore {
            use std::sync::atomic::Ordering;
            obj.insert("tunnel_semaphore_available".to_string(),
                serde_json::json!(sem.available_permits()));
            obj.insert("tunnel_semaphore_capacity".to_string(),
                serde_json::json!(state.config.tunnel_semaphore_permits));
            obj.insert("tunnel_backpressure_count".to_string(),
                serde_json::json!(state.backpressure_count.load(Ordering::Relaxed)));
        }
    }

    // Step 4: append GeneralLane counters (SQLite only; no-op on Supabase backend).
    if let Some(obj) = body.as_object_mut() {
        let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
        let general_today = receipts::count_engine_today(&db_guard, "general_lane").unwrap_or(0);
        let intent_failures = receipts::count_intent_failures_today(&db_guard).unwrap_or(0);
        obj.insert("general_queries_today".to_string(), serde_json::json!(general_today));
        obj.insert("intent_failures_today".to_string(), serde_json::json!(intent_failures));
    }

    // Step 4.5: anonymizer sidecar probe.
    if let Some(obj) = body.as_object_mut() {
        let anon_block = if state.config.anonymizer_enabled {
            let addr = state.config.anonymizer_sidecar_addr.clone();
            let probe_deadline = std::time::Duration::from_millis(500);
            let t0 = std::time::Instant::now();
            let status = match build_channel(&addr) {
                Ok(channel) => tokio::time::timeout(probe_deadline, check_sidecar_health(channel))
                    .await
                    .unwrap_or(SidecarHealth::Unreachable),
                Err(_) => SidecarHealth::Unreachable,
            };
            let latency_ms = t0.elapsed().as_millis() as u64;
            let status_str = match status {
                SidecarHealth::Serving => "serving",
                SidecarHealth::NotServing => "not_serving",
                SidecarHealth::Unreachable => "unreachable",
            };
            serde_json::json!({
                "enabled": true,
                "sidecar_addr": addr,
                "sidecar_status": status_str,
                "probe_latency_ms": latency_ms,
            })
        } else {
            serde_json::json!({
                "enabled": false,
                "sidecar_status": "disabled",
            })
        };
        obj.insert("anonymizer".to_string(), anon_block);
    }

    // Step 5: append schema_validation results.
    if let Some(obj) = body.as_object_mut() {
        let sv = &state.schema_validation;
        let sv_json = serde_json::json!({
            "status": sv.status_summary(),
            "skipped": sv.skipped,
            "tables": sv.tables.iter().map(|t| serde_json::json!({
                "table_key": t.table_key,
                "physical_table": t.physical_table,
                "status": t.status,
                "row_count": t.row_count,
                "warnings": t.warnings,
            })).collect::<Vec<_>>(),
            "zk_tools": {
                "nargo": sv.zk_tools.nargo,
                "bb": sv.zk_tools.bb,
            }
        });
        obj.insert("schema_validation".to_string(), sv_json);
    }

    let status_code = if db_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status_code, Json(body))
}

/// Transparent passthrough for non-intercepted routes.
async fn handle_passthrough() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": {
                "message": "Zemtik proxy only intercepts POST /v1/chat/completions. \
                            For other endpoints, call api.openai.com directly.",
                "type": "zemtik_proxy_passthrough"
            }
        })),
    )
}

/// GET /public-key — unauthenticated. No rate limit implemented (public keys are safe to expose).
/// TODO: add per-IP rate limiting via governor if abuse is observed.
///
/// Returns the ed25519 manifest signing public key and the BabyJubJub public key.
/// Both derive from the same `bank_sk` seed via different algorithms.
///   ed25519_manifest_pub — signs manifest.json in every v3 bundle
///   babyjubjub_pub_x/y  — used for FastLane attestations (not ZK proofs)
///
/// Third-party auditors use this to independently verify bundle signatures without
/// needing bb or nargo installed. See docs/ZK_CIRCUITS.md#independent-verification.
async fn handle_public_key(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    // Both keys are precomputed at startup to avoid per-request scalar multiplication.
    Json(serde_json::json!({
        "ed25519_manifest_pub": state.ed25519_manifest_pub_hex,
        "manifest_key_id": state.manifest_key_id,
        "babyjubjub_pub_x": state.bjj_pub_x,
        "babyjubjub_pub_y": state.bjj_pub_y,
        "algorithm": "ed25519",
        "curve": "babyjubjub",
        "_note": "ed25519_manifest_pub signs bundle manifests. babyjubjub_pub_x/y signs FastLane attestations. Both derive from the same bank_sk root via different algorithms.",
        "created_at": chrono::Utc::now().to_rfc3339()
    }))
}

// ---------------------------------------------------------------------------
// Shared streaming helpers (used by GeneralLane and tunnel mode)
// ---------------------------------------------------------------------------

/// Returns true for HTTP/1.1 hop-by-hop headers that must not be forwarded to clients.
pub(crate) fn is_hop_by_hop(header: &str) -> bool {
    matches!(
        header.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

/// Forward an already-obtained upstream SSE response to the client.
/// Single-consumer variant (no FORK2 tee). Used by GeneralLane streaming passthrough.
pub(crate) async fn stream_openai_passthrough(upstream: reqwest::Response) -> Response {
    use axum::body::Body;
    use bytes::Bytes;
    use futures_util::StreamExt;
    use tokio_stream::wrappers::ReceiverStream;

    let status = upstream.status();
    let resp_headers = upstream.headers().clone();
    let (chunk_tx, chunk_rx) =
        tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1024);

    tokio::spawn(async move {
        let mut byte_stream = upstream.bytes_stream();
        // Per-chunk timeout: if no data arrives within 60s, treat as a stalled
        // connection and terminate the stream to free the connection pool entry.
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(60),
                byte_stream.next(),
            )
            .await
            {
                Ok(Some(Ok(chunk))) => {
                    let _ = chunk_tx.send(Ok(chunk)).await;
                }
                Ok(Some(Err(e))) => {
                    let _ = chunk_tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    break;
                }
                Ok(None) => break, // stream complete
                Err(_timeout) => {
                    eprintln!("[STREAM] Upstream stream stalled for >60s — terminating");
                    let _ = chunk_tx
                        .send(Err(std::io::Error::other("upstream stream timed out after 60s")))
                        .await;
                    break;
                }
            }
        }
    });

    let stream = ReceiverStream::new(chunk_rx);
    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        if !is_hop_by_hop(k.as_str()) {
            builder = builder.header(k, v);
        }
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(axum::body::Body::empty()))
}

// ---------------------------------------------------------------------------
// Error type: typed variants for 500 (Internal) and 504 (Timeout)
// ---------------------------------------------------------------------------

pub(crate) enum ProxyError {
    Internal(anyhow::Error),
    Timeout(String),
    UnprocessableEntity(String),
    DbError(String),
}

impl std::fmt::Debug for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Internal(e) => write!(f, "ProxyError::Internal({:?})", e),
            ProxyError::Timeout(s) => write!(f, "ProxyError::Timeout({:?})", s),
            ProxyError::UnprocessableEntity(s) => write!(f, "ProxyError::UnprocessableEntity({:?})", s),
            ProxyError::DbError(s) => write!(f, "ProxyError::DbError({:?})", s),
        }
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        match self {
            ProxyError::UnprocessableEntity(msg) => {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({
                        "error": {
                            "message": msg,
                            "type": "zemtik_no_data_error"
                        }
                    })),
                )
                    .into_response()
            }
            ProxyError::Timeout(msg) => {
                eprintln!("[ZK] Timeout: {}", msg);
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": {
                            "message": msg,
                            "type": "timeout"
                        }
                    })),
                )
                    .into_response()
            }
            ProxyError::Internal(e) => {
                eprintln!("[ZK] Pipeline error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": {
                            "message": "Internal pipeline error — see server logs for details.",
                            "type": "zemtik_pipeline_error"
                        }
                    })),
                )
                    .into_response()
            }
            ProxyError::DbError(msg) => {
                eprintln!("[PROXY] DB error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": {
                            "type": "zemtik_db_error",
                            "code": ZemtikErrorCode::QueryFailed,
                            "message": "Database query failed — check server logs for details.",
                            "hint": "Check that physical_table, value_column, and timestamp_column match your schema.",
                            "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/TROUBLESHOOTING.md"
                        }
                    })),
                )
                    .into_response()
            }
        }
    }
}

impl From<anyhow::Error> for ProxyError {
    fn from(e: anyhow::Error) -> Self {
        ProxyError::Internal(e)
    }
}

// ---------------------------------------------------------------------------
// Anonymize preview endpoint — no LLM call, returns tokenized messages
// ---------------------------------------------------------------------------

async fn handle_anonymize_preview(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, ProxyError> {
    // Validate Authorization header against the configured API key.
    // The preview endpoint runs the sidecar and exposes PII-detection capabilities.
    let provided_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    // Prefer the dedicated preview key (ZEMTIK_ANONYMIZER_PREVIEW_KEY) when set.
    // Falls back to OPENAI_API_KEY for backwards compatibility with existing deployments.
    // Empty strings are rejected — a blank configured key must never grant access.
    let expected_key = state.config.anonymizer_preview_key.clone()
        .filter(|k| !k.is_empty())
        .or_else(|| state.config.openai_api_key.clone().filter(|k| !k.is_empty()))
        .or_else(|| std::env::var("OPENAI_API_KEY").ok().filter(|k| !k.is_empty()));
    let authorized = match (provided_key, expected_key.as_deref()) {
        // Constant-time comparison prevents timing-based key enumeration.
        (Some(provided), Some(expected)) => constant_time_eq::constant_time_eq(provided.as_bytes(), expected.as_bytes()),
        (Some(_), None) => false, // no key configured — deny all (fail-closed)
        (None, _) => false,
    };
    if !authorized {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {
                    "type": "unauthorized",
                    "message": "Invalid or missing Authorization header."
                }
            })),
        ).into_response());
    }

    if !state.config.anonymizer_enabled {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "type": "anonymizer_disabled",
                    "message": "Set ZEMTIK_ANONYMIZER_ENABLED=1 to use the anonymizer preview endpoint."
                }
            })),
        ).into_response());
    }

    let messages = body.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default();
    let session_id = match headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => {
            let is_v4 = uuid::Uuid::parse_str(s)
                .ok()
                .filter(|u| u.get_version() == Some(uuid::Version::Random))
                .is_some();
            if !is_v4 {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": {
                            "type": "invalid_session_id",
                            "message": "x-session-id must be a valid UUID v4."
                        }
                    })),
                ).into_response());
            }
            s.to_owned()
        }
        None => Uuid::new_v4().to_string(),
    };

    let t0 = Instant::now();
    let mut grpc_client = state.anonymizer_client.clone();
    let result = crate::anonymizer::anonymize_conversation(
        &messages,
        &session_id,
        grpc_client.as_mut(),
        &state.config.anonymizer_entity_types,
        state.config.anonymizer_sidecar_timeout_ms,
        state.config.anonymizer_fallback_regex,
        &state.config.anonymizer_sidecar_addr,
    ).await;

    let sidecar_ms = t0.elapsed().as_millis() as u64;

    match result {
        Ok((anon_messages, vault, meta)) => {
            let tokens: Vec<&str> = vault.iter().map(|e| e.token.as_str()).collect();
            let originals: Vec<&str> = vault.iter().map(|e| e.original.as_str()).collect();
            let entity_types: Vec<&str> = vault.iter().map(|e| e.entity_type.as_str()).collect();
            Ok(Json(serde_json::json!({
                "anonymized_messages": anon_messages,
                "tokens": tokens,
                "originals": originals,
                "entities_found": meta.entities_found,
                "entity_types": entity_types,
                "sidecar_used": meta.sidecar_used,
                "sidecar_ms": sidecar_ms,
            })).into_response())
        }
        Err(e) => {
            Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": {
                        "type": "anonymizer_unavailable",
                        "message": e.to_string()
                    }
                })),
            ).into_response())
        }
    }
}

#[cfg(test)]
mod proxy_error_tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn test_proxy_error_timeout_returns_504() {
        let err = ProxyError::Timeout("bb took too long".to_owned());
        let response = err.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::GATEWAY_TIMEOUT,
            "ProxyError::Timeout must map to HTTP 504"
        );
    }

    #[test]
    fn test_proxy_error_internal_returns_500() {
        let err = ProxyError::Internal(anyhow::anyhow!("something broke"));
        let response = err.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "ProxyError::Internal must map to HTTP 500"
        );
    }

    #[test]
    fn test_proxy_error_unprocessable_entity_returns_422() {
        let err = ProxyError::UnprocessableEntity(
            "AVG: no matching transactions in the queried period (COUNT=0)".to_owned(),
        );
        let response = err.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "ProxyError::UnprocessableEntity must map to HTTP 422"
        );
    }

    // ── compute_prompt_hash_field tests ──────────────────────────────────────

    /// Known-answer test: SHA-256("hello world") with top-3 bits masked must produce
    /// a stable hex output. Pins the derivation spec across refactors.
    #[test]
    fn test_compute_prompt_hash_field_known_answer() {
        // SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        // byte[0] = 0xb9 = 0b10111001; after &= 0x1f: 0b00011001 = 0x19
        // Full expected: 0x194d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        let result = compute_prompt_hash_field("hello world");
        assert_eq!(
            result,
            "0x194d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            "SHA-256('hello world') with 0x1f mask must match known-answer value"
        );
        // Redundant checks kept for clarity.
        assert!(result.starts_with("0x"), "must be 0x-prefixed hex");
        assert_eq!(result.len(), 66, "must be 0x + 64 hex chars (32 bytes)");
        // Top-3-bits mask: byte[0] & 0xe0 must be zero (bits 7, 6, 5 clear).
        let first_byte = u8::from_str_radix(&result[2..4], 16).expect("valid hex");
        assert_eq!(first_byte & 0xe0, 0, "top 3 bits of field element must be clear (BN254 Fr safety)");
    }

    /// Empty string produces a valid, non-zero field element (SHA-256 of empty = non-zero).
    #[test]
    fn test_compute_prompt_hash_field_empty_string_is_nonzero() {
        let result = compute_prompt_hash_field("");
        assert!(result.starts_with("0x"), "must be 0x-prefixed hex");
        // SHA-256("") = e3b0c44298... — byte[0] = 0xe3 & 0x1f = 0x03 (non-zero)
        assert_ne!(result, "0x0000000000000000000000000000000000000000000000000000000000000000",
            "SHA-256 of empty string is never zero");
        // Top 3 bits must still be clear.
        let first_byte = u8::from_str_radix(&result[2..4], 16).expect("valid hex");
        assert_eq!(first_byte & 0xe0, 0, "top 3 bits must be clear for BN254 Fr safety");
    }

    /// Different prompts produce different field values (no collision in test vectors).
    #[test]
    fn test_compute_prompt_hash_field_different_prompts_differ() {
        let h1 = compute_prompt_hash_field("what is the total aws spend for Q1 2024?");
        let h2 = compute_prompt_hash_field("count transactions for client 123");
        assert_ne!(h1, h2, "different prompts must produce different field values");
    }

    /// Same prompt always produces the same field value (deterministic).
    #[test]
    fn test_compute_prompt_hash_field_deterministic() {
        let prompt = "show me the quarterly revenue breakdown";
        let h1 = compute_prompt_hash_field(prompt);
        let h2 = compute_prompt_hash_field(prompt);
        assert_eq!(h1, h2, "same prompt must always produce same field value");
    }
}
