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

use crate::config::{AggFn, AppConfig, RewriterConfig, ZemtikMode};
use crate::intent::{IntentBackend, IntentError};
use crate::types::{
    AuditRecord, EngineResult, EvidencePack, FastLaneResult, IntentResult, MessageContent,
    OpenAiRequestLog, OpenAiResponseLog, QueryParams, RewriteMethod, Route, SchemaValidationResult,
    SignatureData, TokenUsage, ZemtikErrorCode,
};
use crate::{audit, bundle, db, engine_fast, evidence, intent, intent_embed, keys, prover, receipts, rewriter, router};

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
    /// OpenAI base URL for forwarding requests. Injected from AppConfig so tests
    /// can point this at a wiremock server instead of api.openai.com.
    pub(crate) openai_base_url: String,
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

    let schema_config_hash = config.schema_config_hash.clone().unwrap_or_default();
    let schema = config.schema_config.clone().unwrap();
    let openai_base_url = config.openai_base_url.clone();

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
                match intent_embed::try_new_embedding_backend(&config.models_dir) {
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
            eprintln!("[STARTUP] Warning: failed to derive BabyJubJub public key: {}", e);
            ("error".to_owned(), "error".to_owned())
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
            base_url: config.openai_base_url.clone(),
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
        openai_base_url,
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
    });

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
            .route("/receipts", get(handle_receipts_list))
            .route("/verify/{id}", get(handle_verify))
            .route("/{*path}", any(handle_passthrough)),
        ZemtikMode::Tunnel => Router::new()
            .route("/health", get(handle_health))
            .route("/public-key", get(handle_public_key))
            .route("/v1/chat/completions", post(crate::tunnel::handle_tunnel))
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
    Json(body): Json<Value>,
) -> Result<Response, ProxyError> {
    let total_start = Instant::now();

    let api_key = headers
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
        })?;

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
    let prompt = body
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

    // Streaming guard (standard mode only). Tunnel mode supports stream:true via
    // forward_streaming. GeneralLane also supports streaming when
    // ZEMTIK_GENERAL_PASSTHROUGH=1 — allow stream:true through so intent extraction
    // can run; data lanes reject stream:true at their own dispatch point below.
    let is_streaming = body.get("stream").and_then(|v| v.as_bool()) == Some(true);
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
        let prompt_clone = prompt.clone();
        let schema_clone = schema.clone();
        let threshold = state.config.intent_confidence_threshold;
        tokio::task::spawn_blocking(move || {
            intent::extract_intent_with_backend(&prompt_clone, &schema_clone, backend.as_ref(), threshold)
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
                let det_result = {
                    let backend = Arc::clone(&state.intent_backend);
                    let messages_clone = messages.clone();
                    let schema_clone = schema.clone();
                    let threshold = state.config.intent_confidence_threshold;
                    let max_scan = rw_config.max_scan_messages;
                    tokio::task::spawn_blocking(move || {
                        rewriter::deterministic_resolve(
                            &messages_clone,
                            &schema_clone,
                            backend.as_ref(),
                            threshold,
                            max_scan,
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
                        Route::FastLane => handle_fast_lane(state, body, api_key, request_hash, prompt_hash, resolved, effective_client_id, total_start).await,
                        Route::ZkSlowLane => handle_zk_slow_lane(state, body, headers, api_key, request_hash, prompt_hash, prompt.clone(), resolved, effective_client_id, total_start).await,
                        Route::GeneralLane => unreachable!("decide_route never returns GeneralLane"),
                    };
                }

                // ── STEP 2: LLM rewriter (async — do NOT put inside spawn_blocking) ──
                match rewriter::rewrite_query(&messages, &prompt, schema, &rw_config, &state.http_client).await {
                    Ok(rewriter::RewriteResult::Rewritten(q)) => {
                        println!("[REWRITER] LLM: '{}' → '{}'", prompt, q);
                        // Re-run intent on the rewritten query.
                        let backend = Arc::clone(&state.intent_backend);
                        let q_clone = q.clone();
                        let schema_clone = schema.clone();
                        let threshold = state.config.intent_confidence_threshold;
                        let re_intent_join = tokio::task::spawn_blocking(move || {
                            intent::extract_intent_with_backend(&q_clone, &schema_clone, backend.as_ref(), threshold)
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
                                    Route::FastLane => handle_fast_lane(state, body, api_key, request_hash, prompt_hash, r, effective_client_id, total_start).await,
                                    Route::ZkSlowLane => handle_zk_slow_lane(state, body, headers, api_key, request_hash, prompt_hash, prompt.clone(), r, effective_client_id, total_start).await,
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
                                    return handle_general_lane(state, body, api_key, prompt, prompt_hash, Some(intent_err), total_start).await;
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
                            return handle_general_lane(state, body, api_key, prompt, prompt_hash, Some(intent_err), total_start).await;
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
                return handle_general_lane(state, body, api_key, prompt, prompt_hash, Some(intent_err), total_start).await;
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
            handle_fast_lane(state, body, api_key, request_hash, prompt_hash, intent_result, effective_client_id, total_start).await
        }
        Route::ZkSlowLane => {
            handle_zk_slow_lane(state, body, headers, api_key, request_hash, prompt_hash, prompt, intent_result, effective_client_id, total_start).await
        }
        Route::GeneralLane => {
            // GeneralLane variant is never produced by decide_route (it only returns
            // FastLane or ZkSlowLane for successfully resolved intents). Handled defensively.
            handle_general_lane(state, body, api_key, prompt, prompt_hash, None, total_start).await
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
                evidence_json: serde_json::to_string(&ev).ok(),
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
async fn handle_general_lane(
    state: Arc<ProxyState>,
    body: Value,
    api_key: String,
    _prompt: String,
    prompt_hash: String,
    intent_err: Option<IntentError>,
    _total_start: Instant,
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
        })
    };
    if let Err(e) = receipt_write_result {
        eprintln!("[GENERAL_LANE] Warning: failed to write receipt {}: {}", receipt_id, e);
        // Continue — receipt failure does not block the response (FastLane parity).
    }

    let is_streaming = body.get("stream").and_then(|v| v.as_bool()) == Some(true);

    let zemtik_meta = serde_json::json!({
        "engine_used": "general_lane",
        "zk_coverage": "none",
        "reason": reason,
        "receipt_id": receipt_id,
    });
    let meta_header_val = urlencoding::encode(&zemtik_meta.to_string()).into_owned();

    let openai_url = format!("{}/v1/chat/completions", state.openai_base_url);

    if is_streaming {
        // ── Streaming path: SSE passthrough, metadata via header only ──────
        let upstream = state
            .http_client
            .post(&openai_url)
            .bearer_auth(&api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProxyError::Internal(anyhow::anyhow!("GeneralLane upstream error: {}", e)))?;

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
    let upstream = state
        .http_client
        .post(&openai_url)
        .bearer_auth(&api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| ProxyError::Internal(anyhow::anyhow!("GeneralLane upstream error: {}", e)))?;

    let resp_status = upstream.status();
    let content_type = upstream
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let resp_bytes = upstream
        .bytes()
        .await
        .map_err(|e| ProxyError::Internal(anyhow::anyhow!("GeneralLane read body: {}", e)))?;

    // Inject zemtik_meta into the response body when Content-Type is application/json
    // and the body is a JSON object (not array). Fall back to header-only for other cases.
    let final_body: Vec<u8> = if content_type.contains("application/json") {
        if let Ok(mut v) = serde_json::from_slice::<Value>(&resp_bytes) {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("zemtik_meta".to_string(), zemtik_meta);
                serde_json::to_vec(&v).unwrap_or_else(|_| resp_bytes.to_vec())
            } else {
                resp_bytes.to_vec()
            }
        } else {
            resp_bytes.to_vec()
        }
    } else {
        resp_bytes.to_vec()
    };

    let http_status = StatusCode::from_u16(resp_status.as_u16()).unwrap_or(StatusCode::OK);
    let effective_content_type = if content_type.is_empty() {
        "application/json"
    } else {
        &content_type
    };
    let mut response = Response::builder()
        .status(http_status)
        .header(axum::http::header::CONTENT_TYPE, effective_content_type)
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
async fn build_fast_lane_response(
    body: &mut Value,
    payload: Value,
    state: &Arc<ProxyState>,
    api_key: &str,
    receipt_id: &str,
    intent: &IntentResult,
    ev: &EvidencePack,
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

    let openai_url = format!("{}/v1/chat/completions", state.openai_base_url);
    let openai_resp = state
        .http_client
        .post(&openai_url)
        .bearer_auth(api_key)
        .json(body)
        .send()
        .await
        .context("forward FastLane request to OpenAI")
        .map_err(ProxyError::Internal)?;

    let resp_status = openai_resp.status();
    let mut resp_body: Value = openai_resp
        .json()
        .await
        .context("parse OpenAI response")
        .map_err(ProxyError::Internal)?;

    let envelope = zemtik_evidence_envelope(ev, intent).map_err(|e| ProxyError::Internal(anyhow::Error::new(e)))?;
    if let Some(obj) = resp_body.as_object_mut() {
        obj.insert("evidence".to_string(), envelope);
    }

    let mut response = (
        StatusCode::from_u16(resp_status.as_u16()).unwrap_or(StatusCode::OK),
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
                evidence_json: None, // Updated after evidence pack is built
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

    let model = body
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or(&state.config.openai_model)
        .to_owned();
    let openai_url = format!("{}/v1/chat/completions", state.openai_base_url);

    let openai_resp = state
        .http_client
        .post(&openai_url)
        .bearer_auth(&api_key)
        .json(&body)
        .send()
        .await
        .context("forward to OpenAI")
        .map_err(ProxyError::Internal)?;

    let resp_status = openai_resp.status();
    let mut resp_body: Value = openai_resp
        .json()
        .await
        .context("parse OpenAI response")
        .map_err(ProxyError::Internal)?;

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
    );
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
        .unwrap_or(&model)
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
            model: model.clone(),
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
        StatusCode::from_u16(resp_status.as_u16()).unwrap_or(StatusCode::OK),
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

fn render_verify_page(r: &receipts::Receipt, readable: Option<&serde_json::Value>) -> String {
    let (badge_color, status_label) = match r.proof_status.as_str() {
        s if s.starts_with("VALID") => ("#22c55e", "VALID"),
        "FAST_LANE_ATTESTED" => ("#3b82f6", "FAST LANE ATTESTED"),
        _ => ("#ef4444", "INVALID"),
    };

    // Parse evidence_json for richer data (v9+). Fall back to ZK bundle readable inputs.
    let ev: Option<serde_json::Value> = r.evidence_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    let aggregate_display = ev
        .as_ref()
        .and_then(|v| v.get("aggregate"))
        .and_then(|v| v.as_i64())
        .map(|n| {
            // Format with thousands separator
            let s = n.abs().to_string();
            let formatted: String = s.chars().rev().enumerate()
                .flat_map(|(i, c)| if i > 0 && i % 3 == 0 { vec![',', c] } else { vec![c] })
                .collect::<String>().chars().rev().collect();
            if n < 0 { format!("-${}", formatted) } else { format!("${}", formatted) }
        })
        .or_else(|| readable
            .and_then(|v| v.get("verified_aggregate"))
            .and_then(|v| v.as_u64())
            .map(|n| format!("${}", n)))
        .unwrap_or_else(|| "—".to_owned());

    let table_display = ev
        .as_ref()
        .and_then(|v| v.get("engine_used"))
        .and_then(|_| {
            // Extract table from human_summary if available
            ev.as_ref()
                .and_then(|v| v.get("human_summary"))
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    // "Aggregated N rows from 'table_key' into..."
                    let re = s.find("from '")?;
                    let rest = &s[re + 6..];
                    let end = rest.find('\'')?;
                    Some(rest[..end].to_owned())
                })
        })
        .or_else(|| readable
            .and_then(|v| v.get("category_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned()))
        .unwrap_or_else(|| "—".to_owned());

    let engine_label = ev
        .as_ref()
        .and_then(|v| v.get("engine_used"))
        .and_then(|v| v.as_str())
        .unwrap_or(&r.engine_used);

    let human_summary_html = ev
        .as_ref()
        .and_then(|v| v.get("human_summary"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| format!(
            r#"<div class="summary-box"><strong>Summary</strong><p>{}</p></div>"#,
            html_escape(s)
        ))
        .unwrap_or_default();

    let checks_html = ev
        .as_ref()
        .and_then(|v| v.get("checks_performed"))
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .map(|checks| {
            let items: String = checks.iter()
                .filter_map(|c| c.as_str())
                .map(|c| format!("<li><code>{}</code></li>", html_escape(c)))
                .collect();
            format!(r#"<div class="checks"><strong>Checks Performed</strong><ol>{}</ol></div>"#, items)
        })
        .unwrap_or_default();

    let attestation_row = ev
        .as_ref()
        .and_then(|v| v.get("attestation_hash"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|h| format!(
            r#"<tr><td>Attestation Hash</td><td class="mono">{}</td></tr>"#,
            html_escape(h)
        ))
        .unwrap_or_default();

    let proof_row = if !r.circuit_hash.is_empty() || r.proof_hash.is_some() {
        format!(
            r#"<tr><td>Circuit Hash</td><td class="mono">{}</td></tr>
  <tr><td>bb Version</td><td class="mono">{}</td></tr>"#,
            html_escape(&r.circuit_hash),
            html_escape(&r.bb_version),
        )
    } else {
        String::new()
    };

    // Pretty-print evidence JSON for the raw block
    let evidence_json_pretty = ev
        .as_ref()
        .and_then(|v| serde_json::to_string_pretty(v).ok())
        .map(|s| format!(
            r#"<details class="json-block">
  <summary>Evidence Pack JSON</summary>
  <pre><code>{}</code></pre>
</details>"#,
            html_escape(&s)
        ))
        .unwrap_or_default();

    let back_link = r#"<p class="back-link"><a href="/receipts">← All receipts</a></p>"#;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zemtik Receipt — {id}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 760px; margin: 48px auto; padding: 0 24px; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 4px; }}
  .subtitle {{ color: #666; font-size: 0.9rem; margin-bottom: 32px; }}
  .badge {{ display: inline-block; padding: 6px 18px; border-radius: 6px; font-weight: 700;
            font-size: 1.1rem; color: white; background: {badge_color}; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.95rem; margin-bottom: 24px; }}
  td {{ padding: 10px 0; border-bottom: 1px solid #e5e5e5; vertical-align: top; }}
  td:first-child {{ font-weight: 600; width: 200px; color: #444; }}
  .mono {{ font-family: monospace; font-size: 0.85rem; word-break: break-all; }}
  .summary-box {{ background: #f0f9ff; border-left: 3px solid #3b82f6; padding: 12px 16px; margin-bottom: 20px; border-radius: 0 6px 6px 0; font-size: 0.95rem; }}
  .summary-box p {{ margin: 6px 0 0; color: #444; }}
  .checks {{ margin-bottom: 20px; font-size: 0.95rem; }}
  .checks ol {{ margin: 8px 0 0 0; padding-left: 20px; color: #444; }}
  .checks li {{ padding: 2px 0; }}
  .json-block {{ margin-top: 24px; border: 1px solid #e5e5e5; border-radius: 6px; overflow: hidden; }}
  .json-block summary {{ padding: 10px 16px; background: #f8f8f8; cursor: pointer; font-weight: 600; font-size: 0.9rem; }}
  .json-block pre {{ margin: 0; padding: 16px; background: #1a1a1a; color: #e8e8e8; font-size: 0.82rem; overflow-x: auto; }}
  .footer {{ margin-top: 32px; font-size: 0.8rem; color: #999; }}
  .back-link {{ margin-bottom: 24px; font-size: 0.9rem; }}
  .back-link a {{ color: #3b82f6; text-decoration: none; }}
  @media print {{ .footer, .back-link, .json-block {{ display: none; }} }}
</style>
</head>
<body>
{back_link}
<h1>Zemtik Cryptographic Receipt</h1>
<p class="subtitle">Audit evidence — no raw records were transmitted to the LLM</p>

<div class="badge">{status_label}</div>

{human_summary_html}

<table>
  <tr><td>Receipt ID</td><td class="mono">{id}</td></tr>
  <tr><td>Verified Aggregate</td><td><strong>{aggregate_display}</strong></td></tr>
  <tr><td>Table</td><td>{table_display}</td></tr>
  <tr><td>Engine</td><td>{engine_label}</td></tr>
  <tr><td>Proof Status</td><td>{proof_status}</td></tr>
  {attestation_row}
  {proof_row}
  <tr><td>Generated At</td><td>{created_at}</td></tr>
  <tr><td>Raw Rows to LLM</td><td><strong>0</strong></td></tr>
</table>

{checks_html}

{evidence_json_pretty}

<p class="footer">
  Verify this receipt independently: <code>zemtik verify &lt;bundle.zip&gt;</code> (ZK SlowLane only)<br>
  Requires only the <code>bb</code> binary (Barretenberg ≥ v4).
</p>
</body>
</html>"#,
        back_link = back_link,
        id = html_escape(&r.id),
        badge_color = badge_color,
        status_label = status_label,
        human_summary_html = human_summary_html,
        aggregate_display = html_escape(&aggregate_display),
        table_display = html_escape(&table_display),
        engine_label = html_escape(engine_label),
        proof_status = html_escape(&r.proof_status),
        attestation_row = attestation_row,
        proof_row = proof_row,
        created_at = html_escape(&r.created_at),
        checks_html = checks_html,
        evidence_json_pretty = evidence_json_pretty,
    )
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

fn render_receipts_list(list: &[receipts::Receipt], total: usize, page_size: usize) -> String {
    let rows: String = if list.is_empty() {
        r#"<tr><td colspan="5" style="text-align:center;color:#999;padding:32px 0">No receipts yet. Send a query through the proxy to generate one.</td></tr>"#.to_owned()
    } else {
        list.iter().map(|r| {
            let ev: Option<serde_json::Value> = r.evidence_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());

            let aggregate_cell = ev
                .as_ref()
                .and_then(|v| v.get("aggregate"))
                .and_then(|v| v.as_i64())
                .map(|n| {
                    let s = n.abs().to_string();
                    let formatted: String = s.chars().rev().enumerate()
                        .flat_map(|(i, c)| if i > 0 && i % 3 == 0 { vec![',', c] } else { vec![c] })
                        .collect::<String>().chars().rev().collect();
                    if n < 0 { format!("-${}", formatted) } else { format!("${}", formatted) }
                })
                .unwrap_or_else(|| "—".to_owned());

            let table_cell = ev
                .as_ref()
                .and_then(|v| v.get("human_summary"))
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    let re = s.find("from '")?;
                    let rest = &s[re + 6..];
                    let end = rest.find('\'')?;
                    Some(rest[..end].to_owned())
                })
                .unwrap_or_else(|| "—".to_owned());

            let (badge_color, badge_label) = match r.proof_status.as_str() {
                s if s.starts_with("VALID") => ("#22c55e", "ZK VALID"),
                "FAST_LANE_ATTESTED" => ("#3b82f6", "FastLane"),
                s if s.contains("general") => ("#6b7280", "General"),
                _ => ("#ef4444", "—"),
            };

            // Truncate timestamp to date + time without nanoseconds
            let ts_short = r.created_at.get(..19).unwrap_or(&r.created_at);

            format!(
                r#"<tr>
  <td class="mono small"><a href="/verify/{id}">{id_short}…</a></td>
  <td><span class="badge" style="background:{badge_color}">{badge_label}</span></td>
  <td>{table_cell}</td>
  <td><strong>{aggregate_cell}</strong></td>
  <td class="small">{ts_short}</td>
</tr>"#,
                id = html_escape(&r.id),
                id_short = html_escape(r.id.get(..8).unwrap_or(&r.id)),
                badge_color = badge_color,
                badge_label = badge_label,
                table_cell = html_escape(&table_cell),
                aggregate_cell = html_escape(&aggregate_cell),
                ts_short = html_escape(ts_short),
            )
        }).collect()
    };

    let showing = list.len();
    let truncated = total > page_size;
    let count_line = if truncated {
        format!(
            r#"Showing {showing} most recent of {total} receipt(s) total <a class="refresh" href="/receipts">↻ Refresh</a>"#,
            showing = showing,
            total = total,
        )
    } else {
        format!(
            r#"{total} receipt(s) total <a class="refresh" href="/receipts">↻ Refresh</a>"#,
            total = total,
        )
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zemtik — Receipts</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 48px auto; padding: 0 24px; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 4px; }}
  .subtitle {{ color: #666; font-size: 0.9rem; margin-bottom: 28px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
  th {{ text-align: left; padding: 8px 0; border-bottom: 2px solid #e5e5e5; color: #444; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; }}
  td {{ padding: 10px 8px 10px 0; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }}
  tr:hover td {{ background: #fafafa; }}
  a {{ color: #3b82f6; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.78rem; font-weight: 700; color: white; }}
  .mono {{ font-family: monospace; }}
  .small {{ font-size: 0.85rem; color: #666; }}
  .count {{ color: #666; font-size: 0.85rem; margin-bottom: 16px; }}
  .refresh {{ float: right; font-size: 0.85rem; color: #3b82f6; }}
</style>
</head>
<body>
<h1>Zemtik — Audit Trail</h1>
<p class="subtitle">Every query intercepted by this proxy. Click a receipt to see the full evidence pack.</p>
<p class="count">{count_line}</p>
<table>
<thead>
  <tr>
    <th>Receipt ID</th>
    <th>Engine</th>
    <th>Table</th>
    <th>Aggregate</th>
    <th>Timestamp</th>
  </tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"#,
        count_line = count_line,
        rows = rows,
    )
}

fn render_not_found(id: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Receipt not found</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:80px auto;padding:0 24px;color:#1a1a1a;}}</style>
</head>
<body>
<h1>Receipt not found</h1>
<p>No receipt with ID <code>{}</code> exists in this Zemtik instance.</p>
<p style="color:#999;font-size:0.9rem">The bundle may have been generated on a different machine or the receipts database may have been reset.</p>
</body>
</html>"#,
        html_escape(id)
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
