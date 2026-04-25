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
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use constant_time_eq::constant_time_eq;
use crate::config::{AggFn, AppConfig, RewriterConfig, ZemtikMode};
use crate::intent::{IntentBackend, IntentError};
use crate::llm_backend::{AnthropicBackend, LlmBackend, OpenAiBackend};
use crate::types::{
    MessageContent,
    RequestedMode, RewriteMethod, Route,
    ZemtikErrorCode,
};
use crate::{db, intent, intent_embed, keys, prover, receipts, rewriter, router};
use crate::anonymizer::{AnonymizerGrpcClient, Vault, new_vault_store, build_channel, check_sidecar_health, SidecarHealth};

mod state;
pub(crate) use state::ProxyState;
#[allow(unused_imports)]
pub(crate) use state::ZkPipelineResult;

mod lanes;
pub(crate) use lanes::fast::run_fast_lane_engine;
pub(crate) use lanes::zk::{run_zk_pipeline, run_avg_pipeline};
use lanes::fast::handle_fast_lane;
use lanes::zk::handle_zk_slow_lane;
use lanes::general::handle_general_lane;

mod ui;
use ui::{render_verify_page, render_receipts_list, render_not_found};

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
