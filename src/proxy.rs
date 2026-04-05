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

use crate::config::AppConfig;
use crate::intent::IntentBackend;
use crate::types::{
    AuditRecord, EngineResult, EvidencePack, IntentResult, OpenAiRequestLog, OpenAiResponseLog,
    QueryParams, Route, SignatureData, TokenUsage,
};
use crate::{audit, bundle, db, engine_fast, evidence, intent, intent_embed, keys, prover, receipts, router};

const OPENAI_BASE_URL: &str = "https://api.openai.com";

struct ProxyState {
    http_client: reqwest::Client,
    /// Serializes ZK pipeline executions — the circuit uses shared files in circuit_dir.
    pipeline_lock: tokio::sync::Mutex<()>,
    /// File-based receipts DB, shared across requests.
    /// WARNING: std::sync::MutexGuard<Connection> must NEVER be held across an .await point.
    /// Lock inside spawn_blocking or in a synchronous scope that drops before any .await.
    receipts_db: std::sync::Mutex<Connection>,
    /// Separate in-memory ledger DB for FastLane reads (avoids contention with receipts_db).
    /// WARNING: std::sync::MutexGuard<Connection> must NEVER be held across an .await point.
    ledger_db: std::sync::Mutex<Connection>,
    /// Application configuration (ports, paths).
    config: Arc<AppConfig>,
    /// Bank signing key bytes (loaded once at startup, passed into spawn_blocking).
    signing_key_bytes: Vec<u8>,
    /// SHA-256 of schema_config.json bytes (empty string when schema absent).
    schema_config_hash: String,
    /// Intent matching backend — static after startup, no lock needed.
    intent_backend: Arc<dyn IntentBackend>,
}

// Results returned from the blocking ZK pipeline (includes optional bundle).
struct ZkPipelineResult {
    txns_len: usize,
    batch_count: usize,
    aggregate: u64,
    proof_status: &'static str,
    circuit_execution_secs: f32,
    first_sig: SignatureData,
    proof_hex: Option<String>,
    vk_hex: Option<String>,
    fully_verifiable: bool,
    bundle_result: Option<bundle::BundleResult>,
    /// SHA-256 of the ZK payload JSON sent to the LLM (Rust-layer commitment).
    /// None when fully_verifiable=false — no bundle artifact exists to match against.
    outgoing_prompt_hash: Option<String>,
}

/// Entry point for proxy mode. Starts Axum on the configured port.
pub async fn run_proxy(config: AppConfig) -> anyhow::Result<()> {
    // Fail fast: schema_config.json is required for proxy mode routing.
    if config.schema_config.is_none() {
        eprintln!(
            "Fatal: schema_config required for proxy mode. \
             schema_config.json not found at {}. \
             Copy schema_config.example.json to ~/.zemtik/schema_config.json \
             and configure your table sensitivities.",
            config.schema_config_path.display()
        );
        std::process::exit(1);
    }

    // Validate sensitivity values
    crate::config::validate_schema_config(config.schema_config.as_ref().unwrap(), false)
        .context("validate schema_config")?;

    // Fail fast: verify circuit directory has all required files before accepting requests.
    prover::validate_circuit_dir(&config.circuit_dir).context("circuit directory validation")?;

    let schema_config_hash = config.schema_config_hash.clone().unwrap_or_default();
    let schema = config.schema_config.clone().unwrap();

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

    let state = Arc::new(ProxyState {
        http_client: reqwest::Client::new(),
        pipeline_lock: tokio::sync::Mutex::new(()),
        receipts_db: std::sync::Mutex::new(receipts_conn),
        ledger_db: std::sync::Mutex::new(ledger_conn),
        config: Arc::clone(&config),
        signing_key_bytes,
        schema_config_hash,
        intent_backend,
    });

    let app = Router::new()
        .route("/v1/chat/completions", post(handle_chat_completions))
        .route("/verify/{id}", get(handle_verify))
        .route("/{*path}", any(handle_passthrough))
        // Restrict CORS to localhost origins — CorsLayer::permissive() sets
        // Access-Control-Allow-Origin: * which enables cross-origin data exfiltration
        // from any browser page on the developer workstation. This proxy binds to
        // 127.0.0.1 so restrict to same-host origins only.
        .layer(
            CorsLayer::new()
                .allow_origin([
                    axum::http::HeaderValue::from_static("http://localhost:4000"),
                    axum::http::HeaderValue::from_static("http://127.0.0.1:4000"),
                ])
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state);

    let addr = format!("127.0.0.1:{}", config.proxy_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!("╔══════════════════════════════════════════════════╗");
    println!("║   Zemtik Proxy — ZK Middleware for Enterprise AI ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    println!("[PROXY] Listening on http://{}", addr);
    println!(
        "[PROXY] Intercepts POST /v1/chat/completions → ZK pipeline → forwards to OpenAI"
    );
    println!(
        "[PROXY] Point your app to http://localhost:{} instead of api.openai.com",
        config.proxy_port
    );
    println!(
        "[PROXY] Verify receipts at http://localhost:{}/verify/<bundle-id>",
        config.proxy_port
    );
    println!();

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

    // Extract the last user message prompt for intent parsing
    let prompt = body
        .get("messages")
        .and_then(|m| m.as_array())
        .and_then(|arr| {
            arr.iter()
                .rev()
                .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        })
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();

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

    let intent_result = match intent_result_raw {
        Ok(r) => r,
        Err(e) => {
            // Log rejection synchronously — std::sync::Mutex must not be held across .await
            {
                let db_guard = state.receipts_db
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Err(db_err) = receipts::insert_intent_rejection(&db_guard, &prompt, &e.to_string()) {
                    eprintln!("[WARN] Failed to log intent rejection to receipts DB: {}", db_err);
                }
            }
            println!("[ROUTE] Intent rejection: {}", e);
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "message": format!(
                            "Intent extraction failed: {}. Supported patterns: 'Q[1-4] YYYY [table]', '[table] spend YYYY'.",
                            e
                        ),
                        "type": "zemtik_intent_rejection"
                    }
                })),
            ).into_response());
        }
    };

    let route = router::decide_route(&intent_result, schema);

    match route {
        Route::FastLane => {
            handle_fast_lane(state, body, api_key, request_hash, prompt_hash, intent_result, total_start).await
        }
        Route::ZkSlowLane => {
            handle_zk_slow_lane(state, body, headers, api_key, request_hash, prompt_hash, intent_result, total_start).await
        }
    }
}

/// Handle a FastLane request: DB sum → attestation → synthetic evidence response.
async fn handle_fast_lane(
    state: Arc<ProxyState>,
    mut body: Value,
    api_key: String,
    request_hash: String,
    prompt_hash: String,
    intent_result: crate::types::IntentResult,
    total_start: Instant,
) -> Result<Response, ProxyError> {
    println!(
        "[FAST] FastLane route → table='{}' start={} end={}",
        intent_result.table, intent_result.start_unix_secs, intent_result.end_unix_secs
    );

    let category_name = intent_result.category_name.clone();
    let start = intent_result.start_unix_secs;
    let end = intent_result.end_unix_secs;
    let key_bytes = state.signing_key_bytes.clone();
    let schema_config_hash = state.schema_config_hash.clone();

    // Run sum + attestation in a blocking thread:
    //  - rusqlite Connection is !Send, cannot cross await boundaries
    //  - std::sync::MutexGuard is !Send, cannot be moved into spawn_blocking directly
    //  - Clone Arc<ProxyState> and lock inside the blocking thread
    let state2 = Arc::clone(&state);
    let category_name_blocking = category_name.clone();
    let engine_result = tokio::task::spawn_blocking(move || {
        let guard = state2.ledger_db
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let signing_key = db::PrivateKey::import(key_bytes)
            .map_err(|e| anyhow::anyhow!("import signing key: {}", e))?;
        Ok::<EngineResult, anyhow::Error>(
            engine_fast::run_fast_lane(&guard, &signing_key, &category_name_blocking, start, end)
        )
    })
    .await
    .map_err(|e| ProxyError::Internal(anyhow::anyhow!("spawn_blocking join: {}", e)))?
    .map_err(ProxyError::Internal)?;

    let fl = match engine_result {
        EngineResult::Ok(r) => r,
        EngineResult::DbError(e) => {
            return Err(ProxyError::Internal(anyhow::anyhow!("FastLane DB error: {}", e)));
        }
        EngineResult::SignError(e) => {
            return Err(ProxyError::Internal(anyhow::anyhow!("FastLane sign error: {}", e)));
        }
    };

    let receipt_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();

    // Build the financial payload FIRST so we can hash it before building ev and receipt.
    // Hash proves what financial data was transmitted to the LLM.
    let mut payload = serde_json::json!({
        "category": category_name,
        "total_spend_usd": fl.aggregate,
        "row_count": fl.row_count,
        "data_provenance": "ZEMTIK_FAST_LANE_ATTESTATION",
        "raw_data_transmitted": false
    });
    if fl.row_count == 0 {
        payload["note"] = serde_json::Value::String(
            "No rows matched the query criteria.".to_owned()
        );
    }
    let outgoing_hash = hex::encode(Sha256::digest(
        serde_json::to_string(&payload)
            .context("serialize payload for outgoing hash")
            .map_err(ProxyError::Internal)?
            .as_bytes(),
    ));

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
    );

    // Insert receipt — lock synchronously, never hold std::sync::MutexGuard across .await
    {
        let db_guard = state.receipts_db
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = receipts::insert_receipt(
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
            },
        );
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

/// Merge `EvidencePack` + intent summary for API clients (jq-friendly `engine` / `intent`).
fn zemtik_evidence_envelope(ev: &EvidencePack, intent: &IntentResult) -> Result<Value, serde_json::Error> {
    let mut v = serde_json::to_value(ev)?;
    if let Some(obj) = v.as_object_mut() {
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

    let openai_url = format!("{}/v1/chat/completions", OPENAI_BASE_URL);
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
async fn handle_zk_slow_lane(
    state: Arc<ProxyState>,
    mut body: Value,
    _headers: HeaderMap,
    api_key: String,
    request_hash: String,
    prompt_hash: String,
    intent: crate::types::IntentResult,
    total_start: Instant,
) -> Result<Response, ProxyError> {
    println!("[ZK] ZkSlowLane route → starting ZK pipeline");

    let _pipeline_guard = state.pipeline_lock.lock().await;

    let config_clone = Arc::clone(&state.config);
    let key_bytes = state.signing_key_bytes.clone();
    let req_hash = request_hash.clone();
    let prm_hash = prompt_hash.clone();
    let intent_clone = intent.clone();

    let zk = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build local runtime")?;
        rt.block_on(run_zk_pipeline(config_clone, key_bytes, req_hash, prm_hash, intent_clone))
    })
    .await
    .context("ZK blocking task panicked")?
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("timed out") {
            ProxyError::Timeout(msg)
        } else {
            ProxyError::Internal(e)
        }
    })?;

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
        client_id: 123,
        target_category_hash,
        category_name: intent.category_name.clone(),
        start_time: intent.start_unix_secs as u64,
        end_time: intent.end_unix_secs as u64,
    };

    let zk_payload = serde_json::json!({
        "category": intent.category_name,
        "total_spend_usd": zk.aggregate,
        "data_provenance": "ZEMTIK_VALID_ZK_PROOF",
        "raw_data_transmitted": false
    });
    let zk_message = format!(
        "Here is a cryptographically verified financial summary:\n\n{}",
        serde_json::to_string_pretty(&zk_payload)
            .context("serialize ZK payload")
            .map_err(ProxyError::Internal)?
    );

    println!(
        "[ZK] Payload: {{ category: \"{}\", total_spend_usd: {}, provenance: \"ZEMTIK_VALID_ZK_PROOF\" }}",
        intent.category_name, zk.aggregate
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
        .unwrap_or("gpt-5.4-nano")
        .to_owned();
    let openai_url = format!("{}/v1/chat/completions", OPENAI_BASE_URL);

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
    );
    let envelope = zemtik_evidence_envelope(&ev_zk, &intent).map_err(|e| ProxyError::Internal(anyhow::Error::new(e)))?;
    if let Some(obj) = resp_body.as_object_mut() {
        obj.insert("evidence".to_string(), envelope);
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

    if let Some(br) = committed_bundle {
        if let Ok(val) = HeaderValue::from_str(&br.bundle_id) {
            response.headers_mut().insert("x-zemtik-bundle-id", val);
        }
        let verify_url = format!(
            "http://localhost:{}/verify/{}",
            state.config.proxy_port, br.bundle_id
        );
        if let Ok(val) = HeaderValue::from_str(&verify_url) {
            response.headers_mut().insert("x-zemtik-verify-url", val);
        }
        if let Ok(val) = HeaderValue::from_str("zk_slow_lane") {
            response.headers_mut().insert("x-zemtik-engine", val);
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

    let aggregate = readable
        .and_then(|v| v.get("verified_aggregate"))
        .and_then(|v| v.as_u64())
        .map(|n| format!("${}", n))
        .unwrap_or_else(|| "—".to_owned());

    let category = readable
        .and_then(|v| v.get("category_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| "—".to_owned());

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zemtik Receipt — {id}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 700px; margin: 48px auto; padding: 0 24px; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 4px; }}
  .subtitle {{ color: #666; font-size: 0.9rem; margin-bottom: 32px; }}
  .badge {{ display: inline-block; padding: 6px 18px; border-radius: 6px; font-weight: 700;
            font-size: 1.1rem; color: white; background: {badge_color}; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.95rem; }}
  td {{ padding: 10px 0; border-bottom: 1px solid #e5e5e5; vertical-align: top; }}
  td:first-child {{ font-weight: 600; width: 200px; color: #444; }}
  .mono {{ font-family: monospace; font-size: 0.85rem; word-break: break-all; }}
  .footer {{ margin-top: 32px; font-size: 0.8rem; color: #999; }}
  @media print {{ .footer {{ display: none; }} }}
</style>
</head>
<body>
<h1>Zemtik Cryptographic Receipt</h1>
<p class="subtitle">Independent ZK proof verification — no raw data was transmitted to the LLM</p>

<div class="badge">{status_label}</div>

<table>
  <tr><td>Bundle ID</td><td class="mono">{id}</td></tr>
  <tr><td>Verified Aggregate</td><td><strong>{aggregate}</strong></td></tr>
  <tr><td>Category</td><td>{category}</td></tr>
  <tr><td>Proof Status</td><td>{proof_status}</td></tr>
  <tr><td>Circuit Hash</td><td class="mono">{circuit_hash}</td></tr>
  <tr><td>bb Version</td><td class="mono">{bb_version}</td></tr>
  <tr><td>Generated At</td><td>{created_at}</td></tr>
  <tr><td>Raw Rows to LLM</td><td>0</td></tr>
</table>

<p class="footer">
  Verify this receipt independently: <code>zemtik verify &lt;bundle.zip&gt;</code><br>
  Requires only the <code>bb</code> binary (Barretenberg ≥ v4).
</p>
</body>
</html>"#,
        id = html_escape(&r.id),
        badge_color = badge_color,
        status_label = status_label,
        aggregate = aggregate,
        category = category,
        proof_status = html_escape(&r.proof_status),
        circuit_hash = html_escape(&r.circuit_hash),
        bb_version = html_escape(&r.bb_version),
        created_at = html_escape(&r.created_at),
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

/// RAII guard that removes a per-run work directory on drop (success or error).
struct RunDirGuard(std::path::PathBuf);
impl Drop for RunDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the full ZK pipeline (DB → sign → circuit → proof → bundle).
/// Called from within spawn_blocking so DbBackend's !Sync is not an issue.
async fn run_zk_pipeline(
    config: Arc<AppConfig>,
    key_bytes: Vec<u8>,
    request_hash: String,
    prompt_hash: String,
    intent: crate::types::IntentResult,
) -> anyhow::Result<ZkPipelineResult> {
    let target_category_hash = db::poseidon_of_string(&intent.table)
        .map(|fr| db::fr_to_decimal(&fr))
        .map_err(|e| anyhow::anyhow!(
            "cannot hash table key '{}' (key must be ≤93 bytes after lowercasing): {}",
            intent.table, e
        ))?;
    let params = QueryParams {
        client_id: 123,
        target_category_hash,
        category_name: intent.category_name.clone(),
        start_time: intent.start_unix_secs as u64,
        end_time: intent.end_unix_secs as u64,
    };

    let backend = db::init_db().await.context("init DB")?;
    let txns = db::query_transactions(&backend, 123)
        .await
        .context("query transactions")?;
    if txns.len() != 500 {
        anyhow::bail!("Expected 500 transactions, got {}", txns.len());
    }
    let txns_len = txns.len();
    let batch_count = txns_len / db::BATCH_SIZE;
    println!("[ZK] Loaded {} transactions ({} batches)", txns_len, batch_count);

    let key = db::PrivateKey::import(key_bytes)
        .map_err(|e| anyhow::anyhow!("import signing key: {}", e))?;
    let batches = db::sign_transaction_batches(&txns, &key).context("sign batches")?;
    println!("[ZK] Signed {} batches with BabyJubJub EdDSA", batch_count);

    prover::generate_batched_prover_toml(&batches, &params, &config.circuit_dir)
        .context("write Prover.toml")?;

    let circuit_json = config.circuit_dir.join("target/zemtik_circuit.json");
    if !circuit_json.exists() {
        println!("[ZK] Compiling circuit (first run, ~10s)...");
        prover::compile_circuit(&config.circuit_dir).context("compile circuit")?;
    }

    println!("[ZK] Executing circuit (EdDSA verification + aggregation)...");
    let circuit_exec_start = Instant::now();
    let hex_output = prover::execute_circuit(&config.circuit_dir).context("execute circuit")?;
    let circuit_execution_secs = circuit_exec_start.elapsed().as_secs_f32();
    let aggregate = prover::hex_output_to_u64(&hex_output).context("parse aggregate")?;

    println!("[ZK] Generating UltraHonk proof...");
    let run_dir = prover::prepare_run_dir(&config.runs_dir, &config.circuit_dir)
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

    // Compute outgoing_prompt_hash: SHA-256 of the ZK payload that will be sent to LLM.
    // Done here (not in handle_zk_slow_lane) because aggregate is only available inside
    // run_zk_pipeline — the outer handler doesn't have it until ZkPipelineResult returns.
    let zk_payload_for_hash = serde_json::json!({
        "category": intent.category_name,
        "total_spend_usd": aggregate,
        "data_provenance": "ZEMTIK_VALID_ZK_PROOF",
        "raw_data_transmitted": false
    });
    let outgoing_prompt_hash_str = serde_json::to_string(&zk_payload_for_hash)
        .context("serialize ZK payload for outgoing hash")?;
    let outgoing_prompt_hash = hex::encode(Sha256::digest(outgoing_prompt_hash_str.as_bytes()));

    // Generate bundle while run_dir is still present (guard cleans it up after)
    let bundle_result = if fully_verifiable {
        match bundle::generate_bundle(
            &params,
            aggregate,
            proof_status,
            &first_sig,
            Some(&request_hash),
            Some(&prompt_hash),
            Some(&outgoing_prompt_hash),
            &run_dir,
            &config.circuit_dir,
            &config.receipts_dir,
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
    // If fully_verifiable=false (no proof file, nargo-execute path), the receipt
    // should not assert a commitment that has no corresponding artifact.
    let committed_hash = if fully_verifiable {
        Some(outgoing_prompt_hash)
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
    })
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

// ---------------------------------------------------------------------------
// Error type: typed variants for 500 (Internal) and 504 (Timeout)
// ---------------------------------------------------------------------------

enum ProxyError {
    Internal(anyhow::Error),
    Timeout(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        match self {
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
                            "message": format!("Zemtik ZK pipeline error: {}", e),
                            "type": "zemtik_pipeline_error"
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
}
