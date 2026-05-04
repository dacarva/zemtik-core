use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use constant_time_eq::constant_time_eq;
use crate::anonymizer::{build_channel, check_sidecar_health, SidecarHealth};
use crate::proxy::state::ProxyState;
use crate::proxy::ui::{render_verify_page, render_receipts_list, render_not_found};
use crate::proxy::ProxyError;
use crate::receipts;

/// Serve the /verify/:id page — server-rendered HTML receipt.
pub(super) async fn handle_verify(
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
            let readable = read_public_inputs_from_bundle(r.bundle_path.clone()).await;
            Ok(Html(render_verify_page(&r, readable.as_ref())).into_response())
        }
    }
}

async fn read_public_inputs_from_bundle(bundle_path: String) -> Option<serde_json::Value> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&bundle_path).ok()?;
        let mut archive = zip::ZipArchive::new(file).ok()?;
        let mut entry = archive.by_name("public_inputs_readable.json").ok()?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes).ok()?;
        serde_json::from_slice::<serde_json::Value>(&bytes).ok()
    })
    .await
    .ok()
    .flatten()
}

/// Serve the /receipts page — browseable HTML list of all receipts.
pub(super) async fn handle_receipts_list(
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

/// GET /v1/models — returns the configured model as an OpenAI-compatible model list.
/// Gated behind ZEMTIK_PROXY_API_KEY when set (S5). Enables SDK client discovery on init.
pub(super) async fn handle_models(
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
    } else if state.config.llm_provider == "gemini" {
        (state.config.gemini_model.clone(), "google")
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
pub(super) async fn handle_health(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let backend = std::env::var("DB_BACKEND").unwrap_or_default();

    // Step 1: probe DB reachability.
    let db_ok = if backend == "supabase" {
        if let (Some(url), Some(key)) = (
            &state.config.supabase_url,
            &state.config.supabase_service_key,
        ) {
            let probe_url = format!("{}/rest/v1/", url.trim_end_matches('/'));
            // Any HTTP response (even 401/403) means reachable; only network errors or
            // timeout count as down. 3s cap prevents /health from hanging on a slow DB.
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                state.http_client
                    .get(&probe_url)
                    .header("apikey", key.as_str())
                    .header("Authorization", format!("Bearer {}", key))
                    .send(),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
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
        obj.insert("llm_provider".to_string(), serde_json::json!(state.config.llm_provider));
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
            let probe_deadline = Duration::from_millis(500);
            let t0 = std::time::Instant::now();
            let status = match build_channel(&addr, probe_deadline) {
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
pub(super) async fn handle_passthrough() -> impl IntoResponse {
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
pub(super) async fn handle_public_key(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
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
// Anonymize preview endpoint — no LLM call, returns tokenized messages
// ---------------------------------------------------------------------------

pub(super) async fn handle_anonymize_preview(
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
