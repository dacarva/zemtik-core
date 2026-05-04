use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::Value;

use crate::anonymizer::Vault;
use crate::intent::IntentError;
use crate::receipts;
use super::super::state::ProxyState;
use super::super::ProxyError;
use super::super::stream_openai_passthrough;

/// Handle a GeneralLane request: forward non-data queries to OpenAI with a receipt and
/// zemtik_meta metadata block. Supports both streaming (SSE passthrough) and non-streaming.
///
/// Called when ZEMTIK_GENERAL_PASSTHROUGH=1 and intent extraction fails to match a table.
/// `intent_err`: the original IntentError that triggered the GeneralLane route; None for
/// the rare defensive GeneralLane arm from the happy-path route match (should not occur).
#[allow(clippy::too_many_arguments)]
pub(in crate::proxy) async fn handle_general_lane(
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
    let receipt_id = uuid::Uuid::new_v4().to_string();

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

            // Clone data needed for the DB write before dropping the window lock.
            let now_str = Utc::now().to_rfc3339();
            let receipt_id_rl = receipt_id.clone();
            let prompt_hash_rl = prompt_hash.clone();
            let llm_provider_rl = state.config.llm_provider.clone();
            // Drop the window lock before the DB write — holding it across a mutex
            // acquisition serializes all GeneralLane requests on the 429 path.
            drop(window);

            // Write a receipt so rate-limited requests appear in audit trail
            // and general_queries_today counts them.
            let db_guard = state.receipts_db.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = receipts::insert_receipt(&db_guard, &receipts::Receipt {
                id: receipt_id_rl.clone(),
                bundle_path: String::new(),
                proof_status: receipts::PROOF_STATUS_GENERAL_LANE_RATE_LIMITED.to_owned(),
                circuit_hash: String::new(),
                bb_version: String::new(),
                prompt_hash: prompt_hash_rl.clone(),
                request_hash: prompt_hash_rl,
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
                llm_provider: Some(llm_provider_rl),
            }) {
                eprintln!("[GENERAL_LANE] Warning: failed to write rate-limit receipt {}: {}", receipt_id_rl, e);
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

    // Resolve provider, endpoint, and model from config + request body.
    let provider = state.config.llm_provider.clone();
    let endpoint = if provider == "anthropic" {
        state.config.anthropic_base_url.clone()
    } else if provider == "gemini" {
        state.config.gemini_base_url.clone()
    } else {
        state.config.openai_base_url.clone()
    };
    let config_model = if provider == "anthropic" {
        state.config.anthropic_model.clone()
    } else if provider == "gemini" {
        state.config.gemini_model.clone()
    } else {
        state.config.openai_model.clone()
    };
    // Use model from request body if present (client may override); fall back to config default.
    let request_model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or(&config_model)
        .to_owned();

    let mut zemtik_meta = serde_json::json!({
        "engine_used": "general_lane",
        "zk_coverage": "none",
        "reason": reason,
        "receipt_id": receipt_id,
        "provider": provider,
        // endpoint is intentionally omitted: it is server-side config that may
        // contain internal hostnames, Azure resource names, or credentials as
        // query parameters. Persisted to evidence_json (DB/verify) only.
        "model": request_model,
    });
    let meta_header_val = urlencoding::encode(&zemtik_meta.to_string()).into_owned();

    if is_streaming {
        // Anthropic and Gemini streaming not supported in v1. Return 501 so clients
        // get a clear error instead of an unparseable response.
        if state.config.llm_provider == "anthropic" || state.config.llm_provider == "gemini" {
            return Ok((
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({
                    "error": {
                        "type": "streaming_not_supported",
                        "code": "StreamingUnsupported",
                        "message": "Streaming is not supported with llm_provider=anthropic or gemini in this version. Set stream: false."
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

    // Extract _zemtik_resolved_model from AnthropicBackend and inject into zemtik_meta.
    // Also update the "model" field so the evidence pack reflects the actual model used,
    // not the config default (Anthropic may resolve an alias like "claude-sonnet-4-6-20251101").
    if let Some(obj) = resp_body.as_object_mut() {
        if let Some(resolved) = obj.remove("_zemtik_resolved_model") {
            zemtik_meta["model"] = resolved.clone();
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

    // If the vault is empty but the prompt already contains [[Z:...]] tokens, the caller
    // pre-anonymized the text before sending (e.g. zemtik-app client-side anonymization).
    // Count unique tokens so the stored evidence_json and /verify page reflect the real
    // entity count instead of 0.
    let prior_token_count: usize = if vault.as_ref().is_none_or(|v| v.is_empty()) && !prompt.is_empty() {
        // Static regex — compiled once, safe to call on every request.
        static TOKEN_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(r"\[\[Z:[0-9a-f]{4}:\d+\]\]").expect("valid token regex")
        });
        TOKEN_RE.find_iter(&prompt)
            .map(|m| m.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
    } else {
        0
    };

    // Augment zemtik_meta with anonymizer stats (entities, dropped tokens)
    if let Some(ref meta) = anon_meta {
        let (dropped, injected) = general_lane_token_counts;
        // Use prior_token_count when the sidecar found 0 entities on pre-tokenized text.
        let effective_entities = if prior_token_count > 0 { prior_token_count } else { meta.entities_found };
        let mut anon_block = serde_json::json!({
            "entities_found": effective_entities,
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
            "provider": zemtik_meta.get("provider"),
            "endpoint": &endpoint,  // server-side only — not in client-visible zemtik_meta
            "model": zemtik_meta.get("model"),
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
        obj.insert("zemtik_meta".to_string(), zemtik_meta.clone());
    }

    // Recompute after all zemtik_meta mutations (resolved_model, anonymizer) are applied.
    let meta_header_val = urlencoding::encode(&zemtik_meta.to_string()).into_owned();

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
