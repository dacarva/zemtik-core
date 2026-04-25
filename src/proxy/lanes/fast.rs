use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::anonymizer::Vault;
use crate::types::{EngineResult, FastLaneResult, IntentResult};
use crate::{db, engine_fast, evidence, receipts};
use super::super::state::ProxyState;
use super::super::ProxyError;
use super::zemtik_evidence_envelope;

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
        let url = state.config.supabase_url.as_ref()
            .expect("supabase_url must be set when use_supabase_fast_lane() is true");
        let svc_key = state.config.supabase_service_key.as_ref()
            .expect("supabase_service_key must be set when use_supabase_fast_lane() is true");
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
pub(in crate::proxy) async fn handle_fast_lane(
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

/// Replace last user message with FastLane payload and forward to OpenAI.
#[allow(clippy::too_many_arguments)]
pub(in crate::proxy) async fn build_fast_lane_response(
    body: &mut Value,
    payload: Value,
    state: &Arc<ProxyState>,
    api_key: &str,
    receipt_id: &str,
    intent: &IntentResult,
    ev: &crate::types::EvidencePack,
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

    let resp_status = axum::http::StatusCode::from_u16(status_u16_fl).unwrap_or(axum::http::StatusCode::OK);

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
            if let Some(m) = obj.entry("zemtik_meta").or_insert_with(|| serde_json::json!({})).as_object_mut() {
                m.insert("anonymizer".to_string(), serde_json::json!({
                    "entities_found": meta.entities_found,
                    "entity_types": meta.entity_types,
                    "sidecar_used": meta.sidecar_used,
                    "sidecar_ms": meta.sidecar_ms,
                    "dropped_tokens": dropped_fast,
                    "tokens_injected": injected_fast,
                }));
            }
        }
    }

    // Inject resolved_model into zemtik_meta for Anthropic path (D7).
    // zemtik_meta may or may not exist yet (only created above when anon_meta.is_some()).
    if let Some(resolved) = fl_resolved_model {
        if let Some(obj) = resp_body.as_object_mut() {
            if let Some(m) = obj.entry("zemtik_meta").or_insert_with(|| serde_json::json!({})).as_object_mut() {
                m.insert("resolved_model".to_owned(), resolved);
            }
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
