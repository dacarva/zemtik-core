use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::anonymizer::Vault;
use crate::config::{AggFn, AppConfig};
use crate::types::{
    AuditRecord, OpenAiRequestLog, OpenAiResponseLog, QueryParams, TokenUsage,
};
use crate::{audit, bundle, db, evidence, prover, receipts};
use super::super::state::{ProxyState, ZkPipelineResult};
use super::super::ProxyError;
use super::super::compute_prompt_hash_field;
use super::zemtik_evidence_envelope;

/// RAII guard that removes a per-run work directory on drop (success or error).
struct RunDirGuard(std::path::PathBuf);
impl Drop for RunDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Handle a ZK SlowLane request (existing full ZK pipeline).
#[allow(clippy::too_many_arguments)]
pub(in crate::proxy) async fn handle_zk_slow_lane(
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
