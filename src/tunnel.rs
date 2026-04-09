//! Tunnel mode — transparent verification proxy for pilot customers.
//!
//! FORK 1: Forward the original request to OpenAI untouched; return response immediately.
//! FORK 2: Run ZK verification pipeline in background; write audit record with diff.
//!
//! Cardinal rules:
//! - No zemtik error ever reaches the client. FORK 2 is fully isolated.
//! - FORK 1 oneshot always sends: Some(data) on success, None on FORK 1 error.
//! - Semaphore permit is RAII-scoped — always released regardless of exit path.
//! - All SQLite access in sync scopes, never across .await.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Json};
use bytes::Bytes;
use chrono::Utc;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::config::TableConfig;
use crate::intent;
use crate::proxy::{ProxyState, run_fast_lane_engine, run_zk_pipeline, run_avg_pipeline};
use crate::receipts::{insert_tunnel_audit, query_tunnel_audits, tunnel_summary, TunnelAuditFilters};
use crate::router;
use crate::types::{IntentResult, OriginalResponseData, Route, TunnelAuditRecord, TunnelMatchStatus};
use crate::config::AggFn;

// ---------------------------------------------------------------------------
// Main tunnel handler — POST /v1/chat/completions
// ---------------------------------------------------------------------------

pub(crate) async fn handle_tunnel(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let total_start = Instant::now();

    // Parse body as JSON Value (keep original bytes for forwarding).
    let body_value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": {"message": format!("Invalid JSON: {}", e), "type": "invalid_request_error"}})),
            ).into_response();
        }
    };

    let is_streaming = body_value.get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Compute hashes for audit.
    let request_hash = hex::encode(Sha256::digest(&body));
    let prompt_hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&body_value["messages"]).unwrap_or_default(),
    ));

    // Extract last user message for intent extraction.
    let prompt = extract_last_user_message(&body_value);

    // Resolve the model used by the customer (for audit).
    let tunnel_model = body_value.get("model")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    // Resolve API key for FORK 1 (customer's key).
    let fork1_api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_owned())
        .or_else(|| std::env::var("OPENAI_API_KEY").ok())
        .or_else(|| state.config.openai_api_key.clone())
        .unwrap_or_default();

    // Generate audit ID here so it can be injected into the response header before FORK 2 runs.
    let audit_id = Uuid::new_v4().to_string();

    // Oneshot channel: FORK 1 sends OriginalResponseData to FORK 2 (or None on error).
    // original_tx stays in main thread; original_rx is moved to FORK 2.
    let (original_tx, original_rx) = oneshot::channel::<Option<OriginalResponseData>>();

    // --- FORK 2: try to acquire semaphore permit (non-blocking) ---
    let fork2_verified = match state.tunnel_semaphore
        .as_ref()
        .and_then(|sem| Arc::clone(sem).try_acquire_owned().ok())
    {
        Some(permit) => {
            let state2 = Arc::clone(&state);
            let prompt2 = prompt.clone();
            let request_hash2 = request_hash.clone();
            let prompt_hash2 = prompt_hash.clone();
            let tunnel_model2 = tunnel_model.clone();
            let total_start2 = total_start;
            let audit_id2 = audit_id.clone();
            tokio::spawn(async move {
                let _permit = permit; // RAII: released when closure exits in any branch
                let timeout = Duration::from_secs(state2.config.tunnel_timeout_secs);
                match tokio::time::timeout(
                    timeout,
                    run_fork2_pipeline(state2, audit_id2, prompt2, request_hash2, prompt_hash2, original_rx, tunnel_model2, total_start2),
                ).await {
                    Ok(()) => {}
                    Err(_elapsed) => {
                        eprintln!("[TUNNEL] FORK 2 timed out after {}s", timeout.as_secs());
                    }
                }
            });
            true
        }
        None => {
            // Semaphore exhausted: drop receiver, increment counter, write backpressure audit record.
            drop(original_rx);
            state.backpressure_count.fetch_add(1, Ordering::Relaxed);
            let state_bp = Arc::clone(&state);
            let audit_id_bp = audit_id.clone();
            let request_hash_bp = request_hash.clone();
            let prompt_hash_bp = prompt_hash.clone();
            let tunnel_model_bp = tunnel_model.clone();
            tokio::spawn(async move {
                write_audit_record_simple(
                    &state_bp, &audit_id_bp, &Utc::now().to_rfc3339(),
                    &request_hash_bp, &prompt_hash_bp,
                    TunnelMatchStatus::Backpressure,
                    None, None, None, None, None, None,
                    false, None, None, None, None, tunnel_model_bp, total_start,
                );
            });
            false
        }
    };

    // --- FORK 1: forward original request to OpenAI ---
    let fork1_start = Instant::now();

    let client_response = if is_streaming {
        // Streaming: forward_streaming owns original_tx and sends OriginalResponseData to
        // FORK 2 via the oneshot after the SSE stream ends (in a background collector task).
        forward_streaming(&state, &fork1_api_key, body, fork1_start, original_tx).await
    } else {
        let (response, original_data) = forward_non_streaming(&state, &fork1_api_key, body, fork1_start).await;
        // Non-streaming: data is available immediately; send to FORK 2 now.
        let _ = original_tx.send(original_data);
        response
    };

    // Inject tunnel headers into the response.
    let mut response = client_response;
    let headers_mut = response.headers_mut();
    headers_mut.insert(
        "x-zemtik-mode",
        HeaderValue::from_static("tunnel"),
    );
    headers_mut.insert(
        "x-zemtik-verified",
        HeaderValue::from_static(if fork2_verified { "true" } else { "false" }),
    );
    if let Ok(val) = HeaderValue::from_str(&audit_id) {
        headers_mut.insert("x-zemtik-receipt-id", val);
    }

    response
}

// ---------------------------------------------------------------------------
// Forward helpers
// ---------------------------------------------------------------------------

/// Forward non-streaming request. Returns the client Response and the original data for FORK 2.
async fn forward_non_streaming(
    state: &Arc<ProxyState>,
    api_key: &str,
    body: Bytes,
    start: Instant,
) -> (Response, Option<OriginalResponseData>) {
    let openai_url = format!("{}/v1/chat/completions", state.openai_base_url);

    let resp = state.http_client
        .post(&openai_url)
        .bearer_auth(api_key)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let status = r.status();
            let resp_headers = r.headers().clone();
            let latency_ms = start.elapsed().as_millis() as u64;
            match r.bytes().await {
                Ok(resp_bytes) => {
                    let response_body = String::from_utf8_lossy(&resp_bytes).into_owned();
                    let response_body_hash = hex::encode(Sha256::digest(&resp_bytes));
                    let original_data = OriginalResponseData {
                        status_code: status.as_u16(),
                        response_body,
                        response_body_hash,
                        latency_ms,
                    };

                    let mut builder = Response::builder().status(status);
                    for (k, v) in resp_headers.iter() {
                        if !is_hop_by_hop(k.as_str()) {
                            builder = builder.header(k, v);
                        }
                    }
                    let response = builder
                        .body(Body::from(resp_bytes))
                        .unwrap_or_else(|_| Response::new(Body::empty()));

                    (response, Some(original_data))
                }
                Err(e) => {
                    eprintln!("[TUNNEL] FORK 1: failed to read response body: {}", e);
                    let response = Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(format!(r#"{{"error":{{"message":"{}","type":"upstream_error"}}}}"#, e)))
                        .unwrap();
                    (response, None)
                }
            }
        }
        Err(e) => {
            eprintln!("[TUNNEL] FORK 1: OpenAI request failed: {}", e);
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!(r#"{{"error":{{"message":"{}","type":"upstream_error"}}}}"#, e)))
                .unwrap();
            (response, None)
        }
    }
}

/// Forward streaming request (stream:true). Tees SSE chunks to client + accumulator.
/// Returns the streaming Response immediately. Sends OriginalResponseData to FORK 2 via
/// the oneshot sender after the stream ends (in a background collector task).
async fn forward_streaming(
    state: &Arc<ProxyState>,
    api_key: &str,
    body: Bytes,
    start: Instant,
    fork2_tx: oneshot::Sender<Option<OriginalResponseData>>,
) -> Response {
    let openai_url = format!("{}/v1/chat/completions", state.openai_base_url);

    let resp = match state.http_client
        .post(&openai_url)
        .bearer_auth(api_key)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[TUNNEL] FORK 1 streaming: OpenAI request failed: {}", e);
            let _ = fork2_tx.send(None);
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!(r#"{{"error":{{"message":"{}","type":"upstream_error"}}}}"#, e)))
                .unwrap();
            return response;
        }
    };

    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let latency_ms = start.elapsed().as_millis() as u64;

    // Bounded channel: client consumes chunks in real-time.
    let (chunk_tx, chunk_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1024);
    // Accumulator for FORK 2.
    let (accum_tx, accum_rx) = tokio::sync::mpsc::channel::<Bytes>(1024);

    // Spawn tee task: reads from OpenAI stream, sends to both channels.
    tokio::spawn(async move {
        const MAX_BYTES: usize = 1_048_576; // 1 MB cap
        let mut byte_stream = resp.bytes_stream();
        let mut total_bytes = 0usize;
        let mut overflow = false;

        while let Some(chunk_result) = byte_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    total_bytes += chunk.len();
                    if total_bytes <= MAX_BYTES {
                        let _ = accum_tx.send(chunk.clone()).await;
                    } else if !overflow {
                        overflow = true;
                        eprintln!("[TUNNEL] SSE accumulator overflow (>1MB); FORK 2 will use partial content");
                    }
                    let _ = chunk_tx.send(Ok(chunk)).await;
                }
                Err(e) => {
                    let _ = chunk_tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    break;
                }
            }
        }
        // accum_tx drops here, closing accum_rx for the collector task.
    });

    // Spawn SSE collector: drains accumulator AFTER stream ends, then sends OriginalResponseData
    // to FORK 2 via the oneshot sender. This task outlives the streaming response — FORK 2
    // receives the full accumulated SSE content once the client stream is done.
    tokio::spawn(async move {
        let mut accumulated: Vec<u8> = Vec::new();
        let mut accum_rx = accum_rx;
        while let Some(chunk) = accum_rx.recv().await {
            accumulated.extend_from_slice(&chunk);
        }
        let content = extract_content_from_sse(&accumulated);
        let response_body_hash = hex::encode(Sha256::digest(&accumulated));
        let data = OriginalResponseData {
            status_code: status.as_u16(),
            response_body: content,
            response_body_hash,
            latency_ms,
        };
        let _ = fork2_tx.send(Some(data));
    });

    // Build streaming response from chunk channel and return immediately.
    let stream = ReceiverStream::new(chunk_rx);
    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        if !is_hop_by_hop(k.as_str()) {
            builder = builder.header(k, v);
        }
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

// ---------------------------------------------------------------------------
// FORK 2 — background verification pipeline
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_fork2_pipeline(
    state: Arc<ProxyState>,
    audit_id: String,
    prompt: String,
    request_hash: String,
    prompt_hash: String,
    original_rx: oneshot::Receiver<Option<OriginalResponseData>>,
    tunnel_model: Option<String>,
    total_start: Instant,
) {
    let created_at = Utc::now().to_rfc3339();

    // Step 1: Intent extraction.
    let schema = match state.config.schema_config.as_ref() {
        Some(s) => s.clone(),
        None => {
            eprintln!("[TUNNEL] FORK 2: schema_config missing");
            write_audit_error(&state, &audit_id, &created_at, &request_hash, &prompt_hash,
                tunnel_model, None, "schema_config missing", total_start, original_rx).await;
            return;
        }
    };

    let threshold = state.config.intent_confidence_threshold;
    let backend = Arc::clone(&state.intent_backend);
    let prompt_clone = prompt.clone();
    let schema_clone = schema.clone();

    let intent_result: Result<IntentResult, String> = tokio::task::spawn_blocking(move || {
        intent::extract_intent_with_backend(
            &prompt_clone,
            &schema_clone,
            backend.as_ref(),
            threshold,
        ).map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(format!("spawn_blocking panic: {}", e)));

    let intent = match intent_result {
        Ok(i) => i,
        Err(e) => {
            eprintln!("[TUNNEL] FORK 2: intent extraction failed: {}", e);
            let original = original_rx.await.ok().flatten();
            write_audit_record_simple(
                &state, &audit_id, &created_at, &request_hash, &prompt_hash,
                TunnelMatchStatus::Unmatched, None, None, None, None, None,
                None, false, None, None, original.as_ref(), Some(e.to_string()),
                tunnel_model, total_start,
            );
            return;
        }
    };

    let route = router::decide_route(&intent, &schema);
    let effective_client_id = schema.tables
        .get(&intent.table)
        .and_then(|tc| tc.client_id)
        .unwrap_or(state.config.client_id);

    // Step 2: Run ZK engine.
    let engine_start = Instant::now();
    let (zemtik_aggregate, zemtik_row_count, zemtik_engine, engine_err, table_config_opt) =
        match route {
            Route::FastLane => {
                match run_fast_lane_engine(&state, &intent, effective_client_id).await {
                    Ok(out) => {
                        let agg = out.result.aggregate;
                        let row_count = out.result.row_count;
                        let tc = out.table_config.clone();
                        (Some(agg), Some(row_count), Some("fast_lane".to_owned()), None, Some(tc))
                    }
                    Err(e) => (None, None, None, Some(format!("FastLane error: {:?}", e)), None)
                }
            }
            Route::ZkSlowLane => {
                let agg_fn = schema.tables.get(&intent.table)
                    .map(|tc| tc.agg_fn.clone())
                    .unwrap_or(AggFn::Sum);

                let config = Arc::clone(&state.config);
                let key_bytes = state.signing_key_bytes.clone();
                let rh = request_hash.clone();
                let ph = prompt_hash.clone();
                let intent_c = intent.clone();
                let agg_fn_c = agg_fn.clone();

                // Wrap in spawn_blocking + local runtime, same as handle_zk_slow_lane.
                // run_zk_pipeline creates DbBackend with RefCell (!Send), so it must not
                // be held across tokio task boundaries in a tokio::spawn future.
                let pipeline_result = if agg_fn == AggFn::Avg {
                    let _avg_lock = state.avg_pipeline_lock.lock().await;
                    let state2 = Arc::clone(&state);
                    tokio::task::spawn_blocking(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|e| anyhow::anyhow!("build local runtime: {}", e))?;
                        rt.block_on(run_avg_pipeline(state2, rh, ph, intent_c, effective_client_id))
                    })
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("spawn_blocking join: {}", e)))
                } else {
                    let _lock = if let Some(pl) = state.pipeline_locks.get(&agg_fn) {
                        Some(pl.lock().await)
                    } else {
                        None
                    };
                    tokio::task::spawn_blocking(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|e| anyhow::anyhow!("build local runtime: {}", e))?;
                        rt.block_on(run_zk_pipeline(config, key_bytes, rh, ph, intent_c, effective_client_id, agg_fn_c))
                    })
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("spawn_blocking join: {}", e)))
                };

                match pipeline_result {
                    Ok(zk) => {
                        let agg = zk.aggregate as i64;
                        let row_count = zk.actual_row_count;
                        let tc = schema.tables.get(&intent.table).cloned();
                        (Some(agg), Some(row_count), Some("zk_slow_lane".to_owned()), None, tc)
                    }
                    Err(e) => (None, None, None, Some(format!("ZK error: {}", e)), None)
                }
            }
        };

    let zemtik_latency_ms = engine_start.elapsed().as_millis() as u64;

    if let Some(ref err) = engine_err {
        eprintln!("[TUNNEL] FORK 2: engine error: {}", err);
    }

    // Step 3: Await original response from FORK 1 (with remaining timeout).
    let original = original_rx.await.ok().flatten();

    // Step 4: Diff computation.
    let (diff_detected, diff_summary, diff_details) = if let (Some(orig), Some(agg)) = (original.as_ref(), zemtik_aggregate) {
        let tolerance = table_config_opt.as_ref()
            .and_then(|tc: &TableConfig| tc.tunnel_diff_tolerance)
            .unwrap_or(0.01);
        compute_diff(&orig.response_body, agg, tolerance)
    } else if engine_err.is_some() {
        (false, None, None)
    } else {
        (false, Some("no_original_response".to_owned()), None)
    };

    let match_status = if engine_err.is_some() {
        TunnelMatchStatus::Error
    } else if diff_detected {
        TunnelMatchStatus::Diverged
    } else {
        TunnelMatchStatus::Matched
    };

    // Log matched/diverged requests.
    if matches!(match_status, TunnelMatchStatus::Matched | TunnelMatchStatus::Diverged) {
        println!(
            "[TUNNEL] {}: {} | route: {} | diff: {}",
            match_status.as_str(),
            intent.table,
            zemtik_engine.as_deref().unwrap_or("unknown"),
            diff_summary.as_deref().unwrap_or("-"),
        );
    }

    // Step 5: Write audit record.
    write_audit_record_simple(
        &state, &audit_id, &created_at, &request_hash, &prompt_hash,
        match_status,
        Some(&intent),
        zemtik_aggregate,
        zemtik_row_count,
        zemtik_engine.as_deref(),
        Some(zemtik_latency_ms),
        table_config_opt.as_ref().and_then(|tc| tc.agg_fn.circuit_artifact_name()).map(|s| s.to_owned()),
        diff_detected,
        diff_summary.as_deref(),
        diff_details.as_deref(),
        original.as_ref(),
        engine_err,
        tunnel_model,
        total_start,
    );
}

// ---------------------------------------------------------------------------
// Diff computation
// ---------------------------------------------------------------------------

/// Extract numbers from text and compare pairwise against zemtik_aggregate.
/// Returns (diff_detected, diff_summary, diff_details_json).
static NUMERIC_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\$?(\d{1,3}(?:,\d{3})*(?:\.\d+)?|\d+(?:\.\d+)?)").unwrap()
});

fn compute_diff(
    original_body: &str,
    zemtik_aggregate: i64,
    tolerance: f64,
) -> (bool, Option<String>, Option<String>) {
    // Extract all numbers from response text.
    // Pattern matches: $1,234.56  1234567  1,234  etc.
    let re = &*NUMERIC_RE;
    let numbers: Vec<f64> = re.captures_iter(original_body)
        .filter_map(|c| c.get(1))
        .filter_map(|m| {
            let s = m.as_str().replace(',', "");
            s.parse::<f64>().ok()
        })
        .collect();

    if numbers.is_empty() {
        return (false, Some("no_numerical_data".to_owned()), None);
    }

    let zemtik_val = zemtik_aggregate as f64;

    // Find the number in the response closest to zemtik_aggregate.
    let best_match = numbers.iter().copied()
        .min_by(|a, b| {
            let diff_a = (a - zemtik_val).abs();
            let diff_b = (b - zemtik_val).abs();
            diff_a.partial_cmp(&diff_b).unwrap_or(std::cmp::Ordering::Equal)
        });

    match best_match {
        Some(orig_val) if orig_val.abs() > f64::EPSILON => {
            let pct_diff = (zemtik_val - orig_val).abs() / orig_val.abs();
            let details = serde_json::json!({
                "zemtik_aggregate": zemtik_aggregate,
                "closest_original": orig_val,
                "pct_diff": pct_diff,
                "tolerance": tolerance,
            }).to_string();
            if pct_diff <= tolerance {
                (false, Some("within_tolerance".to_owned()), Some(details))
            } else {
                let summary = format!(
                    "numerical_divergence: {} vs {} ({:.2}% diff)",
                    zemtik_aggregate, orig_val, pct_diff * 100.0
                );
                (true, Some(summary), Some(details))
            }
        }
        Some(_) => {
            // orig_val is ~0 and zemtik_aggregate is non-zero → divergence
            if zemtik_aggregate == 0 {
                (false, Some("within_tolerance".to_owned()), None)
            } else {
                (true, Some(format!("numerical_divergence: {} vs 0", zemtik_aggregate)), None)
            }
        }
        None => (false, Some("no_numerical_data".to_owned()), None),
    }
}

// ---------------------------------------------------------------------------
// SSE content extraction
// ---------------------------------------------------------------------------

fn extract_content_from_sse(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut content = String::new();
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            if data == "[DONE]" { continue; }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
                if let Some(delta) = v.get("choices")
                    .and_then(|c| c.get(0))
                    .and_then(|c| c.get("delta"))
                    .and_then(|d| d.get("content"))
                    .and_then(|c| c.as_str())
                {
                    content.push_str(delta);
                }
            }
        }
    }
    content
}

// ---------------------------------------------------------------------------
// Audit write helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn write_audit_record_simple(
    state: &Arc<ProxyState>,
    id: &str,
    created_at: &str,
    request_hash: &str,
    prompt_hash: &str,
    match_status: TunnelMatchStatus,
    intent: Option<&IntentResult>,
    zemtik_aggregate: Option<i64>,
    zemtik_row_count: Option<usize>,
    zemtik_engine: Option<&str>,
    zemtik_latency_ms: Option<u64>,
    matched_agg_fn: Option<String>,
    diff_detected: bool,
    diff_summary: Option<&str>,
    diff_details: Option<&str>,
    original: Option<&OriginalResponseData>,
    error_message: Option<String>,
    tunnel_model: Option<String>,
    total_start: Instant,
) {
    let (orig_status, orig_hash, orig_latency, orig_preview) = match original {
        Some(o) => (
            o.status_code,
            o.response_body_hash.clone(),
            o.latency_ms,
            Some(o.response_body.chars().take(500).collect::<String>()),
        ),
        None => (0u16, String::new(), 0u64, None),
    };

    let record = TunnelAuditRecord {
        id: id.to_owned(),
        receipt_id: None,
        created_at: created_at.to_owned(),
        match_status: match_status.as_str().to_owned(),
        matched_table: intent.map(|i| i.table.clone()),
        matched_agg_fn,
        original_status_code: orig_status,
        original_response_body_hash: orig_hash,
        original_latency_ms: orig_latency,
        zemtik_aggregate,
        zemtik_row_count,
        zemtik_engine: zemtik_engine.map(|s| s.to_owned()),
        zemtik_latency_ms,
        diff_detected,
        diff_summary: diff_summary.map(|s| s.to_owned()),
        diff_details: diff_details.map(|s| s.to_owned()),
        original_response_preview: orig_preview,
        zemtik_response_preview: None,
        error_message,
        request_hash: request_hash.to_owned(),
        prompt_hash: prompt_hash.to_owned(),
        intent_confidence: intent.map(|i| i.confidence),
        tunnel_model,
    };

    if let Some(ref audit_db) = state.tunnel_audit_db {
        let guard = audit_db.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = insert_tunnel_audit(&guard, &record) {
            eprintln!("[TUNNEL] FORK 2: failed to write audit record: {}", e);
        }
    }

    let _ = total_start; // used for timing if needed in future
}

#[allow(clippy::too_many_arguments)]
async fn write_audit_error(
    state: &Arc<ProxyState>,
    id: &str,
    created_at: &str,
    request_hash: &str,
    prompt_hash: &str,
    tunnel_model: Option<String>,
    intent: Option<&IntentResult>,
    error: &str,
    total_start: Instant,
    original_rx: oneshot::Receiver<Option<OriginalResponseData>>,
) {
    let original = original_rx.await.ok().flatten();
    write_audit_record_simple(
        state, id, created_at, request_hash, prompt_hash,
        TunnelMatchStatus::Error, intent, None, None, None, None, None,
        false, None, None, original.as_ref(), Some(error.to_owned()), tunnel_model, total_start,
    );
}

// ---------------------------------------------------------------------------
// Dashboard endpoints
// ---------------------------------------------------------------------------

pub(crate) async fn handle_audit(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = check_dashboard_auth(&state, &headers) {
        return *resp;
    }

    let filters = TunnelAuditFilters {
        match_status: params.get("match_status").cloned(),
        diff_detected: params.get("diff_detected").and_then(|v| v.parse().ok()),
        from: params.get("from").cloned(),
        to: params.get("to").cloned(),
        table: params.get("table").cloned(),
        limit: params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100),
        offset: params.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0),
    };

    match &state.tunnel_audit_db {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "tunnel audit DB not initialized"})),
        ).into_response(),
        Some(db) => {
            let guard = db.lock().unwrap_or_else(|e| e.into_inner());
            match query_tunnel_audits(&guard, &filters) {
                Ok(records) => {
                    let count = records.len();
                    Json(serde_json::json!({
                        "records": records,
                        "count": count,
                    })).into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("{}", e)})),
                ).into_response(),
            }
        }
    }
}

pub(crate) async fn handle_audit_csv(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = check_dashboard_auth(&state, &headers) {
        return *resp;
    }

    let filters = TunnelAuditFilters {
        match_status: params.get("match_status").cloned(),
        diff_detected: params.get("diff_detected").and_then(|v| v.parse().ok()),
        from: params.get("from").cloned(),
        to: params.get("to").cloned(),
        table: params.get("table").cloned(),
        limit: params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100),
        offset: params.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0),
    };

    match &state.tunnel_audit_db {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "tunnel audit DB not initialized"})),
        ).into_response(),
        Some(db) => {
            let guard = db.lock().unwrap_or_else(|e| e.into_inner());
            match query_tunnel_audits(&guard, &filters) {
                Ok(records) => {
                    let mut csv = String::from(
                        "id,created_at,match_status,matched_table,matched_agg_fn,\
                         original_status_code,original_latency_ms,zemtik_aggregate,\
                         zemtik_row_count,zemtik_engine,zemtik_latency_ms,\
                         diff_detected,diff_summary,intent_confidence,tunnel_model\n"
                    );
                    for r in &records {
                        csv.push_str(&format!(
                            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                            csv_escape(&r.id),
                            csv_escape(&r.created_at),
                            csv_escape(&r.match_status),
                            csv_escape(r.matched_table.as_deref().unwrap_or("")),
                            csv_escape(r.matched_agg_fn.as_deref().unwrap_or("")),
                            r.original_status_code,
                            r.original_latency_ms,
                            r.zemtik_aggregate.map(|v| v.to_string()).unwrap_or_default(),
                            r.zemtik_row_count.map(|v| v.to_string()).unwrap_or_default(),
                            csv_escape(r.zemtik_engine.as_deref().unwrap_or("")),
                            r.zemtik_latency_ms.map(|v| v.to_string()).unwrap_or_default(),
                            if r.diff_detected { "1" } else { "0" },
                            csv_escape(r.diff_summary.as_deref().unwrap_or("")),
                            r.intent_confidence.map(|v| format!("{:.4}", v)).unwrap_or_default(),
                            csv_escape(r.tunnel_model.as_deref().unwrap_or("")),
                        ));
                    }
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/csv")
                        .header("content-disposition", "attachment; filename=tunnel_audit.csv")
                        .body(Body::from(csv))
                        .unwrap()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("{}", e)})),
                ).into_response(),
            }
        }
    }
}

pub(crate) async fn handle_summary(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_dashboard_auth(&state, &headers) {
        return *resp;
    }

    match &state.tunnel_audit_db {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "tunnel audit DB not initialized"})),
        ).into_response(),
        Some(db) => {
            let guard = db.lock().unwrap_or_else(|e| e.into_inner());
            match tunnel_summary(&guard) {
                Ok(s) => Json(serde_json::json!({
                    "total_requests": s.total_requests,
                    "matched_rate": s.matched_rate,
                    "diff_rate": s.diff_rate,
                    "avg_zemtik_latency_ms": s.avg_zemtik_latency_ms,
                })).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("{}", e)})),
                ).into_response(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Passthrough handler — /{*path} in tunnel mode
// ---------------------------------------------------------------------------

pub(crate) async fn handle_tunnel_passthrough(
    State(state): State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_url = format!("{}{}", state.openai_base_url, path_and_query);

    let mut req_builder = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
        &target_url,
    );

    // Forward headers (skip hop-by-hop).
    for (key, val) in headers.iter() {
        if !is_hop_by_hop(key.as_str()) {
            req_builder = req_builder.header(key.as_str(), val.as_bytes());
        }
    }

    let resp = match req_builder.body(body.to_vec()).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": {"message": format!("{}", e), "type": "upstream_error"}})),
            ).into_response();
        }
    };

    let status = resp.status();
    let resp_headers = resp.headers().clone();

    let resp_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": {"message": format!("{}", e), "type": "upstream_error"}})),
            ).into_response();
        }
    };

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
    for (k, v) in resp_headers.iter() {
        if !is_hop_by_hop(k.as_str()) {
            builder = builder.header(k, v);
        }
    }
    builder.body(Body::from(resp_bytes)).unwrap_or_else(|_| Response::new(Body::empty()))
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn is_hop_by_hop(header: &str) -> bool {
    matches!(header.to_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" |
        "proxy-authorization" | "te" | "trailer" | "transfer-encoding" |
        "upgrade" | "host"
    )
}

fn check_dashboard_auth(state: &Arc<ProxyState>, headers: &HeaderMap) -> Result<(), Box<Response>> {
    match state.config.dashboard_api_key {
        None => {
            // Deny by default when no key is configured — prevents accidental public exposure of
            // audit records in misconfigured deployments.
            Err(Box::new((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": {"message": "Dashboard API key not configured. Set ZEMTIK_DASHBOARD_API_KEY.", "type": "auth_error"}})),
            ).into_response()))
        }
        Some(ref expected_key) => {
            let provided = headers.get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            if !constant_time_eq::constant_time_eq(provided.as_bytes(), expected_key.as_bytes()) {
                return Err(Box::new((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": {"message": "Unauthorized", "type": "auth_error"}})),
                ).into_response()));
            }
            Ok(())
        }
    }
}

fn csv_escape(s: &str) -> String {
    // Strip leading formula-injection chars (=, +, -, @) to prevent spreadsheet injection.
    let s = s.trim_start_matches(['=', '+', '-', '@']);
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn extract_last_user_message(body: &serde_json::Value) -> String {
    body.get("messages")
        .and_then(|m| m.as_array())
        .and_then(|arr| {
            arr.iter().rev().find(|msg| {
                msg.get("role").and_then(|r| r.as_str()) == Some("user")
            })
        })
        .and_then(|msg| msg.get("content"))
        .map(|c| match c {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(parts) => parts.iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join(" "),
            _ => String::new(),
        })
        .unwrap_or_default()
}
