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

use crate::types::{
    AuditRecord, OpenAiRequestLog, OpenAiResponseLog, QueryParams, SignatureData, TokenUsage,
};
use crate::{audit, bundle, db, prover, receipts};

const PROXY_PORT: u16 = 4000;
const OPENAI_BASE_URL: &str = "https://api.openai.com";

struct ProxyState {
    http_client: reqwest::Client,
    /// Serializes ZK pipeline executions — the circuit uses shared files in circuit/.
    pipeline_lock: tokio::sync::Mutex<()>,
    /// File-based receipts DB (~/.zemtik/receipts.db), shared across requests.
    receipts_db: tokio::sync::Mutex<Connection>,
}

// Results returned from the blocking ZK pipeline.
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
}

/// Entry point for proxy mode. Starts Axum on localhost:4000.
pub async fn run_proxy() -> anyhow::Result<()> {
    let receipts_conn = receipts::open_receipts_db().context("open receipts DB")?;
    let state = Arc::new(ProxyState {
        http_client: reqwest::Client::new(),
        pipeline_lock: tokio::sync::Mutex::new(()),
        receipts_db: tokio::sync::Mutex::new(receipts_conn),
    });

    let app = Router::new()
        .route("/v1/chat/completions", post(handle_chat_completions))
        .route("/verify/{id}", get(handle_verify))
        .route("/{*path}", any(handle_passthrough))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("127.0.0.1:{}", PROXY_PORT);
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
        PROXY_PORT
    );
    println!("[PROXY] Verify receipts at http://localhost:{}/verify/<bundle-id>", PROXY_PORT);
    println!();

    axum::serve(listener, app).await?;
    Ok(())
}

/// Intercept /v1/chat/completions: run ZK pipeline in a blocking thread
/// (DbBackend is !Sync), replace last user message, forward to OpenAI.
async fn handle_chat_completions(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Result<Response, ProxyError> {
    let total_start = Instant::now();

    // Extract the caller's API key from the Authorization header.
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_owned())
        .or_else(|| std::env::var("OPENAI_API_KEY").ok())
        .ok_or_else(|| {
            ProxyError(anyhow::anyhow!(
                "No Authorization header and OPENAI_API_KEY not set"
            ))
        })?;

    // Compute request_hash and prompt_hash BEFORE spawn_blocking, from the original body.
    let request_hash = hex::encode(Sha256::digest(
        &serde_json::to_vec(&body).context("serialize request body for hashing").map_err(ProxyError)?,
    ));
    let prompt_hash = hex::encode(Sha256::digest(
        &serde_json::to_vec(&body["messages"])
            .context("serialize messages for hashing")
            .map_err(ProxyError)?,
    ));

    println!("[ZK] Request intercepted → starting ZK pipeline");

    // -----------------------------------------------------------------------
    // Acquire pipeline lock — only one ZK pipeline at a time (circuit/ is shared).
    // -----------------------------------------------------------------------
    let _pipeline_guard = state.pipeline_lock.lock().await;

    // -----------------------------------------------------------------------
    // Run ZK pipeline in a blocking thread.
    //
    // DbBackend::Sqlite wraps rusqlite::Connection which is !Sync.
    // &DbBackend is therefore !Send, which prevents holding it across .await
    // in a multi-threaded Axum runtime. We isolate all DB + ZK work in a
    // spawn_blocking call with its own single-threaded Tokio runtime.
    // -----------------------------------------------------------------------
    let zk = tokio::task::spawn_blocking(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build local runtime")?;
        rt.block_on(run_zk_pipeline())
    })
    .await
    .context("ZK blocking task panicked")??;

    println!(
        "[ZK] Verified {} spend = ${} ({:.2}s circuit, proof: {})",
        "AWS Infrastructure", zk.aggregate, zk.circuit_execution_secs, zk.proof_status
    );

    // -----------------------------------------------------------------------
    // Generate proof bundle (if fully verifiable).
    // -----------------------------------------------------------------------
    let params = QueryParams {
        client_id: 123,
        target_category: db::CAT_AWS,
        category_name: "AWS Infrastructure",
        start_time: db::Q1_START,
        end_time: db::Q1_END,
    };

    let bundle_result = if zk.fully_verifiable {
        match bundle::generate_bundle(
            &params,
            zk.aggregate,
            zk.proof_status,
            &zk.first_sig,
            Some(&request_hash),
            Some(&prompt_hash),
        ) {
            Ok(br) => {
                println!("[BUNDLE] Receipt: {}", br.bundle_path.display());
                println!("[BUNDLE] ID: {}", br.bundle_id);

                // Insert into receipts DB
                let db_guard = state.receipts_db.lock().await;
                if let Err(e) = receipts::insert_receipt(
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
                    },
                ) {
                    eprintln!("[BUNDLE] Failed to insert receipt: {}", e);
                    // Delete the orphaned bundle
                    let _ = std::fs::remove_file(&br.bundle_path);
                    None
                } else {
                    Some(br)
                }
            }
            Err(e) => {
                eprintln!("[BUNDLE] Bundle generation failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // -----------------------------------------------------------------------
    // Replace the last user message with the ZK-verified payload.
    // Zero raw transaction rows are included.
    // -----------------------------------------------------------------------
    let zk_payload = serde_json::json!({
        "category": "AWS Infrastructure",
        "total_spend_usd": zk.aggregate,
        "period_start": "2024-01-01",
        "period_end": "2024-03-31",
        "data_provenance": "ZEMTIK_VALID_ZK_PROOF",
        "raw_data_transmitted": false
    });
    let zk_message = format!(
        "Here is a cryptographically verified financial summary:\n\n{}",
        serde_json::to_string_pretty(&zk_payload)
            .context("serialize ZK payload")
            .map_err(ProxyError)?
    );

    println!(
        "[ZK] Payload: {{ category: \"AWS Infrastructure\", total_spend_usd: {}, provenance: \"ZEMTIK_VALID_ZK_PROOF\" }}",
        zk.aggregate
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

    // -----------------------------------------------------------------------
    // Forward the sanitized request to OpenAI.
    // -----------------------------------------------------------------------
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
        .map_err(ProxyError)?;

    let resp_status = openai_resp.status();
    let resp_body: Value = openai_resp
        .json()
        .await
        .context("parse OpenAI response")
        .map_err(ProxyError)?;

    // -----------------------------------------------------------------------
    // Write audit record.
    // -----------------------------------------------------------------------
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
                u.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            )
        })
        .unwrap_or((0, 0, 0));

    let audit_record = AuditRecord::build(
        bundle_result.as_ref().map(|b| b.bundle_id.clone()),
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

    // Build response with optional bundle headers
    let mut response = (
        StatusCode::from_u16(resp_status.as_u16()).unwrap_or(StatusCode::OK),
        Json(resp_body),
    )
        .into_response();

    if let Some(ref br) = bundle_result {
        if let Ok(val) = HeaderValue::from_str(&br.bundle_id) {
            response.headers_mut().insert("x-zemtik-bundle-id", val);
        }
        let verify_url = format!("http://localhost:{}/verify/{}", PROXY_PORT, br.bundle_id);
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
    let db_guard = state.receipts_db.lock().await;
    let receipt = receipts::get_receipt(&db_guard, &id).map_err(ProxyError)?;
    drop(db_guard);

    match receipt {
        None => Ok((
            StatusCode::NOT_FOUND,
            Html(render_not_found(&id)),
        )
            .into_response()),
        Some(r) => {
            // Read public_inputs_readable.json from the bundle for aggregate + params
            let readable = read_public_inputs_from_bundle(&r.bundle_path);
            Ok(Html(render_verify_page(&r, readable.as_ref())).into_response())
        }
    }
}

/// Read public_inputs_readable.json from a bundle ZIP.
fn read_public_inputs_from_bundle(bundle_path: &str) -> Option<serde_json::Value> {
    let file = std::fs::File::open(bundle_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let mut entry = archive.by_name("public_inputs_readable.json").ok()?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut bytes).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn render_verify_page(r: &receipts::Receipt, readable: Option<&serde_json::Value>) -> String {
    let (badge_color, status_label) = if r.proof_status.starts_with("VALID") {
        ("#22c55e", "VALID")
    } else {
        ("#ef4444", "INVALID")
    };

    let aggregate = readable
        .and_then(|v| v.get("verified_aggregate"))
        .and_then(|v| v.as_u64())
        .map(|n| format!("${}", n))
        .unwrap_or_else(|| "—".to_owned());

    let category = readable
        .and_then(|v| v.get("target_category"))
        .and_then(|v| v.as_u64())
        .map(|n| match n {
            1 => "Payroll".to_owned(),
            2 => "AWS Infrastructure".to_owned(),
            3 => "Coffee & Meals".to_owned(),
            _ => format!("Category {}", n),
        })
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
        id = r.id,
        badge_color = badge_color,
        status_label = status_label,
        aggregate = aggregate,
        category = category,
        proof_status = html_escape(&r.proof_status),
        circuit_hash = r.circuit_hash,
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
}

/// Run the full ZK pipeline (DB → sign → circuit → proof) on the current thread.
/// Called from within spawn_blocking so DbBackend's !Sync is not an issue.
async fn run_zk_pipeline() -> anyhow::Result<ZkPipelineResult> {
    let params = QueryParams {
        client_id: 123,
        target_category: db::CAT_AWS,
        category_name: "AWS Infrastructure",
        start_time: db::Q1_START,
        end_time: db::Q1_END,
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

    let batches = db::sign_transaction_batches(&txns).context("sign batches")?;
    println!("[ZK] Signed {} batches with BabyJubJub EdDSA", batch_count);

    prover::generate_batched_prover_toml(&batches, &params).context("write Prover.toml")?;

    let circuit_json = std::path::Path::new("circuit/target/zemtik_circuit.json");
    if !circuit_json.exists() {
        println!("[ZK] Compiling circuit (first run, ~10s)...");
        prover::compile_circuit().context("compile circuit")?;
    }

    println!("[ZK] Executing circuit (EdDSA verification + aggregation)...");
    let circuit_exec_start = Instant::now();
    let hex_output = prover::execute_circuit().context("execute circuit")?;
    let circuit_execution_secs = circuit_exec_start.elapsed().as_secs_f32();
    let aggregate = prover::hex_output_to_u64(&hex_output).context("parse aggregate")?;

    println!("[ZK] Generating UltraHonk proof...");
    let proof_generated = prover::generate_proof().context("generate proof")?;
    let proof_status = if proof_generated {
        match prover::verify_proof().context("verify proof")? {
            Some(true) => "VALID (ZK proof generated and verified)",
            Some(false) => anyhow::bail!("Proof verification failed"),
            None => "VERIFIED (nargo execute - circuit constraints satisfied)",
        }
    } else {
        "VERIFIED (nargo execute - all constraints including EdDSA satisfied)"
    };

    let first_sig = batches.into_iter().next().map(|(_, sig)| sig).unwrap();

    let proof_artifacts = prover::read_proof_artifacts().context("read proof artifacts")?;
    let fully_verifiable = proof_artifacts.is_some() && proof_generated;
    let (proof_hex, vk_hex) = match proof_artifacts {
        Some((p, v)) => (Some(p), Some(v)),
        None => (None, None),
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
// Error type: convert anyhow::Error to a 500 JSON response
// ---------------------------------------------------------------------------

struct ProxyError(anyhow::Error);

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        eprintln!("[ZK] Pipeline error: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": {
                    "message": format!("Zemtik ZK pipeline error: {}", self.0),
                    "type": "zemtik_pipeline_error"
                }
            })),
        )
            .into_response()
    }
}

impl From<anyhow::Error> for ProxyError {
    fn from(e: anyhow::Error) -> Self {
        ProxyError(e)
    }
}
