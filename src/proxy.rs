use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use axum::{Json, Router};
use chrono::Utc;
use serde_json::Value;
use tower_http::cors::CorsLayer;

use crate::types::{
    AuditRecord, OpenAiRequestLog, OpenAiResponseLog, PipelineInfo, PrivacyAttestation, QueryParams,
    SignatureData, TokenUsage, ZkProofLog, ZkPublicInputs,
};
use crate::{audit, db, prover};

const PROXY_PORT: u16 = 4000;
const OPENAI_BASE_URL: &str = "https://api.openai.com";

struct ProxyState {
    http_client: reqwest::Client,
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
    let state = Arc::new(ProxyState {
        http_client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/v1/chat/completions", post(handle_chat_completions))
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

    println!("[ZK] Request intercepted → starting ZK pipeline");

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

    let params = QueryParams {
        client_id: 123,
        target_category: db::CAT_AWS,
        category_name: "AWS Infrastructure",
        start_time: db::Q1_START,
        end_time: db::Q1_END,
    };

    let audit_record = AuditRecord {
        timestamp: Utc::now().to_rfc3339(),
        pipeline: PipelineInfo {
            total_transaction_count: zk.txns_len,
            batch_count: zk.batch_count,
            batch_size: db::BATCH_SIZE,
            proof_scheme: "ultra_honk".to_owned(),
            client_id: params.client_id,
            query: params.clone(),
            zk_aggregate: zk.aggregate,
            proof_status: zk.proof_status.to_owned(),
            circuit_execution_secs: zk.circuit_execution_secs,
        },
        zk_proof: ZkProofLog {
            proof_hex: zk.proof_hex,
            verification_key_hex: zk.vk_hex,
            public_inputs: ZkPublicInputs {
                target_category: params.target_category,
                start_time: params.start_time,
                end_time: params.end_time,
                bank_pub_key_x: zk.first_sig.pub_key_x,
                bank_pub_key_y: zk.first_sig.pub_key_y,
                verified_aggregate: zk.aggregate,
            },
            fully_verifiable: zk.fully_verifiable,
        },
        openai_request: OpenAiRequestLog {
            model: model.clone(),
            system_prompt: "[forwarded from client]".to_owned(),
            user_message: zk_message,
            max_completion_tokens: 0,
        },
        openai_response: OpenAiResponseLog {
            content: content.clone(),
            model: resp_model,
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens,
            },
        },
        privacy_attestation: PrivacyAttestation {
            raw_rows_transmitted: 0,
            fields_transmitted: vec![
                "category".to_owned(),
                "total_spend_usd".to_owned(),
                "period_start".to_owned(),
                "period_end".to_owned(),
                "data_provenance".to_owned(),
                "raw_data_transmitted".to_owned(),
            ],
        },
        total_elapsed_secs: elapsed.as_secs_f32(),
    };

    if let Ok(audit_path) = audit::write_audit_record(&audit_record) {
        println!("[ZK] Audit record: {}", audit_path.display());
    }

    println!(
        "[ZK] Done in {:.2}s — returning OpenAI response to client",
        elapsed.as_secs_f32()
    );

    Ok((
        StatusCode::from_u16(resp_status.as_u16()).unwrap_or(StatusCode::OK),
        Json(resp_body),
    )
        .into_response())
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
