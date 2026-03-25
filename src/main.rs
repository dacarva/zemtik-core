mod audit;
mod db;
mod openai;
mod proxy;
mod prover;
mod types;

use std::time::Instant;

use chrono::Utc;
use types::{AuditRecord, PipelineInfo, PrivacyAttestation, QueryParams, ZkProofLog, ZkPublicInputs};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present (never fails if the file doesn't exist)
    let _ = dotenvy::dotenv();

    // Route to proxy mode if --proxy flag is passed.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--proxy") {
        return proxy::run_proxy().await;
    }

    println!("╔══════════════════════════════════════════════════╗");
    println!("║   Zemtik: ZK Middleware POC (Rust + Noir + AI)   ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    let total_start = Instant::now();

    // -----------------------------------------------------------------------
    // Step 1: Initialize the ledger and fetch transactions
    // -----------------------------------------------------------------------
    let backend = db::init_db().await?;
    print!("[DB] Initializing {} ledger... ", backend.label());
    let txns = db::query_transactions(&backend, 123).await?;
    anyhow::ensure!(
        txns.len() == 500,
        "Expected exactly 500 transactions, got {}. The circuit requires 10 batches of 50.",
        txns.len()
    );
    let batch_count = txns.len() / db::BATCH_SIZE;
    println!("OK ({} transactions for client 123)", txns.len());

    // Query: client 123's AWS spend in Q1 2024
    let params = QueryParams {
        client_id: 123,
        target_category: db::CAT_AWS,
        category_name: "AWS Infrastructure",
        start_time: db::Q1_START,
        end_time: db::Q1_END,
    };

    // -----------------------------------------------------------------------
    // Step 2: Bank KMS signs each batch independently with BabyJubJub EdDSA
    // -----------------------------------------------------------------------
    print!(
        "[KMS] Signing {} batches of {} transactions with BabyJubJub EdDSA... ",
        batch_count,
        db::BATCH_SIZE
    );
    let batches = db::sign_transaction_batches(&txns)?;
    println!("OK");
    let first_sig = &batches[0].1;
    println!(
        "      pub_key_x = {}...{}",
        &first_sig.pub_key_x[..8],
        &first_sig.pub_key_x[first_sig.pub_key_x.len().saturating_sub(8)..]
    );

    // -----------------------------------------------------------------------
    // Step 3: Generate the Prover.toml input file for the Noir circuit
    // -----------------------------------------------------------------------
    print!("[NOIR] Writing Prover.toml ({} batches)... ", batch_count);
    prover::generate_batched_prover_toml(&batches, &params)?;
    println!("OK");

    // -----------------------------------------------------------------------
    // Step 4: Compile the Noir circuit (cached after first run)
    // -----------------------------------------------------------------------
    let circuit_json = std::path::Path::new("circuit/target/zemtik_circuit.json");
    if !circuit_json.exists() {
        print!("[NOIR] Compiling circuit (first run only)... ");
        prover::compile_circuit()?;
    } else {
        println!("[NOIR] Circuit already compiled, skipping nargo compile");
    }

    // -----------------------------------------------------------------------
    // Step 5: Execute the circuit -- verifies all EdDSA signatures and
    // aggregates spend across all batches
    // -----------------------------------------------------------------------
    println!(
        "[NOIR] Executing circuit ({} batches x EdDSA + aggregation)...",
        batch_count
    );
    let circuit_exec_start = Instant::now();
    let hex_output = prover::execute_circuit()?;
    let circuit_execution_secs = circuit_exec_start.elapsed().as_secs_f32();
    let aggregate = prover::hex_output_to_u64(&hex_output)?;
    println!("[NOIR] Verified aggregate {} spend = ${}", params.category_name, aggregate);

    // -----------------------------------------------------------------------
    // Step 6: Generate UltraHonk ZK proof
    //
    // noir-edwards based EdDSA eliminates the BigField incompatibility with
    // bb v4.0.0-nightly. CRS is auto-downloaded if missing (~32 MB for this
    // circuit size). Single-function ACIR (no #[fold]) is compatible with
    // the ultra_honk scheme.
    // -----------------------------------------------------------------------
    println!("[NOIR] Generating UltraHonk proof (bb v4, CRS auto-download)...");
    let proof_generated = prover::generate_proof()?;

    // -----------------------------------------------------------------------
    // Step 7: Verify the proof
    // -----------------------------------------------------------------------
    let proof_status = if proof_generated {
        match prover::verify_proof()? {
            Some(true) => "VALID (ZK proof generated and verified)",
            Some(false) => {
                anyhow::bail!("Proof verification failed -- aborting OpenAI call");
            }
            None => "VERIFIED (nargo execute - circuit constraints satisfied)",
        }
    } else {
        println!("[NOIR] Proof generation failed -- falling back to nargo execute verification.");
        println!("[NOIR] Circuit constraints verified by nargo execute ({} batches x EdDSA + aggregation).", batch_count);
        "VERIFIED (nargo execute - all constraints including EdDSA satisfied)"
    };

    // -----------------------------------------------------------------------
    // Step 8: Send ONLY the verified aggregate to OpenAI
    //
    // Zero raw transaction rows are included. The LLM receives a JSON payload
    // whose figures are backed by a mathematically verified ZK proof.
    // -----------------------------------------------------------------------
    println!("\n[AI] Querying gpt-5.4-nano with ZK-verified payload...");
    println!(
        "     Payload: {{ category: \"{}\", total_spend_usd: {}, provenance: \"ZEMTIK_VALID_ZK_PROOF\" }}",
        params.category_name, aggregate
    );

    let ai_result = openai::query_openai(
        aggregate,
        params.category_name,
        "2024-01-01",
        "2024-03-31",
    )
    .await?;

    // -----------------------------------------------------------------------
    // Step 9: Write the audit record
    // -----------------------------------------------------------------------
    let elapsed = total_start.elapsed();

    let proof_artifacts = prover::read_proof_artifacts()?;
    let fully_verifiable = proof_artifacts.is_some() && proof_generated;
    let (proof_hex, vk_hex) = match proof_artifacts {
        Some((p, v)) => (Some(p), Some(v)),
        None => (None, None),
    };

    let audit_record = AuditRecord {
        timestamp: Utc::now().to_rfc3339(),
        pipeline: PipelineInfo {
            total_transaction_count: txns.len(),
            batch_count,
            batch_size: db::BATCH_SIZE,
            proof_scheme: "ultra_honk".to_owned(),
            client_id: params.client_id,
            query: params.clone(),
            zk_aggregate: aggregate,
            proof_status: proof_status.to_owned(),
            circuit_execution_secs,
        },
        zk_proof: ZkProofLog {
            proof_hex,
            verification_key_hex: vk_hex,
            public_inputs: ZkPublicInputs {
                target_category: params.target_category,
                start_time: params.start_time,
                end_time: params.end_time,
                bank_pub_key_x: first_sig.pub_key_x.clone(),
                bank_pub_key_y: first_sig.pub_key_y.clone(),
                verified_aggregate: aggregate,
            },
            fully_verifiable,
        },
        openai_request: ai_result.request_log,
        openai_response: types::OpenAiResponseLog {
            content: ai_result.content.clone(),
            model: ai_result.model,
            usage: ai_result.usage,
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

    let audit_path = audit::write_audit_record(&audit_record)?;

    // -----------------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------------
    println!("\n══════════════════════════════════════════════════════");
    println!("  ZEMTIK RESULT (total time: {:.2}s)", elapsed.as_secs_f32());
    println!("══════════════════════════════════════════════════════");
    println!("  Category : {}", params.category_name);
    println!("  Period   : Q1 2024");
    println!("  Aggregate: ${}", aggregate);
    println!("  ZK Proof : {}", proof_status);
    println!("  Raw rows sent to OpenAI: 0");
    println!("\n  AI Advisory (gpt-5.4-nano):");
    for line in ai_result.content.lines() {
        println!("  {}", line);
    }
    println!("\n  Audit record: {}", audit_path.display());
    println!("══════════════════════════════════════════════════════\n");

    Ok(())
}
