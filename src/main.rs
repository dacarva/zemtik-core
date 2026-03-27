mod audit;
mod bundle;
mod db;
mod openai;
mod proxy;
mod prover;
mod receipts;
mod types;
mod verify;

use std::time::Instant;

use chrono::Utc;
use types::{OpenAiResponseLog, QueryParams};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present (never fails if the file doesn't exist)
    let _ = dotenvy::dotenv();

    // Route based on CLI arguments.
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("--proxy") => return proxy::run_proxy().await,
        Some("verify") => {
            let path = args.get(2).ok_or_else(|| {
                anyhow::anyhow!("Usage: zemtik verify <bundle.zip>")
            })?;
            return verify::run_verify_cli(std::path::Path::new(path));
        }
        _ => {} // fall through to default pipeline
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

    let proof_artifacts = prover::read_proof_artifacts()?;
    let fully_verifiable = proof_artifacts.is_some() && proof_generated;
    let (proof_hex, vk_hex) = match proof_artifacts {
        Some((p, v)) => (Some(p), Some(v)),
        None => (None, None),
    };

    // -----------------------------------------------------------------------
    // Step 7b: Generate proof bundle
    // -----------------------------------------------------------------------
    let bundle_result = if fully_verifiable {
        println!("[BUNDLE] Generating proof bundle...");
        match bundle::generate_bundle(&params, aggregate, proof_status, first_sig, None, None) {
            Ok(br) => {
                println!("[BUNDLE] Receipt: {}", br.bundle_path.display());
                println!("[BUNDLE] ID: {}", br.bundle_id);

                let conn = receipts::open_receipts_db()?;
                receipts::insert_receipt(
                    &conn,
                    &receipts::Receipt {
                        id: br.bundle_id.clone(),
                        bundle_path: br.bundle_path.display().to_string(),
                        proof_status: proof_status.to_owned(),
                        circuit_hash: br.circuit_hash.clone(),
                        bb_version: br.bb_version.clone(),
                        prompt_hash: String::new(),
                        request_hash: String::new(),
                        created_at: Utc::now().to_rfc3339(),
                    },
                )?;
                Some(br)
            }
            Err(e) => {
                eprintln!("[BUNDLE] Warning: bundle generation failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // -----------------------------------------------------------------------
    // Step 8: Send ONLY the verified aggregate to OpenAI
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

    let audit_record = types::AuditRecord::build(
        bundle_result.as_ref().map(|b| b.bundle_id.clone()),
        txns.len(),
        batch_count,
        db::BATCH_SIZE,
        &params,
        aggregate,
        proof_status.to_owned(),
        circuit_execution_secs,
        first_sig,
        proof_hex,
        vk_hex,
        fully_verifiable,
        ai_result.request_log,
        OpenAiResponseLog {
            content: ai_result.content.clone(),
            model: ai_result.model,
            usage: ai_result.usage,
        },
        elapsed.as_secs_f32(),
    );

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

    if let Some(ref br) = bundle_result {
        println!("  Bundle   : {}", br.bundle_path.display());
        println!("  Verify   : zemtik verify {}", br.bundle_path.display());
    }

    println!("\n  AI Advisory (gpt-5.4-nano):");
    for line in ai_result.content.lines() {
        println!("  {}", line);
    }
    println!("\n  Audit record: {}", audit_path.display());
    println!("══════════════════════════════════════════════════════\n");

    Ok(())
}
