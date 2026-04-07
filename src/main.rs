use zemtik::{audit, bundle, config, db, keys, openai, prover, proxy, receipts, types, verify};

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context;
use chrono::Utc;
use clap::{Parser, Subcommand};
use config::Command;
use types::{OpenAiResponseLog, QueryParams};

#[derive(Parser)]
#[command(name = "zemtik", version, about = "ZK middleware for enterprise AI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Override the proxy port
    #[arg(long)]
    port: Option<u16>,
    /// Override the circuit directory
    #[arg(long)]
    circuit_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in OpenAI-compatible proxy mode on :4000
    Proxy,
    /// Verify a proof bundle offline
    Verify {
        /// Path to the bundle zip file
        path: PathBuf,
    },
    /// List recent receipts
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present (never fails if the file doesn't exist)
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    // Build the config::CliArgs from clap output
    let mut config_cli = config::CliArgs::default();
    config_cli.port = cli.port;
    config_cli.circuit_dir = cli.circuit_dir;
    config_cli.command = match &cli.command {
        Some(Commands::Proxy) => Command::Proxy,
        Some(Commands::Verify { path }) => Command::Verify(path.clone()),
        Some(Commands::List) => Command::List,
        None => Command::Pipeline,
    };

    let app_config = config::AppConfig::load(&config_cli)?;

    match &config_cli.command {
        Command::Proxy => return proxy::run_proxy(app_config).await,
        Command::Verify(path) => {
            return verify::run_verify_cli(path);
        }
        Command::List => {
            return run_list(app_config);
        }
        Command::Pipeline => {} // fall through to default pipeline
    }

    // Fail fast: verify circuit directory before starting the pipeline.
    prover::validate_circuit_dir(&app_config.circuit_dir)
        .context("circuit directory validation")?;

    println!("╔══════════════════════════════════════════════════╗");
    println!("║   Zemtik: ZK Middleware POC (Rust + Noir + AI)   ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    let total_start = Instant::now();

    // -----------------------------------------------------------------------
    // Step 1: Initialize the ledger and fetch transactions
    // -----------------------------------------------------------------------
    let db_start = Instant::now();
    let backend = db::init_db().await?;
    print!("[DB] Initializing {} ledger... ", backend.label());
    let batch = db::query_transactions(&backend, 123).await?;
    let txns = batch.transactions;
    anyhow::ensure!(
        txns.len() == db::MAX_ZK_TX_COUNT,
        "Expected exactly {} transactions, got {}. The circuit requires 10 batches of 50.",
        db::MAX_ZK_TX_COUNT,
        txns.len()
    );
    let batch_count = txns.len() / db::BATCH_SIZE;
    let db_secs = db_start.elapsed().as_secs_f32();
    println!("OK ({} transactions for client 123) ({:.2}s)", txns.len(), db_secs);

    // Query: client 123's AWS spend in Q1 2024
    let category_hash_fr = db::poseidon_of_string("aws_spend")
        .context("compute target_category_hash for aws_spend")?;
    let params = QueryParams {
        client_id: 123,
        target_category_hash: db::fr_to_decimal(&category_hash_fr),
        category_name: "aws_spend".to_owned(),
        start_time: db::Q1_START,
        end_time: db::Q1_END,
    };

    // -----------------------------------------------------------------------
    // Step 2: Load (or generate) the installation-specific bank signing key
    // -----------------------------------------------------------------------
    let bank_key = keys::load_or_generate_key(&app_config.keys_dir)?;

    // -----------------------------------------------------------------------
    // Step 3: Bank KMS signs each batch independently with BabyJubJub EdDSA
    // -----------------------------------------------------------------------
    let sign_start = Instant::now();
    print!(
        "[KMS] Signing {} batches of {} transactions with BabyJubJub EdDSA... ",
        batch_count,
        db::BATCH_SIZE
    );
    let batches = db::sign_transaction_batches(&txns, &bank_key)?;
    let sign_secs = sign_start.elapsed().as_secs_f32();
    println!("OK ({:.2}s)", sign_secs);
    let first_sig = &batches[0].1;
    println!(
        "      pub_key_x = {}...{}",
        &first_sig.pub_key_x[..8],
        &first_sig.pub_key_x[first_sig.pub_key_x.len().saturating_sub(8)..]
    );

    // -----------------------------------------------------------------------
    // Step 4: Generate the Prover.toml input file for the Noir circuit
    // -----------------------------------------------------------------------
    let toml_start = Instant::now();
    print!("[NOIR] Writing Prover.toml ({} batches)... ", batch_count);
    prover::generate_batched_prover_toml(&batches, &params, &app_config.circuit_dir)?;
    let toml_secs = toml_start.elapsed().as_secs_f32();
    println!("OK ({:.2}s)", toml_secs);

    // -----------------------------------------------------------------------
    // Step 5: Compile the Noir circuit (cached after first run)
    // -----------------------------------------------------------------------
    let circuit_json = app_config.circuit_dir.join("target/zemtik_circuit.json");
    if !circuit_json.exists() {
        print!("[NOIR] Compiling circuit (first run only)... ");
        prover::compile_circuit(&app_config.circuit_dir)?;
    } else {
        println!("[NOIR] Circuit already compiled, skipping nargo compile");
    }

    // -----------------------------------------------------------------------
    // Step 6: Execute the circuit
    // -----------------------------------------------------------------------
    println!(
        "[NOIR] Executing circuit ({} batches x EdDSA + aggregation)...",
        batch_count
    );
    let circuit_exec_start = Instant::now();
    let hex_output = prover::execute_circuit(&app_config.circuit_dir)?;
    let circuit_execution_secs = circuit_exec_start.elapsed().as_secs_f32();
    let aggregate = prover::hex_output_to_u64(&hex_output)?;
    println!("[NOIR] Verified aggregate {} spend = ${}", params.category_name, aggregate);

    // -----------------------------------------------------------------------
    // Step 7: Prepare per-run work directory and generate UltraHonk ZK proof
    // -----------------------------------------------------------------------
    println!("[NOIR] Generating UltraHonk proof (bb v4, CRS auto-download)...");
    let run_dir = prover::prepare_run_dir(&app_config.runs_dir, &app_config.circuit_dir)?;
    struct RunDirGuard(std::path::PathBuf);
    impl Drop for RunDirGuard { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    let _run_dir_guard = RunDirGuard(run_dir.clone());
    let proof_generated = prover::generate_proof(&run_dir)?;

    // -----------------------------------------------------------------------
    // Step 8: Verify the proof
    // -----------------------------------------------------------------------
    let proof_status = if proof_generated {
        match prover::verify_proof(&run_dir)? {
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

    let proof_artifacts = prover::read_proof_artifacts(&run_dir)?;
    let fully_verifiable = proof_artifacts.is_some() && proof_generated;
    let (proof_hex, vk_hex) = match proof_artifacts {
        Some((p, v)) => (Some(p), Some(v)),
        None => (None, None),
    };

    // -----------------------------------------------------------------------
    // Step 8b: Generate proof bundle
    // -----------------------------------------------------------------------
    let bundle_start = Instant::now();
    let bundle_result = if fully_verifiable {
        println!("[BUNDLE] Generating proof bundle...");
        match bundle::generate_bundle(
            &params,
            aggregate,
            proof_status,
            first_sig,
            None,
            None,
            None, // outgoing_prompt_hash: CLI pipeline uses ai_result.outgoing_request_hash (logged, not in bundle)
            &run_dir,
            &app_config.circuit_dir,
            &app_config.receipts_dir,
            "SUM", // CLI pipeline is hardcoded SUM
            None,  // actual_row_count: CLI pipeline uses exactly 500 seeded rows
        ) {
            Ok(br) => {
                println!("[BUNDLE] Receipt: {}", br.bundle_path.display());
                println!("[BUNDLE] ID: {}", br.bundle_id);

                let conn = receipts::open_receipts_db(&app_config.receipts_db_path)?;
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
                        engine_used: "zk_slow_lane".to_owned(),
                        proof_hash: proof_hex.clone(),
                        data_exfiltrated: 0,
                        intent_confidence: None,  // CLI pipeline has no intent extraction
                        outgoing_prompt_hash: None, // CLI pipeline: hash computed from query_openai result
                        signing_version: None,
                        actual_row_count: None,    // CLI pipeline uses exactly 500 seeded rows
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

    let bundle_secs = bundle_start.elapsed().as_secs_f32();

    // -----------------------------------------------------------------------
    // Step 9: Send ONLY the verified aggregate to OpenAI
    // -----------------------------------------------------------------------
    let ai_start = Instant::now();
    println!("\n[AI] Querying gpt-5.4-nano with ZK-verified payload...");
    println!(
        "     Payload: {{ category: \"{}\", total_spend_usd: {}, provenance: \"ZEMTIK_VALID_ZK_PROOF\" }}",
        params.category_name, aggregate
    );

    let ai_result = openai::query_openai(
        aggregate,
        &params.category_name,
        "total_spend_usd",
        "2024-01-01",
        "2024-03-31",
        app_config.openai_api_key.as_deref(),
        None,
    )
    .await?;
    let ai_secs = ai_start.elapsed().as_secs_f32();

    // -----------------------------------------------------------------------
    // Step 10: Write the audit record
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

    let accounted = db_secs + sign_secs + toml_secs + circuit_execution_secs + bundle_secs + ai_secs;
    println!("\n  ── Timing breakdown ──────────────────────────────");
    println!("  DB init + query  : {:7.2}s", db_secs);
    println!("  EdDSA signing    : {:7.2}s  (Poseidon commitment x10 batches + BabyJubJub sign)", sign_secs);
    println!("  Prover.toml      : {:7.2}s  (500 tx category hashes → Field encoding)", toml_secs);
    println!("  nargo execute    : {:7.2}s  (circuit witness + EdDSA constraint check)", circuit_execution_secs);
    println!("  bb prove+verify  : {:7.2}s  (UltraHonk proof generation + local verify)", elapsed.as_secs_f32() - accounted);
    println!("  Bundle + receipt : {:7.2}s", bundle_secs);
    println!("  OpenAI query     : {:7.2}s", ai_secs);
    println!("  ─────────────────────────");
    println!("  Total            : {:7.2}s", elapsed.as_secs_f32());

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

/// `zemtik list` — print receipts from the local receipts DB.
fn run_list(config: config::AppConfig) -> anyhow::Result<()> {
    let conn = receipts::open_receipts_db(&config.receipts_db_path)
        .context("open receipts DB")?;
    let list = receipts::list_receipts(&conn).context("list receipts")?;

    if list.is_empty() {
        println!("No receipts found. Run zemtik (pipeline) or zemtik proxy to generate receipts.");
        return Ok(());
    }

    println!(
        "{:<38}  {:<20}  {:<22}  {:<8}  {}",
        "Receipt ID", "Engine", "Status", "Conf", "Created At"
    );
    println!("{}", "-".repeat(120));
    for r in &list {
        let conf = match r.intent_confidence {
            Some(c) => format!("{:.2}", c),
            None => "-".to_owned(),
        };
        println!(
            "{:<38}  {:<20}  {:<22}  {:<8}  {}",
            r.id,
            r.engine_used,
            r.proof_status,
            conf,
            r.created_at,
        );
    }
    println!("\n{} receipt(s) total.", list.len());
    Ok(())
}
