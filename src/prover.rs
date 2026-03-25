use std::{
    path::PathBuf,
    process::Command,
    time::Instant,
};

use anyhow::Context;

use crate::db::BATCH_SIZE;
use crate::types::{QueryParams, SignatureData, Transaction};

/// Path to the circuit directory (relative to workspace root).
const CIRCUIT_DIR: &str = "circuit";

/// Serialize the batched circuit inputs to `circuit/Prover.toml`.
///
/// The batched circuit takes BATCH_COUNT batches of BATCH_SIZE transactions.
/// Each batch has its own EdDSA signature and transaction array. Nargo reads
/// nested struct arrays using TOML's array-of-tables syntax:
///
///   [[batches]]
///   sig_s = "..."
///   [[batches.transactions]]
///   amount = "..."
///
/// All Field values are decimal strings; u64 values are also decimal strings
/// (required by the circuit's public input encoding).
pub fn generate_batched_prover_toml(
    batches: &[(Vec<Transaction>, SignatureData)],
    params: &QueryParams,
) -> anyhow::Result<()> {
    // Estimate capacity: ~200 bytes per transaction, ~100 bytes overhead per batch
    let capacity = batches.len() * BATCH_SIZE * 200 + batches.len() * 100 + 512;
    let mut toml = String::with_capacity(capacity);

    // Public inputs (shared across all batches)
    toml.push_str(&format!("target_category = \"{}\"\n", params.target_category));
    toml.push_str(&format!("start_time = \"{}\"\n", params.start_time));
    toml.push_str(&format!("end_time = \"{}\"\n", params.end_time));

    // All batches share the same bank public key
    let (_, first_sig) = &batches[0];
    toml.push_str(&format!("bank_pub_key_x = \"{}\"\n", first_sig.pub_key_x));
    toml.push_str(&format!("bank_pub_key_y = \"{}\"\n", first_sig.pub_key_y));

    // Private per-batch inputs: signature + transaction array
    for (txns, sig) in batches {
        toml.push_str("\n[[batches]]\n");
        toml.push_str(&format!("sig_s = \"{}\"\n", sig.sig_s));
        toml.push_str(&format!("sig_r8_x = \"{}\"\n", sig.sig_r8_x));
        toml.push_str(&format!("sig_r8_y = \"{}\"\n", sig.sig_r8_y));

        for tx in txns {
            toml.push_str("\n[[batches.transactions]]\n");
            toml.push_str(&format!("amount = \"{}\"\n", tx.amount));
            toml.push_str(&format!("category = \"{}\"\n", tx.category));
            toml.push_str(&format!("timestamp = \"{}\"\n", tx.timestamp));
        }
    }

    let path = PathBuf::from(CIRCUIT_DIR).join("Prover.toml");
    std::fs::write(&path, toml)
        .with_context(|| format!("write Prover.toml to {}", path.display()))?;

    Ok(())
}

/// Serialize a single batch of circuit inputs to `circuit/Prover.toml`.
/// Kept for backward compatibility with single-batch use cases.
pub fn generate_prover_toml(
    txns: &[Transaction],
    sig: &SignatureData,
    params: &QueryParams,
) -> anyhow::Result<()> {
    generate_batched_prover_toml(&[(txns.to_vec(), SignatureData {
        pub_key_x: sig.pub_key_x.clone(),
        pub_key_y: sig.pub_key_y.clone(),
        sig_s: sig.sig_s.clone(),
        sig_r8_x: sig.sig_r8_x.clone(),
        sig_r8_y: sig.sig_r8_y.clone(),
    })], params)
}

/// Run `nargo compile` inside the circuit directory.
///
/// Only needs to run once; the compiled ACIR artifact is cached in
/// `circuit/target/zemtik_circuit.json`.
pub fn compile_circuit() -> anyhow::Result<()> {
    let t = Instant::now();
    let out = Command::new("nargo")
        .args(["compile"])
        .current_dir(CIRCUIT_DIR)
        .output()
        .context("spawn nargo compile")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nargo compile failed:\n{}", stderr);
    }
    println!(
        "[NOIR] Circuit compiled in {:.2}s",
        t.elapsed().as_secs_f32()
    );
    Ok(())
}

/// Run `nargo execute` to generate the witness and evaluate the circuit.
///
/// Returns the circuit's public return value (the verified aggregate) as a
/// hex string parsed from stdout: `Circuit output: 0x...`.
pub fn execute_circuit() -> anyhow::Result<String> {
    let t = Instant::now();
    let out = Command::new("nargo")
        .args(["execute"])
        .current_dir(CIRCUIT_DIR)
        .output()
        .context("spawn nargo execute")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nargo execute failed:\n{}", stderr);
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let elapsed = t.elapsed().as_secs_f32();

    // Parse: "[zemtik_circuit] Circuit output: 0x..."
    let hex_val = stdout
        .lines()
        .find(|l| l.contains("Circuit output:"))
        .and_then(|l| l.split("0x").nth(1))
        .map(|s| s.trim().to_owned())
        .context("could not find 'Circuit output:' in nargo execute stdout")?;

    println!("[NOIR] Circuit executed in {:.2}s", elapsed);
    Ok(hex_val)
}

/// Parse the circuit's hex output into a u64 aggregate.
pub fn hex_output_to_u64(hex: &str) -> anyhow::Result<u64> {
    u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .context("parse circuit output as u64")
}

/// Run `bb prove` to generate a UltraHonk ZK proof.
///
/// bb v4.0.0-nightly API: output is a directory containing proof, vk,
/// public_inputs, and vk_hash. CRS is auto-downloaded if missing.
/// Returns `Ok(true)` if proof generated, `Ok(false)` on unexpected failure,
/// `Err` only on fatal I/O errors.
pub fn generate_proof() -> anyhow::Result<bool> {
    let t = Instant::now();

    // Ensure output directory exists (bb writes proof, vk, public_inputs here)
    std::fs::create_dir_all(format!("{}/proofs/proof", CIRCUIT_DIR))
        .context("create circuit/proofs/proof dir")?;

    let out = Command::new("bb")
        .args([
            "prove",
            "-b", "target/zemtik_circuit.json",
            "-w", "target/zemtik_circuit.gz",
            "-o", "proofs/proof",
            "--write_vk",
        ])
        .current_dir(CIRCUIT_DIR)
        .output()
        .context("spawn bb prove")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("bb prove failed:\n{}", stderr);
    }

    println!(
        "[NOIR] UltraHonk proof generated in {:.2}s",
        t.elapsed().as_secs_f32()
    );
    Ok(true)
}

/// Run `bb verify` to verify the proof.
///
/// bb v4.0.0-nightly API: verify needs -p proof, -k vk, -i public_inputs.
/// Returns `Ok(Some(true))` if proof verified, `Ok(None)` if no proof exists,
/// `Ok(Some(false))` if proof is invalid.
pub fn verify_proof() -> anyhow::Result<Option<bool>> {
    let proof_path = std::path::Path::new(CIRCUIT_DIR).join("proofs/proof/proof");
    if !proof_path.exists() {
        return Ok(None);
    }

    let t = Instant::now();

    let verify_out = Command::new("bb")
        .args([
            "verify",
            "-p", "proofs/proof/proof",
            "-k", "proofs/proof/vk",
            "-i", "proofs/proof/public_inputs",
        ])
        .current_dir(CIRCUIT_DIR)
        .output()
        .context("spawn bb verify")?;

    let elapsed = t.elapsed().as_secs_f32();
    let valid = verify_out.status.success();
    println!(
        "[NOIR] Proof verified: {} ({:.2}s)",
        if valid { "VALID" } else { "INVALID" },
        elapsed
    );
    Ok(Some(valid))
}

/// Read the proof and verification key artifacts from disk and return them
/// as hex-encoded strings for inclusion in the audit record.
///
/// bb v4.0.0-nightly writes proof and vk into the output directory.
/// Returns `None` if the proof file does not exist.
pub fn read_proof_artifacts() -> anyhow::Result<Option<(String, String)>> {
    let proof_path = std::path::Path::new(CIRCUIT_DIR).join("proofs/proof/proof");
    let vk_path = std::path::Path::new(CIRCUIT_DIR).join("proofs/proof/vk");

    if !proof_path.exists() || !vk_path.exists() {
        return Ok(None);
    }

    let proof_bytes = std::fs::read(&proof_path)
        .with_context(|| format!("read proof from {}", proof_path.display()))?;
    let vk_bytes = std::fs::read(&vk_path)
        .with_context(|| format!("read vk from {}", vk_path.display()))?;

    let proof_hex = hex::encode(&proof_bytes);
    let vk_hex = hex::encode(&vk_bytes);

    Ok(Some((proof_hex, vk_hex)))
}
