use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::Context;
use uuid::Uuid;

use crate::db::BATCH_SIZE;
use crate::types::{QueryParams, SignatureData, Transaction};

/// Serialize the batched circuit inputs to `circuit_dir/Prover.toml`.
pub fn generate_batched_prover_toml(
    batches: &[(Vec<Transaction>, SignatureData)],
    params: &QueryParams,
    circuit_dir: &Path,
) -> anyhow::Result<()> {
    anyhow::ensure!(!batches.is_empty(), "no transaction batches to write to Prover.toml");

    let capacity = batches.len() * BATCH_SIZE * 200 + batches.len() * 100 + 512;
    let mut toml = String::with_capacity(capacity);

    toml.push_str(&format!("target_category = \"{}\"\n", params.target_category));
    toml.push_str(&format!("start_time = \"{}\"\n", params.start_time));
    toml.push_str(&format!("end_time = \"{}\"\n", params.end_time));

    let (_, first_sig) = &batches[0];
    toml.push_str(&format!("bank_pub_key_x = \"{}\"\n", first_sig.pub_key_x));
    toml.push_str(&format!("bank_pub_key_y = \"{}\"\n", first_sig.pub_key_y));

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

    let path = circuit_dir.join("Prover.toml");
    std::fs::write(&path, toml)
        .with_context(|| format!("write Prover.toml to {}", path.display()))?;

    Ok(())
}

/// Validate that `circuit_dir` has the files nargo needs to compile and execute.
///
/// Called at startup so failures surface immediately with a clear remediation message
/// instead of mid-pipeline as an opaque "No such file or directory" error.
pub fn validate_circuit_dir(circuit_dir: &Path) -> anyhow::Result<()> {
    let nargo_toml = circuit_dir.join("Nargo.toml");
    anyhow::ensure!(
        nargo_toml.exists(),
        "Circuit directory '{}' is missing Nargo.toml.\n\
         Run install.sh from the repo root, or copy manually:\n\
         cp -r circuit/. {} && mkdir -p {}/vendor && cp -r vendor/. {}/vendor/",
        circuit_dir.display(),
        circuit_dir.display(),
        circuit_dir.parent().unwrap_or(circuit_dir).display(),
        circuit_dir.parent().unwrap_or(circuit_dir).display()
    );

    let main_nr = circuit_dir.join("src/main.nr");
    anyhow::ensure!(
        main_nr.exists(),
        "Circuit directory '{}' is missing src/main.nr.\n\
         Run install.sh from the repo root, or copy manually:\n\
         cp -r circuit/. {}",
        circuit_dir.display(),
        circuit_dir.display()
    );

    // Nargo.toml references eddsa as `path = "../vendor/eddsa"` — relative to circuit_dir.
    let vendor_eddsa = circuit_dir.join("../vendor/eddsa/Nargo.toml");
    anyhow::ensure!(
        vendor_eddsa.exists(),
        "Vendor dependency missing at '{}'.\n\
         Nargo.toml expects ../vendor/eddsa relative to the circuit directory.\n\
         Run install.sh from the repo root, or copy manually:\n\
         mkdir -p {}/vendor && cp -r vendor/. {}/vendor/",
        vendor_eddsa.display(),
        circuit_dir.parent().unwrap_or(circuit_dir).display(),
        circuit_dir.parent().unwrap_or(circuit_dir).display()
    );

    Ok(())
}

/// Serialize a single batch of circuit inputs to `circuit_dir/Prover.toml`.
/// Kept for backward compatibility with single-batch use cases.
#[allow(dead_code)]
pub fn generate_prover_toml(
    txns: &[Transaction],
    sig: &SignatureData,
    params: &QueryParams,
    circuit_dir: &Path,
) -> anyhow::Result<()> {
    generate_batched_prover_toml(
        &[(txns.to_vec(), SignatureData {
            pub_key_x: sig.pub_key_x.clone(),
            pub_key_y: sig.pub_key_y.clone(),
            sig_s: sig.sig_s.clone(),
            sig_r8_x: sig.sig_r8_x.clone(),
            sig_r8_y: sig.sig_r8_y.clone(),
        })],
        params,
        circuit_dir,
    )
}

/// Run `nargo compile` inside the circuit directory.
pub fn compile_circuit(circuit_dir: &Path) -> anyhow::Result<()> {
    let t = Instant::now();
    let out = Command::new("nargo")
        .args(["compile"])
        .current_dir(circuit_dir)
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
/// Returns the circuit's public return value as a hex string parsed from stdout.
pub fn execute_circuit(circuit_dir: &Path) -> anyhow::Result<String> {
    let t = Instant::now();
    let out = Command::new("nargo")
        .args(["execute"])
        .current_dir(circuit_dir)
        .output()
        .context("spawn nargo execute")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("nargo execute failed:\n{}", stderr);
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let elapsed = t.elapsed().as_secs_f32();

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

/// Create a per-run working directory and populate it with compiled circuit artifacts.
///
/// Creates `runs_dir/{uuid}/proofs/proof/`, then copies
/// `circuit_dir/target/zemtik_circuit.json` and `zemtik_circuit.gz` into the run root.
/// Returns the run directory path.
pub fn prepare_run_dir(runs_dir: &Path, circuit_dir: &Path) -> anyhow::Result<PathBuf> {
    let run_id = Uuid::new_v4().to_string();
    let run_dir = runs_dir.join(&run_id);
    std::fs::create_dir_all(run_dir.join("proofs/proof"))
        .with_context(|| format!("create run dir {}", run_dir.display()))?;

    for filename in &["zemtik_circuit.json", "zemtik_circuit.gz"] {
        let src = circuit_dir.join("target").join(filename);
        let dst = run_dir.join(filename);
        std::fs::copy(&src, &dst)
            .with_context(|| format!("copy {} to {}", src.display(), dst.display()))?;
    }

    Ok(run_dir)
}

/// Run `bb prove` in `run_dir` to generate a UltraHonk ZK proof.
///
/// Expects `zemtik_circuit.json` and `zemtik_circuit.gz` in `run_dir` (placed by
/// `prepare_run_dir`). Writes proof artifacts to `run_dir/proofs/proof/`.
pub fn generate_proof(run_dir: &Path) -> anyhow::Result<bool> {
    let t = Instant::now();

    let out = Command::new("bb")
        .args([
            "prove",
            "-b", "zemtik_circuit.json",
            "-w", "zemtik_circuit.gz",
            "-o", "proofs/proof",
            "--write_vk",
        ])
        .current_dir(run_dir)
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

/// Run `bb verify` in `run_dir` to verify the proof.
pub fn verify_proof(run_dir: &Path) -> anyhow::Result<Option<bool>> {
    let proof_path = run_dir.join("proofs/proof/proof");
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
        .current_dir(run_dir)
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

/// Read the proof and verification key artifacts from `run_dir` and return them
/// as hex-encoded strings for inclusion in the audit record.
pub fn read_proof_artifacts(run_dir: &Path) -> anyhow::Result<Option<(String, String)>> {
    let proof_path = run_dir.join("proofs/proof/proof");
    let vk_path = run_dir.join("proofs/proof/vk");

    if !proof_path.exists() || !vk_path.exists() {
        return Ok(None);
    }

    let proof_bytes = std::fs::read(&proof_path)
        .with_context(|| format!("read proof from {}", proof_path.display()))?;
    let vk_bytes = std::fs::read(&vk_path)
        .with_context(|| format!("read vk from {}", vk_path.display()))?;

    Ok(Some((hex::encode(&proof_bytes), hex::encode(&vk_bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::types::{QueryParams, SignatureData, Transaction};

    fn dummy_sig() -> SignatureData {
        SignatureData {
            pub_key_x: "1".to_owned(),
            pub_key_y: "2".to_owned(),
            sig_s: "3".to_owned(),
            sig_r8_x: "4".to_owned(),
            sig_r8_y: "5".to_owned(),
        }
    }

    fn dummy_params() -> QueryParams {
        QueryParams {
            client_id: 1,
            target_category: 2,
            category_name: "AWS",
            start_time: 1_704_067_200,
            end_time: 1_711_929_599,
        }
    }

    fn dummy_txns(n: usize) -> Vec<Transaction> {
        (0..n)
            .map(|i| Transaction { id: i as i64, client_id: 1, amount: i as u64 + 1, category: 2, timestamp: 1_704_067_200 + i as u64 })
            .collect()
    }

    #[test]
    fn hex_output_to_u64_parses_hex_with_prefix() {
        assert_eq!(hex_output_to_u64("0xff").unwrap(), 255);
        assert_eq!(hex_output_to_u64("0x0").unwrap(), 0);
        assert_eq!(hex_output_to_u64("0x1").unwrap(), 1);
    }

    #[test]
    fn hex_output_to_u64_parses_hex_without_prefix() {
        assert_eq!(hex_output_to_u64("ff").unwrap(), 255);
        assert_eq!(hex_output_to_u64("64").unwrap(), 100);
    }

    #[test]
    fn hex_output_to_u64_rejects_non_hex() {
        assert!(hex_output_to_u64("xyz").is_err());
    }

    #[test]
    fn generate_batched_prover_toml_creates_file() {
        let dir = TempDir::new().unwrap();
        let txns = dummy_txns(crate::db::BATCH_SIZE);
        let sig = dummy_sig();
        let params = dummy_params();

        generate_batched_prover_toml(&[(txns, sig)], &params, dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join("Prover.toml")).unwrap();
        assert!(content.contains("target_category = \"2\""));
        assert!(content.contains("[[batches]]"));
        assert!(content.contains("[[batches.transactions]]"));
    }

    #[test]
    fn generate_batched_prover_toml_embeds_query_params() {
        let dir = TempDir::new().unwrap();
        let params = dummy_params();
        let txns = dummy_txns(crate::db::BATCH_SIZE);
        let sig = dummy_sig();

        generate_batched_prover_toml(&[(txns, sig)], &params, dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join("Prover.toml")).unwrap();
        assert!(content.contains("start_time = \"1704067200\""));
        assert!(content.contains("end_time = \"1711929599\""));
        assert!(content.contains("bank_pub_key_x = \"1\""));
    }

    #[test]
    fn read_proof_artifacts_returns_none_when_files_absent() {
        let dir = TempDir::new().unwrap();
        let result = read_proof_artifacts(dir.path()).unwrap();
        assert!(result.is_none());
    }
}
