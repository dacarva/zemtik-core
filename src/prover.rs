use std::{
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    time::{Duration, Instant},
};

use anyhow::Context;
use uuid::Uuid;

use crate::db::{fr_to_decimal, poseidon_of_string, BATCH_SIZE};
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

    toml.push_str(&format!("target_category_hash = \"{}\"\n", params.target_category_hash));
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
            let cat_fr = poseidon_of_string(&tx.category_name)?;
            toml.push_str(&format!("category = \"{}\"\n", fr_to_decimal(&cat_fr)));
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

    // If a compiled circuit artifact exists, validate that its ABI matches what this
    // binary expects. A mismatch means the installed circuit is from a different version
    // (e.g. a stale main-branch artifact). Catching this at startup prevents a cryptic
    // mid-pipeline nargo error like "Expected argument X, but none was found".
    let circuit_json = circuit_dir.join("target/zemtik_circuit.json");
    if circuit_json.exists() {
        validate_circuit_abi(&circuit_json).with_context(|| {
            format!(
                "Compiled circuit at '{}' is incompatible with this binary.\n\
                 Re-run install.sh from the repo root to update the installed circuit:\n\
                 ./install.sh",
                circuit_json.display()
            )
        })?;
    }

    Ok(())
}

/// Read the compiled circuit's ABI and verify the first public parameter is
/// `target_category_hash`. This guards against stale compiled artifacts from a
/// different branch (e.g. a v0.4.x main-branch artifact that uses `target_category`
/// instead of the sprint2 Poseidon-hashed form).
fn validate_circuit_abi(circuit_json: &Path) -> anyhow::Result<()> {
    const EXPECTED_FIRST_PARAM: &str = "target_category_hash";

    let bytes = std::fs::read(circuit_json)
        .with_context(|| format!("read circuit JSON from {}", circuit_json.display()))?;
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse circuit JSON")?;

    let first_param = json
        .get("abi")
        .and_then(|a| a.get("parameters"))
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str());

    match first_param {
        Some(name) if name == EXPECTED_FIRST_PARAM => Ok(()),
        Some(name) => anyhow::bail!(
            "circuit ABI mismatch: compiled artifact has '{}' as first parameter, \
             but this binary expects '{}'",
            name,
            EXPECTED_FIRST_PARAM
        ),
        None => anyhow::bail!(
            "circuit ABI missing 'abi.parameters' — artifact may be corrupt or from an \
             incompatible Noir version"
        ),
    }
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

/// Poll a child process until it exits or the deadline is reached.
/// On timeout, kills the child and reaps it to avoid zombies.
/// Returns `Ok(ExitStatus)` on normal exit, `Err` on timeout.
pub fn poll_child_with_timeout(child: &mut Child, timeout_secs: u64) -> anyhow::Result<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait().context("poll child process")? {
            Some(status) => return Ok(status),
            None if Instant::now() >= deadline => {
                child.kill().ok(); // ignore "already exited" errors
                child.wait().ok(); // reap zombie — must happen before temp dir cleanup on macOS
                anyhow::bail!("bb verify timed out after {}s — check CRS availability or bb version mismatch", timeout_secs);
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Run `bb verify` in `run_dir` to verify the proof.
///
/// Timeout is controlled by `ZEMTIK_VERIFY_TIMEOUT_SECS` (default: 120).
/// On timeout, the bb child process is killed and reaped before returning Err.
pub fn verify_proof(run_dir: &Path) -> anyhow::Result<Option<bool>> {
    let proof_path = run_dir.join("proofs/proof/proof");
    if !proof_path.exists() {
        return Ok(None);
    }

    let timeout_secs = read_verify_timeout();
    let t = Instant::now();

    let mut child = Command::new("bb")
        .args([
            "verify",
            "-p", "proofs/proof/proof",
            "-k", "proofs/proof/vk",
            "-i", "proofs/proof/public_inputs",
        ])
        .current_dir(run_dir)
        .spawn()
        .context("spawn bb verify")?;

    let status = poll_child_with_timeout(&mut child, timeout_secs)?;

    let elapsed = t.elapsed().as_secs_f32();
    let valid = status.success();
    println!(
        "[NOIR] Proof verified: {} ({:.2}s)",
        if valid { "VALID" } else { "INVALID" },
        elapsed
    );
    Ok(Some(valid))
}

/// Read the `ZEMTIK_VERIFY_TIMEOUT_SECS` env var.
/// Returns 120 if unset, unparseable, or 0 (floor guard — 0 would cause immediate timeout).
pub fn read_verify_timeout() -> u64 {
    std::env::var("ZEMTIK_VERIFY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(120)
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
mod poll_child_tests {
    use super::*;

    #[test]
    fn kill_on_timeout_kills_and_returns_err() {
        let mut child = Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep");
        let result = poll_child_with_timeout(&mut child, 1);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("timed out"), "expected 'timed out' in: {}", msg);
        // Process should be reaped — try_wait returns Some (not None/zombie)
        assert!(
            child.try_wait().unwrap().is_some(),
            "child should be reaped after kill+wait"
        );
    }

    #[test]
    fn success_path_returns_exit_status() {
        let mut child = Command::new("true").spawn().expect("spawn true");
        let status = poll_child_with_timeout(&mut child, 5).expect("should succeed");
        assert!(status.success());
    }
}
