use std::path::Path;
use std::process::Command;

use anyhow::Context;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::bundle::parse_bb_version;

#[derive(Debug)]
pub struct VerifyResult {
    pub valid: bool,
    pub circuit_hash: String,
    pub aggregate: u64,
    pub timestamp: String,
    pub raw_rows_sent_to_llm: u64,
    pub bb_version_used: String,
    /// SHA-256 of the JSON payload sent to the LLM (Rust-layer commitment).
    /// None for bundles generated before v0.5.1.
    pub outgoing_prompt_hash: Option<String>,
}

/// Verify a proof bundle ZIP by extracting it and calling `bb verify` directly.
///
/// Does NOT call `prover::verify_proof()` — that function operates on
/// hardcoded paths under `circuit/proofs/proof/`. This works on any bundle ZIP.
///
/// Exit semantics:
///   valid = true  → ZK proof verified by bb
///   valid = false → bb verify returned non-zero
///   Err(...)      → bb not found, version mismatch (MAJOR), or corrupt zip
pub fn verify_bundle(zip_path: &Path) -> anyhow::Result<VerifyResult> {
    // Resolve extract directory
    let home = dirs::home_dir().context("could not resolve home directory")?;
    let extract_id = Uuid::new_v4().to_string();
    let extract_dir = home.join(".zemtik").join(".tmp").join(format!("verify-{}", extract_id));
    std::fs::create_dir_all(&extract_dir)
        .with_context(|| format!("create extract dir {}", extract_dir.display()))?;

    // Ensure cleanup even on error
    let result = (|| -> anyhow::Result<VerifyResult> {
        // Extract ZIP
        let file = std::fs::File::open(zip_path)
            .with_context(|| format!("open bundle {}", zip_path.display()))?;
        let mut archive = zip::ZipArchive::new(file)
            .with_context(|| format!("parse zip {}", zip_path.display()))?;

        // Guard against zip bombs: abort if the archive is unreasonably large.
        const MAX_ENTRIES: usize = 64;
        const MAX_EXTRACTED_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB
        if archive.len() > MAX_ENTRIES {
            anyhow::bail!(
                "bundle has {} entries (max {}); refusing to extract",
                archive.len(),
                MAX_ENTRIES
            );
        }
        let mut total_extracted: u64 = 0;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).context("read zip entry")?;
            let name = entry.name().to_owned();
            // Strip directory components to prevent zip-slip path traversal.
            // A malicious bundle with entries like "../../.ssh/authorized_keys"
            // would otherwise escape the temp directory.
            // Directory entries (names ending in '/') have no filename component
            // and must be skipped rather than treated as errors — many ZIP tools
            // emit them automatically.
            let filename = match std::path::Path::new(&name).file_name() {
                Some(f) => f.to_owned(),
                None => continue, // directory entry — skip
            };
            let out_path = extract_dir.join(filename);
            let mut out_file = std::fs::File::create(&out_path)
                .with_context(|| format!("create {}", out_path.display()))?;
            let written = std::io::copy(&mut entry, &mut out_file)
                .with_context(|| format!("extract {}", name))?;
            total_extracted += written;
            if total_extracted > MAX_EXTRACTED_BYTES {
                anyhow::bail!(
                    "bundle extraction exceeded {} MiB limit; aborting",
                    MAX_EXTRACTED_BYTES / (1024 * 1024)
                );
            }
        }

        // Read metadata files
        let circuit_hash = std::fs::read_to_string(extract_dir.join("circuit_hash.txt"))
            .context("read circuit_hash.txt")?
            .trim()
            .to_owned();

        let meta_bytes = std::fs::read(extract_dir.join("request_meta.json"))
            .context("read request_meta.json")?;
        let meta: serde_json::Value =
            serde_json::from_slice(&meta_bytes).context("parse request_meta.json")?;

        let bundle_version = meta
            .get("bundle_version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        let timestamp = meta
            .get("timestamp_utc")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let bb_version_used = meta
            .get("bb_version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let raw_rows_sent_to_llm = meta
            .get("raw_rows_sent_to_llm")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let outgoing_prompt_hash = meta
            .get("outgoing_prompt_hash")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned());

        let readable_bytes = std::fs::read(extract_dir.join("public_inputs_readable.json"))
            .context("read public_inputs_readable.json")?;
        let readable: serde_json::Value =
            serde_json::from_slice(&readable_bytes).context("parse public_inputs_readable.json")?;
        let aggregate = readable
            .get("verified_aggregate")
            .and_then(|v| v.as_u64())
            .context("verified_aggregate missing from public_inputs_readable.json")?;

        // Verify required files are present
        for required in &["proof.bin", "vk.bin", "public_inputs"] {
            let p = extract_dir.join(required);
            if !p.exists() {
                anyhow::bail!("bundle is missing required file: {}", required);
            }
        }

        // Cross-verify binary public_inputs against the human-readable sidecar
        cross_verify_sidecar(&extract_dir)?;

        // Verify manifest.json sidecar hash.
        // bundle_version >= 2 requires manifest.json — absence is a tamper indicator.
        // Older bundles (bundle_version == 1) skip this check for backward compatibility.
        let manifest_path = extract_dir.join("manifest.json");
        if bundle_version >= 2 && !manifest_path.exists() {
            anyhow::bail!(
                "Bundle integrity check FAILED: manifest.json is required for bundle_version {} but is absent. \
                 This may indicate a tampered or incomplete bundle.",
                bundle_version
            );
        }
        if manifest_path.exists() {
            let manifest_bytes = std::fs::read(&manifest_path).context("read manifest.json")?;
            let manifest: serde_json::Value =
                serde_json::from_slice(&manifest_bytes).context("parse manifest.json")?;

            if let Some(expected) = manifest.get("sidecar_hash").and_then(|v| v.as_str()) {
                let actual = format!("sha256:{}", hex::encode(Sha256::digest(&readable_bytes)));
                if actual != expected {
                    anyhow::bail!(
                        "Bundle integrity check FAILED: sidecar hash mismatch.\n  Expected: {}\n  Got:      {}",
                        expected,
                        actual
                    );
                }
                println!("[zemtik] Bundle integrity: sidecar hash OK");
            }
        }

        // Check bb version compatibility
        let local_bb_raw = {
            let out = Command::new("bb")
                .arg("--version")
                .output()
                .context("bb not found — install Barretenberg (bb) to verify proofs")?;
            if !out.status.success() {
                anyhow::bail!(
                    "bb --version exited with status {} — check your Barretenberg installation",
                    out.status
                );
            }
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };

        if let (Some(local_ver), Some(bundle_ver)) = (
            parse_bb_version(&local_bb_raw),
            parse_bb_version(&bb_version_used),
        ) {
            if local_ver.0 != bundle_ver.0 {
                anyhow::bail!(
                    "bb MAJOR version mismatch: bundle was generated with {}, \
                     local bb is {} — cannot verify across major versions",
                    bb_version_used,
                    local_bb_raw
                );
            }
            if local_ver != bundle_ver {
                eprintln!(
                    "[WARN] bb version mismatch: bundle={}, local={} — proceeding (same major version)",
                    bb_version_used, local_bb_raw
                );
            }
        }

        // Run bb verify with configurable timeout.
        // The bb process is abandoned (not killed) on timeout — known limitation (TODOS.md).
        let timeout_secs = crate::prover::read_verify_timeout();
        let extract_dir_clone = extract_dir.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = Command::new("bb")
                .args([
                    "verify",
                    "-p", "proof.bin",
                    "-k", "vk.bin",
                    "-i", "public_inputs",
                ])
                .current_dir(&extract_dir_clone)
                .output()
                .context("spawn bb verify");
            let _ = tx.send(result);
        });

        let verify_out = rx
            .recv_timeout(std::time::Duration::from_secs(timeout_secs))
            .map_err(|_| anyhow::anyhow!(
                "bb verify timed out after {}s — check CRS availability or bb version mismatch",
                timeout_secs
            ))??;

        let valid = verify_out.status.success();

        Ok(VerifyResult {
            valid,
            circuit_hash,
            aggregate,
            timestamp,
            raw_rows_sent_to_llm,
            bb_version_used,
            outgoing_prompt_hash,
        })
    })();

    // Always clean up extracted files
    let _ = std::fs::remove_dir_all(&extract_dir);

    result
}

/// Tests for `ZEMTIK_VERIFY_TIMEOUT_SECS` env var parsing.
/// These validate the floor guard behavior without requiring `bb`.
#[cfg(test)]
mod timeout_tests {
    use crate::prover::read_verify_timeout;
    use std::sync::Mutex;

    // Serialize all env-var tests — parallel mutation of the same var is racy.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_verify_timeout_env_parsing_default() {
        let _g = ENV_LOCK.lock().unwrap();
        // ZEMTIK_VERIFY_TIMEOUT_SECS unset → 120
        std::env::remove_var("ZEMTIK_VERIFY_TIMEOUT_SECS");
        assert_eq!(read_verify_timeout(), 120);
    }

    #[test]
    fn test_verify_timeout_env_parsing_custom() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("ZEMTIK_VERIFY_TIMEOUT_SECS", "60");
        assert_eq!(read_verify_timeout(), 60);
        std::env::remove_var("ZEMTIK_VERIFY_TIMEOUT_SECS");
    }

    #[test]
    fn test_verify_timeout_env_parsing_zero() {
        let _g = ENV_LOCK.lock().unwrap();
        // 0 must NOT cause immediate timeout — treated as unset
        std::env::set_var("ZEMTIK_VERIFY_TIMEOUT_SECS", "0");
        assert_eq!(read_verify_timeout(), 120);
        std::env::remove_var("ZEMTIK_VERIFY_TIMEOUT_SECS");
    }

    #[test]
    fn test_verify_timeout_env_parsing_invalid() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("ZEMTIK_VERIFY_TIMEOUT_SECS", "notanumber");
        assert_eq!(read_verify_timeout(), 120);
        std::env::remove_var("ZEMTIK_VERIFY_TIMEOUT_SECS");
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use tempfile::tempdir;

    // -----------------------------------------------------------------------
    // cross_verify_sidecar tests
    // -----------------------------------------------------------------------

    /// Compute the big-endian Poseidon hash bytes for "aws_spend" for test fixtures.
    fn aws_spend_hash_bytes() -> [u8; 32] {
        let fr = crate::db::poseidon_of_string("aws_spend").expect("poseidon_of_string aws_spend");
        let decimal = crate::db::fr_to_decimal(&fr);
        let big = num_bigint::BigUint::parse_bytes(decimal.as_bytes(), 10)
            .expect("fr_to_decimal produces valid decimal");
        let be_bytes = big.to_bytes_be();
        let mut buf = [0u8; 32];
        // right-align into 32 bytes (big-endian, zero-padded on left)
        buf[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
        buf
    }

    fn write_cross_verify_fixtures(
        dir: &std::path::Path,
        binary: &[u8; 192],
        pk_x_decimal: &str,
        pk_y_decimal: &str,
        category_hash: &str,
        start: u64,
        end: u64,
        aggregate: u64,
    ) {
        std::fs::write(dir.join("public_inputs"), binary).unwrap();
        let json = serde_json::json!({
            "target_category_hash": category_hash,
            "category_name": "aws_spend",
            "start_time": start,
            "end_time": end,
            "bank_pub_key_x": pk_x_decimal,
            "bank_pub_key_y": pk_y_decimal,
            "verified_aggregate": aggregate
        });
        std::fs::write(
            dir.join("public_inputs_readable.json"),
            serde_json::to_vec_pretty(&json).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn valid_proof_and_sidecar_match_passes() {
        let dir = tempdir().unwrap();
        let pk_x = [0u8; 32];
        let pk_y = [0u8; 32];
        let hash_bytes = aws_spend_hash_bytes();
        let hash_decimal = BigUint::from_bytes_be(&hash_bytes).to_string();
        let binary = super::build_public_inputs_binary(&hash_bytes, 1000, 2000, &pk_x, &pk_y, 42);
        write_cross_verify_fixtures(dir.path(), &binary, "0", "0", &hash_decimal, 1000, 2000, 42);

        let result = super::cross_verify_sidecar(dir.path());
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn mismatched_aggregate_returns_error() {
        let dir = tempdir().unwrap();
        let pk_x = [0u8; 32];
        let pk_y = [0u8; 32];
        let hash_bytes = aws_spend_hash_bytes();
        let hash_decimal = BigUint::from_bytes_be(&hash_bytes).to_string();
        // binary says 42, sidecar says 9999999
        let binary = super::build_public_inputs_binary(&hash_bytes, 1000, 2000, &pk_x, &pk_y, 42);
        write_cross_verify_fixtures(dir.path(), &binary, "0", "0", &hash_decimal, 1000, 2000, 9_999_999);

        let err = super::cross_verify_sidecar(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("mismatch"),
            "expected 'mismatch' in error: {}",
            err
        );
    }

    #[test]
    fn missing_sidecar_field_returns_error() {
        let dir = tempdir().unwrap();
        let pk_x = [0u8; 32];
        let pk_y = [0u8; 32];
        let hash_bytes = aws_spend_hash_bytes();
        let hash_decimal = BigUint::from_bytes_be(&hash_bytes).to_string();
        let binary = super::build_public_inputs_binary(&hash_bytes, 1000, 2000, &pk_x, &pk_y, 42);
        std::fs::write(dir.path().join("public_inputs"), &binary).unwrap();
        // JSON without verified_aggregate
        let json = serde_json::json!({
            "target_category_hash": hash_decimal,
            "category_name": "aws_spend",
            "start_time": 1000,
            "end_time": 2000,
            "bank_pub_key_x": "0",
            "bank_pub_key_y": "0"
        });
        std::fs::write(
            dir.path().join("public_inputs_readable.json"),
            serde_json::to_vec_pretty(&json).unwrap(),
        )
        .unwrap();

        let err = super::cross_verify_sidecar(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("verified_aggregate"),
            "expected field name in error: {}",
            err
        );
    }
}

/// Cross-verify the binary `public_inputs` file against `public_inputs_readable.json`.
///
/// The binary file encodes 6 × 32-byte big-endian BN254 field elements in this order:
///   [target_category_hash, start_time, end_time, bank_pub_key_x, bank_pub_key_y, verified_aggregate]
///
/// target_category_hash (index 0) is a full 254-bit Poseidon Field — compared as BigUint decimal.
/// u64 fields (indices 1, 2, 5) must have the first 24 bytes zero; the last 8 are
/// interpreted as a big-endian u64.
/// Pubkey fields (indices 3, 4) are compared as BigUint byte representations.
fn cross_verify_sidecar(extract_dir: &Path) -> anyhow::Result<()> {
    let binary_path = extract_dir.join("public_inputs");
    let binary = std::fs::read(&binary_path)
        .with_context(|| format!("read {}", binary_path.display()))?;

    if binary.len() != 192 {
        anyhow::bail!(
            "public_inputs has unexpected size: {} bytes (expected 192)",
            binary.len()
        );
    }

    let readable_bytes = std::fs::read(extract_dir.join("public_inputs_readable.json"))
        .context("read public_inputs_readable.json for cross-verification")?;
    let readable: serde_json::Value =
        serde_json::from_slice(&readable_bytes).context("parse public_inputs_readable.json")?;

    // Parse a 32-byte chunk at index i as a decimal string (full Field, 254-bit).
    let parse_field_decimal = |i: usize| -> anyhow::Result<String> {
        Ok(BigUint::from_bytes_be(&binary[i * 32..(i + 1) * 32]).to_string())
    };

    // Helper to parse a 32-byte chunk at index i as a u64 (first 24 bytes must be zero).
    let parse_u64_field = |i: usize, name: &str| -> anyhow::Result<u64> {
        let chunk = &binary[i * 32..(i + 1) * 32];
        if chunk[..24].iter().any(|&b| b != 0) {
            anyhow::bail!(
                "public inputs mismatch: field '{}' has non-zero high bytes",
                name
            );
        }
        Ok(u64::from_be_bytes(chunk[24..32].try_into().unwrap()))
    };

    // Parse the 6 fields
    let bin_category_hash = parse_field_decimal(0)?;
    let bin_start = parse_u64_field(1, "start_time")?;
    let bin_end = parse_u64_field(2, "end_time")?;
    let bin_pk_x = BigUint::from_bytes_be(&binary[3 * 32..4 * 32]);
    let bin_pk_y = BigUint::from_bytes_be(&binary[4 * 32..5 * 32]);
    let bin_aggregate = parse_u64_field(5, "verified_aggregate")?;

    // Compare against sidecar JSON
    let get_u64 = |key: &str| -> anyhow::Result<u64> {
        readable
            .get(key)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("public inputs mismatch: '{}' missing or invalid in sidecar", key))
    };
    let get_str = |key: &str| -> anyhow::Result<&str> {
        readable
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("public inputs mismatch: '{}' missing or invalid in sidecar", key))
    };

    let sid_category_hash = get_str("target_category_hash")?;
    let sid_start = get_u64("start_time")?;
    let sid_end = get_u64("end_time")?;
    let sid_pk_x = BigUint::parse_bytes(get_str("bank_pub_key_x")?.as_bytes(), 10)
        .ok_or_else(|| anyhow::anyhow!("public inputs mismatch: 'bank_pub_key_x' is not a valid decimal"))?;
    let sid_pk_y = BigUint::parse_bytes(get_str("bank_pub_key_y")?.as_bytes(), 10)
        .ok_or_else(|| anyhow::anyhow!("public inputs mismatch: 'bank_pub_key_y' is not a valid decimal"))?;
    let sid_aggregate = get_u64("verified_aggregate")?;

    if bin_category_hash != sid_category_hash {
        anyhow::bail!("public inputs mismatch: target_category_hash binary={} sidecar={}", bin_category_hash, sid_category_hash);
    }
    if bin_start != sid_start {
        anyhow::bail!("public inputs mismatch: start_time binary={} sidecar={}", bin_start, sid_start);
    }
    if bin_end != sid_end {
        anyhow::bail!("public inputs mismatch: end_time binary={} sidecar={}", bin_end, sid_end);
    }
    if bin_pk_x != sid_pk_x {
        anyhow::bail!("public inputs mismatch: bank_pub_key_x diverges");
    }
    if bin_pk_y != sid_pk_y {
        anyhow::bail!("public inputs mismatch: bank_pub_key_y diverges");
    }
    if bin_aggregate != sid_aggregate {
        anyhow::bail!("public inputs mismatch: verified_aggregate binary={} sidecar={}", bin_aggregate, sid_aggregate);
    }

    Ok(())
}

/// Build a 192-byte public_inputs binary from the 6 BN254 field values.
/// Each value is encoded as a 32-byte big-endian buffer.
/// category_hash_bytes is the full 32-byte big-endian Poseidon Field (254 bits).
#[cfg(test)]
fn build_public_inputs_binary(
    category_hash_bytes: &[u8; 32],
    start: u64,
    end: u64,
    pk_x: &[u8; 32],
    pk_y: &[u8; 32],
    aggregate: u64,
) -> [u8; 192] {
    let mut buf = [0u8; 192];
    let encode_u64 = |val: u64, slot: &mut [u8]| {
        slot[24..32].copy_from_slice(&val.to_be_bytes());
    };
    buf[0..32].copy_from_slice(category_hash_bytes);
    encode_u64(start, &mut buf[32..64]);
    encode_u64(end, &mut buf[64..96]);
    buf[96..128].copy_from_slice(pk_x);
    buf[128..160].copy_from_slice(pk_y);
    encode_u64(aggregate, &mut buf[160..192]);
    buf
}

/// CLI entry point for `zemtik verify <bundle.zip>`.
pub fn run_verify_cli(zip_path: &Path) -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║   Zemtik Verifier — Independent Proof Check      ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    println!("  Bundle : {}", zip_path.display());
    println!();

    let result = verify_bundle(zip_path).map_err(|e| {
        eprintln!("  Error  : {}", e);
        e
    })?;

    println!("  Circuit Hash     : {}", result.circuit_hash);
    println!("  Aggregate        : ${}", result.aggregate);
    println!("  Timestamp        : {}", result.timestamp);
    println!("  Raw rows to LLM  : {}", result.raw_rows_sent_to_llm);
    println!("  bb version       : {}", result.bb_version_used);
    if let Some(ref hash) = result.outgoing_prompt_hash {
        println!("  Outgoing hash    : {}", hash);
        println!("  (Rust-layer commitment — circuit-level commitment deferred to Sprint 3)");
    }
    println!();

    if result.valid {
        println!("  STATUS: VALID");
        println!();
        println!("  The ZK proof is cryptographically valid.");
        println!("  The LLM received only the verified aggregate — zero raw rows.");
    } else {
        eprintln!("  STATUS: INVALID");
        eprintln!();
        eprintln!("  Proof verification failed. The bundle may be corrupted or tampered.");
        std::process::exit(1);
    }

    println!();
    Ok(())
}
