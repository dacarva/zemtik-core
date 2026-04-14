use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use anyhow::Context;
use ed25519_dalek::Verifier;
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
    pub bundle_version: u64,
    /// SHA-256(original_user_prompt) as BN254 Field, circuit public input #6.
    /// None for bundles generated before v3.
    pub outgoing_prompt_hash: Option<String>,
    /// Whether manifest_sig ed25519 validation passed. None for v2 bundles (no sig).
    pub manifest_sig_valid: Option<bool>,
    /// Number of real (non-dummy padding) rows in the proof.
    pub actual_row_count: Option<u64>,
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
        let actual_row_count = readable
            .get("actual_row_count")
            .and_then(|v| v.as_u64());

        // Verify required files are present
        for required in &["proof.bin", "vk.bin", "public_inputs"] {
            let p = extract_dir.join(required);
            if !p.exists() {
                anyhow::bail!("bundle is missing required file: {}", required);
            }
        }

        // Cross-verify binary public_inputs against the human-readable sidecar
        cross_verify_sidecar(&extract_dir, bundle_version)?;

        // Verify manifest.json.
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

        let mut manifest_sig_valid: Option<bool> = None;

        if manifest_path.exists() {
            let manifest_bytes = std::fs::read(&manifest_path).context("read manifest.json")?;
            let manifest: serde_json::Value =
                serde_json::from_slice(&manifest_bytes).context("parse manifest.json")?;

            // ── v3: validate manifest_sig FIRST, then re-hash all artifacts ──────────
            if bundle_version >= 3 {
                let sig_hex = manifest
                    .get("manifest_sig")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!(
                        "Bundle integrity check FAILED: manifest signature invalid.\n  \
                         The ed25519 signature in manifest.json does not match the bundle's\n  \
                         signing key. This bundle has been tampered with or was signed by a\n  \
                         different key.\n  \
                         To verify independently: GET /public-key and check against\n  \
                         docs/ZK_CIRCUITS.md#independent-verification"
                    ))?;

                // Load bank_sk to derive ed25519 verifying key
                let home = dirs::home_dir().context("could not resolve home directory")?;
                let sk_path = home.join(".zemtik").join("keys").join("bank_sk");
                let sk_bytes = std::fs::read(&sk_path)
                    .with_context(|| format!(
                        "read bank_sk from {} — required for v3 manifest_sig verification",
                        sk_path.display()
                    ))?;
                let seed: [u8; 32] = sk_bytes.as_slice().try_into()
                    .map_err(|_| anyhow::anyhow!("bank_sk must be 32 bytes"))?;
                let (_, verifying_key) = crate::keys::derive_manifest_signing_keypair(&seed)
                    .context("derive manifest verifying key")?;

                // Reconstruct JCS signing payload: all fields except manifest_sig, sorted, compact
                let mut payload_map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
                for key in &["algorithm", "bundle_version", "created_at", "proof_hash",
                             "public_inputs_hash", "request_meta_hash", "sidecar_hash", "vk_hash"] {
                    if let Some(v) = manifest.get(*key) {
                        payload_map.insert(key, v.clone());
                    }
                }
                let signing_payload = serde_json::to_string(&payload_map)
                    .context("reconstruct manifest signing payload")?;

                let sig_bytes = hex::decode(sig_hex).map_err(|_| anyhow::anyhow!(
                    "Bundle integrity check FAILED: manifest signature invalid.\n  \
                     manifest_sig is not valid hex."
                ))?;
                let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!(
                    "Bundle integrity check FAILED: manifest signature invalid.\n  \
                     manifest_sig must be 128 hex chars (64-byte ed25519 signature)."
                ))?;
                let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

                match verifying_key.verify(signing_payload.as_bytes(), &signature) {
                    Ok(()) => {
                        manifest_sig_valid = Some(true);
                    }
                    Err(_) => {
                        anyhow::bail!(
                            "Bundle integrity check FAILED: manifest signature invalid.\n  \
                             The ed25519 signature in manifest.json does not match the bundle's\n  \
                             signing key. This bundle has been tampered with or was signed by a\n  \
                             different key.\n  \
                             To verify independently: GET /public-key and check against\n  \
                             docs/ZK_CIRCUITS.md#independent-verification"
                        );
                    }
                }

                // Re-hash all 5 artifacts from disk (do NOT trust manifest hash values alone)
                let re_hash = |path: &std::path::Path, _label: &str| -> anyhow::Result<String> {
                    let bytes = std::fs::read(path)
                        .with_context(|| format!("re-hash {}", path.display()))?;
                    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
                };
                let check_hash = |manifest_key: &str, actual: &str, label: &str| -> anyhow::Result<()> {
                    let expected = manifest.get(manifest_key).and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("manifest missing field: {}", manifest_key))?;
                    if actual != expected {
                        anyhow::bail!(
                            "Bundle integrity check FAILED: {} hash mismatch.\n  Expected: {}\n  Got:      {}",
                            label, expected, actual
                        );
                    }
                    Ok(())
                };

                let proof_hash = re_hash(&extract_dir.join("proof.bin"), "proof.bin")?;
                check_hash("proof_hash", &proof_hash, "proof artifact")?;

                let vk_hash = re_hash(&extract_dir.join("vk.bin"), "vk.bin")?;
                check_hash("vk_hash", &vk_hash, "VK artifact")?;

                let pi_hash = re_hash(&extract_dir.join("public_inputs"), "public_inputs")?;
                check_hash("public_inputs_hash", &pi_hash, "public inputs artifact")?;

                let sidecar_hash = format!("sha256:{}", hex::encode(Sha256::digest(&readable_bytes)));
                check_hash("sidecar_hash", &sidecar_hash, "sidecar")?;

                let rm_bytes = std::fs::read(extract_dir.join("request_meta.json"))
                    .context("re-hash request_meta.json")?;
                let rm_hash = format!("sha256:{}", hex::encode(Sha256::digest(&rm_bytes)));
                check_hash("request_meta_hash", &rm_hash, "request_meta")?;

            } else {
                // v2: sidecar_hash only
                if let Some(expected) = manifest.get("sidecar_hash").and_then(|v| v.as_str()) {
                    let actual = format!("sha256:{}", hex::encode(Sha256::digest(&readable_bytes)));
                    if actual != expected {
                        anyhow::bail!(
                            "Bundle integrity check FAILED: sidecar hash mismatch.\n  Expected: {}\n  Got:      {}",
                            expected,
                            actual
                        );
                    }
                }
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
        // On timeout, the bb child process is killed and reaped before returning Err.
        let timeout_secs = crate::prover::read_verify_timeout();
        let mut child = Command::new("bb")
            .args([
                "verify",
                "-p", "proof.bin",
                "-k", "vk.bin",
                "-i", "public_inputs",
            ])
            .current_dir(&extract_dir)
            .spawn()
            .context("spawn bb verify")?;

        let status = crate::prover::poll_child_with_timeout(&mut child, timeout_secs)?;
        // Temp dir cleanup happens after this block (in the outer always-run cleanup)
        // which ensures child is already reaped before the directory is removed.

        let valid = status.success();

        Ok(VerifyResult {
            valid,
            circuit_hash,
            aggregate,
            timestamp,
            raw_rows_sent_to_llm,
            bb_version_used,
            bundle_version,
            outgoing_prompt_hash,
            manifest_sig_valid,
            actual_row_count,
        })
    })();

    // Always clean up extracted files
    let _ = std::fs::remove_dir_all(&extract_dir);

    result
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
        binary: &[u8],
        pk_x_decimal: &str,
        pk_y_decimal: &str,
        category_hash: &str,
        start: u64,
        end: u64,
        aggregate: u64,
        outgoing_prompt_hash: Option<&str>,
        bundle_version: u64,
    ) {
        std::fs::write(dir.join("public_inputs"), binary).unwrap();
        let json = serde_json::json!({
            "target_category_hash": category_hash,
            "category_name": "aws_spend",
            "start_time": start,
            "end_time": end,
            "bank_pub_key_x": pk_x_decimal,
            "bank_pub_key_y": pk_y_decimal,
            "outgoing_prompt_hash": outgoing_prompt_hash.unwrap_or(""),
            "verified_aggregate": aggregate
        });
        let _ = bundle_version; // consumed via binary length
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
        write_cross_verify_fixtures(dir.path(), &binary, "0", "0", &hash_decimal, 1000, 2000, 42, None, 2);

        let result = super::cross_verify_sidecar(dir.path(), 2);
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
        write_cross_verify_fixtures(dir.path(), &binary, "0", "0", &hash_decimal, 1000, 2000, 9_999_999, None, 2);

        let err = super::cross_verify_sidecar(dir.path(), 2).unwrap_err();
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

        let err = super::cross_verify_sidecar(dir.path(), 2).unwrap_err();
        assert!(
            err.to_string().contains("verified_aggregate"),
            "expected field name in error: {}",
            err
        );
    }
}

/// Cross-verify the binary `public_inputs` file against `public_inputs_readable.json`.
///
/// v2 (192 bytes = 6 × 32): [target_category_hash, start_time, end_time, bank_pub_key_x, bank_pub_key_y, verified_aggregate]
/// v3 (224 bytes = 7 × 32): [target_category_hash, start_time, end_time, bank_pub_key_x, bank_pub_key_y, outgoing_prompt_hash, verified_aggregate]
///
/// target_category_hash (index 0) is a full 254-bit Poseidon Field — compared as BigUint decimal.
/// u64 fields (start_time, end_time, verified_aggregate) must have the first 24 bytes zero.
/// Pubkey and Field fields are compared as BigUint decimal strings.
fn cross_verify_sidecar(extract_dir: &Path, bundle_version: u64) -> anyhow::Result<()> {
    let binary_path = extract_dir.join("public_inputs");
    let binary = std::fs::read(&binary_path)
        .with_context(|| format!("read {}", binary_path.display()))?;

    let expected_len: usize = if bundle_version >= 3 { 224 } else { 192 };
    if binary.len() != expected_len {
        anyhow::bail!(
            "public_inputs has unexpected size: {} bytes (expected {} for bundle_version {})",
            binary.len(),
            expected_len,
            bundle_version
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

    // Parse the 5 common fields (indices 0-4 same for v2 and v3)
    let bin_category_hash = parse_field_decimal(0)?;
    let bin_start = parse_u64_field(1, "start_time")?;
    let bin_end = parse_u64_field(2, "end_time")?;
    let bin_pk_x = BigUint::from_bytes_be(&binary[3 * 32..4 * 32]);
    let bin_pk_y = BigUint::from_bytes_be(&binary[4 * 32..5 * 32]);

    // v3: index 5 = outgoing_prompt_hash (Field), index 6 = verified_aggregate (u64)
    // v2: index 5 = verified_aggregate (u64)
    let (bin_outgoing_prompt_hash, bin_aggregate) = if bundle_version >= 3 {
        let oph = parse_field_decimal(5)?;
        let agg = parse_u64_field(6, "verified_aggregate")?;
        (Some(oph), agg)
    } else {
        (None, parse_u64_field(5, "verified_aggregate")?)
    };

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

    // v3: check outgoing_prompt_hash field
    if let Some(bin_oph) = bin_outgoing_prompt_hash {
        let sid_oph = get_str("outgoing_prompt_hash")?;
        // Binary is decimal BigUint; sidecar stores hex "0x..." Field element.
        // Both should represent the same 254-bit value.
        let expected_decimal = if let Some(hex_str) = sid_oph.strip_prefix("0x") {
            BigUint::parse_bytes(hex_str.as_bytes(), 16)
                .ok_or_else(|| anyhow::anyhow!("public inputs mismatch: outgoing_prompt_hash in sidecar is not valid hex"))?
                .to_string()
        } else {
            // Already decimal
            sid_oph.to_owned()
        };
        if bin_oph != expected_decimal {
            anyhow::bail!(
                "public inputs mismatch: outgoing_prompt_hash binary={} sidecar={}",
                bin_oph, sid_oph
            );
        }
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
        eprintln!("{}", e);
        e
    })?;

    // ── 7-check output ────────────────────────────────────────────────────────
    if let Some(true) = result.manifest_sig_valid {
        println!("  ✔ Manifest signature (ed25519) — VALID");
    } else if result.bundle_version < 3 {
        println!("  ✔ Manifest integrity (sidecar hash) — VALID (bundle_version < 3, no ed25519 sig)");
    }

    println!("  ✔ Proof artifact hash — sha256 verified");
    println!("  ✔ VK artifact hash — sha256 verified");
    println!("  ✔ Public inputs hash — sha256 verified");
    println!("  ✔ Sidecar hash — sha256 verified");
    if result.bundle_version >= 3 {
        println!("  ✔ Request metadata hash — sha256 verified");
    }

    if let Some(ref hash) = result.outgoing_prompt_hash {
        println!(
            "  ✔ Outgoing prompt commitment — {} (Circuit public input #6 — independently verifiable via GET /public-key)",
            hash
        );
    }

    println!();
    println!("  Circuit Hash  : {}", result.circuit_hash);
    println!("  Aggregate     : {}", result.aggregate);
    println!("  Timestamp     : {}", result.timestamp);
    println!("  bb version    : {}", result.bb_version_used);
    if let Some(count) = result.actual_row_count {
        println!("  Rows in circuit: {} real + {} padding = 500", count, 500u64.saturating_sub(count));
    }
    println!();

    if result.valid {
        println!("  ✔ ZK proof (bb verify) — VALID");
        println!();
        println!("  ✔ ALL CHECKS PASSED — bundle is authentic");
        println!();
        println!("  The ZK proof is cryptographically valid.");
        println!("  The LLM received only the verified aggregate — zero raw rows.");
    } else {
        eprintln!("  ✖ ZK proof (bb verify) — INVALID");
        eprintln!();
        eprintln!("  Proof verification failed. The bundle may be corrupted or tampered.");
        std::process::exit(1);
    }

    println!();
    Ok(())
}
