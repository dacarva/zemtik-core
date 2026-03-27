use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zip::write::SimpleFileOptions;

use crate::types::{QueryParams, SignatureData};

const CIRCUIT_DIR: &str = "circuit";

pub struct BundleResult {
    pub bundle_id: String,
    pub bundle_path: PathBuf,
    pub circuit_hash: String,
    pub bb_version: String,
}

/// Detect the installed `bb` version string (e.g. "4.0.0-nightly").
/// Returns "unknown" if `bb --version` fails or output can't be parsed.
pub fn detect_bb_version() -> String {
    let Ok(out) = Command::new("bb").arg("--version").output() else {
        return "unknown".to_owned();
    };
    let raw = String::from_utf8_lossy(&out.stdout);
    // bb --version prints something like: "bbup version 0.x.x" or "0.x.x" or "4.0.0-nightly"
    // Take the last whitespace-delimited token.
    raw.split_whitespace()
        .last()
        .unwrap_or("unknown")
        .trim()
        .to_owned()
}

/// Parse a `bb` version string into (major, minor, patch), ignoring suffixes like `-nightly`.
/// Returns None on parse failure.
pub fn parse_bb_version(raw: &str) -> Option<(u32, u32, u32)> {
    // Split on whitespace, take last token (handles "bbup version X.Y.Z")
    let token = raw.split_whitespace().last()?;
    // Strip any suffix like "-nightly" → take first "-"-delimited segment
    let semver = token.split('-').next()?;
    let mut parts = semver.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::parse_bb_version;

    #[test]
    fn test_parse_bb_version_plain() {
        assert_eq!(parse_bb_version("4.0.0"), Some((4, 0, 0)));
    }

    #[test]
    fn test_parse_bb_version_nightly_suffix() {
        assert_eq!(parse_bb_version("4.0.0-nightly"), Some((4, 0, 0)));
    }

    #[test]
    fn test_parse_bb_version_bbup_prefix() {
        assert_eq!(parse_bb_version("bbup version 0.5.1"), Some((0, 5, 1)));
    }

    #[test]
    fn test_parse_bb_version_empty() {
        assert_eq!(parse_bb_version(""), None);
    }

    #[test]
    fn test_parse_bb_version_non_semver() {
        assert_eq!(parse_bb_version("invalid"), None);
        assert_eq!(parse_bb_version("4.0"), None);
    }
}

/// Generate a portable proof bundle ZIP after a successful ZK proof.
///
/// Reads raw artifacts from `circuit/proofs/proof/` and writes them atomically
/// to `~/.zemtik/receipts/{uuid}.zip` via a temp file + rename.
///
/// Bundle contents:
///   proof.bin                — raw proof bytes (for `bb verify -p`)
///   vk.bin                   — verification key (for `bb verify -k`)
///   public_inputs            — raw binary public inputs (for `bb verify -i`)
///   public_inputs_readable.json — human-readable labeled public inputs
///   circuit_hash.txt         — SHA-256 of circuit/target/zemtik_circuit.json
///   request_meta.json        — bundle metadata
pub fn generate_bundle(
    params: &QueryParams,
    aggregate: u64,
    proof_status: &str,
    sig: &SignatureData,
    request_hash: Option<&str>,
    prompt_hash: Option<&str>,
) -> anyhow::Result<BundleResult> {
    let bundle_id = Uuid::new_v4().to_string();
    let bb_version = detect_bb_version();
    let timestamp = Utc::now().to_rfc3339();

    // Paths to proof artifacts produced by `bb prove`
    let proof_path = PathBuf::from(CIRCUIT_DIR).join("proofs/proof/proof");
    let vk_path = PathBuf::from(CIRCUIT_DIR).join("proofs/proof/vk");
    let public_inputs_path = PathBuf::from(CIRCUIT_DIR).join("proofs/proof/public_inputs");
    let circuit_json_path = PathBuf::from(CIRCUIT_DIR).join("target/zemtik_circuit.json");

    // Compute circuit hash
    let circuit_bytes = std::fs::read(&circuit_json_path)
        .with_context(|| format!("read {}", circuit_json_path.display()))?;
    let circuit_hash = hex::encode(Sha256::digest(&circuit_bytes));

    // Read raw proof artifacts
    let proof_bytes = std::fs::read(&proof_path)
        .with_context(|| format!("read proof from {}", proof_path.display()))?;
    let vk_bytes = std::fs::read(&vk_path)
        .with_context(|| format!("read vk from {}", vk_path.display()))?;
    let public_inputs_bytes = std::fs::read(&public_inputs_path)
        .with_context(|| format!("read public_inputs from {}", public_inputs_path.display()))?;

    // Build human-readable public inputs JSON
    let public_inputs_readable = serde_json::json!({
        "target_category": params.target_category,
        "start_time": params.start_time,
        "end_time": params.end_time,
        "bank_pub_key_x": sig.pub_key_x,
        "bank_pub_key_y": sig.pub_key_y,
        "verified_aggregate": aggregate
    });
    let public_inputs_readable_bytes =
        serde_json::to_vec_pretty(&public_inputs_readable).context("serialize public_inputs_readable")?;

    // Build request_meta.json
    let request_meta = serde_json::json!({
        "bundle_id": bundle_id,
        "bundle_version": 1,
        "request_hash": request_hash.unwrap_or(""),
        "prompt_hash": prompt_hash.unwrap_or(""),
        "timestamp_utc": timestamp,
        "bb_version": bb_version,
        "proof_status": proof_status,
        "raw_rows_sent_to_llm": 0,
        "query_params": {
            "client_id": params.client_id,
            "target_category": params.target_category,
            "category_name": params.category_name,
            "start_time": params.start_time,
            "end_time": params.end_time
        }
    });
    let request_meta_bytes =
        serde_json::to_vec_pretty(&request_meta).context("serialize request_meta")?;

    // Resolve output paths
    let home = dirs::home_dir().context("could not resolve home directory")?;
    let base = home.join(".zemtik");
    let tmp_dir = base.join(".tmp");
    let receipts_dir = base.join("receipts");
    std::fs::create_dir_all(&tmp_dir)
        .with_context(|| format!("create {}", tmp_dir.display()))?;
    std::fs::create_dir_all(&receipts_dir)
        .with_context(|| format!("create {}", receipts_dir.display()))?;

    let tmp_path = tmp_dir.join(format!("{}.zip.tmp", bundle_id));
    let final_path = receipts_dir.join(format!("{}.zip", bundle_id));

    // Write ZIP to temp file, then rename atomically
    {
        let file = std::fs::File::create(&tmp_path)
            .with_context(|| format!("create temp zip {}", tmp_path.display()))?;
        let mut zip = zip::ZipWriter::new(file);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        zip.start_file("proof.bin", opts).context("zip start proof.bin")?;
        std::io::Write::write_all(&mut zip, &proof_bytes).context("zip write proof.bin")?;

        zip.start_file("vk.bin", opts).context("zip start vk.bin")?;
        std::io::Write::write_all(&mut zip, &vk_bytes).context("zip write vk.bin")?;

        zip.start_file("public_inputs", opts).context("zip start public_inputs")?;
        std::io::Write::write_all(&mut zip, &public_inputs_bytes).context("zip write public_inputs")?;

        zip.start_file("public_inputs_readable.json", opts)
            .context("zip start public_inputs_readable.json")?;
        std::io::Write::write_all(&mut zip, &public_inputs_readable_bytes)
            .context("zip write public_inputs_readable.json")?;

        zip.start_file("circuit_hash.txt", opts).context("zip start circuit_hash.txt")?;
        std::io::Write::write_all(&mut zip, circuit_hash.as_bytes()).context("zip write circuit_hash.txt")?;

        zip.start_file("request_meta.json", opts).context("zip start request_meta.json")?;
        std::io::Write::write_all(&mut zip, &request_meta_bytes).context("zip write request_meta.json")?;

        zip.finish().context("zip finish")?;
    }

    std::fs::rename(&tmp_path, &final_path).with_context(|| {
        format!("rename {} → {}", tmp_path.display(), final_path.display())
    })?;

    Ok(BundleResult {
        bundle_id,
        bundle_path: final_path,
        circuit_hash,
        bb_version,
    })
}
