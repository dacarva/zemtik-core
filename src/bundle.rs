use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use chrono::Utc;
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zip::write::SimpleFileOptions;

use crate::types::{QueryParams, SignatureData};

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

/// Generate a portable proof bundle ZIP after a successful ZK proof.
///
/// Reads raw artifacts from `run_dir/proofs/proof/`, reads the circuit JSON from
/// `circuit_dir/target/zemtik_circuit.json`, and writes the bundle atomically to
/// `receipts_dir/{uuid}.zip` via a temp file + rename.
///
/// Bundle contents (v3):
///   proof.bin                — raw proof bytes (for `bb verify -p`)
///   vk.bin                   — verification key (for `bb verify -k`)
///   public_inputs            — raw binary public inputs (for `bb verify -i`)
///   public_inputs_readable.json — human-readable labeled public inputs
///   circuit_hash.txt         — SHA-256 of the circuit ACIR JSON
///   manifest.json            — ed25519-signed manifest (v3) with 5 artifact hashes
///   request_meta.json        — bundle metadata
///
/// `signing_key_bytes` must be the 32-byte `bank_sk` seed. An ed25519 signing key
/// is derived via HKDF-SHA256(salt=zeros, info="zemtik-manifest-signing-v1").
/// The manifest is signed using JCS (RFC 8785) canonical JSON.
#[allow(clippy::too_many_arguments)]
pub fn generate_bundle(
    params: &QueryParams,
    aggregate: u64,
    proof_status: &str,
    sig: &SignatureData,
    request_hash: Option<&str>,
    prompt_hash: Option<&str>,
    outgoing_prompt_hash: Option<&str>,
    run_dir: &Path,
    circuit_dir: &Path,
    receipts_dir: &Path,
    agg_type: &str,
    actual_row_count: Option<usize>,
    signing_key_bytes: &[u8],
) -> anyhow::Result<BundleResult> {
    let bundle_id = Uuid::new_v4().to_string();
    let bb_version = detect_bb_version();
    let timestamp = Utc::now().to_rfc3339();

    // Paths to proof artifacts produced by `bb prove`
    let proof_path = run_dir.join("proofs/proof/proof");
    let vk_path = run_dir.join("proofs/proof/vk");
    let public_inputs_path = run_dir.join("proofs/proof/public_inputs");
    let circuit_json_path = circuit_dir.join("target/zemtik_circuit.json");

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

    // Build human-readable public inputs JSON (v3: includes outgoing_prompt_hash)
    let public_inputs_readable = serde_json::json!({
        "target_category_hash": params.target_category_hash,
        "category_name": params.category_name,
        "start_time": params.start_time,
        "end_time": params.end_time,
        "bank_pub_key_x": sig.pub_key_x,
        "bank_pub_key_y": sig.pub_key_y,
        "outgoing_prompt_hash": outgoing_prompt_hash.unwrap_or(""),
        "verified_aggregate": aggregate,
        "agg_type": agg_type,
        "actual_row_count": actual_row_count
    });
    let public_inputs_readable_bytes =
        serde_json::to_vec_pretty(&public_inputs_readable).context("serialize public_inputs_readable")?;

    // Compute SHA-256 hashes for all five artifacts
    let proof_hash_hex = format!("sha256:{}", hex::encode(Sha256::digest(&proof_bytes)));
    let vk_hash_hex = format!("sha256:{}", hex::encode(Sha256::digest(&vk_bytes)));
    let public_inputs_hash_hex = format!("sha256:{}", hex::encode(Sha256::digest(&public_inputs_bytes)));
    let sidecar_hash = format!("sha256:{}", hex::encode(Sha256::digest(&public_inputs_readable_bytes)));

    // Build request_meta.json BEFORE manifest (its hash goes into the manifest)
    let request_meta = serde_json::json!({
        "bundle_id": bundle_id,
        "bundle_version": 3,
        "request_hash": request_hash.unwrap_or(""),
        "prompt_hash": prompt_hash.unwrap_or(""),
        "timestamp_utc": timestamp,
        "bb_version": bb_version,
        "proof_status": proof_status,
        "raw_rows_sent_to_llm": 0,
        "outgoing_prompt_hash": outgoing_prompt_hash.unwrap_or(""),
        "agg_type": agg_type,
        "query_params": {
            "client_id": params.client_id,
            "target_category_hash": params.target_category_hash,
            "category_name": params.category_name,
            "start_time": params.start_time,
            "end_time": params.end_time
        }
    });
    let request_meta_bytes =
        serde_json::to_vec_pretty(&request_meta).context("serialize request_meta")?;
    let request_meta_hash = format!("sha256:{}", hex::encode(Sha256::digest(&request_meta_bytes)));

    // Build v3 manifest and sign with ed25519 (JCS — RFC 8785: sorted keys, compact JSON).
    // Sign-then-embed: build the payload WITHOUT manifest_sig, sign it, then add manifest_sig.
    let manifest_bytes = {
        let seed: [u8; 32] = signing_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing_key_bytes must be exactly 32 bytes"))?;
        let (signing_key, _) = crate::keys::derive_manifest_signing_keypair(&seed)
            .context("derive manifest signing keypair")?;

        // JCS: BTreeMap serializes in alphabetical key order; serde_json compact = no whitespace.
        let mut payload_map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        payload_map.insert("algorithm",          serde_json::json!("sha256"));
        payload_map.insert("bundle_version",     serde_json::json!(3u32));
        payload_map.insert("created_at",         serde_json::json!(timestamp));
        payload_map.insert("proof_hash",         serde_json::json!(proof_hash_hex));
        payload_map.insert("public_inputs_hash", serde_json::json!(public_inputs_hash_hex));
        payload_map.insert("request_meta_hash",  serde_json::json!(request_meta_hash));
        payload_map.insert("sidecar_hash",       serde_json::json!(sidecar_hash));
        payload_map.insert("vk_hash",            serde_json::json!(vk_hash_hex));

        let signing_payload = serde_json::to_string(&payload_map)
            .context("serialize manifest signing payload (JCS)")?;
        let signature = signing_key.sign(signing_payload.as_bytes());
        let manifest_sig = hex::encode(signature.to_bytes()); // 128 hex chars (64-byte ed25519 sig)

        // Add manifest_sig and serialize with pretty-print for storage (readability).
        payload_map.insert("manifest_sig", serde_json::json!(manifest_sig));
        serde_json::to_vec_pretty(&payload_map).context("serialize manifest.json")?
    };

    // Resolve output paths
    let tmp_dir = receipts_dir.parent()
        .map(|p| p.join(".tmp"))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    std::fs::create_dir_all(&tmp_dir)
        .with_context(|| format!("create {}", tmp_dir.display()))?;
    std::fs::create_dir_all(receipts_dir)
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

        zip.start_file("manifest.json", opts).context("zip start manifest.json")?;
        std::io::Write::write_all(&mut zip, &manifest_bytes).context("zip write manifest.json")?;

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
