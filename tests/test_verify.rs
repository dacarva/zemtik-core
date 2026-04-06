use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use zemtik::prover::read_verify_timeout;
use zip::write::SimpleFileOptions;

// Serialize all env-var tests — parallel mutation of the same var is racy.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_verify_timeout_env_parsing_default() {
    let _g = ENV_LOCK.lock().unwrap();
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

/// Regression: ISSUE-001 — zip-slip path traversal en verify_bundle
/// Found by /qa on 2026-03-26
#[test]
fn test_zip_slip_entry_rejected_or_sanitized() {
    let tmp = std::env::temp_dir().join(format!("zipslip-test-{}.zip", std::process::id()));
    let file = std::fs::File::create(&tmp).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("../../evil.txt", opts).unwrap();
    zip.write_all(b"should not escape").unwrap();
    zip.finish().unwrap();

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));

    assert!(result.is_err(), "malformed bundle must return an error");

    let evil_path = std::env::temp_dir().parent().unwrap_or(Path::new("/tmp")).join("evil.txt");
    assert!(
        !evil_path.exists(),
        "zip-slip: file was written outside extract dir at {}",
        evil_path.display()
    );

    let _ = std::fs::remove_file(&tmp);
}

/// Regression: ISSUE-001 (edge case) — entry with no filename component
#[test]
fn test_zip_entry_no_filename_returns_error() {
    let tmp = std::env::temp_dir().join(format!("zipslip-noname-{}.zip", std::process::id()));
    let file = std::fs::File::create(&tmp).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("/", opts).unwrap();
    zip.finish().unwrap();

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    assert!(result.is_err(), "entry with no filename must return an error");

    let _ = std::fs::remove_file(&tmp);
}

// ---------------------------------------------------------------------------
// Commit 3: Manifest integrity tests (no bb required — synthetic ZIPs only)
// ---------------------------------------------------------------------------

/// Build a minimal synthetic bundle ZIP with required fields and a valid manifest.
fn make_minimal_bundle(path: &Path, with_manifest: bool, correct_hash: bool) {
    make_minimal_bundle_v(path, with_manifest, correct_hash, 2);
}

fn make_minimal_bundle_v(path: &Path, with_manifest: bool, correct_hash: bool, bundle_version: u64) {
    // Build consistent binary public_inputs and sidecar.
    // Field layout: [target_category_hash(0..32), start(32..64), end(64..96),
    //                pk_x(96..128), pk_y(128..160), aggregate(160..192)]
    // All zeros except aggregate=42 at index 5 (bytes 184..192).
    // target_category_hash = 0 as decimal = "0" (matches zero bytes at index 0).
    // start_time = 1000, end_time = 2000 are at bytes 32..64 and 64..96 (u64 in last 8 bytes).
    let mut pi = [0u8; 192];
    pi[56..64].copy_from_slice(&1000u64.to_be_bytes()); // start_time
    pi[88..96].copy_from_slice(&2000u64.to_be_bytes()); // end_time
    pi[184..192].copy_from_slice(&42u64.to_be_bytes()); // aggregate

    let sidecar = serde_json::json!({
        "target_category_hash": "0",  // matches zero bytes at binary index 0
        "category_name": "aws_spend",
        "start_time": 1000u64,
        "end_time": 2000u64,
        "bank_pub_key_x": "0",
        "bank_pub_key_y": "0",
        "verified_aggregate": 42u64
    });
    let sidecar_bytes = serde_json::to_vec_pretty(&sidecar).unwrap();
    let correct_sidecar_hash = format!("sha256:{}", hex::encode(Sha256::digest(&sidecar_bytes)));

    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("proof.bin", opts).unwrap();
    zip.write_all(b"dummy").unwrap();

    zip.start_file("vk.bin", opts).unwrap();
    zip.write_all(b"dummy").unwrap();

    zip.start_file("public_inputs", opts).unwrap();
    zip.write_all(&pi).unwrap();

    zip.start_file("public_inputs_readable.json", opts).unwrap();
    zip.write_all(&sidecar_bytes).unwrap();

    zip.start_file("circuit_hash.txt", opts).unwrap();
    zip.write_all(b"aaabbbccc").unwrap();

    zip.start_file("request_meta.json", opts).unwrap();
    let meta = serde_json::json!({
        "bundle_id": "test",
        "bundle_version": bundle_version,
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "bb_version": "4.0.0",
        "proof_status": "VALID",
        "raw_rows_sent_to_llm": 0
    });
    zip.write_all(&serde_json::to_vec_pretty(&meta).unwrap()).unwrap();

    if with_manifest {
        zip.start_file("manifest.json", opts).unwrap();
        let hash = if correct_hash {
            correct_sidecar_hash
        } else {
            "sha256:badhash000000000000000000000000000000000000000000000000000000000000".to_owned()
        };
        let manifest = serde_json::json!({
            "zemtik_version": "0.5.1",
            "bundle_version": 2,
            "created_at": "2026-01-01T00:00:00Z",
            "sidecar_hash": hash,
            "algorithm": "sha256"
        });
        zip.write_all(&serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    }

    zip.finish().unwrap();
}

/// Commit 3: wrong sidecar hash in manifest → Err containing "hash mismatch"
#[test]
fn test_manifest_hash_mismatch_detected() {
    let tmp = std::env::temp_dir().join(format!("manifest-mismatch-{}.zip", std::process::id()));
    make_minimal_bundle(&tmp, true, false); // with manifest, bad hash

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    assert!(result.is_err(), "expected Err for hash mismatch, got Ok");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("hash mismatch") || msg.contains("integrity check FAILED"),
        "expected 'hash mismatch' in error, got: {}",
        msg
    );

    let _ = std::fs::remove_file(&tmp);
}

/// Commit 3: correct sidecar hash in manifest → passes integrity check (may still fail at bb)
#[test]
fn test_manifest_hash_matches() {
    let tmp = std::env::temp_dir().join(format!("manifest-match-{}.zip", std::process::id()));
    make_minimal_bundle(&tmp, true, true); // with manifest, correct hash

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    // If bb is available and verifies, Ok — fine.
    // If bb is absent or fails, Err — must NOT contain "hash mismatch" or "integrity check FAILED".
    match &result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("hash mismatch") && !msg.contains("integrity check FAILED"),
                "correct manifest must not trigger integrity error, got: {}",
                msg
            );
        }
        Ok(_) => {} // bb installed and valid proof — fine
    }

    let _ = std::fs::remove_file(&tmp);
}

/// Commit 3: old bundle (bundle_version=1) without manifest.json → backward compat, no manifest error.
/// bundle_version >= 2 requires manifest; bundle_version 1 skips the check.
#[test]
fn test_manifest_absent_old_bundle() {
    let tmp = std::env::temp_dir().join(format!("manifest-absent-{}.zip", std::process::id()));
    make_minimal_bundle_v(&tmp, false, false, 1); // no manifest, bundle_version=1 (old format)

    // verify_bundle will fail at bb version check (bb not in CI), but must NOT fail
    // because of missing manifest — backward compatibility guarantee.
    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    match &result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("manifest") && !msg.contains("hash mismatch"),
                "must not fail on absent manifest, got: {}",
                msg
            );
        }
        Ok(_) => {} // bb installed and verified — fine
    }

    let _ = std::fs::remove_file(&tmp);
}
