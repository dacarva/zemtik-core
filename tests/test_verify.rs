use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use zemtik::keys::derive_manifest_signing_keypair;
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

// ---------------------------------------------------------------------------
// v3 manifest: ed25519 signing + 5-artifact hash coverage
// ---------------------------------------------------------------------------

/// Build a valid v3 bundle with a real ed25519 manifest_sig.
fn make_v3_bundle(path: &Path, seed: &[u8; 32], tamper: Option<&str>) {
    // v3 field layout (7 × 32 bytes = 224):
    //   [0] target_category_hash  [1] start_time  [2] end_time
    //   [3] bank_pub_key_x        [4] bank_pub_key_y
    //   [5] outgoing_prompt_hash  [6] verified_aggregate
    // u64 values live in the last 8 bytes of each 32-byte field.
    let mut pi = [0u8; 224];
    pi[56..64].copy_from_slice(&1000u64.to_be_bytes());  // field[1] last 8 = start_time
    pi[88..96].copy_from_slice(&2000u64.to_be_bytes());  // field[2] last 8 = end_time
    // field[5] = outgoing_prompt_hash: non-zero to match circuit assert(outgoing_prompt_hash != 0)
    pi[160..192].copy_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
    ]); // SHA-256(test prompt) simplified as 0x...42 (non-zero, fits BN254 field)
    pi[216..224].copy_from_slice(&42u64.to_be_bytes()); // field[6] last 8 = aggregate

    let oph_hex = "0x0000000000000000000000000000000000000000000000000000000000000042";

    let sidecar = serde_json::json!({
        "target_category_hash": "0",
        "category_name": "aws_spend",
        "start_time": 1000u64,
        "end_time": 2000u64,
        "bank_pub_key_x": "0",
        "bank_pub_key_y": "0",
        "outgoing_prompt_hash": oph_hex,
        "verified_aggregate": 42u64,
        "agg_type": "SUM",
        "actual_row_count": null
    });
    let sidecar_bytes = serde_json::to_vec_pretty(&sidecar).unwrap();
    let proof_bytes: &[u8] = b"dummy_proof";
    let vk_bytes: &[u8]    = b"dummy_vk";
    let pi_bytes: &[u8]    = &pi;

    let request_meta = serde_json::json!({
        "bundle_id": "test-v3",
        "bundle_version": 3,
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "bb_version": "4.0.0",
        "proof_status": "VALID",
        "raw_rows_sent_to_llm": 0,
        "outgoing_prompt_hash": oph_hex,
        "agg_type": "SUM",
        "query_params": {}
    });
    let rm_bytes = serde_json::to_vec_pretty(&request_meta).unwrap();

    let proof_hash   = format!("sha256:{}", hex::encode(Sha256::digest(proof_bytes)));
    let vk_hash      = format!("sha256:{}", hex::encode(Sha256::digest(vk_bytes)));
    let pi_hash      = format!("sha256:{}", hex::encode(Sha256::digest(pi_bytes)));
    let sidecar_hash = format!("sha256:{}", hex::encode(Sha256::digest(&sidecar_bytes)));
    let rm_hash      = format!("sha256:{}", hex::encode(Sha256::digest(&rm_bytes)));

    // JCS: BTreeMap → sorted keys, compact JSON.
    let mut payload_map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    payload_map.insert("algorithm",          serde_json::json!("sha256"));
    payload_map.insert("bundle_version",     serde_json::json!(3u32));
    payload_map.insert("created_at",         serde_json::json!("2026-01-01T00:00:00Z"));
    payload_map.insert("proof_hash",         serde_json::json!(proof_hash));
    payload_map.insert("public_inputs_hash", serde_json::json!(pi_hash));
    payload_map.insert("request_meta_hash",  serde_json::json!(rm_hash));
    payload_map.insert("sidecar_hash",       serde_json::json!(sidecar_hash));
    payload_map.insert("vk_hash",            serde_json::json!(vk_hash));

    let signing_payload = serde_json::to_string(&payload_map).unwrap();
    let (signing_key, _) = derive_manifest_signing_keypair(seed).unwrap();
    let signature = signing_key.sign(signing_payload.as_bytes());
    let manifest_sig_hex = hex::encode(signature.to_bytes());

    // Allow tampering scenarios.
    let final_sig = if tamper == Some("sig") {
        format!("00{}", &manifest_sig_hex[2..]) // flip first byte
    } else {
        manifest_sig_hex
    };

    let actual_rm_bytes = if tamper == Some("request_meta") {
        serde_json::to_vec_pretty(&serde_json::json!({"tampered": true})).unwrap()
    } else {
        rm_bytes
    };

    let mut manifest_payload = payload_map;
    manifest_payload.insert("manifest_sig", serde_json::json!(final_sig));

    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("proof.bin", opts).unwrap();    zip.write_all(proof_bytes).unwrap();
    zip.start_file("vk.bin", opts).unwrap();       zip.write_all(vk_bytes).unwrap();
    zip.start_file("public_inputs", opts).unwrap();zip.write_all(pi_bytes).unwrap();
    zip.start_file("public_inputs_readable.json", opts).unwrap();
    zip.write_all(&sidecar_bytes).unwrap();
    zip.start_file("circuit_hash.txt", opts).unwrap();
    zip.write_all(b"aaabbbccc").unwrap();
    zip.start_file("request_meta.json", opts).unwrap();
    zip.write_all(&actual_rm_bytes).unwrap();
    zip.start_file("manifest.json", opts).unwrap();
    zip.write_all(&serde_json::to_vec_pretty(&manifest_payload).unwrap()).unwrap();
    zip.finish().unwrap();
}

/// v3 valid manifest_sig — end-to-end test using the LOCAL bank_sk.
///
/// verify_bundle hardcodes ~/.zemtik/keys/bank_sk as the key source.
/// This test reads the actual key (if it exists), uses it to sign a bundle,
/// and expects no integrity error. If no key exists, the test is skipped.
///
/// NOTE: A full refactor of verify_bundle to accept an optional key path
/// would make this test truly hermetic. Tracked in TODOS.md.
#[test]
fn test_v3_valid_manifest_sig_passes_integrity_with_local_key() {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return, // can't resolve home → skip
    };
    let sk_path = home.join(".zemtik").join("keys").join("bank_sk");
    let sk_bytes = match std::fs::read(&sk_path) {
        Ok(b) if b.len() == 32 => b,
        _ => return, // no key or wrong size → skip (expected in CI)
    };
    let seed: [u8; 32] = sk_bytes.try_into().unwrap();

    let tmp = std::env::temp_dir().join(format!("v3-valid-local-{}.zip", std::process::id()));
    make_v3_bundle(&tmp, &seed, None);

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    if let Err(e) = &result {
        let msg = e.to_string();
        assert!(
            !msg.contains("integrity check FAILED") && !msg.contains("hash mismatch"),
            "valid v3 bundle (signed with local bank_sk) must not fail integrity check, got: {}",
            msg
        );
    }
    let _ = std::fs::remove_file(&tmp);
}

/// v3 tampered manifest_sig → must return Err (sig invalid or key-load failure in CI).
#[test]
fn test_v3_tampered_manifest_sig_rejected() {
    let tmp = std::env::temp_dir().join(format!("v3-tampered-sig-{}.zip", std::process::id()));
    let seed = [0x22u8; 32];
    make_v3_bundle(&tmp, &seed, Some("sig"));

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    assert!(result.is_err(), "tampered manifest_sig must not pass verification");
    let msg = result.unwrap_err().to_string();
    let is_sig_error = msg.contains("integrity check FAILED") || msg.contains("manifest signature");
    let is_key_error = msg.contains("bank_sk") || msg.contains("keys");
    assert!(
        is_sig_error || is_key_error,
        "error must be sig or key-related, got: {}",
        msg
    );
    let _ = std::fs::remove_file(&tmp);
}

/// v3 request_meta tampered after signing → Err (hash mismatch or key-load in CI).
/// Guards against the bundle-demotion attack: edit request_meta.json to flip bundle_version.
#[test]
fn test_v3_tampered_request_meta_rejected() {
    let tmp = std::env::temp_dir().join(format!("v3-tampered-rm-{}.zip", std::process::id()));
    let seed = [0x33u8; 32];
    make_v3_bundle(&tmp, &seed, Some("request_meta"));

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    assert!(result.is_err(), "tampered request_meta must not pass verification");
    let _ = std::fs::remove_file(&tmp);
}

/// Bundle with 224-byte public_inputs (v3 size) but request_meta claiming bundle_version=2
/// → demotion attack detected: bail before manifest_sig check.
#[test]
fn test_v3_demotion_attack_detected() {
    let tmp = std::env::temp_dir().join(format!("v3-demotion-{}.zip", std::process::id()));
    let seed = [0x44u8; 32];

    // make_v3_bundle builds a proper 224-byte public_inputs bundle, but
    // we need to override the request_meta to claim bundle_version=2.
    // Build the bundle manually.
    let mut pi = [0u8; 224];
    pi[56..64].copy_from_slice(&1000u64.to_be_bytes());
    pi[88..96].copy_from_slice(&2000u64.to_be_bytes());
    pi[216..224].copy_from_slice(&42u64.to_be_bytes()); // aggregate at field[6]

    let sidecar = serde_json::json!({
        "target_category_hash": "0",
        "category_name": "aws_spend",
        "start_time": 1000u64,
        "end_time": 2000u64,
        "bank_pub_key_x": "0",
        "bank_pub_key_y": "0",
        "outgoing_prompt_hash": "0x0000000000000000000000000000000000000000000000000000000000000042",
        "verified_aggregate": 42u64,
        "agg_type": "SUM",
        "actual_row_count": null
    });
    let sidecar_bytes = serde_json::to_vec_pretty(&sidecar).unwrap();

    // DEMOTION: request_meta claims bundle_version=2, but pi is 224 bytes (v3 size).
    let request_meta_demoted = serde_json::json!({
        "bundle_id": "demotion-test",
        "bundle_version": 2, // <-- attacker demotes from 3 to 2
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "bb_version": "4.0.0",
        "proof_status": "VALID",
        "raw_rows_sent_to_llm": 0,
    });

    // Build a fake manifest (v2 style, no sig) to pass the manifest-present check.
    let sidecar_hash = format!("sha256:{}", hex::encode(Sha256::digest(&sidecar_bytes)));
    let manifest = serde_json::json!({
        "zemtik_version": "0.5.1",
        "bundle_version": 2,
        "created_at": "2026-01-01T00:00:00Z",
        "sidecar_hash": sidecar_hash,
        "algorithm": "sha256"
    });

    let file = std::fs::File::create(&tmp).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("proof.bin", opts).unwrap();      zip.write_all(b"dummy").unwrap();
    zip.start_file("vk.bin", opts).unwrap();         zip.write_all(b"dummy").unwrap();
    zip.start_file("public_inputs", opts).unwrap();  zip.write_all(&pi).unwrap();
    zip.start_file("public_inputs_readable.json", opts).unwrap();
    zip.write_all(&sidecar_bytes).unwrap();
    zip.start_file("circuit_hash.txt", opts).unwrap();
    zip.write_all(b"aaabbbccc").unwrap();
    zip.start_file("request_meta.json", opts).unwrap();
    zip.write_all(&serde_json::to_vec_pretty(&request_meta_demoted).unwrap()).unwrap();
    zip.start_file("manifest.json", opts).unwrap();
    zip.write_all(&serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    zip.finish().unwrap();

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    assert!(result.is_err(), "demotion attack must not pass verification");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("demotion") || msg.contains("bundle_version"),
        "error must mention demotion or bundle_version, got: {}",
        msg
    );
    let _ = std::fs::remove_file(&tmp);
}
