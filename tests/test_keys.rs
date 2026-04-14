use ed25519_dalek::{Signer, Verifier};
use tempfile::tempdir;
use zemtik::keys::{derive_manifest_signing_keypair, load_or_generate_key};

// ── derive_manifest_signing_keypair tests ────────────────────────────────────

/// Derivation must be deterministic: same seed → same keypair every call.
#[test]
fn test_manifest_signing_keypair_deterministic() {
    let seed = [0x42u8; 32];
    let (sk1, vk1) = derive_manifest_signing_keypair(&seed).unwrap();
    let (sk2, vk2) = derive_manifest_signing_keypair(&seed).unwrap();
    // Compare verifying keys (public portion) — SigningKey doesn't implement PartialEq directly
    assert_eq!(vk1.as_bytes(), vk2.as_bytes(), "same seed must yield same verifying key");
    // Sign same payload with both, verify with their verifying keys
    let sig1 = sk1.sign(b"test payload");
    let sig2 = sk2.sign(b"test payload");
    assert_eq!(sig1.to_bytes(), sig2.to_bytes(), "same seed must yield same signature");
}

/// Sign with the derived signing key; verify with the derived verifying key → Ok.
#[test]
fn test_manifest_signing_roundtrip() {
    let seed = [0xABu8; 32];
    let (signing_key, verifying_key) = derive_manifest_signing_keypair(&seed).unwrap();
    let payload = b"zemtik manifest payload v3";
    let signature = signing_key.sign(payload);
    verifying_key.verify(payload, &signature).expect("signature must verify");
}

/// Different seeds must produce different verifying keys (no key collision).
#[test]
fn test_manifest_signing_keypair_unique_per_seed() {
    let seed_a = [0x01u8; 32];
    let seed_b = [0x02u8; 32];
    let (_, vk_a) = derive_manifest_signing_keypair(&seed_a).unwrap();
    let (_, vk_b) = derive_manifest_signing_keypair(&seed_b).unwrap();
    assert_ne!(vk_a.as_bytes(), vk_b.as_bytes(), "different seeds must produce different keys");
}

/// A signature over payload A must NOT verify against payload B.
#[test]
fn test_manifest_sig_rejects_tampered_payload() {
    let seed = [0x7Fu8; 32];
    let (signing_key, verifying_key) = derive_manifest_signing_keypair(&seed).unwrap();
    let original = b"original manifest payload";
    let tampered = b"tampered manifest payload";
    let signature = signing_key.sign(original);
    let result = verifying_key.verify(tampered, &signature);
    assert!(result.is_err(), "signature over original must not verify against tampered payload");
}


#[test]
fn first_run_generates_key() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("bank_sk");

    let _key = load_or_generate_key(dir.path()).unwrap();

    assert!(key_path.exists());
    let bytes = std::fs::read(&key_path).unwrap();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn second_run_loads_same_key() {
    let dir = tempdir().unwrap();

    let key1 = load_or_generate_key(dir.path()).unwrap();
    let key2 = load_or_generate_key(dir.path()).unwrap();

    assert_eq!(
        key1.public().x.to_string(),
        key2.public().x.to_string()
    );
    assert_eq!(
        key1.public().y.to_string(),
        key2.public().y.to_string()
    );
}

#[test]
fn corrupt_key_file_returns_error() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("bank_sk");
    std::fs::write(&key_path, b"short").unwrap();

    let result = load_or_generate_key(dir.path());
    assert!(result.is_err());
}

#[test]
fn missing_dir_is_created() {
    let dir = tempdir().unwrap();
    let nested = dir.path().join("a").join("b").join("keys");

    let _key = load_or_generate_key(&nested).unwrap();

    assert!(nested.exists());
    assert!(nested.join("bank_sk").exists());
}
