use std::io::Write as _;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::Context;
use babyjubjub_rs::PrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

/// Derive an ed25519 manifest-signing keypair from `bank_sk` seed bytes via HKDF-SHA256.
///
/// Derivation spec:
///   IKM  = seed (32 bytes, the `bank_sk` seed)
///   salt = [0u8; 32] (all zeros)
///   info = b"zemtik-manifest-signing-v1"
///   OKM  = 32 bytes → ed25519_dalek::SigningKey::from_bytes
///
/// Key rotation: increment info to "zemtik-manifest-signing-v2" and serve both
/// public keys with timestamps on GET /public-key.
pub fn derive_manifest_signing_keypair(seed: &[u8; 32]) -> anyhow::Result<(SigningKey, VerifyingKey)> {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), seed);
    let mut okm = [0u8; 32];
    hk.expand(b"zemtik-manifest-signing-v1", &mut okm)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed — this should never happen for 32-byte output"))?;
    let signing_key = SigningKey::from_bytes(&okm);
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

/// Load the bank's signing key from `keys_dir/bank_sk`, or generate and persist
/// a fresh 32-byte random key if the file doesn't exist.
///
/// Thread-safe: uses `O_CREAT|O_EXCL` as the exclusive creation mutex so at most
/// one writer ever holds the file open. If the file exists but is still being
/// written (0 bytes in the TOCTOU window), the reader retries up to 10 times.
pub fn load_or_generate_key(keys_dir: &Path) -> anyhow::Result<PrivateKey> {
    std::fs::create_dir_all(keys_dir)
        .with_context(|| format!("create keys directory {}", keys_dir.display()))?;

    let key_path = keys_dir.join("bank_sk");
    let seed: [u8; 32] = rand::thread_rng().gen();

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true).create_new(true);
    #[cfg(unix)]
    open_opts.mode(0o600);
    match open_opts.open(&key_path)
    {
        Ok(mut f) => {
            // We won the creation race — write the seed, clean up on failure.
            match f.write_all(&seed) {
                Ok(()) => PrivateKey::import(seed.to_vec())
                    .map_err(|e| anyhow::anyhow!("import generated key: {}", e)),
                Err(e) => {
                    let _ = std::fs::remove_file(&key_path);
                    Err(e).with_context(|| format!("write key to {}", key_path.display()))
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another thread/process created the file. Retry reading until we see
            // the full 32 bytes — handles the TOCTOU window where the file exists
            // but write_all hasn't completed yet (file is 0 bytes).
            for attempt in 0..10u32 {
                let bytes = std::fs::read(&key_path)
                    .with_context(|| format!("read key from {}", key_path.display()))?;
                if bytes.len() == 32 {
                    return PrivateKey::import(bytes).map_err(|e| {
                        anyhow::anyhow!("import key from {}: {}", key_path.display(), e)
                    });
                }
                if bytes.len() > 32 {
                    anyhow::bail!(
                        "corrupt key file at {}: expected 32 bytes, got {}",
                        key_path.display(),
                        bytes.len()
                    );
                }
                // len < 32: writer is still in progress — wait briefly and retry.
                if attempt < 9 {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            anyhow::bail!(
                "key file at {} remained incomplete after retries",
                key_path.display()
            )
        }
        Err(e) => Err(e).with_context(|| format!("open key file {}", key_path.display())),
    }
}
