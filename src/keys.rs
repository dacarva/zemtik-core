use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;
use babyjubjub_rs::PrivateKey;
use rand::Rng;

/// Load the bank's signing key from `keys_dir/bank_sk`, or generate and persist
/// a fresh 32-byte random key if the file doesn't exist.
pub fn load_or_generate_key(keys_dir: &Path) -> anyhow::Result<PrivateKey> {
    std::fs::create_dir_all(keys_dir)
        .with_context(|| format!("create keys directory {}", keys_dir.display()))?;

    let key_path = keys_dir.join("bank_sk");
    if key_path.exists() {
        let bytes = std::fs::read(&key_path)
            .with_context(|| format!("read key from {}", key_path.display()))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "corrupt key file at {}: expected 32 bytes, got {}",
                key_path.display(),
                bytes.len()
            );
        }
        PrivateKey::import(bytes)
            .map_err(|e| anyhow::anyhow!("import key from {}: {}", key_path.display(), e))
    } else {
        let seed: [u8; 32] = rand::thread_rng().gen();
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .and_then(|mut f| f.write_all(&seed))
        {
            Ok(()) => PrivateKey::import(seed.to_vec())
                .map_err(|e| anyhow::anyhow!("import generated key: {}", e)),
            // Race: another process created the file between our exists() check and open().
            // Fall back to reading the file that already exists.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let bytes = std::fs::read(&key_path)
                    .with_context(|| format!("read key from {}", key_path.display()))?;
                if bytes.len() != 32 {
                    anyhow::bail!(
                        "corrupt key file at {}: expected 32 bytes, got {}",
                        key_path.display(),
                        bytes.len()
                    );
                }
                PrivateKey::import(bytes)
                    .map_err(|e| anyhow::anyhow!("import key from {}: {}", key_path.display(), e))
            }
            Err(e) => Err(e).with_context(|| format!("write key to {}", key_path.display())),
        }
    }
}
