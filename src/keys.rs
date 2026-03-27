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
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .and_then(|mut f| f.write_all(&seed))
            .with_context(|| format!("write key to {}", key_path.display()))?;
        PrivateKey::import(seed.to_vec())
            .map_err(|e| anyhow::anyhow!("import generated key: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
}
