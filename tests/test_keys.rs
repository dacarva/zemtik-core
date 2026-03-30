use tempfile::tempdir;
use zemtik::keys::load_or_generate_key;

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
