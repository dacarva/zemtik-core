use tempfile::TempDir;
use zemtik::db::BATCH_SIZE;
use zemtik::prover::{generate_batched_prover_toml, hex_output_to_u64, read_proof_artifacts};
use zemtik::types::{QueryParams, SignatureData, Transaction};

fn dummy_sig() -> SignatureData {
    SignatureData {
        pub_key_x: "1".to_owned(),
        pub_key_y: "2".to_owned(),
        sig_s: "3".to_owned(),
        sig_r8_x: "4".to_owned(),
        sig_r8_y: "5".to_owned(),
    }
}

fn dummy_params() -> QueryParams {
    QueryParams {
        client_id: 1,
        target_category_hash: "12345".to_owned(),
        category_name: "aws_spend".to_owned(),
        start_time: 1_704_067_200,
        end_time: 1_711_929_599,
    }
}

fn dummy_txns(n: usize) -> Vec<Transaction> {
    (0..n)
        .map(|i| Transaction {
            id: i as i64,
            client_id: 1,
            amount: i as u64 + 1,
            category: 2,
            category_name: "aws_spend".to_owned(),
            timestamp: 1_704_067_200 + i as u64,
        })
        .collect()
}

#[test]
fn hex_output_to_u64_parses_hex_with_prefix() {
    assert_eq!(hex_output_to_u64("0xff").unwrap(), 255);
    assert_eq!(hex_output_to_u64("0x0").unwrap(), 0);
    assert_eq!(hex_output_to_u64("0x1").unwrap(), 1);
}

#[test]
fn hex_output_to_u64_parses_hex_without_prefix() {
    assert_eq!(hex_output_to_u64("ff").unwrap(), 255);
    assert_eq!(hex_output_to_u64("64").unwrap(), 100);
}

#[test]
fn hex_output_to_u64_rejects_non_hex() {
    assert!(hex_output_to_u64("xyz").is_err());
}

#[test]
fn generate_batched_prover_toml_creates_file() {
    let dir = TempDir::new().unwrap();
    let txns = dummy_txns(BATCH_SIZE);
    let sig = dummy_sig();
    let params = dummy_params();

    generate_batched_prover_toml(&[(txns, sig)], &params, dir.path()).unwrap();

    let content = std::fs::read_to_string(dir.path().join("Prover.toml")).unwrap();
    assert!(content.contains("target_category_hash = \""));
    assert!(content.contains("[[batches]]"));
    assert!(content.contains("[[batches.transactions]]"));
}

#[test]
fn generate_batched_prover_toml_embeds_query_params() {
    let dir = TempDir::new().unwrap();
    let params = dummy_params();
    let txns = dummy_txns(BATCH_SIZE);
    let sig = dummy_sig();

    generate_batched_prover_toml(&[(txns, sig)], &params, dir.path()).unwrap();

    let content = std::fs::read_to_string(dir.path().join("Prover.toml")).unwrap();
    assert!(content.contains("start_time = \"1704067200\""));
    assert!(content.contains("end_time = \"1711929599\""));
    assert!(content.contains("bank_pub_key_x = \"1\""));
}

#[test]
fn read_proof_artifacts_returns_none_when_files_absent() {
    let dir = TempDir::new().unwrap();
    let result = read_proof_artifacts(dir.path()).unwrap();
    assert!(result.is_none());
}
