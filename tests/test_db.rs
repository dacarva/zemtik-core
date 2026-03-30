use zemtik::db::{compute_tx_commitment, fr_to_decimal, BATCH_SIZE, Q1_START};
use zemtik::types::Transaction;

fn make_txns(n: usize) -> Vec<Transaction> {
    (0..n)
        .map(|i| Transaction {
            id: i as i64,
            client_id: 1,
            amount: i as u64 + 1,
            category: 2,
            timestamp: Q1_START + i as u64,
        })
        .collect()
}

#[test]
fn compute_tx_commitment_is_deterministic() {
    let txns = make_txns(BATCH_SIZE);
    let h1 = compute_tx_commitment(&txns).unwrap();
    let h2 = compute_tx_commitment(&txns).unwrap();
    assert_eq!(fr_to_decimal(&h1), fr_to_decimal(&h2));
}

#[test]
fn compute_tx_commitment_differs_for_different_inputs() {
    let txns_a = make_txns(BATCH_SIZE);
    let txns_b = {
        let mut b = txns_a.clone();
        b[0].amount += 1;
        b
    };
    let h_a = compute_tx_commitment(&txns_a).unwrap();
    let h_b = compute_tx_commitment(&txns_b).unwrap();
    assert_ne!(fr_to_decimal(&h_a), fr_to_decimal(&h_b));
}
