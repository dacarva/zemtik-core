use zemtik_lib::{BatchInput, BATCH_COUNT, TX_COUNT, verify_batch_commitment, compute_predicate};
use poseidon::poseidon::bn254;

// Process one batch: commit + verify EdDSA + SUM aggregation.
fn process_batch(
    batch: BatchInput,
    target_category_hash: Field,
    start_time: u64,
    end_time: u64,
    bank_pub_key_x: Field,
    bank_pub_key_y: Field,
) -> Field {
    verify_batch_commitment(batch, bank_pub_key_x, bank_pub_key_y);
    let matches = compute_predicate(batch, target_category_hash, start_time, end_time);

    let mut total: Field = 0;
    for i in 0..TX_COUNT {
        total += if matches[i] { batch.transactions[i].amount as Field } else { 0 };
    }
    total
}

// Zemtik ZK SUM circuit: proves the total sum of matching transactions across
// BATCH_COUNT x TX_COUNT transactions, each batch independently signed by the bank KMS.
//
// Public inputs (visible to verifier):
//   target_category_hash - Poseidon hash of the queried table name
//   start_time           - UNIX timestamp range start (inclusive)
//   end_time             - UNIX timestamp range end (inclusive)
//   bank_pub_key_x/y     - BabyJubJub public key of the bank signing KMS
//
// Private inputs (hidden from verifier):
//   batches[i].transactions - raw TX_COUNT-row payload per batch
//   batches[i].sig_*        - EdDSA signature for batch i
//
// Return value (public):
//   The verified SUM of matching transaction amounts across all batches.
fn main(
    target_category_hash: pub Field,
    start_time: pub u64,
    end_time: pub u64,
    bank_pub_key_x: pub Field,
    bank_pub_key_y: pub Field,
    batches: [BatchInput; BATCH_COUNT],
) -> pub Field {
    let mut total: Field = 0;
    for i in 0..BATCH_COUNT {
        total += process_batch(
            batches[i],
            target_category_hash,
            start_time,
            end_time,
            bank_pub_key_x,
            bank_pub_key_y,
        );
    }
    total
}

#[test]
fn test_poseidon_aws_spend() {
    // "aws_spend" encoding: big-endian in 32-byte buffer (1 zero byte prefix + 31 data bytes)
    let chunk0: Field = 0x00000000000000000000000000000000000000000000006177735f7370656e64;
    let chunk1: Field = 0;
    let chunk2: Field = 0;
    let result = bn254::hash_3([chunk0, chunk1, chunk2]);
    println(f"bn254::hash_3(aws_spend) = {result}");
    assert(result != 0);
}
