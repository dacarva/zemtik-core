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
//   outgoing_prompt_hash - SHA-256(original_user_prompt) as BN254 Field (top 3 bits masked)
//                          independently verifiable: SHA-256(prompt), AND first_byte with 0x1f
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
    outgoing_prompt_hash: pub Field,
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
    // Bind outgoing_prompt_hash to the proof via an inverse-witness constraint.
    // `assert(x != 0)` in Noir creates a live gate: "exists y s.t. x * y = 1".
    // Both x and y become circuit witnesses. The optimizer cannot remove them.
    // `let _ = ...` (dead-code discard) is insufficient; the Noir optimizer eliminates
    // gates whose results are never used. An assert is a side effect that survives.
    // In practice outgoing_prompt_hash is SHA-256(prompt) with top 3 bits masked (AND 0x1f).
    // Masking 3 bits guarantees the value < BN254 Fr modulus p ≈ 0x30644e72...
    // The probability it equals zero is ~2^-253 (top 3 bits masked).
    assert(outgoing_prompt_hash != 0);
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
