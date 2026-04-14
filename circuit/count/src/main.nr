use zemtik_lib::{BatchInput, BATCH_COUNT, TX_COUNT, verify_batch_commitment, compute_predicate};

// Process one batch: commit + verify EdDSA + COUNT aggregation.
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
        // COUNT: increment by 1 for each matching transaction, regardless of amount.
        // Dummy sentinel transactions (category "__zemtik_dummy__") have a Poseidon hash
        // that never matches any real category, so they are naturally excluded by the predicate.
        total += if matches[i] { 1 } else { 0 };
    }
    total
}

// Zemtik ZK COUNT circuit: proves the count of matching transactions across
// BATCH_COUNT x TX_COUNT transactions, each batch independently signed by the bank KMS.
//
// Public inputs (visible to verifier):
//   target_category_hash - Poseidon hash of the queried table name
//   start_time           - UNIX timestamp range start (inclusive)
//   end_time             - UNIX timestamp range end (inclusive)
//   bank_pub_key_x/y     - BabyJubJub public key of the bank signing KMS
//   outgoing_prompt_hash - SHA-256(original_user_prompt) as BN254 Field (top 2 bits masked)
//                          independently verifiable: SHA-256(prompt), AND first_byte with 0x3f
//
// Private inputs (hidden from verifier):
//   batches[i].transactions - raw TX_COUNT-row payload per batch
//   batches[i].sig_*        - EdDSA signature for batch i
//
// Return value (public):
//   The verified COUNT of matching transactions across all batches.
//
// Note: this counts rows (not SQL COUNT(value_column) with null semantics).
// The difference only matters if value_column is nullable - schema_config.json
// should use a non-nullable column (PK or equivalent) for COUNT tables.
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
    // See circuit/sum/src/main.nr for rationale.
    assert(outgoing_prompt_hash != 0);
    total
}
