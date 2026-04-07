use eddsa::eddsa_verify;
use poseidon::poseidon::PoseidonHasher;
use poseidon::poseidon::bn254;

// Number of transactions per batch.
// Fixed at compile time -- ACIR loops must have comptime-known bounds.
pub global TX_COUNT: u32 = 50;

// Number of batches processed in a single circuit execution.
// 10 batches x 50 transactions = 500 total transactions.
pub global BATCH_COUNT: u32 = 10;

// A single bank ledger row (private witness data).
pub struct Transaction {
    pub amount: u64,
    pub category: Field,
    pub timestamp: u64,
}

// Private inputs for one batch of TX_COUNT transactions.
// Each batch carries its own EdDSA signature -- the bank KMS signs each
// batch's Poseidon commitment independently.
pub struct BatchInput {
    pub transactions: [Transaction; TX_COUNT],
    pub sig_s: Field,
    pub sig_r8_x: Field,
    pub sig_r8_y: Field,
}

// Commit to a batch's transaction payload (4-level Poseidon Merkle tree) and
// verify the bank EdDSA signature over that commitment.
//
// Tree structure:
//   L1: hash_3([amount, category, timestamp]) per tx  -> TX_COUNT hashes
//   L2: hash_5(5 consecutive L1 hashes)               -> 10 hashes
//   L3: hash_5(5 consecutive L2 hashes)               -> 2 hashes
//   L4: hash_2([L3_0, L3_1])                          -> 1 commitment (msg_hash)
//
// Panics (constraint failure) if the EdDSA signature is invalid.
pub fn verify_batch_commitment(
    batch: BatchInput,
    bank_pub_key_x: Field,
    bank_pub_key_y: Field,
) {
    let mut tx_h: [Field; TX_COUNT] = [0; TX_COUNT];
    for i in 0..TX_COUNT {
        tx_h[i] = bn254::hash_3([
            batch.transactions[i].amount as Field,
            batch.transactions[i].category,
            batch.transactions[i].timestamp as Field,
        ]);
    }

    let l2: [Field; 10] = [
        bn254::hash_5([tx_h[0],  tx_h[1],  tx_h[2],  tx_h[3],  tx_h[4]]),
        bn254::hash_5([tx_h[5],  tx_h[6],  tx_h[7],  tx_h[8],  tx_h[9]]),
        bn254::hash_5([tx_h[10], tx_h[11], tx_h[12], tx_h[13], tx_h[14]]),
        bn254::hash_5([tx_h[15], tx_h[16], tx_h[17], tx_h[18], tx_h[19]]),
        bn254::hash_5([tx_h[20], tx_h[21], tx_h[22], tx_h[23], tx_h[24]]),
        bn254::hash_5([tx_h[25], tx_h[26], tx_h[27], tx_h[28], tx_h[29]]),
        bn254::hash_5([tx_h[30], tx_h[31], tx_h[32], tx_h[33], tx_h[34]]),
        bn254::hash_5([tx_h[35], tx_h[36], tx_h[37], tx_h[38], tx_h[39]]),
        bn254::hash_5([tx_h[40], tx_h[41], tx_h[42], tx_h[43], tx_h[44]]),
        bn254::hash_5([tx_h[45], tx_h[46], tx_h[47], tx_h[48], tx_h[49]]),
    ];

    let l3: [Field; 2] = [
        bn254::hash_5([l2[0], l2[1], l2[2], l2[3], l2[4]]),
        bn254::hash_5([l2[5], l2[6], l2[7], l2[8], l2[9]]),
    ];

    let msg_hash: Field = bn254::hash_2([l3[0], l3[1]]);

    assert(eddsa_verify::<PoseidonHasher>(
        bank_pub_key_x,
        bank_pub_key_y,
        batch.sig_s,
        batch.sig_r8_x,
        batch.sig_r8_y,
        msg_hash,
    ));
}

// Compute the per-transaction predicate match results for a batch.
// Returns true for each transaction that matches category hash AND timestamp range.
pub fn compute_predicate(
    batch: BatchInput,
    target_category_hash: Field,
    start_time: u64,
    end_time: u64,
) -> [bool; TX_COUNT] {
    let mut matches: [bool; TX_COUNT] = [false; TX_COUNT];
    for i in 0..TX_COUNT {
        matches[i] = (batch.transactions[i].category == target_category_hash)
            & (batch.transactions[i].timestamp >= start_time)
            & (batch.transactions[i].timestamp <= end_time);
    }
    matches
}
