use eddsa::eddsa_verify;
use poseidon::poseidon::PoseidonHasher;
use poseidon::poseidon::bn254;

// Number of transactions per batch.
// Fixed at compile time -- ACIR loops must have comptime-known bounds.
global TX_COUNT: u32 = 50;

// Number of batches processed in a single circuit execution.
// 10 batches x 50 transactions = 500 total transactions.
global BATCH_COUNT: u32 = 10;

// A single bank ledger row (private witness data).
struct Transaction {
    amount: u64,
    category: Field,
    timestamp: u64,
}

// Private inputs for one batch of TX_COUNT transactions.
// Each batch carries its own EdDSA signature -- the bank KMS signs each
// batch's Poseidon commitment independently.
struct BatchInput {
    transactions: [Transaction; TX_COUNT],
    sig_s: Field,
    sig_r8_x: Field,
    sig_r8_y: Field,
}

// Process one batch: commit to the transaction payload, verify the bank EdDSA
// signature over that commitment, and aggregate the matching spend.
//
// Inlined into main() -- single ACIR program compatible with ultra_honk.
// The noir-edwards based EdDSA reduces gate count by ~59% vs the ec library,
// making the full 500-tx circuit feasible for UltraHonk proving with CRS
// auto-download in bb v4.0.0-nightly.
//
// Private inputs (hidden from verifier per batch):
//   batch.transactions - the raw TX_COUNT-row DB payload for this batch
//   batch.sig_*        - EdDSA signature over this batch's Poseidon commitment
//
// Public context (shared across all batches):
//   target_category / start_time / end_time - query predicate
//   bank_pub_key_x/y                        - bank's BabyJubJub public key
//
// Returns the partial aggregate spend for this batch.
fn process_batch(
    batch: BatchInput,
    target_category_hash: Field,
    start_time: u64,
    end_time: u64,
    bank_pub_key_x: Field,
    bank_pub_key_y: Field,
) -> Field {
    // -----------------------------------------------------------------------
    // Step 1: Commit to this batch's transaction payload (4-level Poseidon).
    //
    // Identical tree structure to the single-circuit version:
    //   L1: hash_3([amount, category, timestamp]) per tx -> TX_COUNT hashes
    //   L2: hash_5(5 consecutive L1 hashes)             -> 10 hashes
    //   L3: hash_5(5 consecutive L2 hashes)             -> 2 hashes
    //   L4: hash_2([L3_0, L3_1])                        -> 1 commitment
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Step 2: Verify this batch's EdDSA signature.
    //
    // The bank KMS signs each batch's commitment separately. A dishonest
    // prover cannot construct a valid witness if any batch was tampered with.
    // -----------------------------------------------------------------------
    assert(eddsa_verify::<PoseidonHasher>(
        bank_pub_key_x,
        bank_pub_key_y,
        batch.sig_s,
        batch.sig_r8_x,
        batch.sig_r8_y,
        msg_hash,
    ));

    // -----------------------------------------------------------------------
    // Step 3: Aggregate matching spend for this batch.
    // -----------------------------------------------------------------------
    let mut total: Field = 0;
    for i in 0..TX_COUNT {
        let matches_query = (batch.transactions[i].category == target_category_hash)
            & (batch.transactions[i].timestamp >= start_time)
            & (batch.transactions[i].timestamp <= end_time);

        total += if matches_query { batch.transactions[i].amount as Field } else { 0 };
    }

    total
}

// Zemtik ZK circuit: proves an aggregate spend across BATCH_COUNT x TX_COUNT
// transactions, with each batch independently signed by the bank KMS.
//
// Public inputs (visible to verifier):
//   target_category  - the spend category being queried (e.g. 2 = AWS)
//   start_time       - UNIX timestamp range start (inclusive)
//   end_time         - UNIX timestamp range end (inclusive)
//   bank_pub_key_x/y - BabyJubJub public key of the bank signing KMS
//
// Private inputs (hidden from verifier):
//   batches[i].transactions - raw TX_COUNT-row payload per batch
//   batches[i].sig_*        - EdDSA signature for batch i
//
// Return value (public):
//   The total verified aggregate spend across all BATCH_COUNT batches.
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
    // "aws_spend" = 0x6177735f7370656e64 (9 bytes) -&gt; zero-padded to 31 bytes
    // Encoding: big-endian in 32-byte buffer (1 zero byte prefix + 31 data bytes)
    // chunk0 = bytes[0..31] -&gt; place at buf[1..32] -&gt; Field literal
    let chunk0: Field = 0x00000000000000000000000000000000000000000000006177735f7370656e64;
    let chunk1: Field = 0;
    let chunk2: Field = 0;
    let result = bn254::hash_3([chunk0, chunk1, chunk2]);
    // Print the decimal for cross-language verification against Rust poseidon_of_string
    println(f"bn254::hash_3(aws_spend) = {result}");
    // Assert non-trivial (actual cross-language value verified in tests/test_poseidon_compat.rs)
    assert(result != 0);
}
