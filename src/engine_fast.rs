use chrono::Utc;
use num_bigint::BigInt;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::db::{sum_by_category, PrivateKey};
use crate::types::{EngineResult, FastLaneResult};

/// Run the FastLane engine: DB sum → attestation → return result.
///
/// Does NOT acquire `pipeline_lock` — FastLane is fully concurrent.
pub fn run_fast_lane(
    db_conn: &Connection,
    signing_key: &PrivateKey,
    category_name: &str,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> EngineResult {
    // 1. Aggregate from DB
    let (aggregate, row_count) = match sum_by_category(db_conn, category_name, start_unix_secs, end_unix_secs) {
        Ok(v) => v,
        Err(e) => return EngineResult::DbError(e.to_string()),
    };

    if row_count == 0 {
        return EngineResult::EmptyResult;
    }

    // 2. Query hash: SHA-256(category_name_bytes || start.to_le_bytes() || end.to_le_bytes())
    let mut qh = Sha256::new();
    qh.update(category_name.as_bytes());
    qh.update(start_unix_secs.to_le_bytes());
    qh.update(end_unix_secs.to_le_bytes());
    let query_hash = hex::encode(qh.finalize());

    // 3. Timestamp
    let timestamp_unix = Utc::now().timestamp();

    // 4. Attestation payload: SHA-256(aggregate.to_le_bytes() || query_hash_bytes || timestamp.to_le_bytes())
    let query_hash_bytes = hex::decode(&query_hash).unwrap_or_default();
    let mut payload_hasher = Sha256::new();
    payload_hasher.update(aggregate.to_le_bytes());
    payload_hasher.update(&query_hash_bytes);
    payload_hasher.update(timestamp_unix.to_le_bytes());
    let payload_bytes: [u8; 32] = payload_hasher.finalize().into();

    // 5. BabyJubJub sign
    // SHA-256 output is 256 bits; the BN254 scalar field order r ≈ 2^254.
    // ~25% of raw hashes exceed r and babyjubjub_rs::sign rejects them.
    // Reduce mod r to guarantee the message is a valid field element.
    let msg_raw = BigInt::from_bytes_le(num_bigint::Sign::Plus, &payload_bytes);
    let field_order = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("BN254 scalar field order");
    let msg = msg_raw % &field_order;
    let sig = match signing_key.sign(msg) {
        Ok(s) => s,
        Err(e) => return EngineResult::SignError(format!("{}", e)),
    };

    // 6. attestation_hash = SHA-256(sig_r8_x || sig_r8_y || sig_s — raw bytes via to_string())
    let sig_bytes = format!("{}{}{}", sig.r_b8.x, sig.r_b8.y, sig.s);
    let attestation_hash = hex::encode(Sha256::digest(sig_bytes.as_bytes()));

    // 7. key_id = SHA-256(pub_key_x_bytes || pub_key_y_bytes)
    let pub_key = signing_key.public();
    let key_material = format!("{}{}", pub_key.x, pub_key.y);
    let key_id = hex::encode(Sha256::digest(key_material.as_bytes()));

    EngineResult::Ok(FastLaneResult {
        aggregate,
        row_count,
        attestation_hash,
        key_id,
        timestamp_unix,
        query_hash,
    })
}
