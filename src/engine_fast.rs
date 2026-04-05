use std::sync::LazyLock;

use chrono::Utc;
use num_bigint::BigInt;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::db::{sum_by_category, PrivateKey};
use crate::types::{EngineResult, FastLaneResult};

/// BN254 scalar field order — parsed once at startup, never again.
/// SHA-256 produces 256-bit values; ~25% exceed this order. Reduce mod r before signing.
static BN254_FIELD_ORDER: LazyLock<BigInt> = LazyLock::new(|| {
    BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("BN254 scalar field order")
});

/// Run the FastLane engine: DB sum → unified attestation → return result.
///
/// Always returns `EngineResult::Ok` (even for row_count == 0) so that
/// zero-result receipts are cryptographically bound to a specific installation key.
/// Does NOT acquire `pipeline_lock` — FastLane is fully concurrent.
/// Sign an aggregate result and return a `FastLaneResult` with attestation.
/// Called by both the SQLite path (via `run_fast_lane`) and the Supabase path.
pub fn attest_fast_lane(
    signing_key: &PrivateKey,
    category_name: &str,
    aggregate: i64,
    row_count: usize,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> EngineResult {
    // 1. Timestamp
    let timestamp_unix = Utc::now().timestamp();

    // 2. Unified attestation payload
    let mut h = Sha256::new();
    h.update(category_name.as_bytes());
    h.update(start_unix_secs.to_le_bytes());
    h.update(end_unix_secs.to_le_bytes());
    h.update(aggregate.to_le_bytes());
    h.update((row_count as u64).to_le_bytes());
    h.update(timestamp_unix.to_le_bytes());
    let payload_bytes: [u8; 32] = h.finalize().into();

    // 3. BabyJubJub sign
    let msg_raw = BigInt::from_bytes_le(num_bigint::Sign::Plus, &payload_bytes);
    let msg = msg_raw % &*BN254_FIELD_ORDER;
    let sig = match signing_key.sign(msg) {
        Ok(s) => s,
        Err(e) => return EngineResult::SignError(format!("{}", e)),
    };

    // 4. attestation_hash = SHA-256(sig_r8_x || sig_r8_y || sig_s)
    let sig_bytes = format!("{}{}{}", sig.r_b8.x, sig.r_b8.y, sig.s);
    let attestation_hash = hex::encode(Sha256::digest(sig_bytes.as_bytes()));

    // 5. key_id = SHA-256(pub_key_x || pub_key_y)
    let pub_key = signing_key.public();
    let key_material = format!("{}{}", pub_key.x, pub_key.y);
    let key_id = hex::encode(Sha256::digest(key_material.as_bytes()));

    EngineResult::Ok(FastLaneResult {
        aggregate,
        row_count,
        attestation_hash,
        key_id,
        timestamp_unix,
    })
}

pub fn run_fast_lane(
    db_conn: &Connection,
    signing_key: &PrivateKey,
    client_id: i64,
    category_name: &str,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> EngineResult {
    let (aggregate, row_count) = match sum_by_category(db_conn, client_id, category_name, start_unix_secs, end_unix_secs) {
        Ok(v) => v,
        Err(e) => return EngineResult::DbError(e.to_string()),
    };
    attest_fast_lane(signing_key, category_name, aggregate, row_count, start_unix_secs, end_unix_secs)
}
