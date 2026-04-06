use std::sync::LazyLock;

use chrono::Utc;
use num_bigint::BigInt;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::config::TableConfig;
use crate::db::{aggregate_table, PrivateKey};
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

/// Sign an aggregate result and return a `FastLaneResult` with full query-descriptor attestation.
///
/// `now_unix` is injectable for deterministic tests; pass `Utc::now().timestamp()` in production.
///
/// Signing version 2: payload includes the query descriptor (physical_table, value_column,
/// timestamp_column, category_column, agg_fn, metric_label) and the effective client_id
/// (`0` when `skip_client_id_filter=true`, signalling a non-tenant-scoped query).
/// Called by both the SQLite path (via `run_fast_lane`) and the Supabase path.
pub fn attest_fast_lane(
    signing_key: &PrivateKey,
    client_id: i64,
    table_key: &str,
    table_config: &TableConfig,
    category_name: &str,
    aggregate: i64,
    row_count: usize,
    start_unix_secs: i64,
    end_unix_secs: i64,
    now_unix: i64,
) -> EngineResult {
    let timestamp_unix = now_unix;

    // Effective client_id: sentinel 0 when skip_client_id_filter=true (all-tenants query).
    let attested_client_id: i64 = if table_config.skip_client_id_filter { 0 } else { client_id };

    // Attestation payload: query descriptor + result + timestamp.
    let mut h = Sha256::new();
    h.update(category_name.as_bytes());
    h.update(start_unix_secs.to_le_bytes());
    h.update(end_unix_secs.to_le_bytes());
    h.update(aggregate.to_le_bytes());
    h.update((row_count as u64).to_le_bytes());
    h.update(timestamp_unix.to_le_bytes());
    // Descriptor fields (signing_version 2)
    h.update(table_config.resolved_table(table_key).as_bytes());
    h.update(table_config.value_column.as_bytes());
    h.update(table_config.timestamp_column.as_bytes());
    h.update(
        table_config
            .category_column
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    h.update(table_config.agg_fn.as_str().as_bytes());
    h.update(table_config.metric_label.as_bytes());
    h.update(attested_client_id.to_le_bytes());
    let payload_bytes: [u8; 32] = h.finalize().into();

    // BabyJubJub sign
    let msg_raw = BigInt::from_bytes_le(num_bigint::Sign::Plus, &payload_bytes);
    let msg = msg_raw % &*BN254_FIELD_ORDER;
    let sig = match signing_key.sign(msg) {
        Ok(s) => s,
        Err(e) => return EngineResult::SignError(format!("{}", e)),
    };

    // attestation_hash = SHA-256(sig_r8_x || sig_r8_y || sig_s)
    let sig_bytes = format!("{}{}{}", sig.r_b8.x, sig.r_b8.y, sig.s);
    let attestation_hash = hex::encode(Sha256::digest(sig_bytes.as_bytes()));

    // key_id = SHA-256(pub_key_x || pub_key_y)
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

/// Run the FastLane engine on the SQLite path: DB aggregate → sign → return result.
///
/// Always returns `EngineResult::Ok` (even for row_count == 0) so that
/// zero-result receipts are cryptographically bound to a specific installation key.
/// Does NOT acquire `pipeline_lock` — FastLane is fully concurrent.
pub fn run_fast_lane(
    db_conn: &Connection,
    signing_key: &PrivateKey,
    client_id: i64,
    table_key: &str,
    table_config: TableConfig,
    category_name: &str,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> EngineResult {
    let (agg, row_count) = match aggregate_table(
        db_conn,
        "transactions", // SQLite ledger always uses 'transactions'
        &table_config.value_column,
        &table_config.timestamp_column,
        table_config.category_column.as_deref(),
        category_name,
        &table_config.agg_fn,
        client_id,
        start_unix_secs,
        end_unix_secs,
    ) {
        Ok(v) => v,
        Err(e) => return EngineResult::DbError(e.to_string()),
    };
    attest_fast_lane(
        signing_key,
        client_id,
        table_key,
        &table_config,
        category_name,
        agg,
        row_count,
        start_unix_secs,
        end_unix_secs,
        Utc::now().timestamp(),
    )
}
