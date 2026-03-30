use anyhow::Context;
pub use babyjubjub_rs::PrivateKey;
use babyjubjub_rs::Fr;
use ff_ce::{PrimeField, PrimeFieldRepr};
use num_bigint::{BigInt, Sign};
use poseidon_rs::Poseidon;
use rusqlite::Connection;
use serde::Deserialize;

use crate::types::{SignatureData, Transaction};

// Category codes matching the Noir circuit's public inputs.
pub const CAT_PAYROLL: u64 = 1;
pub const CAT_AWS: u64 = 2;
pub const CAT_COFFEE: u64 = 3;

// Q1 2024 UNIX timestamp boundaries.
pub const Q1_START: u64 = 1_704_067_200; // 2024-01-01 00:00:00 UTC
pub const Q1_END: u64 = 1_711_929_599; // 2024-03-31 23:59:59 UTC


/// Number of transactions per batch. Must match TX_COUNT in main.nr.
pub const BATCH_SIZE: usize = 50;

/// Map a category integer to its human-readable name (for the DB display column).
fn category_name(cat: u64) -> &'static str {
    match cat {
        CAT_PAYROLL => "Payroll",
        CAT_AWS => "AWS Infrastructure",
        CAT_COFFEE => "Coffee & Snacks",
        _ => "Unknown",
    }
}

// -------------------------------------------------------------------------
// Database backend abstraction
// -------------------------------------------------------------------------

/// The active database backend. Selected by the `DB_BACKEND` env var.
pub enum DbBackend {
    Sqlite(Connection),
    Supabase {
        url: String,
        key: String,
        client: reqwest::Client,
    },
}

impl DbBackend {
    /// Human-readable label for log output.
    pub fn label(&self) -> &'static str {
        match self {
            DbBackend::Sqlite(_) => "in-memory SQLite",
            DbBackend::Supabase { .. } => "Supabase (PostgREST)",
        }
    }
}

/// Initialize the database backend based on `DB_BACKEND` env var.
///
/// - `supabase` → connects to Supabase PostgREST; auto-seeds if the table
///   is empty. Requires `SUPABASE_URL` and `SUPABASE_SERVICE_KEY`.
/// - anything else (default) → in-memory SQLite with 500 seeded rows.
pub async fn init_db() -> anyhow::Result<DbBackend> {
    let backend = std::env::var("DB_BACKEND").unwrap_or_default();
    if backend.eq_ignore_ascii_case("supabase") {
        init_supabase().await
    } else {
        init_sqlite()
    }
}

/// Fetch all transactions for a given client, ordered by id.
pub async fn query_transactions(
    backend: &DbBackend,
    client_id: i64,
) -> anyhow::Result<Vec<Transaction>> {
    match backend {
        DbBackend::Sqlite(conn) => query_sqlite(conn, client_id),
        DbBackend::Supabase { url, key, client } => {
            query_supabase(client, url, key, client_id).await
        }
    }
}

// -------------------------------------------------------------------------
// Shared seed data generator
// -------------------------------------------------------------------------

/// Generate the canonical 500 demo transactions. Used by both SQLite and
/// Supabase seeders to guarantee identical data.
fn generate_seed_transactions() -> Vec<Transaction> {
    let day = 86_400u64;
    (0..500u64)
        .map(|i| {
            let (category, base_amount) = match i % 3 {
                0 => (CAT_PAYROLL, 45_000u64),
                1 => (CAT_AWS, 8_500u64),
                _ => (CAT_COFFEE, 250u64),
            };
            Transaction {
                id: i as i64 + 1,
                client_id: 123,
                amount: base_amount + (i / 3) * 100,
                category,
                timestamp: Q1_START + i * (day * 90 / 500),
            }
        })
        .collect()
}

// -------------------------------------------------------------------------
// SQLite backend
// -------------------------------------------------------------------------

/// Initialize a standalone ledger SQLite connection (in-memory, seeded) for
/// FastLane reads. Returned `Connection` is not wrapped in `DbBackend`.
pub fn init_ledger_sqlite() -> anyhow::Result<Connection> {
    let conn = Connection::open_in_memory().context("open in-memory ledger SQLite")?;
    conn.execute_batch(
        "CREATE TABLE transactions (
            id            INTEGER PRIMARY KEY,
            client_id     INTEGER NOT NULL,
            amount        INTEGER NOT NULL,
            category      INTEGER NOT NULL,
            category_name TEXT    NOT NULL,
            timestamp     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_txns_category_ts
            ON transactions(category_name, timestamp);",
    )
    .context("create ledger transactions table")?;
    seed_sqlite(&conn)?;
    Ok(conn)
}

fn init_sqlite() -> anyhow::Result<DbBackend> {
    let conn = Connection::open_in_memory().context("open in-memory SQLite")?;
    conn.execute_batch(
        "CREATE TABLE transactions (
            id            INTEGER PRIMARY KEY,
            client_id     INTEGER NOT NULL,
            amount        INTEGER NOT NULL,
            category      INTEGER NOT NULL,
            category_name TEXT    NOT NULL,
            timestamp     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_txns_category_ts
            ON transactions(category_name, timestamp);",
    )
    .context("create transactions table")?;
    seed_sqlite(&conn)?;
    Ok(DbBackend::Sqlite(conn))
}

/// Sum amounts and count rows for a given category name within a time range.
///
/// Returns `(sum, count)`. Both are 0 when no rows match.
/// Returns `Err(SumOverflow)` if the SQLite aggregate is negative (overflow guard).
pub fn sum_by_category(
    conn: &Connection,
    category_name: &str,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> anyhow::Result<(i64, usize)> {
    let (sum, count): (Option<i64>, i64) = conn.query_row(
        "SELECT SUM(amount), COUNT(*) FROM transactions
         WHERE category_name = ?1 AND timestamp >= ?2 AND timestamp <= ?3",
        rusqlite::params![category_name, start_unix_secs, end_unix_secs],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let total = sum.unwrap_or(0);
    if total < 0 {
        anyhow::bail!("sum_by_category: aggregate overflow detected (negative sum)");
    }
    Ok((total, count as usize))
}

fn seed_sqlite(conn: &Connection) -> anyhow::Result<()> {
    let mut stmt = conn.prepare(
        "INSERT INTO transactions (id, client_id, amount, category, category_name, timestamp) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for tx in generate_seed_transactions() {
        stmt.execute(rusqlite::params![
            tx.id,
            tx.client_id,
            tx.amount as i64,
            tx.category as i64,
            category_name(tx.category),
            tx.timestamp as i64,
        ])?;
    }
    Ok(())
}

fn query_sqlite(conn: &Connection, client_id: i64) -> anyhow::Result<Vec<Transaction>> {
    let mut stmt = conn.prepare(
        "SELECT id, client_id, amount, category, timestamp \
         FROM transactions WHERE client_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map(rusqlite::params![client_id], |row| {
        Ok(Transaction {
            id: row.get(0)?,
            client_id: row.get(1)?,
            amount: row.get::<_, i64>(2)? as u64,
            category: row.get::<_, i64>(3)? as u64,
            timestamp: row.get::<_, i64>(4)? as u64,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("query transactions")
}

// -------------------------------------------------------------------------
// Supabase backend (raw reqwest → PostgREST)
// -------------------------------------------------------------------------

/// Row shape returned by PostgREST (JSON integers → i64).
#[derive(Deserialize)]
struct SupabaseRow {
    id: i64,
    client_id: i64,
    amount: i64,
    category: i64,
    timestamp: i64,
}

/// Create the transactions table via a direct Postgres connection if it
/// doesn't already exist. PostgREST only supports DML, so we need this
/// one-time DDL step. The connection is dropped immediately after.
async fn ensure_supabase_table() -> anyhow::Result<()> {
    let db_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL env var required when DB_BACKEND=supabase")?;

    let tls_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("create TLS connector")?;
    let tls = postgres_native_tls::MakeTlsConnector::new(tls_connector);

    let (pg, connection) = tokio_postgres::connect(&db_url, tls)
        .await
        .context("connect to Supabase Postgres (check DATABASE_URL)")?;
    // Drive the connection in the background; it will close when `pg` drops.
    tokio::spawn(async move {
        let _ = connection.await;
    });

    pg.batch_execute(
        "CREATE TABLE IF NOT EXISTS transactions (
            id            BIGINT  PRIMARY KEY,
            client_id     BIGINT  NOT NULL,
            amount        BIGINT  NOT NULL,
            category      BIGINT  NOT NULL,
            category_name TEXT    NOT NULL,
            timestamp     BIGINT  NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_transactions_client_id
            ON transactions (client_id);
        NOTIFY pgrst, 'reload schema';",
    )
    .await
    .context("create transactions table via Postgres")?;

    // Give PostgREST a moment to reload its schema cache.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    Ok(())
}

async fn init_supabase() -> anyhow::Result<DbBackend> {
    // Ensure the table exists (DDL via direct Postgres) only when enabled.
    // For most demos you may already have the table and want to avoid
    // any direct Postgres connectivity requirements.
    if supabase_auto_create_table_enabled() {
        print!("[DB] Ensuring Supabase table exists... ");
        ensure_supabase_table().await?;
        println!("OK");
    } else {
        println!("[DB] SUPABASE_AUTO_CREATE_TABLE disabled — skipping DDL");
    }

    let url = std::env::var("SUPABASE_URL")
        .context("SUPABASE_URL env var required when DB_BACKEND=supabase")?;
    let key = std::env::var("SUPABASE_SERVICE_KEY")
        .context("SUPABASE_SERVICE_KEY env var required when DB_BACKEND=supabase")?;
    let client = reqwest::Client::new();

    let backend = DbBackend::Supabase {
        url: url.trim_end_matches('/').to_owned(),
        key,
        client,
    };

    if supabase_auto_seed_enabled() {
        // Use a real row probe rather than PostgREST Content-Range parsing
        // (which can be absent and previously caused duplicate inserts).
        let is_empty = supabase_is_empty(&backend).await?;
        if is_empty {
            println!("[DB] Supabase table empty — seeding 500 transactions...");
            supabase_seed(&backend).await?;
            println!("[DB] Seeding complete.");
        } else {
            println!("[DB] Supabase table already populated — skipping demo seed");
        }
    } else {
        println!("[DB] SUPABASE_AUTO_SEED disabled — skipping demo seed");
    }

    Ok(backend)
}

/// `true` when `SUPABASE_AUTO_SEED` is unset or any truthy value; `false` for
/// `0`, `false`, `no`, `off` (case-insensitive).
fn supabase_auto_seed_enabled() -> bool {
    match std::env::var("SUPABASE_AUTO_SEED") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "no" | "off")
        }
        Err(_) => true,
    }
}

/// `true` when `SUPABASE_AUTO_CREATE_TABLE` is unset or any truthy value;
/// `false` for `0`, `false`, `no`, `off` (case-insensitive).
fn supabase_auto_create_table_enabled() -> bool {
    match std::env::var("SUPABASE_AUTO_CREATE_TABLE") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "no" | "off")
        }
        Err(_) => true,
    }
}

/// Whether PostgREST returns zero rows for `transactions` (any row counts).
async fn supabase_is_empty(backend: &DbBackend) -> anyhow::Result<bool> {
    let DbBackend::Supabase { url, key, client } = backend else {
        unreachable!()
    };

    let resp = client
        .get(format!("{}/rest/v1/transactions", url))
        .header("apikey", key)
        .bearer_auth(key)
        .query(&[
            ("select", "id"),
            ("limit", "1"),
        ])
        .send()
        .await
        .context("Supabase empty-check request failed")?;

    let status = resp.status();
    let body = resp.text().await.context("read Supabase empty-check body")?;
    if !status.is_success() {
        anyhow::bail!("Supabase empty-check error ({}): {}", status, body);
    }

    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&body).context("parse Supabase empty-check JSON")?;
    Ok(rows.is_empty())
}

async fn supabase_seed(backend: &DbBackend) -> anyhow::Result<()> {
    let DbBackend::Supabase { url, key, client } = backend else {
        unreachable!()
    };

    let txns = generate_seed_transactions();
    let rows: Vec<serde_json::Value> = txns
        .iter()
        .map(|tx| {
            serde_json::json!({
                "id": tx.id,
                "client_id": tx.client_id,
                "amount": tx.amount as i64,
                "category": tx.category as i64,
                "category_name": category_name(tx.category),
                "timestamp": tx.timestamp as i64,
            })
        })
        .collect();

    // Insert in chunks of 100 to stay within PostgREST payload limits.
    for chunk in rows.chunks(100) {
        let body = serde_json::to_string(chunk)?;
        let resp = client
            .post(format!("{}/rest/v1/transactions", url))
            .header("apikey", key)
            .bearer_auth(key)
            .header("Content-Type", "application/json")
            .header("Prefer", "return=minimal")
            .body(body)
            .send()
            .await
            .context("Supabase seed insert failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Supabase seed error ({}): {}", status, text);
        }
    }
    Ok(())
}

async fn query_supabase(
    client: &reqwest::Client,
    url: &str,
    key: &str,
    client_id: i64,
) -> anyhow::Result<Vec<Transaction>> {
    let resp = client
        .get(format!("{}/rest/v1/transactions", url))
        .header("apikey", key)
        .bearer_auth(key)
        .query(&[
            ("client_id", format!("eq.{}", client_id)),
            ("order", "id.asc".to_owned()),
            ("select", "id,client_id,amount,category,timestamp".to_owned()),
        ])
        .send()
        .await
        .context("Supabase query failed")?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Supabase API error ({}): {}", status, text);
    }

    let rows: Vec<SupabaseRow> = resp
        .json()
        .await
        .context("deserialize Supabase response")?;

    Ok(rows
        .into_iter()
        .map(|r| Transaction {
            id: r.id,
            client_id: r.client_id,
            amount: r.amount as u64,
            category: r.category as u64,
            timestamp: r.timestamp as u64,
        })
        .collect())
}

/// Convert a BN254 field element (Fr) to a decimal string.
///
/// Uses `PrimeFieldRepr::write_le` which writes the canonical (non-Montgomery)
/// little-endian byte representation. This matches the decimal values that
/// Noir's `Prover.toml` format expects.
pub fn fr_to_decimal(fr: &Fr) -> String {
    let mut buf = [0u8; 32];
    fr.into_repr()
        .write_le(&mut buf[..])
        .expect("write_le on fixed 32-byte buffer never fails");
    BigInt::from_bytes_le(Sign::Plus, &buf).to_string()
}

fn fr_from_u64(n: u64) -> Fr {
    use ff_ce::PrimeField;
    Fr::from_str(&n.to_string()).expect("u64 is always a valid BN254 field element")
}

/// Compute the 4-level Poseidon commitment to the transaction array.
///
/// This is the scalar the bank signs and the circuit verifies. All nodes use
/// the circomlib-compatible BN254 Poseidon with arity <= 5, matching
/// `poseidon::poseidon::bn254::hash_N` in the Noir circuit.
///
///   L1: hash_3([amount, category, timestamp]) per tx -> 50 hashes
///   L2: hash_5(5 consecutive L1 hashes)             -> 10 hashes
///   L3: hash_5(5 consecutive L2 hashes)             -> 2 hashes
///   L4: hash_2([L3_0, L3_1])                        -> 1 commitment
pub fn compute_tx_commitment(txns: &[Transaction]) -> anyhow::Result<Fr> {
    assert_eq!(txns.len(), BATCH_SIZE, "circuit expects exactly {} transactions per batch", BATCH_SIZE);
    let poseidon = Poseidon::new();

    let h = |inputs: Vec<Fr>| -> anyhow::Result<Fr> {
        poseidon
            .hash(inputs)
            .map_err(|e| anyhow::anyhow!("poseidon hash failed: {}", e))
    };

    // Level 1: hash_3 per transaction
    let l1: Vec<Fr> = txns
        .iter()
        .map(|tx| {
            h(vec![
                fr_from_u64(tx.amount),
                fr_from_u64(tx.category),
                fr_from_u64(tx.timestamp),
            ])
        })
        .collect::<anyhow::Result<_>>()?;

    // Level 2: ten groups of 5 L1 hashes -> 10 hashes
    let l2: Vec<Fr> = l1
        .chunks(5)
        .map(|chunk| h(chunk.to_vec()))
        .collect::<anyhow::Result<_>>()?;

    // Level 3: two groups of 5 L2 hashes -> 2 hashes
    let l3: Vec<Fr> = l2
        .chunks(5)
        .map(|chunk| h(chunk.to_vec()))
        .collect::<anyhow::Result<_>>()?;

    // Level 4: final hash_2 of the 2 L3 hashes
    h(l3)
}

/// Sign the transaction array with the provided BabyJubJub EdDSA key.
///
/// Returns all signature components as BN254 decimal strings for Prover.toml.
#[allow(dead_code)]
pub fn sign_transactions(txns: &[Transaction], key: &PrivateKey) -> anyhow::Result<SignatureData> {
    let pub_key = key.public();

    let msg_hash_fr = compute_tx_commitment(txns)?;
    let msg_hash_dec = fr_to_decimal(&msg_hash_fr);
    let msg_hash_bigint =
        BigInt::parse_bytes(msg_hash_dec.as_bytes(), 10).expect("decimal string from fr_to_decimal");

    let sig = key
        .sign(msg_hash_bigint)
        .map_err(|e| anyhow::anyhow!("EdDSA sign: {}", e))?;

    Ok(SignatureData {
        pub_key_x: fr_to_decimal(&pub_key.x),
        pub_key_y: fr_to_decimal(&pub_key.y),
        sig_s: sig.s.to_string(),
        sig_r8_x: fr_to_decimal(&sig.r_b8.x),
        sig_r8_y: fr_to_decimal(&sig.r_b8.y),
    })
}

/// Split transactions into batches of BATCH_SIZE and sign each independently.
///
/// Each batch is signed with a fresh EdDSA signature over its own Poseidon
/// commitment. Returns a vector of (batch_transactions, signature) pairs
/// ready for `generate_batched_prover_toml`.
pub fn sign_transaction_batches(
    txns: &[Transaction],
    key: &PrivateKey,
) -> anyhow::Result<Vec<(Vec<Transaction>, SignatureData)>> {
    anyhow::ensure!(
        txns.len() % BATCH_SIZE == 0,
        "transaction count ({}) must be a multiple of BATCH_SIZE ({})",
        txns.len(),
        BATCH_SIZE
    );

    let pub_key = key.public();

    let mut batches = Vec::with_capacity(txns.len() / BATCH_SIZE);

    for chunk in txns.chunks(BATCH_SIZE) {
        let msg_hash_fr = compute_tx_commitment(chunk)?;
        let msg_hash_dec = fr_to_decimal(&msg_hash_fr);
        let msg_hash_bigint = BigInt::parse_bytes(msg_hash_dec.as_bytes(), 10)
            .expect("decimal string from fr_to_decimal");

        let sig = key
            .sign(msg_hash_bigint)
            .map_err(|e| anyhow::anyhow!("EdDSA sign batch: {}", e))?;

        let sig_data = SignatureData {
            pub_key_x: fr_to_decimal(&pub_key.x),
            pub_key_y: fr_to_decimal(&pub_key.y),
            sig_s: sig.s.to_string(),
            sig_r8_x: fr_to_decimal(&sig.r_b8.x),
            sig_r8_y: fr_to_decimal(&sig.r_b8.y),
        };

        batches.push((chunk.to_vec(), sig_data));
    }

    Ok(batches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_to_decimal_zero() {
        let fr = fr_from_u64(0);
        assert_eq!(fr_to_decimal(&fr), "0");
    }

    #[test]
    fn fr_to_decimal_one() {
        let fr = fr_from_u64(1);
        assert_eq!(fr_to_decimal(&fr), "1");
    }

    #[test]
    fn fr_to_decimal_known_value() {
        let fr = fr_from_u64(12345);
        assert_eq!(fr_to_decimal(&fr), "12345");
    }
}
