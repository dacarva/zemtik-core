use anyhow::Context;
pub use babyjubjub_rs::PrivateKey;
use babyjubjub_rs::Fr;
use ff_ce::{Field, PrimeField, PrimeFieldRepr};
use num_bigint::{BigInt, Sign};
use poseidon_rs::Poseidon;
use rusqlite::Connection;
use serde::Deserialize;

use crate::types::{SignatureData, Transaction, TransactionBatch};

// Category codes matching the Noir circuit's public inputs.
pub const CAT_PAYROLL: u64 = 1;
pub const CAT_AWS: u64 = 2;
pub const CAT_COFFEE: u64 = 3;
pub const CAT_DEAL_SIZE: u64 = 4;

/// Compute the Poseidon BN254 hash of a table name string.
///
/// Canonicalizes input (trim + lowercase) and encodes as 3×31-byte chunks
/// zero-padded → 3 Fr elements → poseidon hash (arity 3).
/// Compatible with `bn254::hash_3` in the Noir circuit.
///
/// Max input length after canonicalization: 93 bytes (3 × 31).
pub fn poseidon_of_string(s: &str) -> anyhow::Result<Fr> {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static CACHE: RefCell<HashMap<String, Fr>> = RefCell::new(HashMap::new());
    }

    let key = s.trim().to_ascii_lowercase();

    // Fast path: ~996 of 1001 calls per ZK request hit the same 3-5 category names.
    let cached = CACHE.with(|c| c.borrow().get(&key).copied());
    if let Some(fr) = cached {
        return Ok(fr);
    }

    anyhow::ensure!(!key.is_empty(), "poseidon_of_string: empty string is not a valid table key");
    anyhow::ensure!(
        key.is_ascii(),
        "poseidon_of_string: key '{}' contains non-ASCII bytes — table keys must be ASCII",
        key
    );
    anyhow::ensure!(
        key.len() <= 93,
        "poseidon_of_string: input '{}' is {} bytes (max 93)",
        key,
        key.len()
    );

    let bytes = key.as_bytes();
    let mut chunks = [Fr::zero(); 3];
    for (i, chunk_fr) in chunks.iter_mut().enumerate() {
        let start = i * 31;
        if start >= bytes.len() {
            // Already zero-initialized
            continue;
        }
        let end = std::cmp::min(start + 31, bytes.len());
        // Encode bytes as least-significant part of a 31-byte big-endian chunk,
        // matching Noir's Field literal: 0x000...006177735f7370656e64 for "aws_spend".
        // bytes go at the END (LSB side) of padded, with leading zeros.
        let len = end - start;
        let mut padded = [0u8; 31];
        padded[31 - len..].copy_from_slice(&bytes[start..end]);
        // Place the 31-byte chunk as the low bytes of a 32-byte big-endian Field.
        let mut be_buf = [0u8; 32];
        be_buf[1..32].copy_from_slice(&padded);
        let big = BigInt::from_bytes_be(Sign::Plus, &be_buf);
        *chunk_fr = Fr::from_str(&big.to_string())
            .ok_or_else(|| anyhow::anyhow!("chunk {} exceeds BN254 field order", i))?;
    }

    let poseidon = Poseidon::new();
    let result = poseidon
        .hash(chunks.to_vec())
        .map_err(|e| anyhow::anyhow!("poseidon hash failed: {}", e))?;

    CACHE.with(|c| c.borrow_mut().insert(key, result));
    Ok(result)
}

// Q1 2024 UNIX timestamp boundaries.
pub const Q1_START: u64 = 1_704_067_200; // 2024-01-01 00:00:00 UTC
pub const Q1_END: u64 = 1_711_929_599; // 2024-03-31 23:59:59 UTC


/// Number of transactions per batch. Must match TX_COUNT in main.nr.
pub const BATCH_SIZE: usize = 50;

/// Map a category integer to its schema-config key (must match schema_config.json table keys).
///
/// These values are stored in transactions.category_name and used by FastLane's
/// sum_by_category() query. They must align with the keys in schema_config.json
/// so that intent.rs → extract_intent() → category_name routes correctly.
fn category_name(cat: u64) -> &'static str {
    match cat {
        CAT_PAYROLL => "payroll",
        CAT_AWS => "aws_spend",
        CAT_COFFEE => "travel",
        CAT_DEAL_SIZE => "deal_size",
        _ => "unknown",
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

/// Maximum number of transactions supported by the ZK SlowLane circuit
/// (BATCH_COUNT=10 × BATCH_SIZE=50 = 500).
pub const MAX_ZK_TX_COUNT: usize = BATCH_SIZE * 10;

/// Sentinel category name used for dummy padding transactions.
/// Its Poseidon hash never matches any real category because
/// the '__' prefix is not a valid table key (validated at startup).
pub const DUMMY_CATEGORY: &str = "__zemtik_dummy__";

/// Fetch transactions for a given client and pad to exactly MAX_ZK_TX_COUNT (500).
///
/// - N == MAX_ZK_TX_COUNT: pass through unchanged.
/// - N < MAX_ZK_TX_COUNT: pad with dummy sentinel transactions (amount=0, timestamp=0,
///   category_name="__zemtik_dummy__"). Dummies are excluded naturally by the
///   circuit predicate filter since their Poseidon hash never matches any real category.
/// - N > MAX_ZK_TX_COUNT: hard-fail — the circuit requires exactly 500 transactions.
///   Future fix: parametric circuit (P1-1 in ZK_SLOWLANE_SPEC.md).
pub async fn query_transactions(
    backend: &DbBackend,
    client_id: i64,
) -> anyhow::Result<TransactionBatch> {
    let mut txns = match backend {
        DbBackend::Sqlite(conn) => query_sqlite(conn, client_id)?,
        DbBackend::Supabase { url, key, client } => {
            query_supabase(client, url, key, client_id).await?
        }
    };

    let actual_row_count = txns.len();

    if actual_row_count > MAX_ZK_TX_COUNT {
        anyhow::bail!(
            "Too many matching rows (N={}); ZK SlowLane supports up to {} transactions per query. \
             Narrow the time range or set sensitivity to 'low' to use FastLane instead.",
            actual_row_count,
            MAX_ZK_TX_COUNT
        );
    }

    // Pad with dummy sentinel transactions to reach exactly MAX_ZK_TX_COUNT.
    if actual_row_count < MAX_ZK_TX_COUNT {
        let padding_count = MAX_ZK_TX_COUNT - actual_row_count;
        for _ in 0..padding_count {
            txns.push(Transaction {
                id: 0,
                client_id: 0,
                amount: 0,
                category: 0,
                category_name: DUMMY_CATEGORY.to_owned(),
                timestamp: 0,
            });
        }
    }

    Ok(TransactionBatch {
        transactions: txns,
        actual_row_count,
    })
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
            let (category, base_amount) = match i % 4 {
                0 => (CAT_PAYROLL, 45_000u64),
                1 => (CAT_AWS, 8_500u64),
                2 => (CAT_COFFEE, 250u64),
                _ => (CAT_DEAL_SIZE, 12_000u64),
            };
            Transaction {
                id: i as i64 + 1,
                client_id: 123,
                amount: base_amount + (i / 3) * 100,
                category,
                // category_name is still used here by the seeder (NOT dead code post-Sprint 2)
                category_name: category_name(category).to_owned(),
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
///
/// Deprecated: use `aggregate_table` instead (table-agnostic, supports COUNT).
#[deprecated(since = "0.7.0", note = "use aggregate_table instead")]
pub fn sum_by_category(
    conn: &Connection,
    client_id: i64,
    category_name: &str,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> anyhow::Result<(i64, usize)> {
    let (sum, count): (Option<i64>, i64) = conn.query_row(
        "SELECT SUM(amount), COUNT(*) FROM transactions
         WHERE category_name = ?1 AND timestamp >= ?2 AND timestamp <= ?3 AND client_id = ?4",
        rusqlite::params![category_name, start_unix_secs, end_unix_secs, client_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let total = sum.unwrap_or(0);
    if total < 0 {
        anyhow::bail!("sum_by_category: aggregate overflow detected (negative sum)");
    }
    Ok((total, count as usize))
}

/// Aggregate amounts for a category from a Supabase PostgREST endpoint.
///
/// Uses a pagination loop (1000 rows per page) to handle any table size.
/// The `amount` column is read as `i64` (integer minor units — no f64 to avoid
/// precision loss on large aggregates). Null amounts are skipped with a warning.
/// Returns `(sum, row_count)`.
///
/// Deprecated: use `query_aggregate_table` instead (table-agnostic, supports COUNT, no pagination required).
#[deprecated(since = "0.7.0", note = "use query_aggregate_table instead")]
pub async fn query_sum_by_category(
    client: &reqwest::Client,
    url: &str,
    key: &str,
    table: &str,
    category_name: &str,
    client_id: i64,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> anyhow::Result<(i64, usize)> {
    let base = url.trim_end_matches('/');
    let mut total: i64 = 0;
    let mut row_count: usize = 0;
    let page_size: usize = 1000;
    let mut offset: usize = 0;

    loop {
        let end_idx = offset + page_size - 1;
        let endpoint = format!(
            "{}/rest/v1/{}?category_name=eq.{}&client_id=eq.{}&timestamp=gte.{}&timestamp=lte.{}&select=amount&order=id",
            base, table, category_name, client_id, start_unix_secs, end_unix_secs
        );

        let resp = client
            .get(&endpoint)
            .header("apikey", key)
            .header("Authorization", format!("Bearer {}", key))
            .header("Range", format!("{}-{}", offset, end_idx))
            .send()
            .await
            .context("PostgREST query_sum_by_category request")?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!(
                "PostgREST returned {} for table '{}' query",
                status,
                table
            );
        }

        let rows: Vec<serde_json::Value> = resp
            .json()
            .await
            .context("parse PostgREST response JSON")?;

        let page_len = rows.len();
        for row in &rows {
            let amount = row
                .get("amount")
                .and_then(|v| {
                    v.as_i64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
                })
                .unwrap_or_else(|| {
                    eprintln!("[WARN] query_sum_by_category: skipping row with null/unparseable amount");
                    0
                });
            total = total.checked_add(amount).ok_or_else(|| {
                anyhow::anyhow!("query_sum_by_category: i64 sum overflow — amounts too large for safe aggregation")
            })?;
        }
        row_count += page_len;

        if page_len < page_size {
            break; // last page
        }
        offset += page_size;
    }

    Ok((total, row_count))
}

/// Generic aggregate query on an SQLite connection.
///
/// Builds `SELECT {agg_expr}({value_col}), COUNT(*) FROM {table}` with optional
/// category and mandatory client_id filters. All column/table names must be
/// validated via `is_safe_identifier` before calling (enforced by `validate_schema_config`
/// at proxy startup).
///
/// Returns `(aggregate, row_count)`. Negative SUM → `Err` (overflow guard).
/// COUNT always returns a non-negative result.
pub fn aggregate_table(
    conn: &Connection,
    table: &str,
    value_col: &str,
    timestamp_col: &str,
    category_col: Option<&str>,
    category_value: &str,
    agg_fn: &crate::config::AggFn,
    client_id: i64,
    skip_client_id_filter: bool,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> anyhow::Result<(i64, usize)> {
    // Defense-in-depth: identifiers are validated at startup by validate_schema_config,
    // but enforce here too so any future call-site that bypasses startup validation
    // fails with a clear error in both debug and release builds.
    fn safe_ident(s: &str) -> bool {
        let mut chars = s.chars();
        match chars.next() {
            Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_') && s.len() <= 63
    }
    anyhow::ensure!(safe_ident(table), "aggregate_table: unsafe table identifier '{}'", table);
    anyhow::ensure!(safe_ident(value_col), "aggregate_table: unsafe value_col identifier '{}'", value_col);
    anyhow::ensure!(safe_ident(timestamp_col), "aggregate_table: unsafe timestamp_col identifier '{}'", timestamp_col);
    if let Some(cc) = category_col {
        anyhow::ensure!(safe_ident(cc), "aggregate_table: unsafe category_col identifier '{}'", cc);
    }

    let agg_expr = match agg_fn {
        crate::config::AggFn::Sum => format!("SUM({})", value_col),
        crate::config::AggFn::Count => format!("COUNT({})", value_col),
        // AVG is handled at the pipeline level (SUM + COUNT composite); it should not
        // reach this function directly. If it does, fall back to AVG() for FastLane-only use.
        crate::config::AggFn::Avg => format!("AVG({})", value_col),
    };

    // Build SQL and execute based on category and client_id filter presence.
    let (agg_val, count): (Option<i64>, i64) = match (category_col, skip_client_id_filter) {
        (Some(cat_col), false) => {
            let sql = format!(
                "SELECT {agg}, COUNT(*) FROM {table} \
                 WHERE {cat_col} = ?1 AND {ts_col} >= ?2 AND {ts_col} <= ?3 AND client_id = ?4",
                agg = agg_expr, table = table, cat_col = cat_col, ts_col = timestamp_col,
            );
            conn.query_row(&sql,
                rusqlite::params![category_value, start_unix_secs, end_unix_secs, client_id],
                |row| Ok((row.get(0)?, row.get(1)?)))?
        }
        (Some(cat_col), true) => {
            let sql = format!(
                "SELECT {agg}, COUNT(*) FROM {table} \
                 WHERE {cat_col} = ?1 AND {ts_col} >= ?2 AND {ts_col} <= ?3",
                agg = agg_expr, table = table, cat_col = cat_col, ts_col = timestamp_col,
            );
            conn.query_row(&sql,
                rusqlite::params![category_value, start_unix_secs, end_unix_secs],
                |row| Ok((row.get(0)?, row.get(1)?)))?
        }
        (None, false) => {
            let sql = format!(
                "SELECT {agg}, COUNT(*) FROM {table} \
                 WHERE {ts_col} >= ?1 AND {ts_col} <= ?2 AND client_id = ?3",
                agg = agg_expr, table = table, ts_col = timestamp_col,
            );
            conn.query_row(&sql,
                rusqlite::params![start_unix_secs, end_unix_secs, client_id],
                |row| Ok((row.get(0)?, row.get(1)?)))?
        }
        (None, true) => {
            let sql = format!(
                "SELECT {agg}, COUNT(*) FROM {table} \
                 WHERE {ts_col} >= ?1 AND {ts_col} <= ?2",
                agg = agg_expr, table = table, ts_col = timestamp_col,
            );
            conn.query_row(&sql,
                rusqlite::params![start_unix_secs, end_unix_secs],
                |row| Ok((row.get(0)?, row.get(1)?)))?
        }
    };

    Ok((agg_val.unwrap_or(0), count as usize))
}

/// Generic aggregate query against a Supabase/PostgREST endpoint.
///
/// Uses PostgREST ≥ v9 aggregate syntax (single HTTP call, no pagination).
/// `category_value` is URL-encoded before insertion. `skip_client_id_filter`
/// omits the `client_id=eq.{X}` query param (for tables without a client_id column).
///
/// Returns `(aggregate, 0)` — row_count is not available from PostgREST aggregate response.
pub async fn query_aggregate_table(
    client: &reqwest::Client,
    url: &str,
    key: &str,
    table: &str,
    value_col: &str,
    timestamp_col: &str,
    category_col: Option<&str>,
    category_value: &str,
    agg_fn: &crate::config::AggFn,
    client_id: i64,
    skip_client_id_filter: bool,
    start_unix_secs: i64,
    end_unix_secs: i64,
) -> anyhow::Result<(i64, usize)> {
    let base = url.trim_end_matches('/');

    let agg_expr = match agg_fn {
        crate::config::AggFn::Sum => format!("{}:sum({})", value_col, value_col),
        crate::config::AggFn::Count => format!("{}:{}.count()", value_col, value_col),
        // AVG is handled at pipeline level (SUM + COUNT composite).
        // If called directly (e.g., FastLane AVG), fall back to sum for safety.
        crate::config::AggFn::Avg => format!("{}:sum({})", value_col, value_col),
    };

    let mut endpoint = format!(
        "{}/rest/v1/{}?select={}",
        base, table, agg_expr
    );

    if !skip_client_id_filter {
        endpoint.push_str(&format!("&client_id=eq.{}", client_id));
    }
    endpoint.push_str(&format!(
        "&{}=gte.{}&{}=lte.{}",
        timestamp_col, start_unix_secs, timestamp_col, end_unix_secs
    ));
    if let Some(cat_col) = category_col {
        let encoded = urlencoding::encode(category_value);
        endpoint.push_str(&format!("&{}=eq.{}", cat_col, encoded));
    }

    let resp = client
        .get(&endpoint)
        .header("apikey", key)
        .header("Authorization", format!("Bearer {}", key))
        .send()
        .await
        .context("PostgREST query_aggregate_table request")?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!(
            "PostgREST returned {} for aggregate query on table '{}'",
            status,
            table
        );
    }

    let resp_json: Vec<serde_json::Value> = resp
        .json()
        .await
        .context("parse PostgREST aggregate response")?;

    let field = value_col;

    // An empty array means zero rows matched — return Ok((0, 0)) explicitly.
    // Any other parse failure (wrong field name, schema drift, RLS-filtered response)
    // is a hard error: signing a coerced 0 would produce a false attestation.
    let n = if resp_json.is_empty() {
        0i64
    } else {
        resp_json
            .first()
            .and_then(|obj| obj.get(field))
            .and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
            })
            .ok_or_else(|| anyhow::anyhow!(
                "query_aggregate_table: missing or unparseable '{}' field in PostgREST response; \
                 check that schema_config value_column matches the actual column name and \
                 that PostgREST aggregate syntax is supported (requires PostgREST ≥ v9)",
                field
            ))?
    };

    Ok((n, 0))
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
        "SELECT id, client_id, amount, category, timestamp, category_name \
         FROM transactions WHERE client_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map(rusqlite::params![client_id], |row| {
        Ok(Transaction {
            id: row.get(0)?,
            client_id: row.get(1)?,
            amount: row.get::<_, i64>(2)? as u64,
            category: row.get::<_, i64>(3)? as u64,
            timestamp: row.get::<_, i64>(4)? as u64,
            category_name: row.get(5)?,
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
    category_name: String,
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

/// `true` only when `SUPABASE_AUTO_SEED` is explicitly set to a truthy value
/// (`1`, `true`, `yes`, `on`). Defaults to `false` when unset — prevents demo
/// rows from being inserted into a client's production database on first run.
/// Local dev: set `SUPABASE_AUTO_SEED=1`.
fn supabase_auto_seed_enabled() -> bool {
    match std::env::var("SUPABASE_AUTO_SEED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// `true` only when `SUPABASE_AUTO_CREATE_TABLE` is explicitly set to a truthy
/// value (`1`, `true`, `yes`, `on`). Defaults to `false` when unset — prevents
/// DDL from running against a client's production database on first run.
/// Local dev: set `SUPABASE_AUTO_CREATE_TABLE=1`.
fn supabase_auto_create_table_enabled() -> bool {
    match std::env::var("SUPABASE_AUTO_CREATE_TABLE") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
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
            ("select", "id,client_id,amount,category,timestamp,category_name".to_owned()),
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
            category_name: r.category_name,
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
                poseidon_of_string(&tx.category_name)?,
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
mod auto_flag_tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that mutate env vars to avoid parallel-test races.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn auto_seed_and_create_table_defaults_and_values() {
        let _guard = ENV_LOCK.lock().unwrap();

        // Default: unset → false (opt-in, not opt-out)
        std::env::remove_var("SUPABASE_AUTO_SEED");
        assert!(!supabase_auto_seed_enabled(), "must be opt-in — default must be false");
        std::env::remove_var("SUPABASE_AUTO_CREATE_TABLE");
        assert!(!supabase_auto_create_table_enabled(), "must be opt-in — default must be false");

        // Truthy values → true
        for val in &["1", "true", "yes", "on", "TRUE", "YES"] {
            std::env::set_var("SUPABASE_AUTO_SEED", val);
            assert!(supabase_auto_seed_enabled(), "expected true for SUPABASE_AUTO_SEED='{}'", val);
        }
        for val in &["1", "true", "yes", "on"] {
            std::env::set_var("SUPABASE_AUTO_CREATE_TABLE", val);
            assert!(supabase_auto_create_table_enabled(), "expected true for SUPABASE_AUTO_CREATE_TABLE='{}'", val);
        }

        // Falsy values → false
        for val in &["0", "false", "no", "off", "", "random"] {
            std::env::set_var("SUPABASE_AUTO_SEED", val);
            assert!(!supabase_auto_seed_enabled(), "expected false for SUPABASE_AUTO_SEED='{}'", val);
        }
        for val in &["0", "false", "no", "off", ""] {
            std::env::set_var("SUPABASE_AUTO_CREATE_TABLE", val);
            assert!(!supabase_auto_create_table_enabled(), "expected false for SUPABASE_AUTO_CREATE_TABLE='{}'", val);
        }

        // Cleanup
        std::env::remove_var("SUPABASE_AUTO_SEED");
        std::env::remove_var("SUPABASE_AUTO_CREATE_TABLE");
    }
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
