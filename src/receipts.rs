use anyhow::Context;
use rusqlite::Connection;

/// A row in the receipts table — one per successfully generated proof bundle.
pub struct Receipt {
    pub id: String,           // uuid v4
    pub bundle_path: String,  // absolute path to .zip
    pub proof_status: String, // VALID | INVALID | bundle_write_failed
    pub circuit_hash: String,
    pub bb_version: String,
    pub prompt_hash: String,
    pub request_hash: String,
    pub created_at: String, // ISO 8601 UTC
    /// "fast_lane" | "zk_slow_lane" | "zk_slow_lane_legacy"
    pub engine_used: String,
    /// SHA-256(proof bytes) for ZK path; None for legacy rows
    pub proof_hash: Option<String>,
    /// 0 — no raw data ever transmitted
    pub data_exfiltrated: i64,
}

/// Open (or create) the file-based receipts SQLite database at `db_path`.
/// Creates parent directories and the `receipts` table if they don't exist.
/// Runs migrations to add new columns (idempotent via PRAGMA user_version).
pub fn open_receipts_db(db_path: &std::path::Path) -> anyhow::Result<Connection> {
    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create directory {}", dir.display()))?;
    }

    let conn = Connection::open(db_path)
        .with_context(|| format!("open receipts DB at {}", db_path.display()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS receipts (
            receipt_id   TEXT PRIMARY KEY,
            bundle_path  TEXT NOT NULL,
            proof_status TEXT NOT NULL,
            circuit_hash TEXT NOT NULL,
            bb_version   TEXT NOT NULL,
            prompt_hash  TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            created_at   TEXT NOT NULL
        );",
    )
    .context("create receipts table")?;

    run_migration(&conn).context("run receipts DB migration")?;

    Ok(conn)
}

/// Apply schema migrations guarded by PRAGMA user_version.
/// Version 0 → 1: adds engine_used, proof_hash, data_exfiltrated columns
///                 and creates intent_rejections table.
pub fn run_migration(conn: &Connection) -> anyhow::Result<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .context("read user_version")?;

    if version >= 1 {
        return Ok(());
    }

    conn.execute_batch(
        "BEGIN;
         ALTER TABLE receipts ADD COLUMN engine_used TEXT DEFAULT 'zk_slow_lane_legacy';
         ALTER TABLE receipts ADD COLUMN proof_hash TEXT;
         ALTER TABLE receipts ADD COLUMN data_exfiltrated INTEGER DEFAULT 0;
         CREATE TABLE IF NOT EXISTS intent_rejections (
             id         INTEGER PRIMARY KEY AUTOINCREMENT,
             prompt     TEXT NOT NULL,
             error      TEXT NOT NULL,
             created_at TEXT NOT NULL
         );
         PRAGMA user_version = 1;
         COMMIT;",
    )
    .context("apply migration v1")?;

    Ok(())
}

/// Insert a receipt row after a bundle has been successfully written.
pub fn insert_receipt(conn: &Connection, r: &Receipt) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO receipts
            (receipt_id, bundle_path, proof_status, circuit_hash, bb_version,
             prompt_hash, request_hash, created_at, engine_used, proof_hash, data_exfiltrated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            r.id,
            r.bundle_path,
            r.proof_status,
            r.circuit_hash,
            r.bb_version,
            r.prompt_hash,
            r.request_hash,
            r.created_at,
            r.engine_used,
            r.proof_hash,
            r.data_exfiltrated,
        ],
    )
    .with_context(|| format!("insert receipt {}", r.id))?;
    Ok(())
}

/// Insert an intent rejection log entry.
pub fn insert_intent_rejection(
    conn: &Connection,
    prompt: &str,
    error: &str,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO intent_rejections (prompt, error, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![prompt, error, now],
    )
    .context("insert intent rejection")?;
    Ok(())
}

/// List all receipts ordered by created_at DESC (for `zemtik list`).
pub fn list_receipts(conn: &Connection) -> anyhow::Result<Vec<Receipt>> {
    let mut stmt = conn
        .prepare(
            "SELECT receipt_id, bundle_path, proof_status, circuit_hash, bb_version,
                    prompt_hash, request_hash, created_at,
                    COALESCE(engine_used, 'zk_slow_lane_legacy'),
                    proof_hash,
                    COALESCE(data_exfiltrated, 0)
             FROM receipts ORDER BY created_at DESC",
        )
        .context("prepare list_receipts")?;

    let rows = stmt
        .query_map([], |row| {
            Ok(Receipt {
                id: row.get(0)?,
                bundle_path: row.get(1)?,
                proof_status: row.get(2)?,
                circuit_hash: row.get(3)?,
                bb_version: row.get(4)?,
                prompt_hash: row.get(5)?,
                request_hash: row.get(6)?,
                created_at: row.get(7)?,
                engine_used: row.get(8)?,
                proof_hash: row.get(9)?,
                data_exfiltrated: row.get(10)?,
            })
        })
        .context("query receipts")?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect receipts")
}

/// Look up a receipt by UUID for the /verify/:id page.
pub fn get_receipt(conn: &Connection, id: &str) -> anyhow::Result<Option<Receipt>> {
    let mut stmt = conn
        .prepare(
            "SELECT receipt_id, bundle_path, proof_status, circuit_hash, bb_version,
                    prompt_hash, request_hash, created_at,
                    COALESCE(engine_used, 'zk_slow_lane_legacy'),
                    proof_hash,
                    COALESCE(data_exfiltrated, 0)
             FROM receipts WHERE receipt_id = ?1",
        )
        .context("prepare get_receipt")?;

    let mut rows = stmt
        .query_map(rusqlite::params![id], |row| {
            Ok(Receipt {
                id: row.get(0)?,
                bundle_path: row.get(1)?,
                proof_status: row.get(2)?,
                circuit_hash: row.get(3)?,
                bb_version: row.get(4)?,
                prompt_hash: row.get(5)?,
                request_hash: row.get(6)?,
                created_at: row.get(7)?,
                engine_used: row.get(8)?,
                proof_hash: row.get(9)?,
                data_exfiltrated: row.get(10)?,
            })
        })
        .context("query receipt")?;

    match rows.next() {
        Some(r) => Ok(Some(r.context("read receipt row")?)),
        None => Ok(None),
    }
}
