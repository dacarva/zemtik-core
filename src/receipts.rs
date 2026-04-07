use anyhow::Context;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

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
    /// Intent matching confidence score; None for legacy rows (pre-v2).
    pub intent_confidence: Option<f32>,
    /// SHA-256 of the JSON payload sent to the LLM (Rust-layer commitment).
    /// None for legacy rows (pre-v3) or CLI pipeline rows.
    pub outgoing_prompt_hash: Option<String>,
    /// FastLane attestation payload version: None or 1 = pre-v0.7.0; 2 = descriptor-bound.
    pub signing_version: Option<u8>,
    /// Number of real (non-dummy padding) transactions in the ZK proof.
    /// None for FastLane path or legacy rows (pre-v5).
    pub actual_row_count: Option<usize>,
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
/// Version 1 → 2: adds intent_confidence column.
/// Version 2 → 3: adds outgoing_prompt_hash column.
/// Version 3 → 4: adds signing_version column.
/// Version 4 → 5: adds actual_row_count column (pre-padding real row count for ZK path).
pub fn run_migration(conn: &Connection) -> anyhow::Result<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .context("read user_version")?;

    if version < 1 {
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
    }

    if version < 2 {
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE receipts ADD COLUMN intent_confidence REAL DEFAULT NULL;
             PRAGMA user_version = 2;
             COMMIT;",
        )
        .context("apply migration v2")?;
    }

    if version < 3 {
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE receipts ADD COLUMN outgoing_prompt_hash TEXT DEFAULT NULL;
             PRAGMA user_version = 3;
             COMMIT;",
        )
        .context("apply migration v3")?;
    }

    if version < 4 {
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE receipts ADD COLUMN signing_version INTEGER DEFAULT NULL;
             PRAGMA user_version = 4;
             COMMIT;",
        )
        .context("apply migration v4")?;
    }

    if version < 5 {
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE receipts ADD COLUMN actual_row_count INTEGER DEFAULT NULL;
             PRAGMA user_version = 5;
             COMMIT;",
        )
        .context("apply migration v5")?;
    }

    Ok(())
}

/// Insert a receipt row after a bundle has been successfully written.
pub fn insert_receipt(conn: &Connection, r: &Receipt) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO receipts
            (receipt_id, bundle_path, proof_status, circuit_hash, bb_version,
             prompt_hash, request_hash, created_at, engine_used, proof_hash,
             data_exfiltrated, intent_confidence, outgoing_prompt_hash, signing_version,
             actual_row_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
            r.intent_confidence,
            r.outgoing_prompt_hash,
            r.signing_version.map(|v| v as i64),
            r.actual_row_count.map(|v| v as i64),
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
    // Store first 100 chars for debuggability + SHA-256 of the full prompt.
    // Avoids persisting PII or sensitive financial data in plaintext.
    let prompt_preview = prompt.chars().take(100).collect::<String>();
    let prompt_hash = hex::encode(Sha256::digest(prompt.as_bytes()));
    let stored = format!("{}…[sha256:{}]", prompt_preview, &prompt_hash[..16]);
    conn.execute(
        "INSERT INTO intent_rejections (prompt, error, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![stored, error, now],
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
                    COALESCE(data_exfiltrated, 0),
                    intent_confidence,
                    outgoing_prompt_hash,
                    signing_version,
                    actual_row_count
             FROM receipts ORDER BY created_at DESC",
        )
        .context("prepare list_receipts")?;

    let rows = stmt
        .query_map([], |row| {
            let sv: Option<i64> = row.get(13)?;
            let arc: Option<i64> = row.get(14)?;
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
                intent_confidence: row.get(11)?,
                outgoing_prompt_hash: row.get(12)?,
                signing_version: sv.map(|v| v as u8),
                actual_row_count: arc.map(|v| v as usize),
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
                    COALESCE(data_exfiltrated, 0),
                    intent_confidence,
                    outgoing_prompt_hash,
                    signing_version,
                    actual_row_count
             FROM receipts WHERE receipt_id = ?1",
        )
        .context("prepare get_receipt")?;

    let mut rows = stmt
        .query_map(rusqlite::params![id], |row| {
            let sv: Option<i64> = row.get(13)?;
            let arc: Option<i64> = row.get(14)?;
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
                intent_confidence: row.get(11)?,
                outgoing_prompt_hash: row.get(12)?,
                signing_version: sv.map(|v| v as u8),
                actual_row_count: arc.map(|v| v as usize),
            })
        })
        .context("query receipt")?;

    match rows.next() {
        Some(r) => Ok(Some(r.context("read receipt row")?)),
        None => Ok(None),
    }
}
