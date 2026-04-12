use std::path::Path;

use anyhow::Context;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::types::TunnelAuditRecord;

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
    /// How the query rewriter resolved this intent. "deterministic" | "llm" | None.
    /// None when no rewriting was performed. Added in v6.
    pub rewrite_method: Option<String>,
    /// The original (pre-rewrite) query text. None when no rewriting was performed. Added in v6.
    pub rewritten_query: Option<String>,
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
/// Version 5 → 6: adds rewrite_method and rewritten_query columns (hybrid rewriter audit trail).
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

    if version < 6 {
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE receipts ADD COLUMN rewrite_method TEXT DEFAULT NULL;
             ALTER TABLE receipts ADD COLUMN rewritten_query TEXT DEFAULT NULL;
             PRAGMA user_version = 6;
             COMMIT;",
        )
        .context("apply migration v6")?;
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
             actual_row_count, rewrite_method, rewritten_query)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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
            r.rewrite_method,
            r.rewritten_query,
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
                    actual_row_count,
                    rewrite_method,
                    rewritten_query
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
                rewrite_method: row.get(15)?,
                rewritten_query: row.get(16)?,
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
                    actual_row_count,
                    rewrite_method,
                    rewritten_query
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
                rewrite_method: row.get(15)?,
                rewritten_query: row.get(16)?,
            })
        })
        .context("query receipt")?;

    match rows.next() {
        Some(r) => Ok(Some(r.context("read receipt row")?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Tunnel audit DB (separate SQLite file: tunnel_audit.db)
// ---------------------------------------------------------------------------

/// Open (or create) the tunnel_audit.db SQLite database.
/// Uses WAL journal mode for concurrent read/write access.
pub fn open_tunnel_audit_db(db_path: &Path) -> anyhow::Result<Connection> {
    // Handle in-memory DBs used in tests (":memory:" path).
    if db_path.to_str() != Some(":memory:") {
        if let Some(dir) = db_path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create directory {}", dir.display()))?;
        }
    }
    let conn = Connection::open(db_path)
        .with_context(|| format!("open tunnel_audit DB at {}", db_path.display()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS tunnel_audit (
            id                          TEXT PRIMARY KEY,
            receipt_id                  TEXT,
            created_at                  TEXT NOT NULL,
            match_status                TEXT NOT NULL,
            matched_table               TEXT,
            matched_agg_fn              TEXT,
            original_status_code        INTEGER NOT NULL,
            original_response_body_hash TEXT NOT NULL,
            original_latency_ms         INTEGER NOT NULL,
            zemtik_aggregate            INTEGER,
            zemtik_row_count            INTEGER,
            zemtik_engine               TEXT,
            zemtik_latency_ms           INTEGER,
            diff_detected               INTEGER NOT NULL DEFAULT 0,
            diff_summary                TEXT,
            diff_details                TEXT,
            original_response_preview   TEXT,
            zemtik_response_preview     TEXT,
            error_message               TEXT,
            request_hash                TEXT NOT NULL,
            prompt_hash                 TEXT NOT NULL,
            intent_confidence           REAL,
            tunnel_model                TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_tunnel_audit_created ON tunnel_audit(created_at);
        CREATE INDEX IF NOT EXISTS idx_tunnel_audit_status ON tunnel_audit(match_status);
    ")?;
    Ok(conn)
}

/// Insert a tunnel audit record. Never hold the MutexGuard across .await.
pub fn insert_tunnel_audit(conn: &Connection, r: &TunnelAuditRecord) -> anyhow::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO tunnel_audit (
            id, receipt_id, created_at, match_status, matched_table, matched_agg_fn,
            original_status_code, original_response_body_hash, original_latency_ms,
            zemtik_aggregate, zemtik_row_count, zemtik_engine, zemtik_latency_ms,
            diff_detected, diff_summary, diff_details,
            original_response_preview, zemtik_response_preview, error_message,
            request_hash, prompt_hash, intent_confidence, tunnel_model
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
        rusqlite::params![
            r.id,
            r.receipt_id,
            r.created_at,
            r.match_status,
            r.matched_table,
            r.matched_agg_fn,
            r.original_status_code as i64,
            r.original_response_body_hash,
            r.original_latency_ms as i64,
            r.zemtik_aggregate,
            r.zemtik_row_count.map(|v| v as i64),
            r.zemtik_engine,
            r.zemtik_latency_ms.map(|v| v as i64),
            r.diff_detected as i64,
            r.diff_summary,
            r.diff_details,
            r.original_response_preview,
            r.zemtik_response_preview,
            r.error_message,
            r.request_hash,
            r.prompt_hash,
            r.intent_confidence,
            r.tunnel_model,
        ],
    ).context("insert tunnel_audit record")?;
    Ok(())
}

/// Filters for querying tunnel audit records.
pub struct TunnelAuditFilters {
    pub match_status: Option<String>,
    pub diff_detected: Option<bool>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub table: Option<String>,
    pub limit: usize,
    pub offset: usize,
}

impl Default for TunnelAuditFilters {
    fn default() -> Self {
        TunnelAuditFilters {
            match_status: None,
            diff_detected: None,
            from: None,
            to: None,
            table: None,
            limit: 100,
            offset: 0,
        }
    }
}

fn row_to_tunnel_audit(row: &rusqlite::Row<'_>) -> rusqlite::Result<TunnelAuditRecord> {
    Ok(TunnelAuditRecord {
        id: row.get(0)?,
        receipt_id: row.get(1)?,
        created_at: row.get(2)?,
        match_status: row.get(3)?,
        matched_table: row.get(4)?,
        matched_agg_fn: row.get(5)?,
        original_status_code: row.get::<_, i64>(6)? as u16,
        original_response_body_hash: row.get(7)?,
        original_latency_ms: row.get::<_, i64>(8)? as u64,
        zemtik_aggregate: row.get(9)?,
        zemtik_row_count: row.get::<_, Option<i64>>(10)?.map(|v| v as usize),
        zemtik_engine: row.get(11)?,
        zemtik_latency_ms: row.get::<_, Option<i64>>(12)?.map(|v| v as u64),
        diff_detected: row.get::<_, i64>(13)? != 0,
        diff_summary: row.get(14)?,
        diff_details: row.get(15)?,
        original_response_preview: row.get(16)?,
        zemtik_response_preview: row.get(17)?,
        error_message: row.get(18)?,
        request_hash: row.get(19)?,
        prompt_hash: row.get(20)?,
        intent_confidence: row.get(21)?,
        tunnel_model: row.get(22)?,
    })
}

/// Query tunnel audit records with optional filters and pagination.
pub fn query_tunnel_audits(
    conn: &Connection,
    filters: &TunnelAuditFilters,
) -> anyhow::Result<Vec<TunnelAuditRecord>> {
    let mut sql = "SELECT id, receipt_id, created_at, match_status, matched_table, matched_agg_fn,
        original_status_code, original_response_body_hash, original_latency_ms,
        zemtik_aggregate, zemtik_row_count, zemtik_engine, zemtik_latency_ms,
        diff_detected, diff_summary, diff_details,
        original_response_preview, zemtik_response_preview, error_message,
        request_hash, prompt_hash, intent_confidence, tunnel_model
        FROM tunnel_audit WHERE 1=1".to_owned();

    let mut param_values: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    let mut idx = 1usize;

    if let Some(ref status) = filters.match_status {
        sql.push_str(&format!(" AND match_status = ?{idx}"));
        param_values.push(Box::new(status.clone()));
        idx += 1;
    }
    if let Some(diff) = filters.diff_detected {
        sql.push_str(&format!(" AND diff_detected = ?{idx}"));
        param_values.push(Box::new(diff as i64));
        idx += 1;
    }
    if let Some(ref from) = filters.from {
        sql.push_str(&format!(" AND created_at >= ?{idx}"));
        param_values.push(Box::new(from.clone()));
        idx += 1;
    }
    if let Some(ref to) = filters.to {
        sql.push_str(&format!(" AND created_at <= ?{idx}"));
        param_values.push(Box::new(to.clone()));
        idx += 1;
    }
    if let Some(ref table) = filters.table {
        sql.push_str(&format!(" AND matched_table = ?{idx}"));
        param_values.push(Box::new(table.clone()));
        idx += 1;
    }
    sql.push_str(&format!(" ORDER BY created_at DESC LIMIT ?{idx} OFFSET ?{}", idx + 1));
    param_values.push(Box::new(filters.limit as i64));
    param_values.push(Box::new(filters.offset as i64));

    let params: Vec<&dyn rusqlite::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params.as_slice(), row_to_tunnel_audit)
        .context("query tunnel_audit")?;
    let mut results = Vec::new();
    for row in rows {
        results.push(row.context("read tunnel_audit row")?);
    }
    Ok(results)
}

/// List tunnel audit records (most recent first).
pub fn list_tunnel_audits(conn: &Connection, limit: usize) -> anyhow::Result<Vec<TunnelAuditRecord>> {
    query_tunnel_audits(conn, &TunnelAuditFilters {
        limit,
        ..Default::default()
    })
}

/// Aggregate summary metrics for the /tunnel/summary endpoint.
pub struct TunnelSummary {
    pub total_requests: u64,
    pub matched_rate: f64,
    pub diff_rate: f64,
    pub avg_zemtik_latency_ms: f64,
}

pub fn tunnel_summary(conn: &Connection) -> anyhow::Result<TunnelSummary> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM tunnel_audit",
        [],
        |r| r.get(0),
    )?;

    if total == 0 {
        return Ok(TunnelSummary {
            total_requests: 0,
            matched_rate: 0.0,
            diff_rate: 0.0,
            avg_zemtik_latency_ms: 0.0,
        });
    }

    let matched: i64 = conn.query_row(
        "SELECT COUNT(*) FROM tunnel_audit WHERE match_status = 'matched'",
        [],
        |r| r.get(0),
    )?;

    let diff_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM tunnel_audit WHERE diff_detected = 1",
        [],
        |r| r.get(0),
    )?;

    let avg_latency: f64 = conn.query_row(
        "SELECT COALESCE(AVG(CAST(zemtik_latency_ms AS REAL)), 0.0) FROM tunnel_audit WHERE zemtik_latency_ms IS NOT NULL",
        [],
        |r| r.get(0),
    )?;

    Ok(TunnelSummary {
        total_requests: total as u64,
        matched_rate: matched as f64 / total as f64,
        diff_rate: diff_count as f64 / total as f64,
        avg_zemtik_latency_ms: avg_latency,
    })
}
