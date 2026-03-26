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
}

/// Open (or create) the file-based receipts SQLite database at `~/.zemtik/receipts.db`.
/// Creates the directory and the `receipts` table if they don't exist.
pub fn open_receipts_db() -> anyhow::Result<Connection> {
    let home = dirs::home_dir().context("could not resolve home directory")?;
    let dir = home.join(".zemtik");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create directory {}", dir.display()))?;

    let db_path = dir.join("receipts.db");
    let conn = Connection::open(&db_path)
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

    Ok(conn)
}

/// Insert a receipt row after a bundle has been successfully written.
pub fn insert_receipt(conn: &Connection, r: &Receipt) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO receipts
            (receipt_id, bundle_path, proof_status, circuit_hash, bb_version, prompt_hash, request_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            r.id,
            r.bundle_path,
            r.proof_status,
            r.circuit_hash,
            r.bb_version,
            r.prompt_hash,
            r.request_hash,
            r.created_at,
        ],
    )
    .with_context(|| format!("insert receipt {}", r.id))?;
    Ok(())
}

/// Look up a receipt by UUID for the /verify/:id page.
pub fn get_receipt(conn: &Connection, id: &str) -> anyhow::Result<Option<Receipt>> {
    let mut stmt = conn
        .prepare(
            "SELECT receipt_id, bundle_path, proof_status, circuit_hash, bb_version,
                    prompt_hash, request_hash, created_at
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
            })
        })
        .context("query receipt")?;

    match rows.next() {
        Some(r) => Ok(Some(r.context("read receipt row")?)),
        None => Ok(None),
    }
}
