use rusqlite::Connection;
use zemtik::receipts::{
    get_receipt, insert_intent_rejection, insert_receipt, list_receipts, run_migration, Receipt,
};

fn open_in_memory() -> anyhow::Result<Connection> {
    let conn = Connection::open_in_memory()?;
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
    )?;
    run_migration(&conn)?;
    Ok(conn)
}

fn sample_receipt(id: &str) -> Receipt {
    Receipt {
        id: id.to_owned(),
        bundle_path: "/tmp/test.zip".to_owned(),
        proof_status: "VALID".to_owned(),
        circuit_hash: "abc123".to_owned(),
        bb_version: "4.0.0".to_owned(),
        prompt_hash: "ph".to_owned(),
        request_hash: "rh".to_owned(),
        created_at: "2026-01-01T00:00:00Z".to_owned(),
        engine_used: "zk_slow_lane".to_owned(),
        proof_hash: Some("deadbeef".to_owned()),
        data_exfiltrated: 0,
        intent_confidence: None,
        outgoing_prompt_hash: None,
        signing_version: None,
    }
}

#[test]
fn test_insert_and_get_receipt() {
    let conn = open_in_memory().unwrap();
    let r = sample_receipt("test-uuid-1");
    insert_receipt(&conn, &r).unwrap();

    let found = get_receipt(&conn, "test-uuid-1").unwrap();
    assert!(found.is_some());
    let got = found.unwrap();
    assert_eq!(got.id, "test-uuid-1");
    assert_eq!(got.proof_status, "VALID");
    assert_eq!(got.circuit_hash, "abc123");
    assert_eq!(got.engine_used, "zk_slow_lane");
}

#[test]
fn test_get_receipt_not_found() {
    let conn = open_in_memory().unwrap();
    let result = get_receipt(&conn, "nonexistent-uuid").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_insert_duplicate_receipt_fails() {
    let conn = open_in_memory().unwrap();
    let r = sample_receipt("dup-uuid");
    insert_receipt(&conn, &r).unwrap();
    assert!(insert_receipt(&conn, &r).is_err(), "duplicate primary key must fail");
}

#[test]
fn test_migration_on_fresh_db() {
    let conn = Connection::open_in_memory().unwrap();
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
    .unwrap();
    run_migration(&conn).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 4, "expected migration to reach version 4");
}

#[test]
fn test_migration_idempotent() {
    let conn = open_in_memory().unwrap();
    run_migration(&conn).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 4, "migration should be idempotent at version 4");
}

#[test]
fn test_migration_v2_to_v3() {
    // Simulate a v2 database: create base table + run only v1+v2 migrations manually
    let conn = Connection::open_in_memory().unwrap();
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
        );
        BEGIN;
        ALTER TABLE receipts ADD COLUMN engine_used TEXT DEFAULT 'zk_slow_lane_legacy';
        ALTER TABLE receipts ADD COLUMN proof_hash TEXT;
        ALTER TABLE receipts ADD COLUMN data_exfiltrated INTEGER DEFAULT 0;
        CREATE TABLE IF NOT EXISTS intent_rejections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            error TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        PRAGMA user_version = 1;
        COMMIT;
        BEGIN;
        ALTER TABLE receipts ADD COLUMN intent_confidence REAL DEFAULT NULL;
        PRAGMA user_version = 2;
        COMMIT;",
    )
    .unwrap();

    let version_before: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_before, 2);

    run_migration(&conn).unwrap();

    let version_after: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_after, 4, "v2→v4 migration must bump to version 4");

    // Verify the column exists
    let col_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('receipts') WHERE name='outgoing_prompt_hash'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(col_count, 1, "outgoing_prompt_hash column must exist after v3 migration");
}

#[test]
fn test_intent_confidence_stored_and_retrieved() {
    let conn = open_in_memory().unwrap();
    let mut r = sample_receipt("conf-uuid");
    r.intent_confidence = Some(0.87);
    insert_receipt(&conn, &r).unwrap();

    let found = get_receipt(&conn, "conf-uuid").unwrap().unwrap();
    assert!(
        found.intent_confidence.is_some(),
        "intent_confidence should be stored"
    );
    assert!(
        (found.intent_confidence.unwrap() - 0.87).abs() < 0.001,
        "intent_confidence value mismatch"
    );
}

#[test]
fn test_list_receipts() {
    let conn = open_in_memory().unwrap();
    insert_receipt(&conn, &sample_receipt("id-1")).unwrap();
    insert_receipt(&conn, &sample_receipt("id-2")).unwrap();
    let list = list_receipts(&conn).unwrap();
    assert_eq!(list.len(), 2);
}

#[test]
fn test_outgoing_prompt_hash_stored_and_retrieved() {
    let conn = open_in_memory().unwrap();
    let mut r = sample_receipt("hash-uuid");
    r.outgoing_prompt_hash = Some("sha256:abc123def456".to_owned());
    insert_receipt(&conn, &r).unwrap();

    let found = get_receipt(&conn, "hash-uuid").unwrap().unwrap();
    assert_eq!(
        found.outgoing_prompt_hash,
        Some("sha256:abc123def456".to_owned()),
        "outgoing_prompt_hash must round-trip through DB"
    );
}

#[test]
fn test_outgoing_prompt_hash_null_for_old_rows() {
    let conn = open_in_memory().unwrap();
    let r = sample_receipt("null-hash-uuid"); // outgoing_prompt_hash: None
    insert_receipt(&conn, &r).unwrap();

    let found = get_receipt(&conn, "null-hash-uuid").unwrap().unwrap();
    assert_eq!(
        found.outgoing_prompt_hash, None,
        "None outgoing_prompt_hash must deserialize correctly"
    );
}

#[test]
fn test_list_receipts_includes_outgoing_hash() {
    let conn = open_in_memory().unwrap();
    let mut r = sample_receipt("list-hash-uuid");
    r.outgoing_prompt_hash = Some("sha256:listtest123".to_owned());
    insert_receipt(&conn, &r).unwrap();

    let list = list_receipts(&conn).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        list[0].outgoing_prompt_hash,
        Some("sha256:listtest123".to_owned()),
        "list_receipts must return outgoing_prompt_hash field"
    );
}

#[test]
fn test_insert_intent_rejection() {
    let conn = open_in_memory().unwrap();
    insert_intent_rejection(&conn, "some prompt", "NoTableIdentified").unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM intent_rejections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}
