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
    assert_eq!(version, 1);
}

#[test]
fn test_migration_idempotent() {
    let conn = open_in_memory().unwrap();
    run_migration(&conn).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1);
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
fn test_insert_intent_rejection() {
    let conn = open_in_memory().unwrap();
    insert_intent_rejection(&conn, "some prompt", "NoTableIdentified").unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM intent_rejections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}
