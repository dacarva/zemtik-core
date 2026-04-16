use rusqlite::Connection;
use zemtik::receipts::{
    count_engine_today, count_intent_failures_today, count_receipts, get_receipt,
    insert_intent_rejection, insert_receipt, list_receipts, run_migration, update_evidence_json,
    Receipt, PROOF_STATUS_GENERAL_LANE,
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
        actual_row_count: None,
        rewrite_method: None,
        rewritten_query: None,
        manifest_key_id: None,
        evidence_json: None,
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
    assert_eq!(version, 9, "expected migration to reach version 9");
}

#[test]
fn test_migration_idempotent() {
    let conn = open_in_memory().unwrap();
    run_migration(&conn).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 9, "migration should be idempotent at version 9");
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
    assert_eq!(version_after, 9, "v2→v9 migration must bump to version 9");

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
fn test_migration_v4_to_v5() {
    // Simulate a v4 database: create base table + run v1-v4 migrations manually
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
        COMMIT;
        BEGIN;
        ALTER TABLE receipts ADD COLUMN outgoing_prompt_hash TEXT DEFAULT NULL;
        PRAGMA user_version = 3;
        COMMIT;
        BEGIN;
        ALTER TABLE receipts ADD COLUMN signing_version INTEGER DEFAULT NULL;
        PRAGMA user_version = 4;
        COMMIT;",
    )
    .unwrap();

    let version_before: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_before, 4);

    run_migration(&conn).unwrap();

    let version_after: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_after, 9, "v4→v9 migration must bump to version 9");

    // Regression: ISSUE-001 — actual_row_count column missing after v4→v5 migration
    // Found by /qa on 2026-04-07
    // Report: .gstack/qa-reports/qa-report-zemtik-core-2026-04-07.md
    let col_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('receipts') WHERE name='actual_row_count'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(col_count, 1, "actual_row_count column must exist after v5 migration");
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
    let list = list_receipts(&conn, 50).unwrap();
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

    let list = list_receipts(&conn, 50).unwrap();
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

#[test]
fn receipts_v6_rewrite_fields_written_and_retrieved() {
    let conn = open_in_memory().unwrap();

    // Insert a receipt that was produced by the LLM rewriter path.
    let mut r = sample_receipt("v6-llm-uuid");
    r.rewrite_method = Some("llm".to_owned());
    r.rewritten_query = Some("What was aws_spend in Q1 2024?".to_owned());
    insert_receipt(&conn, &r).unwrap();

    // get_receipt must return both fields.
    let found = get_receipt(&conn, "v6-llm-uuid").unwrap().unwrap();
    assert_eq!(
        found.rewrite_method,
        Some("llm".to_owned()),
        "rewrite_method must round-trip"
    );
    assert_eq!(
        found.rewritten_query,
        Some("What was aws_spend in Q1 2024?".to_owned()),
        "rewritten_query must round-trip"
    );

    // Insert a direct (non-rewritten) receipt — both fields must be None.
    insert_receipt(&conn, &sample_receipt("v6-direct-uuid")).unwrap();
    let direct = get_receipt(&conn, "v6-direct-uuid").unwrap().unwrap();
    assert_eq!(direct.rewrite_method, None, "direct receipt rewrite_method must be None");
    assert_eq!(direct.rewritten_query, None, "direct receipt rewritten_query must be None");

    // list_receipts must return the rewrite fields.
    let list = list_receipts(&conn, 50).unwrap();
    let llm_row = list.iter().find(|r| r.id == "v6-llm-uuid").unwrap();
    assert_eq!(llm_row.rewrite_method, Some("llm".to_owned()));
}

#[test]
fn test_migration_v5_to_v6_adds_rewrite_columns() {
    // Simulate a v5 database and verify that run_migration adds the v6 columns.
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
        COMMIT;
        BEGIN;
        ALTER TABLE receipts ADD COLUMN outgoing_prompt_hash TEXT DEFAULT NULL;
        PRAGMA user_version = 3;
        COMMIT;
        BEGIN;
        ALTER TABLE receipts ADD COLUMN signing_version INTEGER DEFAULT NULL;
        PRAGMA user_version = 4;
        COMMIT;
        BEGIN;
        ALTER TABLE receipts ADD COLUMN actual_row_count INTEGER DEFAULT NULL;
        PRAGMA user_version = 5;
        COMMIT;",
    )
    .unwrap();

    let version_before: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_before, 5);

    run_migration(&conn).unwrap();

    let version_after: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_after, 9, "v5→v9 migration must bump to version 9");

    for col in &["rewrite_method", "rewritten_query"] {
        let count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM pragma_table_info('receipts') WHERE name='{col}'"
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "column '{col}' must exist after v5→v7 migration");
    }
}

#[test]
fn test_migration_v6_to_v7_adds_index() {
    // Simulate a v6 database and verify that run_migration creates the v7 index.
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
            created_at   TEXT NOT NULL,
            engine_used  TEXT DEFAULT 'zk_slow_lane_legacy',
            proof_hash   TEXT,
            data_exfiltrated INTEGER DEFAULT 0,
            intent_confidence REAL DEFAULT NULL,
            outgoing_prompt_hash TEXT DEFAULT NULL,
            signing_version INTEGER DEFAULT NULL,
            actual_row_count INTEGER DEFAULT NULL,
            rewrite_method TEXT DEFAULT NULL,
            rewritten_query TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS intent_rejections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            error TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        PRAGMA user_version = 6;",
    )
    .unwrap();

    let version_before: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_before, 6);

    run_migration(&conn).unwrap();

    let version_after: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version_after, 9, "v6→v9 migration must bump to version 9");

    let idx_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_receipts_engine_created'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx_count, 1, "idx_receipts_engine_created must exist after v6→v7 migration");
}

#[test]
fn test_count_engine_today_returns_correct_count() {
    let conn = open_in_memory().unwrap();

    // Insert a general_lane receipt with today's timestamp
    let mut r = sample_receipt("r1");
    r.engine_used = "general_lane".to_owned();
    r.proof_status = PROOF_STATUS_GENERAL_LANE.to_owned();
    r.bundle_path = String::new();
    r.circuit_hash = String::new();
    r.bb_version = String::new();
    r.created_at = chrono::Utc::now().to_rfc3339();
    insert_receipt(&conn, &r).unwrap();

    // Insert a fast_lane receipt (should NOT be counted)
    let mut r2 = sample_receipt("r2");
    r2.engine_used = "fast_lane".to_owned();
    r2.created_at = chrono::Utc::now().to_rfc3339();
    insert_receipt(&conn, &r2).unwrap();

    // Insert a general_lane receipt with a past day's timestamp (should NOT be counted)
    let mut r3 = sample_receipt("r3");
    r3.engine_used = "general_lane".to_owned();
    r3.created_at = "2020-01-01T00:00:00Z".to_owned();
    insert_receipt(&conn, &r3).unwrap();

    let count = count_engine_today(&conn, "general_lane").unwrap();
    assert_eq!(count, 1, "count_engine_today must count only today's general_lane receipts");
}

#[test]
fn test_count_intent_failures_today_returns_correct_count() {
    let conn = open_in_memory().unwrap();

    // Insert an intent rejection with today's timestamp
    insert_intent_rejection(&conn, "test prompt", "NoTableIdentified").unwrap();

    // Insert one with a past day's timestamp directly (bypassing the helper)
    conn.execute(
        "INSERT INTO intent_rejections (prompt, error, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params!["old prompt", "some error", "2020-01-01T00:00:00Z"],
    ).unwrap();

    let count = count_intent_failures_today(&conn).unwrap();
    assert_eq!(count, 1, "count_intent_failures_today must count only today's intent rejections");
}

#[test]
fn test_count_receipts() {
    let conn = open_in_memory().unwrap();
    assert_eq!(count_receipts(&conn).unwrap(), 0, "empty DB must return 0");
    insert_receipt(&conn, &sample_receipt("count-1")).unwrap();
    assert_eq!(count_receipts(&conn).unwrap(), 1);
    insert_receipt(&conn, &sample_receipt("count-2")).unwrap();
    assert_eq!(count_receipts(&conn).unwrap(), 2);
}

#[test]
fn test_update_evidence_json() {
    let conn = open_in_memory().unwrap();
    let mut r = sample_receipt("ev-json-uuid");
    r.evidence_json = None;
    insert_receipt(&conn, &r).unwrap();

    // Verify starts as None
    let found = get_receipt(&conn, "ev-json-uuid").unwrap().unwrap();
    assert_eq!(found.evidence_json, None, "evidence_json must start as None");

    // Update to a JSON string
    let json = r#"{"engine_used":"fast_lane","aggregate":42}"#;
    update_evidence_json(&conn, "ev-json-uuid", json).unwrap();

    let updated = get_receipt(&conn, "ev-json-uuid").unwrap().unwrap();
    assert_eq!(
        updated.evidence_json.as_deref(),
        Some(json),
        "update_evidence_json must persist the JSON string"
    );
}

#[test]
fn test_evidence_json_round_trips_through_insert() {
    let conn = open_in_memory().unwrap();
    let mut r = sample_receipt("ev-insert-uuid");
    r.evidence_json = Some(r#"{"engine_used":"fast_lane","aggregate":100}"#.to_owned());
    insert_receipt(&conn, &r).unwrap();

    let found = get_receipt(&conn, "ev-insert-uuid").unwrap().unwrap();
    assert_eq!(
        found.evidence_json,
        r.evidence_json,
        "evidence_json must round-trip through insert_receipt"
    );
}

#[test]
fn test_list_receipts_respects_limit() {
    let conn = open_in_memory().unwrap();
    for i in 0..10 {
        insert_receipt(&conn, &sample_receipt(&format!("limit-{}", i))).unwrap();
    }
    let list5 = list_receipts(&conn, 5).unwrap();
    assert_eq!(list5.len(), 5, "list_receipts must respect the limit parameter");

    let list_all = list_receipts(&conn, 100).unwrap();
    assert_eq!(list_all.len(), 10, "list_receipts with generous limit returns all rows");
}

#[test]
fn test_migration_v8_to_v9_adds_evidence_json_column() {
    // Simulate a v8 database (all columns through manifest_key_id, no evidence_json)
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
            created_at   TEXT NOT NULL,
            engine_used  TEXT DEFAULT 'zk_slow_lane_legacy',
            proof_hash   TEXT,
            data_exfiltrated INTEGER DEFAULT 0,
            intent_confidence REAL DEFAULT NULL,
            outgoing_prompt_hash TEXT DEFAULT NULL,
            signing_version INTEGER DEFAULT NULL,
            actual_row_count INTEGER DEFAULT NULL,
            rewrite_method TEXT DEFAULT NULL,
            rewritten_query TEXT DEFAULT NULL,
            manifest_key_id TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS intent_rejections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            error TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        PRAGMA user_version = 8;",
    )
    .unwrap();

    run_migration(&conn).unwrap();

    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 9, "v8→v9 migration must bump to version 9");

    let col_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('receipts') WHERE name='evidence_json'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(col_count, 1, "evidence_json column must exist after v9 migration");
}
