use zemtik::config::{AggFn, TableConfig};
use zemtik::db::init_ledger_sqlite;
use zemtik::engine_fast::{attest_fast_lane, run_fast_lane};
use zemtik::keys::load_or_generate_key;
use zemtik::types::EngineResult;

/// Helper: build a TableConfig that matches the in-memory SQLite ledger schema.
fn default_aws_table_config() -> TableConfig {
    TableConfig {
        sensitivity: "low".to_owned(),
        value_column: "amount".to_owned(),
        timestamp_column: "timestamp".to_owned(),
        category_column: Some("category_name".to_owned()),
        agg_fn: AggFn::Sum,
        metric_label: "total_spend_usd".to_owned(),
        ..Default::default()
    }
}

/// Zero-row results now return Ok(FastLaneResult) — not EmptyResult.
/// The attestation must be signed even when no rows matched.
#[test]
fn fast_lane_zero_result_has_signed_attestation() {
    let conn = init_ledger_sqlite().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    // "nonexistent_category" has no rows in the ledger DB.
    let result = run_fast_lane(
        &conn, &key, 123, "nonexistent_category", default_aws_table_config(),
        "nonexistent_category", 1704067200, 1711929599,
    );
    match result {
        EngineResult::Ok(fl) => {
            assert_eq!(fl.row_count, 0, "expected zero rows");
            assert_eq!(fl.aggregate, 0, "expected zero aggregate");
            assert!(!fl.key_id.is_empty(), "zero-result receipt must have a signed key_id");
            assert!(!fl.attestation_hash.is_empty(), "zero-result receipt must have an attestation_hash");
        }
        _ => panic!("expected Ok(fl), got unexpected variant"),
    }
}

/// Regression test: FastLane signing must never fail with
/// "msg outside the Finite Field", even for hashes whose raw 256-bit value
/// exceeds the BN254 scalar field order (~2^254).
///
/// Before the fix, ~25% of runs hit this error nondeterministically.
/// The fix reduces msg mod field_order before calling .sign().
#[test]
fn fast_lane_sign_never_exceeds_field() {
    let conn = init_ledger_sqlite().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    for _ in 0..20 {
        let result = run_fast_lane(
            &conn, &key, 123, "aws_spend", default_aws_table_config(),
            "aws_spend", 1704067200, 1711929599,
        );
        assert!(
            !matches!(result, EngineResult::SignError(_)),
            "FastLane sign failed with SignError"
        );
        assert!(
            matches!(result, EngineResult::Ok(_)),
            "Expected Ok result from FastLane"
        );
    }
}

/// Attestation hashes must differ across categories.
#[test]
fn fast_lane_attestation_differs_by_category() {
    let conn = init_ledger_sqlite().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    let r1 = run_fast_lane(&conn, &key, 123, "aws_spend", default_aws_table_config(), "aws_spend", 1704067200, 1711929599);
    let r2 = run_fast_lane(&conn, &key, 123, "payroll",   default_aws_table_config(), "payroll",            1704067200, 1711929599);

    match (r1, r2) {
        (EngineResult::Ok(fl1), EngineResult::Ok(fl2)) => {
            assert_ne!(
                fl1.attestation_hash, fl2.attestation_hash,
                "attestation_hash must differ when category differs"
            );
        }
        _ => panic!("expected Ok for both categories"),
    }
}

/// COUNT aggregation returns count value in the aggregate field.
#[test]
fn run_fast_lane_count_agg_returns_count_in_aggregate_field() {
    let conn = init_ledger_sqlite().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    let count_config = TableConfig {
        sensitivity: "low".to_owned(),
        value_column: "amount".to_owned(),
        timestamp_column: "timestamp".to_owned(),
        category_column: Some("category_name".to_owned()),
        agg_fn: AggFn::Count,
        metric_label: "row_count".to_owned(),
        ..Default::default()
    };

    let result = run_fast_lane(
        &conn, &key, 123, "aws_spend", count_config,
        "aws_spend", 1704067200, 1711929599,
    );
    match result {
        EngineResult::Ok(fl) => {
            assert!(fl.aggregate > 0, "COUNT should return a positive value for seeded data");
            assert_eq!(fl.aggregate, fl.row_count as i64, "COUNT aggregate == row_count");
        }
        _ => panic!("expected Ok"),
    }
}

/// Same data, different descriptor (agg_fn or value_column) → different attestation hash.
/// Uses fixed now_unix for determinism.
#[test]
fn attest_fast_lane_different_descriptor_produces_different_hash() {
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    let config_sum = TableConfig {
        sensitivity: "low".to_owned(),
        value_column: "amount".to_owned(),
        timestamp_column: "timestamp".to_owned(),
        category_column: Some("category_name".to_owned()),
        agg_fn: AggFn::Sum,
        metric_label: "total_spend_usd".to_owned(),
        ..Default::default()
    };
    let config_count = TableConfig {
        agg_fn: AggFn::Count,
        ..config_sum.clone()
    };

    let r1 = attest_fast_lane(&key, 123, "aws_spend", &config_sum,   "aws", 500, 5, 0, 999, 1_000_000);
    let r2 = attest_fast_lane(&key, 123, "aws_spend", &config_count, "aws", 500, 5, 0, 999, 1_000_000);

    match (r1, r2) {
        (EngineResult::Ok(fl1), EngineResult::Ok(fl2)) => {
            assert_ne!(
                fl1.attestation_hash, fl2.attestation_hash,
                "different agg_fn must produce different attestation hash"
            );
        }
        _ => panic!("expected Ok for both"),
    }
}

/// Same config, same data, different client_id → different attestation hash.
#[test]
fn attest_fast_lane_different_client_id_produces_different_hash() {
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    let config = default_aws_table_config();

    let r1 = attest_fast_lane(&key, 123, "aws_spend", &config, "aws", 500, 5, 0, 999, 1_000_000);
    let r2 = attest_fast_lane(&key, 456, "aws_spend", &config, "aws", 500, 5, 0, 999, 1_000_000);

    match (r1, r2) {
        (EngineResult::Ok(fl1), EngineResult::Ok(fl2)) => {
            assert_ne!(
                fl1.attestation_hash, fl2.attestation_hash,
                "different client_id must produce different attestation hash"
            );
        }
        _ => panic!("expected Ok for both"),
    }
}

/// When category_column is None, run_fast_lane completes without error.
/// The payload note about non-category-based filtering is added in proxy.rs, not here.
#[test]
fn fast_lane_category_col_none_succeeds() {
    let conn = init_ledger_sqlite().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    let config_no_cat = TableConfig {
        sensitivity: "low".to_owned(),
        value_column: "amount".to_owned(),
        timestamp_column: "timestamp".to_owned(),
        category_column: None, // no category filtering
        agg_fn: AggFn::Sum,
        metric_label: "total_spend_usd".to_owned(),
        ..Default::default()
    };

    let result = run_fast_lane(
        &conn, &key, 123, "aws_spend", config_no_cat,
        "aws_spend", 1704067200, 1711929599,
    );
    assert!(
        matches!(result, EngineResult::Ok(_)),
        "category_col=None should succeed, got: {:?}",
        result,
    );
}
