use zemtik::db::init_ledger_sqlite;
use zemtik::engine_fast::run_fast_lane;
use zemtik::keys::load_or_generate_key;
use zemtik::types::EngineResult;

/// EmptyResult when no rows match the category/time range.
#[test]
fn fast_lane_empty_result_when_no_rows() {
    let conn = init_ledger_sqlite().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    // "nonexistent_category" has no rows in the ledger DB.
    let result = run_fast_lane(&conn, &key, "nonexistent_category", 1704067200, 1711929599);
    assert!(
        matches!(result, EngineResult::EmptyResult),
        "Expected EmptyResult for unknown category"
    );
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

    // Run enough iterations to statistically exercise payloads that exceed field_order
    // (probability ~25% per run, so 20 runs has <0.003% chance of not hitting one).
    for _ in 0..20 {
        let result = run_fast_lane(
            &conn,
            &key,
            "aws_spend",
            1704067200,
            1711929599,
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
