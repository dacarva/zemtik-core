use zemtik::db::init_ledger_sqlite;
use zemtik::engine_fast::run_fast_lane;
use zemtik::keys::load_or_generate_key;
use zemtik::types::EngineResult;

/// Zero-row results now return Ok(FastLaneResult) — not EmptyResult.
/// The attestation must be signed even when no rows matched.
#[test]
fn fast_lane_zero_result_has_signed_attestation() {
    let conn = init_ledger_sqlite().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    // "nonexistent_category" has no rows in the ledger DB.
    let result = run_fast_lane(&conn, &key, "nonexistent_category", 1704067200, 1711929599);
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

/// Attestation hashes must differ across categories.
/// Guards the unified format from regressions where category is not included in the payload.
#[test]
fn fast_lane_attestation_differs_by_category() {
    let conn = init_ledger_sqlite().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = load_or_generate_key(dir.path()).unwrap();

    let r1 = run_fast_lane(&conn, &key, "aws_spend", 1704067200, 1711929599);
    let r2 = run_fast_lane(&conn, &key, "payroll",   1704067200, 1711929599);

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
