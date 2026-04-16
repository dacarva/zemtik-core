use zemtik::evidence::{build_evidence_pack, evidence_summary};
use zemtik::types::EvidencePack;

fn make_ev(hash: Option<String>) -> EvidencePack {
    let (human_summary, checks_performed) =
        evidence_summary("fast_lane", "portfolio_holdings", "SUM", 10);
    build_evidence_pack(
        "test-receipt-id",
        "fast_lane",
        1000,
        10,
        None,
        Some("attestation-hex".to_owned()),
        "key-id",
        "schema-hash",
        "2026-01-01T00:00:00Z",
        Some(0.95),
        hash,
        None,
        human_summary,
        checks_performed,
    )
}

#[test]
fn test_build_evidence_pack_has_outgoing_hash() {
    let ev = make_ev(Some("sha256:abc123".to_owned()));
    assert_eq!(ev.outgoing_prompt_hash, Some("sha256:abc123".to_owned()));
    assert_eq!(ev.data_exfiltrated, 0);
    assert_eq!(ev.engine_used, "fast_lane");
}

#[test]
fn test_build_evidence_pack_no_hash() {
    let ev = make_ev(None);
    assert_eq!(ev.outgoing_prompt_hash, None);
}

#[test]
fn test_fast_lane_human_summary_non_empty() {
    let ev = make_ev(None);
    assert!(
        ev.human_summary.contains("portfolio_holdings"),
        "human_summary should contain table name, got: {:?}",
        ev.human_summary
    );
    assert!(
        ev.human_summary.contains("10 rows"),
        "human_summary should contain row count, got: {:?}",
        ev.human_summary
    );
    assert!(
        ev.human_summary.contains("SUM"),
        "human_summary should embed agg_fn, got: {:?}",
        ev.human_summary
    );
    assert_eq!(
        ev.row_count, 10,
        "row_count in pack should match evidence_summary row_count"
    );
    assert_eq!(
        ev.checks_performed,
        vec![
            "intent_classification",
            "schema_sensitivity_check",
            "aggregate_only_enforcement",
            "babyjubjub_attestation",
        ],
        "checks_performed mismatch for fast_lane"
    );
}

#[test]
fn test_zk_slow_lane_human_summary_non_empty() {
    let (human_summary, checks_performed) =
        evidence_summary("zk_slow_lane", "transactions", "COUNT", 250);
    assert!(
        human_summary.contains("transactions"),
        "human_summary should contain table name, got: {:?}",
        human_summary
    );
    assert!(
        human_summary.contains("250 rows"),
        "human_summary should contain row count, got: {:?}",
        human_summary
    );
    assert_eq!(
        checks_performed,
        vec![
            "intent_classification",
            "schema_sensitivity_check",
            "babyjubjub_signing",
            "poseidon_commitment",
            "ultrahonk_proof",
            "bb_verify_local",
        ],
        "checks_performed mismatch for zk_slow_lane"
    );
}

#[test]
fn test_zk_slow_lane_avg_human_summary_uppercase() {
    // Regression: ISSUE-001 — AggFn::as_str() returns "AVG" (uppercase) but the original
    // match guard used agg_fn == "avg" (lowercase), causing the AVG arm to never trigger
    // in production. Found by /qa on 2026-04-16.
    // Report: .gstack/qa-reports/qa-report-zemtik-core-2026-04-16.md
    let (summary, checks) = evidence_summary("zk_slow_lane", "deals", "AVG", 50);
    assert!(
        summary.contains("two sequential zero-knowledge circuits"),
        "uppercase AVG should still hit the AVG composite arm, got: {:?}",
        summary
    );
    assert_eq!(checks.len(), 11, "uppercase AVG should produce 11 checks, got: {:?}", checks);
    assert_eq!(checks[10], "babyjubjub_attestation", "last check should be division attestation");
}

#[test]
fn test_zk_slow_lane_avg_human_summary() {
    let (summary, checks) = evidence_summary("zk_slow_lane", "deals", "avg", 50);
    assert!(
        summary.contains("deals"),
        "AVG summary should contain table name, got: {:?}",
        summary
    );
    assert!(
        summary.contains("50 rows"),
        "AVG summary should contain row count, got: {:?}",
        summary
    );
    assert!(
        summary.contains("AVG"),
        "AVG summary should mention AVG, got: {:?}",
        summary
    );
    assert!(
        summary.contains("two sequential zero-knowledge circuits"),
        "AVG summary should describe composite nature, got: {:?}",
        summary
    );
    assert_eq!(checks.len(), 11, "AVG checks_performed should have 11 entries, got: {:?}", checks);
    assert_eq!(checks[0], "intent_classification");
    assert_eq!(checks[10], "babyjubjub_attestation", "last check should be division attestation");
}
