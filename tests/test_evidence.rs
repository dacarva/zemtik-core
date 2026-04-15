use zemtik::evidence::{build_evidence_pack, evidence_summary};
use zemtik::types::EvidencePack;

fn make_ev(hash: Option<String>) -> EvidencePack {
    let (human_summary, checks_performed) =
        evidence_summary("fast_lane", "portfolio_holdings", "SUM", 100);
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
        ev.human_summary.len() >= 20,
        "human_summary too short: {:?}",
        ev.human_summary
    );
    assert!(
        ev.human_summary.contains("portfolio_holdings"),
        "human_summary should contain table name, got: {:?}",
        ev.human_summary
    );
    assert!(
        ev.checks_performed.len() >= 4,
        "expected >= 4 checks, got {}",
        ev.checks_performed.len()
    );
}

#[test]
fn test_zk_slow_lane_human_summary_non_empty() {
    let (human_summary, checks_performed) =
        evidence_summary("zk_slow_lane", "transactions", "COUNT", 250);
    assert!(
        human_summary.len() >= 20,
        "human_summary too short: {:?}",
        human_summary
    );
    assert!(
        checks_performed.len() >= 6,
        "expected >= 6 checks for ZK path, got {}",
        checks_performed.len()
    );
}
