use zemtik::evidence::build_evidence_pack;
use zemtik::types::EvidencePack;

fn make_ev(hash: Option<String>) -> EvidencePack {
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
