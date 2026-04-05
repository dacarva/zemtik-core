use crate::types::EvidencePack;

#[cfg(test)]
mod tests {
    use super::*;

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
}

/// Build an EvidencePack from either engine's output.
///
/// FastLane path: `attestation_hash` is set, `proof_hash` is None.
/// ZK SlowLane path: `proof_hash` is set, `attestation_hash` is None.
/// `outgoing_prompt_hash`: SHA-256 of the JSON payload sent to the LLM (Rust-layer commitment).
#[allow(clippy::too_many_arguments)]
pub fn build_evidence_pack(
    receipt_id: &str,
    engine_used: &str,
    aggregate: i64,
    row_count: usize,
    proof_hash: Option<String>,
    attestation_hash: Option<String>,
    key_id: &str,
    schema_config_hash: &str,
    timestamp: &str,
    zemtik_confidence: Option<f32>,
    outgoing_prompt_hash: Option<String>,
) -> EvidencePack {
    EvidencePack {
        engine_used: engine_used.to_owned(),
        proof_hash,
        attestation_hash,
        data_exfiltrated: 0,
        privacy_model: "architectural_isolation".to_owned(),
        key_id: key_id.to_owned(),
        schema_config_hash: schema_config_hash.to_owned(),
        timestamp: timestamp.to_owned(),
        aggregate,
        row_count,
        receipt_id: receipt_id.to_owned(),
        zemtik_confidence,
        outgoing_prompt_hash,
    }
}
