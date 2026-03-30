use crate::types::EvidencePack;

/// Build an EvidencePack from either engine's output.
///
/// FastLane path: `attestation_hash` is set, `proof_hash` is None.
/// ZK SlowLane path: `proof_hash` is set, `attestation_hash` is None.
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
    }
}
