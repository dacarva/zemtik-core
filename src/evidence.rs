use crate::types::EvidencePack;

const CHECK_INTENT: &str = "intent_classification";
const CHECK_SCHEMA_SENS: &str = "schema_sensitivity_check";
const CHECK_AGG_ONLY: &str = "aggregate_only_enforcement";
const CHECK_BJJ_ATTEST: &str = "babyjubjub_attestation";
const CHECK_BJJ_SIGN: &str = "babyjubjub_signing";
const CHECK_POSEIDON: &str = "poseidon_commitment";
const CHECK_ULTRAHONK: &str = "ultrahonk_proof";
const CHECK_BB_VERIFY: &str = "bb_verify_local";

/// Generate a human-readable compliance summary and ordered check list for
/// a given engine path. Called by each call site before `build_evidence_pack`.
///
/// FastLane: 4 checks (intent → schema → agg-only → BabyJubJub attestation).
/// ZK SlowLane (SUM/COUNT): 6 checks (intent → schema → BabyJubJub sign →
///   Poseidon → UltraHonk proof → bb local verify).
/// ZK SlowLane (AVG composite): 9 checks — two full ZK circuits (SUM + COUNT),
///   each with signing/Poseidon/proof/verify, plus BabyJubJub attestation for
///   the final avg = sum ÷ count division.
///
/// # Panics
/// Panics via `unreachable!` if `engine` is not `"fast_lane"` or `"zk_slow_lane"`.
/// This is intentional — callers are internal and use string literals; an unknown
/// engine indicates a programming error, not a runtime condition.
pub fn evidence_summary(
    engine: &str,
    table: &str,
    agg_fn: &str,
    row_count: usize,
) -> (String, Vec<String>) {
    match engine {
        "fast_lane" => (
            format!(
                "Aggregated {} rows from '{}' into a single {} attested by Zemtik \
                 (BabyJubJub EdDSA). No individual records left the institution's infrastructure.",
                row_count, table, agg_fn
            ),
            vec![
                CHECK_INTENT.into(),
                CHECK_SCHEMA_SENS.into(),
                CHECK_AGG_ONLY.into(),
                CHECK_BJJ_ATTEST.into(),
            ],
        ),
        "zk_slow_lane" if agg_fn.eq_ignore_ascii_case("avg") => (
            format!(
                "Computed AVG over {} rows from '{}' using two sequential zero-knowledge circuits \
                 (SUM + COUNT, each UltraHonk proof), then attested the division result with \
                 BabyJubJub EdDSA. Raw records never left the institution's infrastructure. \
                 SUM proof is independently verifiable offline via `zemtik verify <bundle.zip>`.",
                row_count, table
            ),
            vec![
                CHECK_INTENT.into(),
                CHECK_SCHEMA_SENS.into(),
                // SUM circuit
                CHECK_BJJ_SIGN.into(),
                CHECK_POSEIDON.into(),
                CHECK_ULTRAHONK.into(),
                CHECK_BB_VERIFY.into(),
                // COUNT circuit
                CHECK_ULTRAHONK.into(),
                CHECK_BB_VERIFY.into(),
                // Division attestation
                CHECK_BJJ_ATTEST.into(),
            ],
        ),
        "zk_slow_lane" => (
            format!(
                "Computed {} over {} rows from '{}' inside a zero-knowledge circuit (UltraHonk proof). \
                 Raw records never left the institution's infrastructure. \
                 Proof is independently verifiable offline via `zemtik verify <bundle.zip>`.",
                agg_fn, row_count, table
            ),
            vec![
                CHECK_INTENT.into(),
                CHECK_SCHEMA_SENS.into(),
                CHECK_BJJ_SIGN.into(),
                CHECK_POSEIDON.into(),
                CHECK_ULTRAHONK.into(),
                CHECK_BB_VERIFY.into(),
            ],
        ),
        _ => unreachable!("evidence_summary: unknown engine '{}'", engine),
    }
}

/// Build an EvidencePack from either engine's output.
///
/// FastLane path: `attestation_hash` is set, `proof_hash` is None.
/// ZK SlowLane path: `proof_hash` is set, `attestation_hash` is None.
/// `outgoing_prompt_hash`: SHA-256 of the JSON payload sent to the LLM (Rust-layer commitment).
/// `human_summary` and `checks_performed`: call `evidence_summary` first and pass the results.
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
    actual_row_count: Option<usize>,
    human_summary: String,
    checks_performed: Vec<String>,
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
        actual_row_count,
        human_summary,
        checks_performed,
    }
}
