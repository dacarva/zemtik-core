use chrono::Utc;
use serde::Serialize;

/// A single row from the bank's ledger (private circuit witness).
#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: i64,
    pub client_id: i64,
    pub amount: u64,
    pub category: u64,
    pub timestamp: u64,
}

/// Query parameters that define which spend to aggregate.
#[derive(Debug, Clone, Serialize)]
pub struct QueryParams {
    pub client_id: i64,
    pub target_category: u64,
    /// Category name for display (e.g. "AWS")
    pub category_name: String,
    pub start_time: u64,
    pub end_time: u64,
}

/// BabyJubJub EdDSA signature data with all field elements serialized as
/// BN254 decimal strings, ready for Prover.toml injection.
#[derive(Debug)]
pub struct SignatureData {
    pub pub_key_x: String,
    pub pub_key_y: String,
    pub sig_s: String,
    pub sig_r8_x: String,
    pub sig_r8_y: String,
}

// ---------------------------------------------------------------------------
// Audit types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AuditRecord {
    pub timestamp: String,
    pub bundle_id: Option<String>,
    pub pipeline: PipelineInfo,
    pub zk_proof: ZkProofLog,
    pub openai_request: OpenAiRequestLog,
    pub openai_response: OpenAiResponseLog,
    pub privacy_attestation: PrivacyAttestation,
    pub total_elapsed_secs: f32,
}

/// The raw ZK proof artifacts an auditor can use to independently verify
/// the computation with `bb verify -s ultra_honk -p <proof> -k <vk>`.
#[derive(Serialize)]
pub struct ZkProofLog {
    /// Hex-encoded UltraHonk proof bytes. `None` when the local CRS is
    /// insufficient for full proof generation; nargo execute still verifies
    /// all constraints in that case.
    pub proof_hex: Option<String>,
    /// Hex-encoded verification key corresponding to this circuit compilation.
    pub verification_key_hex: Option<String>,
    /// Public inputs committed to by the proof.
    pub public_inputs: ZkPublicInputs,
    /// True only when a full proof was generated AND independently verified.
    pub fully_verifiable: bool,
}

#[derive(Serialize)]
pub struct PipelineInfo {
    pub total_transaction_count: usize,
    pub batch_count: usize,
    pub batch_size: usize,
    pub proof_scheme: String,
    pub client_id: i64,
    pub query: QueryParams,
    pub zk_aggregate: u64,
    pub proof_status: String,
    pub circuit_execution_secs: f32,
}

#[derive(Serialize)]
pub struct OpenAiRequestLog {
    pub model: String,
    pub system_prompt: String,
    pub user_message: String,
    pub max_completion_tokens: u32,
}

#[derive(Serialize)]
pub struct OpenAiResponseLog {
    pub content: String,
    pub model: String,
    pub usage: TokenUsage,
}

#[derive(Serialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// The public inputs visible to anyone holding the proof.
#[derive(Serialize)]
pub struct ZkPublicInputs {
    pub target_category: u64,
    pub start_time: u64,
    pub end_time: u64,
    pub bank_pub_key_x: String,
    pub bank_pub_key_y: String,
    pub verified_aggregate: u64,
}

#[derive(Serialize)]
pub struct PrivacyAttestation {
    pub raw_rows_transmitted: u32,
    pub fields_transmitted: Vec<String>,
}

impl AuditRecord {
    /// Build a complete AuditRecord, deduplicating construction across CLI and proxy modes.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        bundle_id: Option<String>,
        txns_len: usize,
        batch_count: usize,
        batch_size: usize,
        params: &QueryParams,
        aggregate: u64,
        proof_status: String,
        circuit_execution_secs: f32,
        sig: &SignatureData,
        proof_hex: Option<String>,
        vk_hex: Option<String>,
        fully_verifiable: bool,
        openai_request: OpenAiRequestLog,
        openai_response: OpenAiResponseLog,
        total_elapsed_secs: f32,
    ) -> Self {
        AuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            bundle_id,
            pipeline: PipelineInfo {
                total_transaction_count: txns_len,
                batch_count,
                batch_size,
                proof_scheme: "ultra_honk".to_owned(),
                client_id: params.client_id,
                query: params.clone(),
                zk_aggregate: aggregate,
                proof_status,
                circuit_execution_secs,
            },
            zk_proof: ZkProofLog {
                proof_hex,
                verification_key_hex: vk_hex,
                public_inputs: ZkPublicInputs {
                    target_category: params.target_category,
                    start_time: params.start_time,
                    end_time: params.end_time,
                    bank_pub_key_x: sig.pub_key_x.clone(),
                    bank_pub_key_y: sig.pub_key_y.clone(),
                    verified_aggregate: aggregate,
                },
                fully_verifiable,
            },
            openai_request,
            openai_response,
            privacy_attestation: PrivacyAttestation {
                raw_rows_transmitted: 0,
                fields_transmitted: vec![
                    "category".to_owned(),
                    "total_spend_usd".to_owned(),
                    "period_start".to_owned(),
                    "period_end".to_owned(),
                    "data_provenance".to_owned(),
                    "raw_data_transmitted".to_owned(),
                ],
            },
            total_elapsed_secs,
        }
    }
}

/// Enriched result returned by `query_openai`, carrying both the advisory
/// text and the data needed to build the audit record.
pub struct OpenAiResult {
    pub content: String,
    pub model: String,
    pub usage: TokenUsage,
    pub request_log: OpenAiRequestLog,
}

// ---------------------------------------------------------------------------
// Routing engine types
// ---------------------------------------------------------------------------

/// Resolved intent extracted from a user prompt.
#[derive(Clone)]
pub struct IntentResult {
    pub table: String,
    pub category_name: String,
    pub start_unix_secs: i64,
    pub end_unix_secs: i64,
    /// Cosine similarity score from embedding match (1.0 for regex backend).
    pub confidence: f32,
}

/// Routing decision: fast BabyJubJub attestation vs. full ZK proof.
pub enum Route {
    FastLane,
    ZkSlowLane,
}

/// Result of the FastLane engine.
pub struct FastLaneResult {
    pub aggregate: i64,
    pub row_count: usize,
    /// SHA-256(sig_bytes) hex
    pub attestation_hash: String,
    /// SHA-256(pub_key_x_bytes || pub_key_y_bytes) hex
    pub key_id: String,
    #[allow(dead_code)]
    pub timestamp_unix: i64,
}

/// Outcome returned by `engine_fast::run_fast_lane`.
///
/// `EmptyResult` has been removed: zero-row results now return `Ok(FastLaneResult)`
/// with `row_count == 0` so the receipt is cryptographically signed.
pub enum EngineResult {
    Ok(FastLaneResult),
    DbError(String),
    SignError(String),
}

/// Evidence pack produced by both engines — serialized into the LLM response.
#[derive(Serialize)]
pub struct EvidencePack {
    pub engine_used: String,
    /// ZK path: SHA-256(ultraHonk_proof_bytes)
    pub proof_hash: Option<String>,
    /// FastLane path: SHA-256(sig_bytes)
    pub attestation_hash: Option<String>,
    /// Always 0 — no raw data transmitted
    pub data_exfiltrated: u8,
    /// Always "architectural_isolation"
    pub privacy_model: String,
    pub key_id: String,
    pub schema_config_hash: String,
    pub timestamp: String,
    pub aggregate: i64,
    pub row_count: usize,
    pub receipt_id: String,
    /// Intent matching confidence score (None for legacy/CLI pipeline rows).
    pub zemtik_confidence: Option<f32>,
}
