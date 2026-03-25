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
    pub category_name: &'static str,
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

/// Enriched result returned by `query_openai`, carrying both the advisory
/// text and the data needed to build the audit record.
pub struct OpenAiResult {
    pub content: String,
    pub model: String,
    pub usage: TokenUsage,
    pub request_log: OpenAiRequestLog,
}
