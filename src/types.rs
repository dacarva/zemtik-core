use chrono::Utc;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// OpenAI message content normalization
// ---------------------------------------------------------------------------

/// OpenAI `content` field — either a plain string or an array of content parts
/// (as sent by modern SDKs such as openai-python v1.x).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Deserialize)]
pub struct ContentPart {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: Option<String>,
}

impl MessageContent {
    /// Extract all text parts, joined without separator.
    /// Non-text parts (images, tool_calls, etc.) are dropped with a warning.
    pub fn to_text(&self) -> String {
        match self {
            MessageContent::Text(s) => s.clone(),
            MessageContent::Parts(parts) => {
                let mut result = String::new();
                for part in parts {
                    if part.kind == "text" {
                        if let Some(ref t) = part.text {
                            result.push_str(t);
                        }
                    } else {
                        eprintln!(
                            "[WARN] Dropping non-text content part of type '{}' from prompt extraction",
                            part.kind
                        );
                    }
                }
                result
            }
        }
    }
}

/// A single row from the bank's ledger (private circuit witness).
#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: i64,
    pub client_id: i64,
    pub amount: u64,
    pub category: u64,
    /// Schema-config table key (e.g. "aws_spend"). Used by poseidon_of_string
    /// at the ZK boundary. Stored as-is from DB; category: u64 stays for DB INSERTs.
    pub category_name: String,
    pub timestamp: u64,
}

/// Batch of transactions fetched from the DB for ZK pipeline use.
/// Contains the actual (pre-padding) row count for audit transparency.
#[derive(Debug)]
pub struct TransactionBatch {
    /// Exactly 500 transactions, padded with dummy sentinels if actual_row_count < 500.
    pub transactions: Vec<Transaction>,
    /// Number of real (non-dummy) rows returned by the DB query.
    pub actual_row_count: usize,
}

/// Query parameters that define which spend to aggregate.
#[derive(Debug, Clone, Serialize)]
pub struct QueryParams {
    pub client_id: i64,
    /// Poseidon BN254 hash of the table name, as decimal string.
    /// Pre-serialized once at the proxy call site.
    pub target_category_hash: String,
    /// Human-readable category name (e.g. "aws_spend") for display.
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
#[derive(Debug)]
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
#[derive(Debug)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// The public inputs visible to anyone holding the proof.
#[derive(Serialize)]
pub struct ZkPublicInputs {
    /// Poseidon BN254 hash of the queried table name, as decimal string.
    pub target_category_hash: String,
    /// Human-readable category name for auditors (the 77-digit hash is not user-friendly).
    pub category_name: String,
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
                    target_category_hash: params.target_category_hash.clone(),
                    category_name: params.category_name.clone(),
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
#[derive(Debug)]
pub struct OpenAiResult {
    pub content: String,
    pub model: String,
    pub usage: TokenUsage,
    pub request_log: OpenAiRequestLog,
    /// SHA-256 of the serialized JSON request body sent to the LLM.
    pub outgoing_request_hash: String,
}

// ---------------------------------------------------------------------------
// Routing engine types
// ---------------------------------------------------------------------------

/// How a failing query was resolved by the rewriter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteMethod {
    /// Prior conversation context resolved table+time deterministically (no LLM call).
    Deterministic,
    /// LLM rewrote the query to include explicit table and time range.
    #[serde(rename = "llm")]
    LlmRewrite,
}

impl std::fmt::Display for RewriteMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deterministic => write!(f, "deterministic"),
            Self::LlmRewrite => write!(f, "llm"),
        }
    }
}

/// Resolved intent extracted from a user prompt.
#[derive(Clone)]
pub struct IntentResult {
    pub table: String,
    pub category_name: String,
    pub start_unix_secs: i64,
    pub end_unix_secs: i64,
    /// Cosine similarity score from embedding match (1.0 for regex backend).
    pub confidence: f32,
    /// Self-contained query produced by the rewriter (canonical form used for audit).
    /// None for direct intent extraction.
    pub rewritten_query: Option<String>,
    /// How the rewriter resolved this intent. None for direct intent extraction.
    pub rewrite_method: Option<RewriteMethod>,
}

/// Routing decision: fast BabyJubJub attestation vs. full ZK proof vs. general passthrough.
pub enum Route {
    FastLane,
    ZkSlowLane,
    GeneralLane,
}

/// Result of the FastLane engine.
#[derive(Debug)]
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
#[derive(Debug)]
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
    /// SHA-256 of the JSON payload sent to the LLM (Rust-layer commitment).
    /// None for legacy rows (pre-v3) or CLI pipeline rows.
    /// NOTE: Circuit-level commitment deferred to Sprint 3 (TODOS.md).
    #[serde(default)]
    pub outgoing_prompt_hash: Option<String>,
    /// Number of real (non-padding) transactions included in the ZK proof.
    /// None for FastLane path or legacy rows.
    #[serde(default)]
    pub actual_row_count: Option<usize>,
}

// ---------------------------------------------------------------------------
// Structured error types (v0.9.1+)
// ---------------------------------------------------------------------------

/// Typed error codes for all zemtik proxy errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ZemtikErrorCode {
    NoTableIdentified,
    StreamingNotSupported,
    InvalidRequest,
    QueryFailed,
    RewritingFailed,
    GeneralLaneBudgetExceeded,
}

impl std::fmt::Display for ZemtikErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTableIdentified => write!(f, "NoTableIdentified"),
            Self::StreamingNotSupported => write!(f, "StreamingNotSupported"),
            Self::InvalidRequest => write!(f, "InvalidRequest"),
            Self::QueryFailed => write!(f, "QueryFailed"),
            Self::RewritingFailed => write!(f, "RewritingFailed"),
            Self::GeneralLaneBudgetExceeded => write!(f, "GeneralLaneBudgetExceeded"),
        }
    }
}

// ---------------------------------------------------------------------------
// Schema validation types (v0.9.1+)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ZkToolsStatus {
    pub nargo: bool,
    pub bb: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TableValidationResult {
    pub table_key: String,
    pub physical_table: String,
    pub status: String,
    pub row_count: Option<i64>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemaValidationResult {
    pub tables: Vec<TableValidationResult>,
    pub zk_tools: ZkToolsStatus,
    pub skipped: bool,
}

impl SchemaValidationResult {
    pub fn skipped() -> Self {
        Self {
            tables: vec![],
            zk_tools: ZkToolsStatus { nargo: false, bb: false },
            skipped: true,
        }
    }

    pub fn status_summary(&self) -> &'static str {
        if self.skipped {
            "skipped"
        } else if self.tables.iter().any(|t| !t.warnings.is_empty())
            || !self.zk_tools.nargo
            || !self.zk_tools.bb
        {
            "warnings"
        } else {
            "ok"
        }
    }
}

// ---------------------------------------------------------------------------
// Tunnel mode types
// ---------------------------------------------------------------------------

/// Status of FORK 2 (background verification pipeline) for a tunnel request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMatchStatus {
    /// Intent matched + engine ran + zemtik value agrees with OpenAI response (diff within tolerance).
    Matched,
    /// Intent matched + engine ran + zemtik value diverges from OpenAI response (diff outside tolerance).
    Diverged,
    /// Intent extraction failed (no table identified / ambiguous).
    Unmatched,
    /// Engine error or zemtik OpenAI call failed.
    Error,
    /// FORK 2 exceeded ZEMTIK_TUNNEL_TIMEOUT_SECS.
    Timeout,
    /// Semaphore full — FORK 2 was skipped entirely.
    Backpressure,
}

impl TunnelMatchStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Diverged => "diverged",
            Self::Unmatched => "unmatched",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Backpressure => "backpressure",
        }
    }
}

/// Audit record stored in tunnel_audit.db for each tunnel request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelAuditRecord {
    pub id: String,
    pub receipt_id: Option<String>,
    pub created_at: String,
    pub match_status: String,          // TunnelMatchStatus::as_str()
    pub matched_table: Option<String>,
    pub matched_agg_fn: Option<String>,
    pub original_status_code: u16,
    pub original_response_body_hash: String,
    pub original_latency_ms: u64,
    pub zemtik_aggregate: Option<i64>,
    pub zemtik_row_count: Option<usize>,
    pub zemtik_engine: Option<String>,
    pub zemtik_latency_ms: Option<u64>,
    pub diff_detected: bool,
    pub diff_summary: Option<String>,
    pub diff_details: Option<String>,
    pub original_response_preview: Option<String>,
    pub zemtik_response_preview: Option<String>,
    pub error_message: Option<String>,
    pub request_hash: String,
    pub prompt_hash: String,
    pub intent_confidence: Option<f32>,
    pub tunnel_model: Option<String>,
}

/// Payload sent from FORK 1 to FORK 2 via oneshot channel.
/// FORK 1 sends Some(data) on success OR None on error.
/// FORK 2 treats None as "original request failed" → match_status=Error, no diff.
#[derive(Debug, Clone)]
pub struct OriginalResponseData {
    pub status_code: u16,
    pub response_body: String,
    pub response_body_hash: String,
    pub latency_ms: u64,
}
