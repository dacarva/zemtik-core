use std::collections::HashMap;
use std::sync::Arc;

use rusqlite::Connection;

use crate::anonymizer::{AnonymizerGrpcClient, VaultStore};
use crate::config::{AggFn, AppConfig, RewriterConfig};
use crate::intent::IntentBackend;
use crate::llm_backend::LlmBackend;
use crate::types::{SchemaValidationResult, SignatureData};
use crate::bundle;

pub(crate) struct ProxyState {
    pub(crate) http_client: reqwest::Client,
    /// Per-aggregation-type locks for ZK pipeline executions.
    /// Each mini-circuit uses its own directory, so SUM and COUNT can run concurrently.
    /// Two requests hitting the same aggregation type still contend on Prover.toml.
    pub(crate) pipeline_locks: HashMap<AggFn, tokio::sync::Mutex<()>>,
    /// Lock held across BOTH SUM and COUNT pipeline runs for AVG queries.
    /// Ensures both proofs operate on the same 500 transactions.
    pub(crate) avg_pipeline_lock: tokio::sync::Mutex<()>,
    /// File-based receipts DB, shared across requests.
    /// WARNING: std::sync::MutexGuard<Connection> must NEVER be held across an .await point.
    /// Lock inside spawn_blocking or in a synchronous scope that drops before any .await.
    pub(crate) receipts_db: std::sync::Mutex<Connection>,
    /// Separate in-memory ledger DB for FastLane reads (avoids contention with receipts_db).
    /// WARNING: std::sync::MutexGuard<Connection> must NEVER be held across an .await point.
    pub(crate) ledger_db: std::sync::Mutex<Connection>,
    /// Application configuration (ports, paths).
    pub(crate) config: Arc<AppConfig>,
    /// Bank signing key bytes (loaded once at startup, passed into spawn_blocking).
    pub(crate) signing_key_bytes: Vec<u8>,
    /// SHA-256 of schema_config.json bytes (empty string when schema absent).
    pub(crate) schema_config_hash: String,
    /// Intent matching backend — static after startup, no lock needed.
    pub(crate) intent_backend: Arc<dyn IntentBackend>,
    /// Provider-abstracted LLM backend. OpenAiBackend or AnthropicBackend.
    /// Constructed once at startup from ZEMTIK_LLM_PROVIDER.
    pub(crate) llm_backend: Arc<dyn LlmBackend>,
    /// Base URL for the query rewriter's OpenAI calls. Always points at OpenAI regardless
    /// of ZEMTIK_LLM_PROVIDER — the rewriter is OpenAI-only in v1.
    /// Renamed from openai_base_url in ProxyState (AppConfig.openai_base_url unchanged).
    pub(crate) rewriter_base_url: String,
    /// Semaphore for bounding concurrent FORK 2 background tasks (tunnel mode only).
    pub(crate) tunnel_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    /// Separate SQLite connection for tunnel audit records (tunnel mode only).
    /// WARNING: Never hold MutexGuard across .await.
    pub(crate) tunnel_audit_db: Option<std::sync::Mutex<Connection>>,
    /// Count of requests where FORK 2 was skipped due to semaphore exhaustion.
    pub(crate) backpressure_count: std::sync::atomic::AtomicU64,
    /// Schema validation result from startup. Exposed via /health.
    pub(crate) schema_validation: Arc<SchemaValidationResult>,
    /// Query rewriter configuration. None when ZEMTIK_QUERY_REWRITER is off (default).
    pub(crate) rewriter_config: Option<Arc<RewriterConfig>>,
    /// Whether ZEMTIK_GENERAL_PASSTHROUGH is enabled. Copied from config at startup.
    pub(crate) general_passthrough_enabled: bool,
    /// Sliding-window rate limiter for GeneralLane. None when general_max_rpm == 0 (unlimited).
    pub(crate) general_rate_limiter: Option<Arc<std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>>>,
    /// Max requests/minute for GeneralLane (0 = unlimited).
    pub(crate) general_max_rpm: u32,
    /// ed25519 manifest signing public key, hex-encoded. Derived from bank_sk at startup.
    /// Served on GET /public-key. Stable across restarts as long as bank_sk is unchanged.
    pub(crate) ed25519_manifest_pub_hex: String,
    /// SHA-256(raw ed25519 verifying key bytes) — key fingerprint added to every receipt.
    pub(crate) manifest_key_id: String,
    /// BabyJubJub public key components, precomputed at startup for GET /public-key.
    /// Avoids per-request scalar multiplication (expensive) on the /public-key hot path.
    pub(crate) bjj_pub_x: String,
    pub(crate) bjj_pub_y: String,
    /// Optional public base URL for this deployment (e.g. "https://zemtik.example.com").
    /// When set, zemtik_meta blocks include a verify_url hint.
    #[allow(dead_code)]
    pub(crate) public_url: Option<String>,
    /// Session-scoped vault store. std::sync::Mutex — never hold guard across .await.
    pub(crate) vault_store: VaultStore,
    /// Lazy gRPC client for the anonymizer sidecar. Clone per request (tonic client is cheap to clone).
    /// None when ZEMTIK_ANONYMIZER_ENABLED=false.
    pub(crate) anonymizer_client: Option<AnonymizerGrpcClient>,
}

// Results returned from the blocking ZK pipeline (includes optional bundle).
pub(crate) struct ZkPipelineResult {
    pub(crate) txns_len: usize,
    pub(crate) batch_count: usize,
    pub(crate) aggregate: u64,
    pub(crate) proof_status: &'static str,
    pub(crate) circuit_execution_secs: f32,
    pub(crate) first_sig: SignatureData,
    pub(crate) proof_hex: Option<String>,
    pub(crate) vk_hex: Option<String>,
    pub(crate) fully_verifiable: bool,
    pub(crate) bundle_result: Option<bundle::BundleResult>,
    /// SHA-256 of the ZK payload JSON sent to the LLM (Rust-layer commitment).
    /// None when fully_verifiable=false — no bundle artifact exists to match against.
    pub(crate) outgoing_prompt_hash: Option<String>,
    /// Number of real (non-dummy padding) rows included in the proof.
    pub(crate) actual_row_count: usize,
}
