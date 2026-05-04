// ── Internal modules (not part of the stable public API) ────────────────────
#[doc(hidden)] pub mod audit;
#[doc(hidden)] pub mod llm_backend;
#[doc(hidden)] pub mod provider_registry;
#[doc(hidden)] pub mod bundle;
#[doc(hidden)] pub mod db;
#[doc(hidden)] pub mod engine_fast;
#[doc(hidden)] pub mod evidence;
#[doc(hidden)] pub mod intent;
#[doc(hidden)] pub mod intent_embed;
#[doc(hidden)] pub mod keys;
#[doc(hidden)] pub mod openai;
#[doc(hidden)] pub mod prover;
#[doc(hidden)] pub mod tunnel;
#[doc(hidden)] pub mod mcp_auth;
#[doc(hidden)] pub mod mcp_proxy;
#[doc(hidden)] pub mod mcp_tools;
#[doc(hidden)] pub mod receipts;
#[doc(hidden)] pub mod rewriter;
#[doc(hidden)] pub mod router;
#[doc(hidden)] pub mod startup;
#[doc(hidden)] pub mod time_parser;
#[doc(hidden)] pub mod verify;
#[doc(hidden)] pub mod anonymizer;
#[doc(hidden)] pub mod entity_hashes;

// ── Public modules (stable API surface) ─────────────────────────────────────
pub mod config;
pub mod error;
#[doc(hidden)] pub mod proxy;
pub mod types;

// ── Stable re-exports ────────────────────────────────────────────────────────

/// Error type returned by public entry points.
pub use error::ZemtikError;

/// Configuration types.
pub use config::{AppConfig, ZemtikMode, SchemaConfig, TableConfig, AggFn};
pub use config::load_from_sources;

/// Core result and evidence types.
pub use types::{
    EvidencePack, IntentResult, Route, AuditRecord, Transaction,
    TunnelAuditRecord, McpAuditRecord, EngineResult, FastLaneResult,
};

/// Build the Axum router. Stable entry point — wraps [`proxy::build_proxy_router`]
/// and maps internal errors to [`ZemtikError`].
pub async fn build_proxy_router(config: AppConfig) -> Result<axum::Router, ZemtikError> {
    proxy::build_proxy_router(config).await.map_err(ZemtikError::from)
}

/// Start the proxy server. Stable entry point — wraps [`proxy::run_proxy`]
/// and maps internal errors to [`ZemtikError`].
pub async fn run_proxy(config: AppConfig) -> Result<(), ZemtikError> {
    proxy::run_proxy(config).await.map_err(ZemtikError::from)
}
