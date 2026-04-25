use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Returns true if `s` is a safe SQL/JSON identifier: non-empty, ASCII alphanumeric
/// or underscore only, max 63 chars. Column/table names from schema_config are
/// server-controlled, but this defends against misconfiguration.
pub(crate) fn is_safe_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_') && s.len() <= 63
}

// ---------------------------------------------------------------------------
// SchemaConfig — table sensitivity configuration for the routing engine
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct SchemaConfig {
    #[serde(default)]
    pub fiscal_year_offset_months: i64,
    pub tables: HashMap<String, TableConfig>,
}

/// Aggregation function. Uppercase required in JSON: "SUM", "COUNT", or "AVG".
/// For critical tables: SUM and COUNT route to ZK SlowLane (one proof each).
/// AVG routes to ZK SlowLane as a composite: SUM proof + COUNT proof + BabyJubJub attestation (~40-120s).
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum AggFn {
    #[default]
    Sum,
    Count,
    Avg,
}

impl AggFn {
    pub fn as_str(&self) -> &'static str {
        match self {
            AggFn::Sum => "SUM",
            AggFn::Count => "COUNT",
            AggFn::Avg => "AVG",
        }
    }

    /// Name of the compiled circuit artifact directory for this aggregation.
    /// AVG has no dedicated circuit — it uses sum/ and count/ sequentially.
    pub fn circuit_artifact_name(&self) -> Option<&'static str> {
        match self {
            AggFn::Sum => Some("sum"),
            AggFn::Count => Some("count"),
            AggFn::Avg => None, // composite: uses sum + count
        }
    }
}

fn default_value_column() -> String { "amount".to_owned() }
fn default_timestamp_column() -> String { "timestamp".to_owned() }
fn default_metric_label() -> String { "total_spend_usd".to_owned() }

#[derive(Debug, Deserialize, Clone)]
pub struct TableConfig {
    pub sensitivity: String,
    pub aliases: Option<Vec<String>>,
    /// One-sentence description of what this table contains (used for embedding index).
    #[serde(default)]
    pub description: String,
    /// Example natural-language prompts that should match this table.
    #[serde(default)]
    pub example_prompts: Vec<String>,
    /// Per-table client_id override. When set, takes precedence over the global
    /// ZEMTIK_CLIENT_ID. Useful for multi-client deployments where each table
    /// belongs to a different end client.
    #[serde(default)]
    pub client_id: Option<i64>,

    // --- FastLane engine fields (all optional, backward-compatible) ---

    /// Physical table name in the DB. None → falls back to the schema_config key.
    /// NOTE: physical_table override only applies to the Supabase path.
    /// The in-memory SQLite ledger always uses the 'transactions' table.
    #[serde(default)]
    pub physical_table: Option<String>,

    /// Column to aggregate (SUM) or count non-nulls from (COUNT).
    /// Defaults to "amount". For COUNT tables, use a non-nullable column (PK or equivalent).
    #[serde(default = "default_value_column")]
    pub value_column: String,

    /// Column for Unix-seconds timestamp filtering. Defaults to "timestamp".
    #[serde(default = "default_timestamp_column")]
    pub timestamp_column: String,

    /// Column for category filtering within the physical table.
    /// None → no category filter (aggregate entire table).
    #[serde(default)]
    pub category_column: Option<String>,

    /// Aggregation function: "SUM" (default) or "COUNT". Uppercase required.
    #[serde(default)]
    pub agg_fn: AggFn,

    /// Label for the aggregate metric in the OpenAI payload. Defaults to "total_spend_usd".
    /// Must match [a-zA-Z0-9_] — used as a JSON field value for the LLM.
    #[serde(default = "default_metric_label")]
    pub metric_label: String,

    /// When true, omit the client_id filter from Supabase queries.
    /// Use for tables without a client_id column (e.g., single-tenant HR tables).
    /// WARNING: setting this on a multi-tenant table exposes all tenants' data.
    #[serde(default)]
    pub skip_client_id_filter: bool,

    /// Tunnel mode: numerical diff tolerance for this table. Default: 0.01 (1%).
    /// Override per-table when the default tolerance doesn't fit the column's scale.
    #[serde(default)]
    pub tunnel_diff_tolerance: Option<f64>,

    /// Per-table query rewriting control. Three-state:
    /// - absent (None) → follow ZEMTIK_QUERY_REWRITER global setting
    /// - true  → force enable rewriting for this table
    /// - false → force disable rewriting for this table (fail-secure override)
    #[serde(default)]
    pub query_rewriting: Option<bool>,
}

impl Default for TableConfig {
    fn default() -> Self {
        TableConfig {
            sensitivity: String::new(),
            aliases: None,
            description: String::new(),
            example_prompts: Vec::new(),
            client_id: None,
            physical_table: None,
            value_column: default_value_column(),
            timestamp_column: default_timestamp_column(),
            category_column: None,
            agg_fn: AggFn::Sum,
            metric_label: default_metric_label(),
            skip_client_id_filter: false,
            tunnel_diff_tolerance: None,
            query_rewriting: None,
        }
    }
}

impl TableConfig {
    /// Returns the physical table name: physical_table override if set, otherwise the schema key.
    pub fn resolved_table<'a>(&'a self, key: &'a str) -> &'a str {
        self.physical_table.as_deref().unwrap_or(key)
    }
}

/// Load a schema_config.json file. Returns `(config, sha256_hex_of_file_bytes)`.
pub fn load_schema_config(path: &Path) -> anyhow::Result<(SchemaConfig, String)> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read schema_config at {}", path.display()))?;
    let hash = hex::encode(Sha256::digest(&bytes));
    let config: SchemaConfig =
        serde_json::from_slice(&bytes).context("parse schema_config.json")?;
    Ok((config, hash))
}

/// Validate a SchemaConfig — called at proxy startup. Returns Err with a
/// human-readable message on the first validation failure.
///
/// When `require_embed_fields` is true, also validates that each table has a
/// non-empty `description` and at least one `example_prompts` entry (required
/// for the embedding index).
pub fn validate_schema_config(config: &SchemaConfig, require_embed_fields: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        (0..=11).contains(&config.fiscal_year_offset_months),
        "schema_config: fiscal_year_offset_months must be 0–11, got {}",
        config.fiscal_year_offset_months
    );
    for (key, tc) in &config.tables {
        if key.is_empty() {
            anyhow::bail!("schema_config: table key must not be empty");
        }
        if key.trim().eq_ignore_ascii_case("__zemtik_dummy__") {
            anyhow::bail!(
                "schema_config: table key '{}' is reserved as a padding sentinel — choose a different key",
                key
            );
        }
        if !is_safe_identifier(key) {
            anyhow::bail!(
                "schema_config: table key '{}' is not a safe SQL identifier \
                 (must match [a-zA-Z_][a-zA-Z0-9_]*, max 63 chars)",
                key
            );
        }
        if tc.sensitivity != "critical" && tc.sensitivity != "low" {
            anyhow::bail!(
                "schema_config: table '{}' has invalid sensitivity '{}' (must be 'critical' or 'low')",
                key, tc.sensitivity
            );
        }
        if require_embed_fields {
            if tc.description.is_empty() {
                anyhow::bail!(
                    "schema_config: table '{}': description is required for embedding backend",
                    key
                );
            }
            if tc.example_prompts.is_empty() {
                anyhow::bail!(
                    "schema_config: table '{}': example_prompts must be non-empty for embedding backend",
                    key
                );
            }
        }

        // Validate identifier safety for FastLane engine fields
        if !is_safe_identifier(&tc.value_column) {
            anyhow::bail!(
                "schema_config: table '{}': invalid value_column '{}'  \
                 (must match [a-zA-Z0-9_], max 63 chars)",
                key, tc.value_column
            );
        }
        if !is_safe_identifier(&tc.timestamp_column) {
            anyhow::bail!(
                "schema_config: table '{}': invalid timestamp_column '{}' \
                 (must match [a-zA-Z0-9_], max 63 chars)",
                key, tc.timestamp_column
            );
        }
        if let Some(ref cat_col) = tc.category_column {
            if !is_safe_identifier(cat_col) {
                anyhow::bail!(
                    "schema_config: table '{}': invalid category_column '{}' \
                     (must match [a-zA-Z0-9_], max 63 chars)",
                    key, cat_col
                );
            }
        }
        if let Some(ref phys) = tc.physical_table {
            if !is_safe_identifier(phys) {
                anyhow::bail!(
                    "schema_config: table '{}': invalid physical_table '{}' \
                     (must match [a-zA-Z0-9_], max 63 chars)",
                    key, phys
                );
            }
        }
        if !is_safe_identifier(&tc.metric_label) {
            anyhow::bail!(
                "schema_config: table '{}': invalid metric_label '{}' \
                 (must match [a-zA-Z0-9_], max 63 chars)",
                key, tc.metric_label
            );
        }

        // AVG on low-sensitivity tables: not supported (FastLane has no composite path).
        if tc.agg_fn == AggFn::Avg && tc.sensitivity == "low" {
            anyhow::bail!(
                "schema_config: table '{}': agg_fn=AVG is not supported for low-sensitivity tables. \
                 AVG requires the ZK SlowLane composite pipeline. Set sensitivity to 'critical' or \
                 use agg_fn=SUM or agg_fn=COUNT instead.",
                key
            );
        }

        // AVG on critical tables: composite ZK proof (SUM + COUNT). Warn about latency.
        if tc.agg_fn == AggFn::Avg && tc.sensitivity == "critical" {
            eprintln!(
                "[INFO] schema_config: table '{}': agg_fn=AVG on a critical table runs two ZK \
                 pipeline proofs sequentially (~40-120s per request). The response will include \
                 sum_proof_hash and count_proof_hash with avg_evidence_model='zk_composite+attestation'.",
                key
            );
        }

        // Warn (non-blocking) if physical_table override is used outside Supabase.
        // SQLite always queries the 'transactions' table; physical_table only works on Supabase.
        if tc.physical_table.is_some()
            && std::env::var("DB_BACKEND").unwrap_or_default().to_lowercase() != "supabase"
        {
            eprintln!(
                "[WARN] schema_config: table '{}': physical_table override is Supabase-only — \
                 SQLite always uses 'transactions'. Requests to this table will fail at runtime \
                 if the physical table name differs.",
                key
            );
        }

        // Warn when skip_client_id_filter is set — this aggregates across ALL tenants in Supabase.
        // Operator must explicitly acknowledge the cross-tenant scope.
        if tc.skip_client_id_filter {
            eprintln!(
                "[WARN] schema_config: table '{}': skip_client_id_filter=true — queries will \
                 aggregate across ALL client_ids in Supabase. Ensure this table is single-tenant \
                 or intentionally global.",
                key
            );
        }
    }
    Ok(())
}
