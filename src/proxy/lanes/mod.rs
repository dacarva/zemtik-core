pub(in crate::proxy) mod fast;
pub(in crate::proxy) mod zk;
pub(in crate::proxy) mod general;

use serde_json::Value;
use crate::types::{EvidencePack, IntentResult};

/// Merge `EvidencePack` + intent summary for API clients (jq-friendly `engine` / `intent`).
/// Adds `evidence_version: 3` to enable downstream parsers to distinguish v1 (row_count,
/// single-proof), v2 (actual_row_count, AVG dual-proof), and v3 (human_summary,
/// checks_performed) response shapes.
/// When intent was rewritten, injects `rewrite_method` field into the envelope.
pub(in crate::proxy) fn zemtik_evidence_envelope(ev: &EvidencePack, intent: &IntentResult) -> Result<Value, serde_json::Error> {
    let mut v = serde_json::to_value(ev)?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("evidence_version".to_string(), serde_json::json!(3));
        obj.insert("engine".to_string(), Value::String(ev.engine_used.clone()));
        obj.insert(
            "intent".to_string(),
            serde_json::json!({
                "table": intent.table,
                "category_name": intent.category_name,
                "start_unix_secs": intent.start_unix_secs,
                "end_unix_secs": intent.end_unix_secs,
                "confidence": intent.confidence,
            }),
        );
        if let Some(ref method) = intent.rewrite_method {
            obj.insert("rewrite_method".to_string(), serde_json::json!(method.to_string()));
        }
    }
    Ok(v)
}
