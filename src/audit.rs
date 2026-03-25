use std::path::PathBuf;

use anyhow::Context;
use chrono::Utc;

use crate::types::AuditRecord;

/// Write an audit record as a pretty-printed JSON file under `audit/`.
///
/// The file is named with a UTC timestamp (`2026-03-21T14-30-05Z.json`) so
/// that each run produces a distinct, time-ordered artifact. Returns the path
/// of the file written.
pub fn write_audit_record(record: &AuditRecord) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all("audit").context("create audit/ directory")?;

    // Colons are not valid in Windows filenames; replace with hyphens.
    let filename = format!(
        "audit/{}.json",
        Utc::now().format("%Y-%m-%dT%H-%M-%SZ")
    );
    let path = PathBuf::from(&filename);

    let json = serde_json::to_string_pretty(record).context("serialize audit record")?;
    std::fs::write(&path, json).with_context(|| format!("write audit record to {}", filename))?;

    Ok(path)
}
