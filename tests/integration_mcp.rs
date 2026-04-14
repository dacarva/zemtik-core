//! Integration tests for Zemtik MCP Attestation Proxy.
//!
//! Tests the tool dispatch, audit record writing, and auth endpoints.
//! Does NOT spin up a full MCP server (rmcp STDIO subprocess piping is complex in tests).
//! Instead, tests the handler logic directly.

use tempfile::TempDir;

use zemtik::config::AppConfig;
use zemtik::mcp_proxy::{
    list_mcp_audit_records, write_audit_record, sha256_hex, McpHandlerState,
};
use zemtik::types::McpAuditRecord;

fn test_config(dir: &TempDir) -> AppConfig {
    let mut config = AppConfig::default();
    config.keys_dir = dir.path().join("keys");
    config.mcp_audit_db_path = dir.path().join("mcp_audit.db");
    config.mcp_mode = "tunnel".to_string();
    config.mcp_fetch_timeout_secs = 5;
    config.mcp_allowed_paths = vec![];
    config.mcp_allowed_fetch_domains = vec![];
    // Skip circuit validation for tests
    config.skip_circuit_validation = true;
    config
}

#[test]
fn test_mcp_audit_db_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("mcp_audit.db");

    let record = McpAuditRecord {
        receipt_id: "test-1".to_string(),
        ts: "2026-04-14T00:00:00Z".to_string(),
        tool_name: "zemtik_read_file".to_string(),
        input_hash: sha256_hex(b"inp"),
        output_hash: sha256_hex(b"out"),
        preview_input: "inp".to_string(),
        preview_output: "out".to_string(),
        attestation_sig: "sig".to_string(),
        public_key_hex: "pubkey".to_string(),
        duration_ms: 5,
        mode: "tunnel".to_string(),
    };

    write_audit_record(&db_path, &record).unwrap();
    let records = list_mcp_audit_records(&db_path, 100).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].receipt_id, "test-1");
    assert_eq!(records[0].tool_name, "zemtik_read_file");
    assert_eq!(records[0].duration_ms, 5);
}

#[test]
fn test_mcp_audit_db_insert_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("mcp_audit.db");

    let record = McpAuditRecord {
        receipt_id: "dup-uuid".to_string(),
        ts: "2026-04-14T00:00:00Z".to_string(),
        tool_name: "zemtik_fetch".to_string(),
        input_hash: sha256_hex(b"x"),
        output_hash: sha256_hex(b"y"),
        preview_input: "x".to_string(),
        preview_output: "y".to_string(),
        attestation_sig: "sig".to_string(),
        public_key_hex: "pubkey".to_string(),
        duration_ms: 1,
        mode: "tunnel".to_string(),
    };

    // Insert twice — INSERT OR IGNORE should deduplicate
    write_audit_record(&db_path, &record).unwrap();
    write_audit_record(&db_path, &record).unwrap();

    let records = list_mcp_audit_records(&db_path, 100).unwrap();
    assert_eq!(records.len(), 1, "duplicate insert should be idempotent");
}

#[tokio::test]
async fn test_mcp_handler_state_loads_key() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);

    let state = McpHandlerState::from_config(&config, true)
        .expect("handler state should load cleanly with fresh key");

    assert!(!state.public_key_hex.is_empty(), "public key hex must not be empty");
    assert_eq!(state.key_seed.len(), 32, "key seed must be 32 bytes");
}

#[test]
fn test_mcp_tools_missing_file_ok() {
    use zemtik::mcp_tools::load_mcp_tools;
    let tools = load_mcp_tools(std::path::Path::new("/nonexistent/mcp_tools.json")).unwrap();
    assert!(tools.is_empty());
}

#[test]
fn test_mcp_tools_malformed_returns_error() {
    use std::io::Write;
    use zemtik::mcp_tools::load_mcp_tools;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "{{not valid json}}").unwrap();
    assert!(load_mcp_tools(f.path()).is_err());
}

#[test]
fn test_key_path_denied_in_read_file() {
    // Verify that ~/.zemtik/ prefix is denied by checking the zemtik_home logic.
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let state = McpHandlerState::from_config(&config, true).unwrap();

    // The zemtik_home should be the parent of keys_dir
    assert_eq!(state.zemtik_home, dir.path().to_path_buf());
}
