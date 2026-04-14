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
    // Regression: ISSUE-001 — zemtik_home symlink bypass on macOS
    // Found by /qa on 2026-04-14
    // Report: .gstack/qa-reports/qa-report-zemtik-core-2026-04-14.md
    //
    // zemtik_home must be canonicalized at construction time. On macOS,
    // /var/folders is a symlink to /private/var/folders. Without canonicalization,
    // path.canonicalize() returns /private/... but zemtik_home stores /var/...,
    // causing starts_with() to return false and silently allowing reads of ~/.zemtik/.
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let state = McpHandlerState::from_config(&config, true).unwrap();

    // zemtik_home must equal the CANONICAL parent of keys_dir
    let expected = dir.path().canonicalize().unwrap();
    assert_eq!(state.zemtik_home, expected,
        "zemtik_home must be canonical so starts_with() correctly catches symlinked paths");

    // Directly test that a file inside zemtik_home is denied.
    // Create a real file inside the temp dir (simulates ~/.zemtik/keys/bank_sk).
    let sentinel = dir.path().join("sentinel.txt");
    std::fs::write(&sentinel, b"secret").unwrap();
    let sentinel_str = sentinel.to_string_lossy().to_string();

    let result = zemtik::mcp_proxy::read_file_blocking(&sentinel_str, &state);
    assert!(result.is_err(), "read inside zemtik_home must be denied");
    let err = result.unwrap_err();
    assert!(
        err.message.contains("file_access_denied"),
        "error message must say file_access_denied, got: {}",
        err.message
    );
}
