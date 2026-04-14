//! Unit tests for MCP attestation proxy components.

use zemtik::mcp_auth::check_mcp_auth;
use zemtik::mcp_proxy::{sha256_hex, write_audit_record, list_mcp_audit_records};
use zemtik::types::McpAuditRecord;

#[test]
fn test_mcp_auth_valid_bearer() {
    assert!(check_mcp_auth(Some("Bearer testkey123"), None, Some("testkey123")));
}

#[test]
fn test_mcp_auth_valid_token_param() {
    assert!(check_mcp_auth(None, Some("testkey123"), Some("testkey123")));
}

#[test]
fn test_mcp_auth_invalid_key() {
    assert!(!check_mcp_auth(Some("Bearer wrong"), None, Some("testkey123")));
}

#[test]
fn test_mcp_auth_no_key_allows_all() {
    assert!(check_mcp_auth(None, None, None));
    assert!(check_mcp_auth(Some("Bearer anything"), None, None));
}

#[test]
fn test_sha256_hex_format() {
    let h = sha256_hex(b"hello");
    assert!(h.starts_with("sha256:"), "hash must start with sha256: prefix");
    assert_eq!(h.len(), 7 + 64); // "sha256:" + 64 hex chars
}

#[test]
fn test_mcp_audit_record_schema() {
    let record = McpAuditRecord {
        receipt_id: "test-uuid".to_string(),
        ts: "2026-04-14T00:00:00Z".to_string(),
        tool_name: "zemtik_read_file".to_string(),
        input_hash: sha256_hex(b"input"),
        output_hash: sha256_hex(b"output"),
        preview_input: "input".to_string(),
        preview_output: "output".to_string(),
        attestation_sig: "deadsig".to_string(),
        public_key_hex: "deadpubkey".to_string(),
        duration_ms: 42,
        mode: "tunnel".to_string(),
    };

    // Must serialize/deserialize round-trip cleanly
    let json = serde_json::to_string(&record).unwrap();
    let back: McpAuditRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.receipt_id, "test-uuid");
    assert_eq!(back.tool_name, "zemtik_read_file");
    assert_eq!(back.duration_ms, 42);
}

#[test]
fn test_mcp_audit_db_write_read() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test_mcp_audit.db");

    let record = McpAuditRecord {
        receipt_id: "round-trip-uuid".to_string(),
        ts: "2026-04-14T00:00:00Z".to_string(),
        tool_name: "zemtik_read_file".to_string(),
        input_hash: sha256_hex(b"test_input"),
        output_hash: sha256_hex(b"test_output"),
        preview_input: "test input".to_string(),
        preview_output: "test output".to_string(),
        attestation_sig: "testsig".to_string(),
        public_key_hex: "testpubkey".to_string(),
        duration_ms: 10,
        mode: "tunnel".to_string(),
    };

    write_audit_record(&db_path, &record).unwrap();

    let records = list_mcp_audit_records(&db_path, 10).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].receipt_id, "round-trip-uuid");
    assert_eq!(records[0].tool_name, "zemtik_read_file");
}
