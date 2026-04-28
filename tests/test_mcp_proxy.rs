//! Unit tests for zemtik_read_file: format detection, PDF/DOCX extraction, size caps, error paths.

use std::io::Write;
use tempfile::NamedTempFile;
use zemtik::config::AppConfig;
use zemtik::mcp_proxy::{detect_format, read_file_blocking, write_audit_record, list_mcp_audit_records, sha256_hex, FileFormat, McpHandlerState};
use zemtik::types::McpAuditRecord;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_state() -> McpHandlerState {
    let dir = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.keys_dir = dir.path().join("keys");
    config.mcp_audit_db_path = dir.path().join("mcp_audit.db");
    config.skip_circuit_validation = true;
    config.mcp_allowed_paths = vec![];
    // Leak the tempdir so it stays alive for the test duration
    std::mem::forget(dir);
    McpHandlerState::from_config(&config, true)
        .expect("McpHandlerState::from_config in test")
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

#[test]
fn test_detect_format_pdf_by_extension() {
    let path = std::path::Path::new("/tmp/foo.pdf");
    assert_eq!(detect_format(path, b"%PDFextra"), FileFormat::Pdf);
}

#[test]
fn test_detect_format_docx_by_extension() {
    let path = std::path::Path::new("/tmp/doc.docx");
    assert_eq!(detect_format(path, b"PK\x03\x04"), FileFormat::Docx);
}

#[test]
fn test_detect_format_pdf_magic_no_extension() {
    let path = std::path::Path::new("/tmp/no_ext_file");
    assert_eq!(detect_format(path, b"%PDF-1.4"), FileFormat::Pdf);
}

#[test]
fn test_detect_format_docx_magic_no_extension() {
    let path = std::path::Path::new("/tmp/no_ext_file");
    assert_eq!(detect_format(path, b"\x50\x4B\x03\x04rest"), FileFormat::Docx);
}

#[test]
fn test_detect_format_text_fallback() {
    let path = std::path::Path::new("/tmp/file.txt");
    assert_eq!(detect_format(path, b"Hello world"), FileFormat::Text);
}

// ---------------------------------------------------------------------------
// DOCX extraction
// ---------------------------------------------------------------------------

#[test]
fn test_read_file_docx() {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.docx");
    let state = make_state();
    let result = read_file_blocking(fixture, &state).expect("docx read should succeed");
    assert_eq!(result.file_format.as_deref(), Some("docx"));
    assert!(
        result.content.contains("Zemtik test document"),
        "content should contain paragraph text, got: {:?}",
        &result.content[..result.content.len().min(200)],
    );
    // xml:space="preserve" test: spaces between runs must be preserved
    assert!(
        result.content.contains("Second paragraph with"),
        "space-preserved text should appear, got: {:?}",
        &result.content[..result.content.len().min(200)],
    );
}

#[test]
fn test_read_file_docx_corrupted() {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample_corrupted.docx");
    let state = make_state();
    let err = read_file_blocking(fixture, &state).expect_err("corrupted docx should fail");
    let msg = err.message.to_lowercase();
    assert!(
        msg.contains("zip") || msg.contains("archive") || msg.contains("parse"),
        "error should mention archive/zip/parse, got: {}",
        err.message,
    );
}

// ---------------------------------------------------------------------------
// PDF extraction via real fixtures
// ---------------------------------------------------------------------------

#[test]
fn test_read_file_pdf_text_layer() {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.pdf");
    let state = make_state();
    let result = read_file_blocking(fixture, &state).expect("PDF with text layer should succeed");
    assert_eq!(result.file_format.as_deref(), Some("pdf"));
    assert!(
        !result.content.is_empty(),
        "extracted text must be non-empty"
    );
}

#[test]
fn test_read_file_pdf_scanned_no_text_layer() {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample_scanned.pdf");
    let state = make_state();
    let err = read_file_blocking(fixture, &state).expect_err("scanned PDF should fail");
    assert!(
        err.message.contains("no_extractable_text_layer"),
        "error should mention no_extractable_text_layer, got: {}",
        err.message
    );
}

#[test]
fn test_read_file_pdf_encrypted() {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample_encrypted.pdf");
    let state = make_state();
    // Encrypted PDFs: either pdf_password_protected error or no_extractable_text_layer
    // depending on whether pdf-extract can detect encryption
    let err = read_file_blocking(fixture, &state).expect_err("encrypted PDF should fail");
    assert!(
        err.message.contains("pdf_password_protected") || err.message.contains("no_extractable_text_layer") || err.message.contains("pdf_parse_error"),
        "error should be encryption/parse related, got: {}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// PDF format detection via fixture (magic bytes)
// ---------------------------------------------------------------------------

#[test]
fn test_read_file_pdf_magic_detection() {
    let mut tmp = NamedTempFile::new().unwrap();
    // Write PDF magic bytes but no valid PDF structure — should be detected as PDF
    // and fail with a PDF parse error (not "unknown format")
    tmp.write_all(b"%PDF-1.4\ngarbage\n%%EOF\n").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    // Rename wouldn't work for NamedTempFile, but detect_format checks extension first,
    // then magic. With no extension, magic takes over.
    let state = make_state();
    let result = read_file_blocking(&path, &state);
    // Should get a PDF error (parse/extract), not a "file not found" error
    match result {
        Err(e) => {
            assert!(
                e.message.contains("pdf") || e.message.contains("PDF") || e.message.contains("text"),
                "error should be PDF-related, got: {}",
                e.message,
            );
        }
        Ok(r) => {
            // Some PDF parsers may succeed on minimal PDFs — that's fine too
            assert_eq!(r.file_format.as_deref(), Some("pdf"));
        }
    }
}

// ---------------------------------------------------------------------------
// Hash separation (D7)
// ---------------------------------------------------------------------------

#[test]
fn test_read_file_docx_hash_separation() {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.docx");
    let state = make_state();
    let result = read_file_blocking(fixture, &state).expect("docx read should succeed");
    // content (extracted text) hash is done by caller on result.content
    // raw_file_hash is hash of the raw DOCX bytes
    // For a DOCX, extracted text != raw bytes, so content hash (sha256 of content)
    // != raw_file_hash (sha256 of binary ZIP)
    let content_hash = sha256_hex(result.content.as_bytes());
    assert_ne!(
        content_hash, result.raw_file_hash,
        "content_hash (of extracted text) should differ from raw_file_hash (of binary zip)"
    );
}

#[test]
fn test_read_file_plain_text_hash_same() {
    let mut tmp = NamedTempFile::with_suffix(".txt").unwrap();
    let text = b"Hello, plain text world.";
    tmp.write_all(text).unwrap();
    let state = make_state();
    let result = read_file_blocking(tmp.path().to_str().unwrap(), &state)
        .expect("plain text read should succeed");
    // For plain text, content == raw bytes, so hashes should match
    let content_hash = sha256_hex(result.content.as_bytes());
    assert_eq!(
        content_hash, result.raw_file_hash,
        "plain text: content_hash should equal raw_file_hash"
    );
}

// ---------------------------------------------------------------------------
// Size caps (D9)
// ---------------------------------------------------------------------------

#[test]
fn test_read_file_plain_text_10mb_cap() {
    let mut tmp = NamedTempFile::with_suffix(".txt").unwrap();
    // 10MB + 1 byte
    let big = vec![b'A'; 10 * 1024 * 1024 + 1];
    tmp.write_all(&big).unwrap();
    let state = make_state();
    let err = read_file_blocking(tmp.path().to_str().unwrap(), &state)
        .expect_err("should fail with file_too_large");
    assert!(
        err.message.contains("file_too_large"),
        "error should be file_too_large, got: {}",
        err.message,
    );
}

#[test]
fn test_read_file_pdf_25mb_cap() {
    let mut tmp = NamedTempFile::with_suffix(".pdf").unwrap();
    // 25MB + 1 byte, start with PDF magic
    let mut big = b"%PDF-1.4\n".to_vec();
    big.extend(vec![b'X'; 25 * 1024 * 1024 + 1]);
    tmp.write_all(&big).unwrap();
    let state = make_state();
    let err = read_file_blocking(tmp.path().to_str().unwrap(), &state)
        .expect_err("should fail with file_too_large");
    assert!(
        err.message.contains("file_too_large"),
        "error should be file_too_large, got: {}",
        err.message,
    );
}

// ---------------------------------------------------------------------------
// File not found — human-readable error
// ---------------------------------------------------------------------------

#[test]
fn test_read_file_not_found_human_error() {
    let state = make_state();
    let err = read_file_blocking("/nonexistent/path/file.pdf", &state)
        .expect_err("missing file should fail");
    // Should mention the path and macOS tip
    assert!(
        err.message.contains("file_not_found") || err.message.contains("does not exist"),
        "error should mention file_not_found, got: {}",
        err.message,
    );
}

// ---------------------------------------------------------------------------
// DB: file_format column written and read back
// ---------------------------------------------------------------------------

#[test]
fn test_file_format_audit_column() {
    let tmp_db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
    let db_path = tmp_db.path();

    let record = McpAuditRecord {
        receipt_id: "test-ff-uuid".to_string(),
        ts: "2026-04-27T00:00:00Z".to_string(),
        tool_name: "zemtik_read_file".to_string(),
        input_hash: sha256_hex(b"test_input"),
        output_hash: sha256_hex(b"test_output"),
        preview_input: "test".to_string(),
        preview_output: "test".to_string(),
        attestation_sig: "fake_sig".to_string(),
        public_key_hex: "fake_pk".to_string(),
        duration_ms: 42,
        mode: "tunnel".to_string(),
        file_format: Some("pdf".to_string()),
    };

    write_audit_record(db_path, &record).expect("write_audit_record should succeed");
    let records = list_mcp_audit_records(db_path, 10).expect("list_mcp_audit_records should succeed");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].file_format.as_deref(), Some("pdf"));
}
