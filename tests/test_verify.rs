use std::io::Write;
use std::path::Path;

use zip::write::SimpleFileOptions;

/// Regression: ISSUE-001 — zip-slip path traversal en verify_bundle
/// Found by /qa on 2026-03-26
#[test]
fn test_zip_slip_entry_rejected_or_sanitized() {
    let tmp = std::env::temp_dir().join(format!("zipslip-test-{}.zip", std::process::id()));
    let file = std::fs::File::create(&tmp).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("../../evil.txt", opts).unwrap();
    zip.write_all(b"should not escape").unwrap();
    zip.finish().unwrap();

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));

    assert!(result.is_err(), "malformed bundle must return an error");

    let evil_path = std::env::temp_dir().parent().unwrap_or(Path::new("/tmp")).join("evil.txt");
    assert!(
        !evil_path.exists(),
        "zip-slip: file was written outside extract dir at {}",
        evil_path.display()
    );

    let _ = std::fs::remove_file(&tmp);
}

/// Regression: ISSUE-001 (edge case) — entry with no filename component
#[test]
fn test_zip_entry_no_filename_returns_error() {
    let tmp = std::env::temp_dir().join(format!("zipslip-noname-{}.zip", std::process::id()));
    let file = std::fs::File::create(&tmp).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();

    zip.start_file("/", opts).unwrap();
    zip.finish().unwrap();

    let result = zemtik::verify::verify_bundle(Path::new(&tmp));
    assert!(result.is_err(), "entry with no filename must return an error");

    let _ = std::fs::remove_file(&tmp);
}
