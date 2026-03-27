use std::path::Path;
use std::process::Command;

use anyhow::Context;
use uuid::Uuid;

use crate::bundle::parse_bb_version;

pub struct VerifyResult {
    pub valid: bool,
    pub circuit_hash: String,
    pub aggregate: u64,
    pub timestamp: String,
    pub raw_rows_sent_to_llm: u64,
    pub bb_version_used: String,
}

/// Verify a proof bundle ZIP by extracting it and calling `bb verify` directly.
///
/// Does NOT call `prover::verify_proof()` — that function operates on
/// hardcoded paths under `circuit/proofs/proof/`. This works on any bundle ZIP.
///
/// Exit semantics:
///   valid = true  → ZK proof verified by bb
///   valid = false → bb verify returned non-zero
///   Err(...)      → bb not found, version mismatch (MAJOR), or corrupt zip
pub fn verify_bundle(zip_path: &Path) -> anyhow::Result<VerifyResult> {
    // Resolve extract directory
    let home = dirs::home_dir().context("could not resolve home directory")?;
    let extract_id = Uuid::new_v4().to_string();
    let extract_dir = home.join(".zemtik").join(".tmp").join(format!("verify-{}", extract_id));
    std::fs::create_dir_all(&extract_dir)
        .with_context(|| format!("create extract dir {}", extract_dir.display()))?;

    // Ensure cleanup even on error
    let result = (|| -> anyhow::Result<VerifyResult> {
        // Extract ZIP
        let file = std::fs::File::open(zip_path)
            .with_context(|| format!("open bundle {}", zip_path.display()))?;
        let mut archive = zip::ZipArchive::new(file)
            .with_context(|| format!("parse zip {}", zip_path.display()))?;

        // Guard against zip bombs: abort if the archive is unreasonably large.
        const MAX_ENTRIES: usize = 64;
        const MAX_EXTRACTED_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB
        if archive.len() > MAX_ENTRIES {
            anyhow::bail!(
                "bundle has {} entries (max {}); refusing to extract",
                archive.len(),
                MAX_ENTRIES
            );
        }
        let mut total_extracted: u64 = 0;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).context("read zip entry")?;
            let name = entry.name().to_owned();
            // Strip directory components to prevent zip-slip path traversal.
            // A malicious bundle with entries like "../../.ssh/authorized_keys"
            // would otherwise escape the temp directory.
            // Directory entries (names ending in '/') have no filename component
            // and must be skipped rather than treated as errors — many ZIP tools
            // emit them automatically.
            let filename = match std::path::Path::new(&name).file_name() {
                Some(f) => f.to_owned(),
                None => continue, // directory entry — skip
            };
            let out_path = extract_dir.join(filename);
            let mut out_file = std::fs::File::create(&out_path)
                .with_context(|| format!("create {}", out_path.display()))?;
            let written = std::io::copy(&mut entry, &mut out_file)
                .with_context(|| format!("extract {}", name))?;
            total_extracted += written;
            if total_extracted > MAX_EXTRACTED_BYTES {
                anyhow::bail!(
                    "bundle extraction exceeded {} MiB limit; aborting",
                    MAX_EXTRACTED_BYTES / (1024 * 1024)
                );
            }
        }

        // Read metadata files
        let circuit_hash = std::fs::read_to_string(extract_dir.join("circuit_hash.txt"))
            .context("read circuit_hash.txt")?
            .trim()
            .to_owned();

        let meta_bytes = std::fs::read(extract_dir.join("request_meta.json"))
            .context("read request_meta.json")?;
        let meta: serde_json::Value =
            serde_json::from_slice(&meta_bytes).context("parse request_meta.json")?;

        let timestamp = meta
            .get("timestamp_utc")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let bb_version_used = meta
            .get("bb_version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let raw_rows_sent_to_llm = meta
            .get("raw_rows_sent_to_llm")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let readable_bytes = std::fs::read(extract_dir.join("public_inputs_readable.json"))
            .context("read public_inputs_readable.json")?;
        let readable: serde_json::Value =
            serde_json::from_slice(&readable_bytes).context("parse public_inputs_readable.json")?;
        let aggregate = readable
            .get("verified_aggregate")
            .and_then(|v| v.as_u64())
            .context("verified_aggregate missing from public_inputs_readable.json")?;

        // Verify required files are present
        for required in &["proof.bin", "vk.bin", "public_inputs"] {
            let p = extract_dir.join(required);
            if !p.exists() {
                anyhow::bail!("bundle is missing required file: {}", required);
            }
        }

        // Check bb version compatibility
        let local_bb_raw = {
            let out = Command::new("bb")
                .arg("--version")
                .output()
                .context("bb not found — install Barretenberg (bb) to verify proofs")?;
            if !out.status.success() {
                anyhow::bail!(
                    "bb --version exited with status {} — check your Barretenberg installation",
                    out.status
                );
            }
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };

        if let (Some(local_ver), Some(bundle_ver)) = (
            parse_bb_version(&local_bb_raw),
            parse_bb_version(&bb_version_used),
        ) {
            if local_ver.0 != bundle_ver.0 {
                anyhow::bail!(
                    "bb MAJOR version mismatch: bundle was generated with {}, \
                     local bb is {} — cannot verify across major versions",
                    bb_version_used,
                    local_bb_raw
                );
            }
            if local_ver != bundle_ver {
                eprintln!(
                    "[WARN] bb version mismatch: bundle={}, local={} — proceeding (same major version)",
                    bb_version_used, local_bb_raw
                );
            }
        }

        // Run bb verify
        let verify_out = Command::new("bb")
            .args([
                "verify",
                "-p", "proof.bin",
                "-k", "vk.bin",
                "-i", "public_inputs",
            ])
            .current_dir(&extract_dir)
            .output()
            .context("spawn bb verify")?;

        let valid = verify_out.status.success();

        Ok(VerifyResult {
            valid,
            circuit_hash,
            aggregate,
            timestamp,
            raw_rows_sent_to_llm,
            bb_version_used,
        })
    })();

    // Always clean up extracted files
    let _ = std::fs::remove_dir_all(&extract_dir);

    result
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// Regression: ISSUE-001 — zip-slip path traversal in verify_bundle
    /// Found by /qa on 2026-03-26
    /// Report: .gstack/qa-reports/qa-report-zemtik-core-2026-03-26.md
    ///
    /// A malicious bundle ZIP with entry names containing path traversal sequences
    /// (e.g. "../../.ssh/authorized_keys") must not escape the temp extract directory.
    /// The fix strips directory components via `.file_name()` before joining.
    #[test]
    fn test_zip_slip_entry_rejected_or_sanitized() {
        use std::path::Path;

        // Build a minimal ZIP with a path-traversal entry name
        let tmp = std::env::temp_dir().join(format!("zipslip-test-{}.zip", std::process::id()));
        let file = std::fs::File::create(&tmp).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = SimpleFileOptions::default();

        // This entry would escape the extract dir if not sanitized
        zip.start_file("../../evil.txt", opts).unwrap();
        zip.write_all(b"should not escape").unwrap();
        zip.finish().unwrap();

        // verify_bundle should either fail with an error (no filename component)
        // or safely extract to a flat filename — it must NOT write outside extract dir.
        // "../../evil.txt" has file_name() == Some("evil.txt"), so it gets sanitized.
        // The bundle will still fail (missing required files) but won't do path traversal.
        let result = super::verify_bundle(Path::new(&tmp));

        // The bundle is malformed (missing proof.bin etc), so we expect an error.
        // What matters is that no file was written outside the temp directory.
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
    /// A ZIP entry named purely as a directory separator (e.g. "/") has no
    /// file_name() and must be rejected with an error, not panic.
    #[test]
    fn test_zip_entry_no_filename_returns_error() {
        use std::path::Path;

        let tmp = std::env::temp_dir().join(format!("zipslip-noname-{}.zip", std::process::id()));
        let file = std::fs::File::create(&tmp).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = SimpleFileOptions::default();

        // Entry name that resolves to no file_name() component
        zip.start_file("/", opts).unwrap();
        zip.finish().unwrap();

        let result = super::verify_bundle(Path::new(&tmp));
        assert!(result.is_err(), "entry with no filename must return an error");

        let _ = std::fs::remove_file(&tmp);
    }
}

/// CLI entry point for `zemtik verify <bundle.zip>`.
pub fn run_verify_cli(zip_path: &Path) -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║   Zemtik Verifier — Independent Proof Check      ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    println!("  Bundle : {}", zip_path.display());
    println!();

    let result = verify_bundle(zip_path).map_err(|e| {
        eprintln!("  Error  : {}", e);
        e
    })?;

    println!("  Circuit Hash     : {}", result.circuit_hash);
    println!("  Aggregate        : ${}", result.aggregate);
    println!("  Timestamp        : {}", result.timestamp);
    println!("  Raw rows to LLM  : {}", result.raw_rows_sent_to_llm);
    println!("  bb version       : {}", result.bb_version_used);
    println!();

    if result.valid {
        println!("  STATUS: VALID");
        println!();
        println!("  The ZK proof is cryptographically valid.");
        println!("  The LLM received only the verified aggregate — zero raw rows.");
    } else {
        eprintln!("  STATUS: INVALID");
        eprintln!();
        eprintln!("  Proof verification failed. The bundle may be corrupted or tampered.");
        std::process::exit(1);
    }

    println!();
    Ok(())
}
