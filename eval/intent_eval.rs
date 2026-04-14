/// Intent Engine v2 — Eval Harness
///
/// Measures routing accuracy against `eval/labeled_prompts.json`.
///
/// Acceptance gates (per design doc):
///   - Table match accuracy: ≥95% on full labeled set
///   - False-FastLane rate: zero false positives on adversarial entries (expected_table: null)
///   - Time-range accuracy: ≥90% on entries with expected_time
///
/// Run with:
///   cargo run --bin intent-eval --features eval
///
/// Override backend:
///   ZEMTIK_INTENT_BACKEND=regex cargo run --bin intent-eval --features eval
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LabeledEntry {
    prompt: String,
    expected_table: Option<String>,
    expected_route: String,
    expected_time: Option<ExpectedTime>,
}

#[derive(Debug, Deserialize)]
struct ExpectedTime {
    start: i64,
    end: i64,
}

fn main() -> anyhow::Result<()> {
    // Load labeled prompts
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let labels_path = manifest_dir.join("eval").join("labeled_prompts.json");
    let labels_bytes = std::fs::read(&labels_path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", labels_path.display(), e))?;
    let entries: Vec<LabeledEntry> = serde_json::from_slice(&labels_bytes)?;

    println!("Loaded {} labeled prompts from {}", entries.len(), labels_path.display());

    // Load schema config (use example if no user config present)
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let schema_path = home.join(".zemtik").join("schema_config.json");
    let example_path = manifest_dir.join("schema_config.example.json");
    let schema_file = if schema_path.exists() { schema_path } else { example_path };

    let (schema, _) = zemtik::config::load_schema_config(&schema_file)?;
    println!("Using schema from: {}", schema_file.display());

    // Resolve intent backend
    let backend_env = std::env::var("ZEMTIK_INTENT_BACKEND").unwrap_or_default().to_lowercase();
    let use_embed = backend_env != "regex";
    let threshold: f32 = std::env::var("ZEMTIK_INTENT_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.65);

    println!(
        "Backend: {}, threshold: {}",
        if use_embed { "embed" } else { "regex" },
        threshold
    );

    let mut backend: Box<dyn zemtik::intent::IntentBackend> = if use_embed {
        let models_dir = home.join(".zemtik").join("models");
        match zemtik::intent_embed::try_new_embedding_backend(&models_dir) {
            Some(b) => b,
            None => {
                eprintln!("WARN: embedding backend unavailable, falling back to regex");
                Box::new(zemtik::intent::RegexBackend::new())
            }
        }
    } else {
        Box::new(zemtik::intent::RegexBackend::new())
    };

    backend.index_schema(&schema);

    // Run evaluation
    let mut table_correct = 0usize;
    let mut table_total = 0usize;
    let mut time_correct = 0usize;
    let mut time_total = 0usize;
    let mut false_fastlane = 0usize;  // adversarial entries that incorrectly routed to FastLane
    let mut adversarial_total = 0usize;
    let mut route_correct = 0usize;
    let mut route_total = 0usize;

    let mut failures: Vec<String> = Vec::new();

    for entry in &entries {
        let is_adversarial = entry.expected_table.is_none();
        if is_adversarial {
            adversarial_total += 1;
        }

        let result = zemtik::intent::extract_intent_with_backend(
            &entry.prompt,
            &schema,
            backend.as_ref(),
            threshold,
        );

        match &entry.expected_table {
            None => {
                // Adversarial: should NOT return Ok (should be rejected or route to ZK)
                if let Ok(r) = &result {
                    // Check if this would route to FastLane
                    let route = zemtik::router::decide_route(r, &schema);
                    if matches!(route, zemtik::types::Route::FastLane) {
                        false_fastlane += 1;
                        failures.push(format!(
                            "FALSE-FASTLANE: {:?} → {} (conf={:.3})",
                            entry.prompt, r.table, r.confidence
                        ));
                    }
                }
                // If rejected (Err), that's correct for adversarial entries
            }
            Some(expected) => {
                table_total += 1;
                match &result {
                    Ok(r) if r.table == *expected => {
                        table_correct += 1;
                        // Check route correctness
                        route_total += 1;
                        let actual_route = zemtik::router::decide_route(r, &schema);
                        let actual_route_str = match actual_route {
                            zemtik::types::Route::FastLane => "FastLane",
                            zemtik::types::Route::ZkSlowLane => "ZkSlowLane",
                            zemtik::types::Route::GeneralLane => "GeneralLane",
                        };
                        if actual_route_str == entry.expected_route.as_str() {
                            route_correct += 1;
                        } else {
                            failures.push(format!(
                                "WRONG-ROUTE: {:?} → {} (expected {})",
                                entry.prompt, actual_route_str, entry.expected_route
                            ));
                        }
                        // Check time range if expected
                        if let Some(ref et) = entry.expected_time {
                            time_total += 1;
                            // Allow ±1s tolerance for wall-clock-dependent expressions
                            let start_ok = (r.start_unix_secs - et.start).abs() <= 1;
                            let end_ok = (r.end_unix_secs - et.end).abs() <= 1;
                            if start_ok && end_ok {
                                time_correct += 1;
                            } else {
                                failures.push(format!(
                                    "TIME-MISMATCH: {:?} → start={} (expected {}), end={} (expected {})",
                                    entry.prompt,
                                    r.start_unix_secs, et.start,
                                    r.end_unix_secs, et.end,
                                ));
                            }
                        }
                    }
                    Ok(r) => {
                        failures.push(format!(
                            "WRONG-TABLE: {:?} → {} (expected {})",
                            entry.prompt, r.table, expected
                        ));
                    }
                    Err(e) => {
                        failures.push(format!(
                            "REJECTED: {:?} → {} (expected {})",
                            entry.prompt, e, expected
                        ));
                    }
                }
            }
        }
    }

    // Print results
    println!();
    println!("═══════════════════════════════════════════════════");
    println!("  INTENT ENGINE EVAL RESULTS");
    println!("═══════════════════════════════════════════════════");

    let table_accuracy = if table_total > 0 {
        (table_correct as f64 / table_total as f64) * 100.0
    } else {
        0.0
    };
    let time_accuracy = if time_total > 0 {
        (time_correct as f64 / time_total as f64) * 100.0
    } else {
        100.0
    };
    let route_wrong = route_total - route_correct;

    println!(
        "  Table accuracy : {}/{} ({:.1}%)  [gate: ≥95%]  {}",
        table_correct,
        table_total,
        table_accuracy,
        if table_accuracy >= 95.0 { "✓ PASS" } else { "✗ FAIL" }
    );
    println!(
        "  False-FastLane : {}/{}           [gate: 0]     {}",
        false_fastlane,
        adversarial_total,
        if false_fastlane == 0 { "✓ PASS" } else { "✗ FAIL" }
    );
    println!(
        "  Time accuracy  : {}/{} ({:.1}%)  [gate: ≥90%]  {}",
        time_correct,
        time_total,
        time_accuracy,
        if time_accuracy >= 90.0 { "✓ PASS" } else { "✗ FAIL" }
    );
    println!(
        "  Route correct  : {}/{}           [gate: 0 wrong] {}",
        route_correct,
        route_total,
        if route_wrong == 0 { "✓ PASS" } else { "✗ FAIL" }
    );
    println!("═══════════════════════════════════════════════════");

    if !failures.is_empty() {
        println!();
        println!("  Failures ({}):", failures.len());
        for f in &failures {
            println!("    {}", f);
        }
    }

    let all_pass = table_accuracy >= 95.0 && false_fastlane == 0 && time_accuracy >= 90.0 && route_wrong == 0;

    if all_pass {
        println!();
        println!("  ALL GATES PASSED — intent engine v2 cleared for release.");
        println!();
        Ok(())
    } else {
        println!();
        println!("  EVAL FAILED — one or more acceptance gates not met.");
        println!();
        std::process::exit(1);
    }
}
