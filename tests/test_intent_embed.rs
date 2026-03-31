use std::collections::HashMap;

use zemtik::config::{SchemaConfig, TableConfig};
use zemtik::intent::{extract_intent_with_backend, IntentBackend};

// ---------------------------------------------------------------------------
// MockIntentBackend — runs in standard cargo test (no model required)
// ---------------------------------------------------------------------------

struct MockBackend {
    results: Vec<(String, f32)>,
    indexed: bool,
}

impl MockBackend {
    fn with_results(results: Vec<(&str, f32)>) -> Self {
        MockBackend {
            results: results.into_iter().map(|(k, s)| (k.to_owned(), s)).collect(),
            indexed: false,
        }
    }
}

impl IntentBackend for MockBackend {
    fn index_schema(&mut self, _schema: &SchemaConfig) {
        self.indexed = true;
    }

    fn match_prompt(&self, _prompt: &str, _k: usize) -> Vec<(String, f32)> {
        self.results.clone()
    }
}

fn test_schema() -> SchemaConfig {
    let mut tables = HashMap::new();
    tables.insert(
        "aws_spend".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            aliases: Some(vec!["AWS".to_owned(), "cloud".to_owned()]),
            description: "AWS cloud costs.".to_owned(),
            example_prompts: vec!["What was our AWS spend?".to_owned()],
            ..Default::default()
        },
    );
    tables.insert(
        "payroll".to_owned(),
        TableConfig {
            sensitivity: "critical".to_owned(),
            description: "Employee salary data.".to_owned(),
            example_prompts: vec!["Total payroll Q1?".to_owned()],
            ..Default::default()
        },
    );
    SchemaConfig { fiscal_year_offset_months: 0, tables }
}

#[test]
fn mock_backend_index_schema_called() {
    let schema = test_schema();
    let mut backend = MockBackend::with_results(vec![("aws_spend", 0.85)]);
    backend.index_schema(&schema);
    assert!(backend.indexed, "index_schema should mark backend as indexed");
}

#[test]
fn mock_backend_high_confidence_routes_fast_lane() {
    let schema = test_schema();
    let backend = MockBackend::with_results(vec![("aws_spend", 0.90), ("payroll", 0.40)]);
    let result = extract_intent_with_backend("Q1 2026 cloud spend", &schema, &backend, 0.65);
    assert!(result.is_ok());
    let r = result.unwrap();
    assert_eq!(r.table, "aws_spend");
    assert!((r.confidence - 0.90).abs() < 0.001);
}

#[test]
fn mock_backend_below_threshold_rejected() {
    let schema = test_schema();
    let backend = MockBackend::with_results(vec![("aws_spend", 0.50)]);
    let result = extract_intent_with_backend("some query 2025", &schema, &backend, 0.65);
    assert!(result.is_err());
}

#[test]
fn mock_backend_empty_results_rejected() {
    let schema = test_schema();
    let backend = MockBackend::with_results(vec![]);
    let result = extract_intent_with_backend("AWS spend 2025", &schema, &backend, 0.65);
    assert!(result.is_err());
}

#[test]
fn mock_backend_single_result_no_margin_check() {
    // A single result should pass without a margin check (no second result to compare)
    let schema = test_schema();
    let backend = MockBackend::with_results(vec![("aws_spend", 0.70)]);
    let result = extract_intent_with_backend("AWS spend Q1 2026", &schema, &backend, 0.65);
    assert!(result.is_ok(), "single result should succeed without margin check");
}

// ---------------------------------------------------------------------------
// EmbeddingBackend smoke test (requires embed feature + cached model)
// These tests are skipped unless the model is present at ~/.zemtik/models.
// Run with: cargo test --features embed -- --include-ignored embed_
// ---------------------------------------------------------------------------

#[cfg(feature = "embed")]
#[test]
#[ignore = "requires BGE-small-en model to be downloaded (~130MB)"]
fn embed_backend_new_succeeds_with_model() {
    let home = dirs::home_dir().expect("home dir");
    let models_dir = home.join(".zemtik").join("models");
    let result = zemtik::intent_embed::EmbeddingBackend::new(&models_dir);
    assert!(result.is_ok(), "EmbeddingBackend::new should succeed when model is cached");
}

#[cfg(feature = "embed")]
#[test]
#[ignore = "requires BGE-small-en model to be downloaded (~130MB)"]
fn embed_backend_matches_aws_spend() {
    let home = dirs::home_dir().expect("home dir");
    let models_dir = home.join(".zemtik").join("models");
    let mut backend =
        zemtik::intent_embed::EmbeddingBackend::new(&models_dir).expect("init model");
    let schema = test_schema();
    backend.index_schema(&schema);
    let results = backend.match_prompt("Q1 2026 cloud infrastructure costs", 3);
    assert!(!results.is_empty(), "should return at least one result");
    assert_eq!(results[0].0, "aws_spend", "aws_spend should rank first");
}
