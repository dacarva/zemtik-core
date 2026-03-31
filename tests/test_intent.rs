use std::collections::HashMap;

use zemtik::config::{SchemaConfig, TableConfig};
use zemtik::intent::{extract_intent, extract_intent_with_backend, IntentBackend, IntentError};

// ---------------------------------------------------------------------------
// Mock backend for threshold / margin tests
// ---------------------------------------------------------------------------

struct MockBackend {
    results: Vec<(String, f32)>,
}

impl MockBackend {
    fn new(results: Vec<(&str, f32)>) -> Self {
        MockBackend {
            results: results.into_iter().map(|(k, s)| (k.to_owned(), s)).collect(),
        }
    }
}

impl IntentBackend for MockBackend {
    fn index_schema(&mut self, _schema: &SchemaConfig) {}
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
            aliases: Some(vec![
                "AWS".to_owned(),
                "amazon".to_owned(),
                "cloud spend".to_owned(),
            ]),
            ..Default::default()
        },
    );
    tables.insert(
        "payroll".to_owned(),
        TableConfig {
            sensitivity: "critical".to_owned(),
            aliases: None,
            ..Default::default()
        },
    );
    SchemaConfig {
        fiscal_year_offset_months: 0,
        tables,
    }
}

#[test]
fn quarter_with_table() {
    let schema = test_schema();
    let result = extract_intent("Q1 2026 AWS spend", &schema).unwrap();
    assert_eq!(result.table, "aws_spend");
    // Q1 2026 calendar: 2026-01-01 00:00:00 UTC
    assert_eq!(result.start_unix_secs, 1_767_225_600);
    // 2026-03-31 23:59:59 UTC (2026-04-01 00:00:00 - 1s)
    assert_eq!(result.end_unix_secs, 1_775_001_599);
}

#[test]
fn quarter_with_fiscal_offset() {
    let mut schema = test_schema();
    schema.fiscal_year_offset_months = 9;
    // Q1 of FY2026 with offset=9: fiscal year starts October (month 10 of prior year).
    // Fiscal Q1 of FY2026 = Oct 2025 – Dec 2025.
    let result = extract_intent("Q1 2026 AWS spend", &schema).unwrap();
    assert_eq!(result.table, "aws_spend");
    // 2025-10-01 00:00:00 UTC
    assert_eq!(result.start_unix_secs, 1_759_276_800);
    // 2025-12-31 23:59:59 UTC
    assert_eq!(result.end_unix_secs, 1_767_225_599);
}

#[test]
fn alias_match_aws() {
    let schema = test_schema();
    let result = extract_intent("Show me AWS costs for Q2 2025", &schema).unwrap();
    assert_eq!(result.table, "aws_spend");
}

#[test]
fn alias_match_cloud_spend() {
    let schema = test_schema();
    let result = extract_intent("What was our cloud spend in 2024?", &schema).unwrap();
    assert_eq!(result.table, "aws_spend");
}

#[test]
fn payroll_q2_2025() {
    let schema = test_schema();
    let result = extract_intent("payroll expenses Q2 2025", &schema).unwrap();
    assert_eq!(result.table, "payroll");
    // Q2 2025: Apr 1 – Jun 30
    assert_eq!(result.start_unix_secs, 1_743_465_600);
    assert_eq!(result.end_unix_secs, 1_751_327_999);
}

#[test]
fn unknown_table_returns_error() {
    let schema = test_schema();
    let result = extract_intent("What is the weather like?", &schema);
    assert!(matches!(result, Err(IntentError::NoTableIdentified)));
}

#[test]
fn case_insensitive_payroll() {
    let schema = test_schema();
    let result = extract_intent("PAYROLL Q3 2024", &schema).unwrap();
    assert_eq!(result.table, "payroll");
}

#[test]
fn year_only_range_timestamps() {
    let schema = test_schema();
    // Year-only path (no Q[1-4] in prompt)
    let result = extract_intent("AWS spend in 2025", &schema).unwrap();
    assert_eq!(result.table, "aws_spend");
    // 2025-01-01 00:00:00 UTC
    assert_eq!(result.start_unix_secs, 1_735_689_600);
    // 2025-12-31 23:59:59 UTC
    assert_eq!(result.end_unix_secs, 1_767_225_599);
}

// ---------------------------------------------------------------------------
// Backend / confidence / margin tests (Phase 3)
// ---------------------------------------------------------------------------

#[test]
fn ambiguous_time_returns_error() {
    let schema = test_schema();
    let backend = MockBackend::new(vec![("aws_spend", 0.90)]);
    let result = extract_intent_with_backend("What happened recently?", &schema, &backend, 0.65);
    assert!(
        matches!(result, Err(IntentError::TimeRangeAmbiguous)),
        "ambiguous time expression should return TimeRangeAmbiguous"
    );
}

#[test]
fn low_score_returns_no_table() {
    let schema = test_schema();
    let backend = MockBackend::new(vec![("aws_spend", 0.40)]);
    let result = extract_intent_with_backend("AWS spend", &schema, &backend, 0.65);
    assert!(matches!(result, Err(IntentError::NoTableIdentified)));
}

#[test]
fn narrow_margin_returns_no_table() {
    // Scores 0.68 and 0.67 — margin = 0.01 < 0.10, should reject
    let schema = test_schema();
    let backend = MockBackend::new(vec![("aws_spend", 0.68), ("payroll", 0.67)]);
    let result = extract_intent_with_backend("Q1 2026 spend", &schema, &backend, 0.65);
    assert!(
        matches!(result, Err(IntentError::NoTableIdentified)),
        "narrow margin 0.01 should be rejected"
    );
}

#[test]
fn sufficient_margin_succeeds() {
    // Scores 0.70 and 0.55 — margin = 0.15 >= 0.10 — should succeed
    let schema = test_schema();
    let backend = MockBackend::new(vec![("aws_spend", 0.70), ("payroll", 0.55)]);
    let result =
        extract_intent_with_backend("Q1 2026 AWS spend", &schema, &backend, 0.65).unwrap();
    assert_eq!(result.table, "aws_spend");
    assert!((result.confidence - 0.70).abs() < 0.001);
}

#[test]
fn exact_threshold_passes() {
    // Score exactly 0.65 should pass (>= not >)
    let schema = test_schema();
    let backend = MockBackend::new(vec![("aws_spend", 0.65)]);
    let result = extract_intent_with_backend("AWS spend 2025", &schema, &backend, 0.65);
    assert!(result.is_ok(), "score exactly at threshold should pass");
}

#[test]
fn exact_margin_passes() {
    // Margin exactly 0.10 should pass (>= not >)
    let schema = test_schema();
    let backend = MockBackend::new(vec![("aws_spend", 0.80), ("payroll", 0.70)]);
    let result = extract_intent_with_backend("AWS spend 2025", &schema, &backend, 0.65);
    assert!(result.is_ok(), "margin exactly 0.10 should pass");
}

#[test]
fn regex_backend_backward_compat() {
    // extract_intent (shim) should behave identically to v1 for standard prompts
    let schema = test_schema();
    let result = extract_intent("payroll expenses Q2 2025", &schema).unwrap();
    assert_eq!(result.table, "payroll");
    assert_eq!(result.confidence, 1.0);
}

#[test]
fn prompt_truncation_does_not_panic() {
    let schema = test_schema();
    let long_prompt = format!("AWS spend Q1 2026 {}", "x".repeat(3000));
    // Should not panic even on very long prompts
    let result = extract_intent(&long_prompt, &schema);
    assert!(result.is_ok());
}
