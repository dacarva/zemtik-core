use std::collections::HashMap;

use zemtik::config::{SchemaConfig, TableConfig};
use zemtik::intent::{extract_intent, IntentError};

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
        },
    );
    tables.insert(
        "payroll".to_owned(),
        TableConfig {
            sensitivity: "critical".to_owned(),
            aliases: None,
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
    // Q1 2026 with offset=9: calendar Jan-Mar shifted back 9 months → Apr-Jun 2025
    let result = extract_intent("Q1 2026 AWS spend", &schema).unwrap();
    assert_eq!(result.table, "aws_spend");
    // 2025-04-01 00:00:00 UTC
    assert_eq!(result.start_unix_secs, 1_743_465_600);
    // 2025-06-30 23:59:59 UTC
    assert_eq!(result.end_unix_secs, 1_751_327_999);
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
