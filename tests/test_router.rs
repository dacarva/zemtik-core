use std::collections::HashMap;

use zemtik::config::{SchemaConfig, TableConfig};
use zemtik::router::{decide_route, decide_route_multi};
use zemtik::types::{IntentResult, Route};

fn test_schema() -> SchemaConfig {
    let mut tables = HashMap::new();
    tables.insert(
        "aws_spend".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            aliases: Some(vec!["AWS".to_owned()]),
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

fn intent(table: &str) -> IntentResult {
    IntentResult {
        table: table.to_owned(),
        category_name: table.to_owned(),
        start_unix_secs: 0,
        end_unix_secs: 0,
    }
}

#[test]
fn aws_spend_routes_fast_lane() {
    let schema = test_schema();
    assert!(matches!(decide_route(&intent("aws_spend"), &schema), Route::FastLane));
}

#[test]
fn payroll_routes_zk_slow_lane() {
    let schema = test_schema();
    assert!(matches!(decide_route(&intent("payroll"), &schema), Route::ZkSlowLane));
}

#[test]
fn unknown_table_fails_secure() {
    let schema = test_schema();
    assert!(matches!(decide_route(&intent("unknown_table"), &schema), Route::ZkSlowLane));
}

#[test]
fn multi_table_or_rule() {
    let schema = test_schema();
    // payroll is critical → ZkSlowLane even when combined with low-sensitivity table
    assert!(matches!(
        decide_route_multi(&["payroll", "aws_spend"], &schema),
        Route::ZkSlowLane
    ));
    // all low → FastLane
    assert!(matches!(
        decide_route_multi(&["aws_spend"], &schema),
        Route::FastLane
    ));
}
