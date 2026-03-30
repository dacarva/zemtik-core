use crate::config::SchemaConfig;
use crate::types::{IntentResult, Route};

/// Route a single-table intent to FastLane or ZK SlowLane.
///
/// Unknown tables default to ZkSlowLane (fail-secure).
pub fn decide_route(intent: &IntentResult, schema: &SchemaConfig) -> Route {
    match schema.tables.get(&intent.table) {
        None => Route::ZkSlowLane,
        Some(tc) => {
            if tc.sensitivity == "critical" {
                Route::ZkSlowLane
            } else {
                Route::FastLane
            }
        }
    }
}

/// Route a multi-table query: if ANY table is critical → ZkSlowLane (OR rule).
///
/// v1 always produces single-table intents; this is here for future use and
/// is exercised only in unit tests.
#[allow(dead_code)]
pub fn decide_route_multi(tables: &[&str], schema: &SchemaConfig) -> Route {
    for table in tables {
        if schema
            .tables
            .get(*table)
            .map_or(true, |t| t.sensitivity == "critical")
        {
            return Route::ZkSlowLane;
        }
    }
    Route::FastLane
}
