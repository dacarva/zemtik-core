use regex::Regex;

use crate::config::SchemaConfig;
use crate::types::IntentResult;

#[derive(Debug)]
pub enum IntentError {
    NoTableIdentified,
    #[allow(dead_code)]
    TimeRangeAmbiguous,
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentError::NoTableIdentified => write!(f, "no table identified in prompt"),
            IntentError::TimeRangeAmbiguous => write!(f, "time range is ambiguous"),
        }
    }
}

/// Extract intent from a user prompt using the provided SchemaConfig.
///
/// Returns an `IntentResult` on success, or an `IntentError` if no table
/// could be identified.
pub fn extract_intent(prompt: &str, schema: &SchemaConfig) -> Result<IntentResult, IntentError> {
    let lower = prompt.to_lowercase();

    // Build alias map: normalized-alias → table_key
    let mut matched_table: Option<String> = None;
    'outer: for (key, tc) in &schema.tables {
        // Check the table key itself (case-insensitive)
        if lower.contains(&key.to_lowercase()) {
            matched_table = Some(key.clone());
            break 'outer;
        }
        // Check all aliases
        if let Some(ref aliases) = tc.aliases {
            for alias in aliases {
                if lower.contains(&alias.to_lowercase()) {
                    matched_table = Some(key.clone());
                    break 'outer;
                }
            }
        }
    }

    let table = matched_table.ok_or(IntentError::NoTableIdentified)?;

    let (start_unix, end_unix) = extract_time_range(prompt, schema.fiscal_year_offset_months);

    Ok(IntentResult {
        category_name: table.clone(),
        table,
        start_unix_secs: start_unix,
        end_unix_secs: end_unix,
    })
}

/// Extract a UNIX timestamp range from a prompt.
///
/// Priority:
/// 1. `Q[1-4] YYYY` → calendar quarter boundaries, offset by fiscal months
/// 2. `YYYY` (4-digit year) → Jan 1 – Dec 31, offset by fiscal months
/// 3. Default: current calendar year
fn extract_time_range(prompt: &str, fiscal_offset_months: i64) -> (i64, i64) {
    // Try quarter match first
    let re_quarter = Regex::new(r"[Qq]([1-4])\s+(20\d{2})").expect("valid regex");
    if let Some(cap) = re_quarter.captures(prompt) {
        let quarter: u32 = cap[1].parse().expect("digit");
        let year: i32 = cap[2].parse().expect("4-digit year");
        return quarter_to_unix(quarter, year, fiscal_offset_months);
    }

    // Try plain year match
    let re_year = Regex::new(r"\b(20\d{2})\b").expect("valid regex");
    if let Some(cap) = re_year.captures(prompt) {
        let year: i32 = cap[1].parse().expect("4-digit year");
        return year_to_unix(year, fiscal_offset_months);
    }

    // Default: current calendar year
    let now = chrono::Utc::now();
    year_to_unix(now.format("%Y").to_string().parse().unwrap_or(2026), 0)
}

/// Calendar quarter → Unix second range, applying `fiscal_offset_months`.
///
/// Offset is subtracted from calendar boundaries:
///   `fiscal_start = calendar_start - offset_months`
///
/// Example: Q1 2026 with offset=9 → Oct 1 2025 – Dec 31 2025
fn quarter_to_unix(quarter: u32, year: i32, offset_months: i64) -> (i64, i64) {
    // Calendar quarter start months (1-indexed)
    let (cal_start_month, cal_end_month) = match quarter {
        1 => (1u32, 3u32),
        2 => (4, 6),
        3 => (7, 9),
        4 => (10, 12),
        _ => unreachable!(),
    };

    let (start_year, start_month) = offset_month(year, cal_start_month as i64, offset_months);
    let (end_year, end_month) = offset_month(year, cal_end_month as i64, offset_months);

    let start = month_start_unix(start_year, start_month as u32);
    let end = month_end_unix(end_year, end_month as u32);
    (start, end)
}

/// Full year → Unix second range (Jan 1 – Dec 31), applying fiscal offset.
fn year_to_unix(year: i32, offset_months: i64) -> (i64, i64) {
    let (start_year, start_month) = offset_month(year, 1, offset_months);
    let (end_year, end_month) = offset_month(year, 12, offset_months);
    let start = month_start_unix(start_year, start_month as u32);
    let end = month_end_unix(end_year, end_month as u32);
    (start, end)
}

/// Subtract `offset_months` from (year, month), with year-wrap handling.
fn offset_month(year: i32, month: i64, offset_months: i64) -> (i32, i64) {
    let mut m = month - offset_months;
    let mut y = year;
    while m < 1 {
        m += 12;
        y -= 1;
    }
    while m > 12 {
        m -= 12;
        y += 1;
    }
    (y, m)
}

/// Unix timestamp of the first second of a given month (UTC).
fn month_start_unix(year: i32, month: u32) -> i64 {
    use chrono::{TimeZone, Utc};
    Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .map(|dt| dt.timestamp())
        .unwrap_or(0)
}

/// Unix timestamp of the last second of a given month (UTC).
fn month_end_unix(year: i32, month: u32) -> i64 {
    use chrono::{TimeZone, Utc};
    // Last day: first day of next month minus 1 second
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1u32)
    } else {
        (year, month + 1)
    };
    Utc.with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0)
        .single()
        .map(|dt| dt.timestamp() - 1)
        .unwrap_or(0)
}

