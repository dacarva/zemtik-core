/// Deterministic time expression parser for financial query routing.
///
/// Supported patterns (in priority order — first match wins):
///
/// | Pattern           | Example         | Resolution                               |
/// |-------------------|-----------------|------------------------------------------|
/// | `Q[1-4] YYYY`     | Q1 2026         | Calendar quarter with fiscal offset      |
/// | `H[1-2] YYYY`     | H1 2024         | Half-year (H1=Jan–Jun, H2=Jul–Dec)       |
/// | `FY YYYY`/`FYYYYY`| FY2025          | Fiscal year with offset                  |
/// | `MMM YYYY`        | March 2024      | Month name + year                        |
/// | `past N days`     | past 30 days    | now − N days → now                       |
/// | `last quarter`    | last quarter    | Previous calendar quarter from today     |
/// | `prior quarter`   | prior quarter   | Alias for last quarter                   |
/// | `this quarter`    | this quarter    | Current calendar quarter                 |
/// | `last month`      | last month      | Previous calendar month                  |
/// | `prior month`     | prior month     | Alias for last month                     |
/// | `this month`      | this month      | Current calendar month                   |
/// | `last year`       | last year       | Full prior calendar year                 |
/// | `prior year`      | prior year      | Alias for last year                      |
/// | `YTD`/`year to date`| YTD           | Jan 1 of current year → now             |
/// | `YYYY` (bare year)| 2024            | Full year, fiscal offset applied         |
/// | (no time token)   | —               | Default to current calendar year; no err |
/// | (unrecognized)    | "recently"      | Returns `TimeAmbiguousError`             |
///
/// Unrecognized time-signaling words trigger `TimeAmbiguousError`, which the
/// caller maps to `IntentError::TimeRangeAmbiguous` → proxy routes to ZK SlowLane.
use std::sync::LazyLock;

use chrono::{Datelike, Duration, TimeZone, Utc};
use regex::Regex;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Returned when a time expression is present but cannot be deterministically resolved.
#[derive(Debug)]
pub struct TimeAmbiguousError;

impl std::fmt::Display for TimeAmbiguousError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "time range is ambiguous — rephrase using Q[1-4] YYYY, FY YYYY, or a supported time expression")
    }
}

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct TimeRange {
    pub start_unix_secs: i64,
    pub end_unix_secs: i64,
}

// ---------------------------------------------------------------------------
// Compiled regexes (LazyLock — compiled once, never again)
// ---------------------------------------------------------------------------

static RE_QUARTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[Qq]([1-4])\s+(20\d{2})").unwrap());

static RE_HALF_YEAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bH([12])\s+(20\d{2})\b").unwrap());

static RE_FISCAL_YEAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bFY\s*(20\d{2})\b").unwrap());

static RE_MONTH_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(20\d{2})\b").unwrap()
});

static RE_PAST_N_DAYS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bpast\s+(\d+)\s+days?\b").unwrap());

static RE_LAST_QUARTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(last|prior)\s+quarter\b").unwrap());

static RE_THIS_QUARTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bthis\s+quarter\b").unwrap());

static RE_LAST_MONTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(last|prior)\s+month\b").unwrap());

static RE_THIS_MONTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bthis\s+month\b").unwrap());

static RE_LAST_YEAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(last|prior)\s+year\b").unwrap());

static RE_YTD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(ytd|year[- ]to[- ]date)\b").unwrap());

// Range 2010–2099: avoids false matches on "2000 employees" etc.
static RE_BARE_YEAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(20[1-9][0-9])\b").unwrap());

/// Patterns that signal a time expression without being a supported format.
/// When any of these match but no supported pattern did, we return TimeAmbiguousError.
static RE_AMBIGUOUS_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(recently|soon|lately|recent|previously|next\s+(year|quarter|month)|previous\s+(year|quarter|month)|current\s+year|ago|earlier)\b").unwrap()
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a time expression from `prompt`, applying `fiscal_offset_months` to
/// shift calendar dates.
///
/// Returns `Ok(TimeRange)` on success (including the "no time token" default),
/// or `Err(TimeAmbiguousError)` when an unrecognized time expression is present.
pub fn parse_time_range(
    prompt: &str,
    fiscal_offset_months: i64,
) -> Result<TimeRange, TimeAmbiguousError> {
    let now = Utc::now();

    // Q[1-4] YYYY — highest priority
    if let Some(cap) = RE_QUARTER.captures(prompt) {
        let quarter: u32 = cap[1].parse().unwrap();
        let year: i32 = cap[2].parse().unwrap();
        let (start, end) = quarter_to_unix(quarter, year, fiscal_offset_months);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // H[1-2] YYYY
    if let Some(cap) = RE_HALF_YEAR.captures(prompt) {
        let half: u32 = cap[1].parse().unwrap();
        let year: i32 = cap[2].parse().unwrap();
        let (start_month, end_month) = if half == 1 { (1u32, 6u32) } else { (7u32, 12u32) };
        let start = month_start_unix(year, start_month);
        let end = month_end_unix(year, end_month);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // FY YYYY / FYYYYY
    if let Some(cap) = RE_FISCAL_YEAR.captures(prompt) {
        let year: i32 = cap[1].parse().unwrap();
        let (start, end) = year_to_unix(year, fiscal_offset_months);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // MMM YYYY / MMMM YYYY
    if let Some(cap) = RE_MONTH_NAME.captures(prompt) {
        let month = month_name_to_number(&cap[1]).unwrap_or(1);
        let year: i32 = cap[2].parse().unwrap();
        let start = month_start_unix(year, month);
        let end = month_end_unix(year, month);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // past N days (cap at 36500 days / ~100 years to prevent Duration overflow)
    if let Some(cap) = RE_PAST_N_DAYS.captures(prompt) {
        let n: i64 = cap[1].parse().unwrap_or(1).clamp(1, 36500);
        let end = now.timestamp();
        let start = (now - Duration::days(n)).timestamp();
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // last quarter
    if RE_LAST_QUARTER.is_match(prompt) {
        let (start, end) = last_quarter_range(now.year(), now.month(), fiscal_offset_months);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // this quarter
    if RE_THIS_QUARTER.is_match(prompt) {
        let q = month_to_quarter(now.month());
        let (start, end) = quarter_to_unix(q, now.year(), fiscal_offset_months);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // last month
    if RE_LAST_MONTH.is_match(prompt) {
        let (prev_year, prev_month) = prev_month(now.year(), now.month());
        let start = month_start_unix(prev_year, prev_month);
        let end = month_end_unix(prev_year, prev_month);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // this month
    if RE_THIS_MONTH.is_match(prompt) {
        let start = month_start_unix(now.year(), now.month());
        let end = month_end_unix(now.year(), now.month());
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // last year / prior year → full prior calendar year
    if RE_LAST_YEAR.is_match(prompt) {
        let (start, end) = year_to_unix(now.year() - 1, fiscal_offset_months);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // YTD / year to date
    if RE_YTD.is_match(prompt) {
        let start = month_start_unix(now.year(), 1);
        let end = now.timestamp();
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // Bare YYYY (lowest explicit priority, checked after all named patterns)
    if let Some(cap) = RE_BARE_YEAR.captures(prompt) {
        let year: i32 = cap[1].parse().unwrap();
        let (start, end) = year_to_unix(year, fiscal_offset_months);
        return Ok(TimeRange { start_unix_secs: start, end_unix_secs: end });
    }

    // Check for ambiguous time signals — only after all supported patterns fail
    if RE_AMBIGUOUS_TIME.is_match(prompt) {
        return Err(TimeAmbiguousError);
    }

    // No time expression at all — default to current calendar year
    let (start, end) = year_to_unix(now.year(), 0);
    Ok(TimeRange { start_unix_secs: start, end_unix_secs: end })
}

// ---------------------------------------------------------------------------
// Helper functions (pub(crate) for use in intent.rs)
// ---------------------------------------------------------------------------

/// Calendar quarter → Unix second range with fiscal offset subtracted.
pub(crate) fn quarter_to_unix(quarter: u32, year: i32, offset_months: i64) -> (i64, i64) {
    let (cal_start_month, cal_end_month): (u32, u32) = match quarter {
        1 => (1, 3),
        2 => (4, 6),
        3 => (7, 9),
        4 => (10, 12),
        _ => unreachable!(),
    };
    let (start_year, start_month) = offset_month(year, cal_start_month as i64, offset_months);
    let (end_year, end_month) = offset_month(year, cal_end_month as i64, offset_months);
    (
        month_start_unix(start_year, start_month as u32),
        month_end_unix(end_year, end_month as u32),
    )
}

/// Full year → Unix second range (Jan 1 – Dec 31), with fiscal offset.
pub(crate) fn year_to_unix(year: i32, offset_months: i64) -> (i64, i64) {
    let (start_year, start_month) = offset_month(year, 1, offset_months);
    let (end_year, end_month) = offset_month(year, 12, offset_months);
    (
        month_start_unix(start_year, start_month as u32),
        month_end_unix(end_year, end_month as u32),
    )
}

/// Apply `fiscal_year_offset_months` to `(year, month)` with year-wrap handling.
///
/// `fiscal_year_offset_months = N` means the fiscal year starts `N` months after
/// January 1, i.e. in calendar month `N + 1`:
///
/// - `offset = 0` → fiscal = calendar (January start), subtract 0 months.
/// - `offset = 9` → fiscal year starts October (month 10 of prior year),
///   equivalent to subtracting `(12 - 9) % 12 = 3` calendar months.
/// - `offset = 3` → fiscal year starts April (month 4), subtract 9 months.
///
/// The effective subtraction is `(12 - offset_months) % 12`.
pub(crate) fn offset_month(year: i32, month: i64, offset_months: i64) -> (i32, i64) {
    let effective_sub = (12 - (offset_months % 12)) % 12;
    let mut m = month - effective_sub;
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
pub(crate) fn month_start_unix(year: i32, month: u32) -> i64 {
    Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .unwrap_or_else(|| panic!("month_start_unix: invalid date year={} month={}", year, month))
        .timestamp()
}

/// Unix timestamp of the last second of a given month (UTC).
pub(crate) fn month_end_unix(year: i32, month: u32) -> i64 {
    let (next_year, next_month) = if month == 12 { (year + 1, 1u32) } else { (year, month + 1) };
    Utc.with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0)
        .single()
        .unwrap_or_else(|| panic!("month_end_unix: invalid date year={} month={}", next_year, next_month))
        .timestamp() - 1
}

fn month_to_quarter(month: u32) -> u32 {
    match month {
        1..=3 => 1,
        4..=6 => 2,
        7..=9 => 3,
        _ => 4,
    }
}

fn prev_month(year: i32, month: u32) -> (i32, u32) {
    if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    }
}

fn last_quarter_range(current_year: i32, current_month: u32, fiscal_offset_months: i64) -> (i64, i64) {
    let current_q = month_to_quarter(current_month);
    let (prev_year, prev_q) = if current_q == 1 {
        (current_year - 1, 4u32)
    } else {
        (current_year, current_q - 1)
    };
    quarter_to_unix(prev_q, prev_year, fiscal_offset_months)
}

fn month_name_to_number(name: &str) -> Option<u32> {
    match name.to_lowercase().as_str() {
        "january" | "jan" => Some(1),
        "february" | "feb" => Some(2),
        "march" | "mar" => Some(3),
        "april" | "apr" => Some(4),
        "may" => Some(5),
        "june" | "jun" => Some(6),
        "july" | "jul" => Some(7),
        "august" | "aug" => Some(8),
        "september" | "sep" => Some(9),
        "october" | "oct" => Some(10),
        "november" | "nov" => Some(11),
        "december" | "dec" => Some(12),
        _ => None,
    }
}
