use zemtik::time_parser::parse_time_range;

// Reference timestamps (UTC):
// 2026-01-01 00:00:00 = 1_767_225_600
// 2026-03-31 23:59:59 = 1_775_001_599
// 2025-10-01 00:00:00 = 1_759_276_800
// 2025-12-31 23:59:59 = 1_767_225_599
// 2025-07-01 00:00:00 = 1_751_328_000
// 2025-09-30 23:59:59 = 1_759_276_799
// 2024-01-01 00:00:00 = 1_704_067_200
// 2024-12-31 23:59:59 = 1_735_689_599
// 2024-01-01 00:00:00 = 1_704_067_200
// 2024-06-30 23:59:59 = 1_719_791_999
// 2024-07-01 00:00:00 = 1_719_792_000
// 2024-12-31 23:59:59 = 1_735_689_599
// 2024-03-01 00:00:00 = 1_709_251_200
// 2024-03-31 23:59:59 = 1_711_929_599

#[test]
fn quarter_no_offset() {
    let tr = parse_time_range("Q1 2026 AWS spend", 0).unwrap();
    // 2026-01-01 → 2026-03-31
    assert_eq!(tr.start_unix_secs, 1_767_225_600);
    assert_eq!(tr.end_unix_secs, 1_775_001_599);
}

#[test]
fn quarter_with_offset_9() {
    // Q1 2026, offset=9: calendar Jan–Mar shifted back 9 months → Oct–Dec 2025
    let tr = parse_time_range("Q1 2026 AWS spend", 9).unwrap();
    // 2025-10-01 → 2025-12-31
    assert_eq!(tr.start_unix_secs, 1_759_276_800);
    assert_eq!(tr.end_unix_secs, 1_767_225_599);
}

#[test]
fn q4_2025_with_offset_9() {
    // Q4 2025, offset=9: calendar Oct–Dec shifted back 9 months → Jul–Sep 2025
    let tr = parse_time_range("Q4 2025 payroll", 9).unwrap();
    // 2025-07-01 → 2025-09-30
    assert_eq!(tr.start_unix_secs, 1_751_328_000);
    assert_eq!(tr.end_unix_secs, 1_759_276_799);
}

#[test]
fn bare_year_no_offset() {
    let tr = parse_time_range("AWS spend in 2024", 0).unwrap();
    // 2024-01-01 → 2024-12-31
    assert_eq!(tr.start_unix_secs, 1_704_067_200);
    assert_eq!(tr.end_unix_secs, 1_735_689_599);
}

#[test]
fn h1_2024() {
    let tr = parse_time_range("H1 2024 cloud spend", 0).unwrap();
    // 2024-01-01 → 2024-06-30
    assert_eq!(tr.start_unix_secs, 1_704_067_200);
    assert_eq!(tr.end_unix_secs, 1_719_791_999);
}

#[test]
fn h2_2024() {
    let tr = parse_time_range("H2 2024 cloud spend", 0).unwrap();
    // 2024-07-01 → 2024-12-31
    assert_eq!(tr.start_unix_secs, 1_719_792_000);
    assert_eq!(tr.end_unix_secs, 1_735_689_599);
}

#[test]
fn fy_year() {
    // FY2025 with no offset = same as calendar 2025
    let tr = parse_time_range("FY2025 payroll", 0).unwrap();
    // 2025-01-01 → 2025-12-31
    assert_eq!(tr.start_unix_secs, 1_735_689_600);
    assert_eq!(tr.end_unix_secs, 1_767_225_599);
}

#[test]
fn fy_year_with_space() {
    let tr = parse_time_range("FY 2025 payroll", 0).unwrap();
    assert_eq!(tr.start_unix_secs, 1_735_689_600);
    assert_eq!(tr.end_unix_secs, 1_767_225_599);
}

#[test]
fn month_name_long() {
    let tr = parse_time_range("March 2024 AWS spend", 0).unwrap();
    // 2024-03-01 → 2024-03-31
    assert_eq!(tr.start_unix_secs, 1_709_251_200);
    assert_eq!(tr.end_unix_secs, 1_711_929_599);
}

#[test]
fn month_name_abbrev() {
    let tr = parse_time_range("Mar 2024 travel expenses", 0).unwrap();
    assert_eq!(tr.start_unix_secs, 1_709_251_200);
    assert_eq!(tr.end_unix_secs, 1_711_929_599);
}

#[test]
fn quarter_priority_over_bare_year() {
    // Q1 2026 contains "2026" — quarter pattern must win
    let tr = parse_time_range("Q1 2026 AWS spend", 0).unwrap();
    // Should be Q1 range, NOT full 2026
    assert_eq!(tr.start_unix_secs, 1_767_225_600); // Jan 1 2026
    assert_eq!(tr.end_unix_secs, 1_775_001_599);   // Mar 31 2026
}

#[test]
fn no_time_expression_defaults_to_current_year() {
    // No time tokens at all — should succeed with some year range
    let result = parse_time_range("total AWS spend", 0);
    assert!(result.is_ok(), "should default to current year without error");
    let tr = result.unwrap();
    // start should be Jan 1 of some year >= 2024
    assert!(tr.start_unix_secs >= 1_704_067_200);
    assert!(tr.end_unix_secs > tr.start_unix_secs);
}

#[test]
fn recently_is_ambiguous() {
    let result = parse_time_range("What happened recently with AWS?", 0);
    assert!(result.is_err(), "\"recently\" should be ambiguous");
}

#[test]
fn soon_is_ambiguous() {
    let result = parse_time_range("cloud spend soon", 0);
    assert!(result.is_err(), "\"soon\" should be ambiguous");
}

#[test]
fn last_year_resolves_to_prior_year() {
    let result = parse_time_range("what was our AWS spend last year", 0);
    assert!(result.is_ok(), "\"last year\" should resolve to prior calendar year");
    let tr = result.unwrap();
    assert!(tr.end_unix_secs > tr.start_unix_secs);
    // prior year ends before current year starts
    let now = chrono::Utc::now().timestamp();
    assert!(tr.end_unix_secs < now, "prior year end should be in the past");
}

#[test]
fn prior_year_resolves_to_prior_year() {
    let result = parse_time_range("salary expenses prior year", 0);
    assert!(result.is_ok(), "\"prior year\" should resolve to prior calendar year");
    let tr = result.unwrap();
    assert!(tr.end_unix_secs > tr.start_unix_secs);
}

#[test]
fn last_quarter_succeeds() {
    // "last quarter" is a supported pattern — should not be ambiguous
    let result = parse_time_range("AWS spend last quarter", 0);
    assert!(result.is_ok(), "\"last quarter\" should be supported");
    let tr = result.unwrap();
    assert!(tr.end_unix_secs > tr.start_unix_secs);
}

#[test]
fn prior_quarter_succeeds() {
    let result = parse_time_range("payroll vs prior quarter", 0);
    assert!(result.is_ok(), "\"prior quarter\" should resolve like last quarter");
    let tr = result.unwrap();
    assert!(tr.end_unix_secs > tr.start_unix_secs);
}

#[test]
fn prior_month_succeeds() {
    let result = parse_time_range("travel expenses prior month", 0);
    assert!(result.is_ok(), "\"prior month\" should resolve like last month");
    let tr = result.unwrap();
    assert!(tr.end_unix_secs > tr.start_unix_secs);
}

#[test]
fn this_quarter_succeeds() {
    let result = parse_time_range("payroll this quarter", 0);
    assert!(result.is_ok());
    let tr = result.unwrap();
    assert!(tr.end_unix_secs > tr.start_unix_secs);
}

#[test]
fn last_month_succeeds() {
    let result = parse_time_range("travel expenses last month", 0);
    assert!(result.is_ok());
}

#[test]
fn this_month_succeeds() {
    let result = parse_time_range("what is our cloud spend this month", 0);
    assert!(result.is_ok());
}

#[test]
fn ytd_succeeds() {
    let result = parse_time_range("payroll YTD", 0);
    assert!(result.is_ok());
    let tr = result.unwrap();
    // start should be Jan 1 of current year
    assert!(tr.end_unix_secs >= tr.start_unix_secs);
}

#[test]
fn year_to_date_alias_succeeds() {
    let result = parse_time_range("AWS spend year to date", 0);
    assert!(result.is_ok());
}

#[test]
fn past_30_days() {
    let result = parse_time_range("travel costs for the past 30 days", 0);
    assert!(result.is_ok());
    let tr = result.unwrap();
    // 30 days ≈ 2592000 seconds, allow ±5s for test execution time
    let diff = tr.end_unix_secs - tr.start_unix_secs;
    assert!((diff - 2_592_000).abs() < 5, "expected ~30 days, got {}s", diff);
}

#[test]
fn past_1_day() {
    let result = parse_time_range("past 1 day AWS spend", 0);
    assert!(result.is_ok());
    let tr = result.unwrap();
    let diff = tr.end_unix_secs - tr.start_unix_secs;
    assert!((diff - 86_400).abs() < 5);
}

#[test]
fn may_2024() {
    let tr = parse_time_range("May 2024 payroll", 0).unwrap();
    // 2024-05-01 00:00:00 UTC = 1714521600
    // 2024-05-31 23:59:59 UTC = 1717199999
    assert_eq!(tr.start_unix_secs, 1_714_521_600);
    assert_eq!(tr.end_unix_secs, 1_717_199_999);
}

#[test]
fn bare_year_ignores_non_year_numbers() {
    // "2000" is not a valid bare year (range is 2010-2099) — should default to current year
    let tr_control = parse_time_range("total payroll", 0).unwrap();
    let tr = parse_time_range("we have 2000 employees, show payroll", 0).unwrap();
    assert_eq!(tr.start_unix_secs, tr_control.start_unix_secs,
        "2000 should NOT match as a year — expected current-year default");
}
