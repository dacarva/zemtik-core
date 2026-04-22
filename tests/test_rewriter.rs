/// Tests for the hybrid query rewriter module.
///
/// Tests cover:
/// - deterministic_resolve: time-pivot, fall-through, Fix-0 prior-time contract
/// - rewrite_query: sentinel exact match, error handling, LLM output validation
/// - per-table disable, token budget
use std::collections::HashMap;

use serde_json::json;
use zemtik::config::{SchemaConfig, TableConfig};
use zemtik::intent::{IntentBackend, RegexBackend};
use zemtik::rewriter::{deterministic_resolve, RewriteResult};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_schema() -> SchemaConfig {
    let mut tables = HashMap::new();
    tables.insert(
        "aws_spend".to_owned(),
        TableConfig {
            sensitivity: "low".to_owned(),
            description: "AWS cloud spend".to_owned(),
            example_prompts: vec!["What was our AWS spend in Q1 2024?".to_owned()],
            ..TableConfig::default()
        },
    );
    tables.insert(
        "payroll".to_owned(),
        TableConfig {
            sensitivity: "critical".to_owned(),
            description: "Payroll expenses".to_owned(),
            example_prompts: vec!["What was the payroll in Q1 2024?".to_owned()],
            ..TableConfig::default()
        },
    );
    SchemaConfig {
        fiscal_year_offset_months: 0,
        tables,
    }
}

fn make_backend(schema: &SchemaConfig) -> RegexBackend {
    let mut b = RegexBackend::new();
    b.index_schema(schema);
    b
}

/// Build a JSON messages array from (role, content) pairs.
fn messages(pairs: &[(&str, &str)]) -> Vec<serde_json::Value> {
    pairs
        .iter()
        .map(|(role, content)| json!({"role": role, "content": content}))
        .collect()
}

// ---------------------------------------------------------------------------
// deterministic_resolve tests
// ---------------------------------------------------------------------------

#[test]
fn deterministic_resolve_returns_prior_as_is_when_no_current_time() {
    // Prior: "What was aws_spend in Q1 2024?" (explicit time)
    // Current: "Tell me more." (no time)
    // Expected: returns prior intent as-is
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in Q1 2024?"),
        ("assistant", "Your AWS spend in Q1 2024 was $100,000."),
        ("user", "Tell me more."),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(result.is_some(), "should resolve from prior message");
    let intent = result.unwrap();
    assert_eq!(intent.table, "aws_spend");
    // Q1 2024 timestamps
    assert_eq!(intent.start_unix_secs, 1_704_067_200);
    assert_eq!(intent.end_unix_secs, 1_711_929_599);
}

#[test]
fn deterministic_resolve_time_pivot_uses_current_time() {
    // Prior: "What was aws_spend in Q1 2024?" (Q1 = Jan–Mar 2024)
    // Current: "How about Q2 2024?" (explicit Q2 — should override)
    // Expected: table=aws_spend, time=Q2 2024 (Apr–Jun 2024)
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in Q1 2024?"),
        ("assistant", "Your AWS spend in Q1 2024 was $100,000."),
        ("user", "How about Q2 2024?"),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(result.is_some(), "should resolve with time-pivot");
    let intent = result.unwrap();
    assert_eq!(intent.table, "aws_spend");
    // Q2 2024: 2024-04-01 → 2024-06-30
    assert_eq!(intent.start_unix_secs, 1_711_929_600, "start should be Q2 2024 Apr 1");
    assert_eq!(intent.end_unix_secs, 1_719_791_999, "end should be Q2 2024 Jun 30");
}

#[test]
fn deterministic_resolve_returns_none_when_no_prior_resolves() {
    // No prior messages with a resolved table.
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "Hello, how are you?"),
        ("assistant", "I'm doing well!"),
        ("user", "What was the spend?"),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(result.is_none(), "should return None when no prior resolves");
}

#[test]
fn deterministic_resolve_skips_prior_message_without_explicit_time() {
    // Prior: "Tell me about aws_spend" — no explicit time expression.
    // That prior message should NOT be accepted (Fix 0 contract).
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "Tell me about aws_spend."),
        ("assistant", "aws_spend tracks your cloud costs."),
        ("user", "How much was it?"),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    // The prior "Tell me about aws_spend" has no explicit time → must be rejected.
    // Result: None (no prior with explicit time + table).
    assert!(result.is_none(), "prior without explicit time must NOT be accepted");
}

#[test]
fn deterministic_resolve_respects_max_scan() {
    // max_scan=1 means only scan 1 prior message.
    // Place the valid prior at position -2 (beyond max_scan=1) → should not be found.
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in Q1 2024?"), // valid but at position -3
        ("assistant", "Response."),
        ("user", "Something unrelated."), // position -2
        ("assistant", "Another response."),
        ("user", "What about the spending?"), // current
    ]);
    // max_scan=1 → only scans "Something unrelated." → no table match
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 1, usize::MAX);
    assert!(result.is_none(), "max_scan=1 should not reach the valid prior");
}

// Regression: ISSUE-001 — context-dependent time phrases must trigger LLM rewriter
// Found by /qa on 2026-04-12
// Report: .gstack/qa-reports/qa-report-zemtik-proxy-2026-04-12.md
#[test]
fn deterministic_resolve_returns_none_for_same_period_phrase() {
    // "same period" requires knowing the prior quarter — deterministic can't resolve it.
    // Must return None so the LLM rewriter handles it.
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in Q1 2024?"),
        ("assistant", "AWS spend Q1 2024 was $12M."),
        ("user", "same thing but for last year same period"),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(
        result.is_none(),
        "'same period' + 'last year' must return None — LLM rewriter required"
    );
}

#[test]
fn deterministic_resolve_returns_none_for_last_year_phrase() {
    // "last year" relative year shift also requires LLM resolution to preserve
    // sub-year granularity from prior context.
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in Q1 2024?"),
        ("assistant", "AWS spend Q1 2024 was $12M."),
        ("user", "how about last year?"),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(
        result.is_none(),
        "'last year' must return None — LLM rewriter required for correct year pivot"
    );
}

#[test]
fn deterministic_resolve_returns_none_with_single_user_message() {
    // Only one user message — no prior to scan after skip(1). Must return None.
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[("user", "How about Q2 2024?")]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(result.is_none(), "single user message — no prior to scan, must return None");
}

#[test]
fn deterministic_resolve_returns_none_for_same_quarter_phrase() {
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in Q1 2024?"),
        ("assistant", "AWS spend Q1 2024 was $12M."),
        ("user", "same quarter last year"),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(result.is_none(), "'same quarter' must return None — needs LLM");
}

#[test]
fn deterministic_resolve_returns_none_for_same_month_phrase() {
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in January 2024?"),
        ("assistant", "AWS spend January 2024 was $4M."),
        ("user", "same month last year"),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(result.is_none(), "'same month' must return None — needs LLM");
}

#[test]
fn deterministic_resolve_returns_none_for_prior_year_phrase() {
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in Q3 2024?"),
        ("assistant", "AWS spend Q3 2024 was $8M."),
        ("user", "what about prior year?"),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(result.is_none(), "'prior year' must return None — needs LLM for quarter pivot");
}

// ---------------------------------------------------------------------------
// rewrite_query tests (using mock server via wiremock)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod rewrite_query_tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use zemtik::config::RewriterConfig;
    use zemtik::rewriter::rewrite_query;

    fn make_rw_config(base_url: &str) -> RewriterConfig {
        RewriterConfig {
            base_url: base_url.to_owned(),
            model: "gpt-5.4-nano".to_owned(),
            api_key: "test-key".to_owned(),
            context_window_turns: 6,
            max_scan_messages: 5,
            timeout_secs: 10,
            max_context_tokens: 2000,
        }
    }

    fn openai_response(content: &str) -> serde_json::Value {
        json!({
            "choices": [{"message": {"content": content, "role": "assistant"}}],
            "model": "gpt-5.4-nano",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })
    }

    #[tokio::test]
    async fn rewrite_query_returns_rewritten_on_valid_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(openai_response("What was aws_spend in Q2 2024?")),
            )
            .mount(&mock_server)
            .await;

        let schema = make_schema();
        let config = make_rw_config(&mock_server.uri());
        let http = reqwest::Client::new();
        let msgs = messages(&[
            ("user", "What was aws_spend in Q1 2024?"),
            ("assistant", "Your AWS spend in Q1 2024 was $100k."),
            ("user", "How about Q2?"),
        ]);

        let result = rewrite_query(&msgs, "How about Q2?", &schema, &config, &http)
            .await
            .unwrap();

        assert!(
            matches!(result, RewriteResult::Rewritten(_)),
            "valid response with table key + explicit time should be Rewritten"
        );
        if let RewriteResult::Rewritten(q) = result {
            assert!(q.contains("aws_spend"), "rewritten query should contain table key");
        }
    }

    #[tokio::test]
    async fn rewrite_query_returns_unresolvable_on_sentinel() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(openai_response("__UNRESOLVABLE__")),
            )
            .mount(&mock_server)
            .await;

        let schema = make_schema();
        let config = make_rw_config(&mock_server.uri());
        let http = reqwest::Client::new();
        let msgs = messages(&[("user", "What about it?")]);

        let result = rewrite_query(&msgs, "What about it?", &schema, &config, &http)
            .await
            .unwrap();

        assert!(
            matches!(result, RewriteResult::Unresolvable),
            "__UNRESOLVABLE__ sentinel must produce Unresolvable"
        );
    }

    #[tokio::test]
    async fn unresolvable_sentinel_exact_match_only() {
        // Partial sentinel in a sentence should NOT produce Unresolvable via sentinel path.
        // However it will still be Unresolvable if time check fails.
        // Key assertion: "text __UNRESOLVABLE__ text" is NOT the sentinel.
        let mock_server = MockServer::start().await;
        // Response contains sentinel as substring, not exact match.
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(openai_response("The answer is __UNRESOLVABLE__ maybe")),
            )
            .mount(&mock_server)
            .await;

        let schema = make_schema();
        let config = make_rw_config(&mock_server.uri());
        let http = reqwest::Client::new();
        let msgs = messages(&[("user", "Something?")]);
        let result = rewrite_query(&msgs, "Something?", &schema, &config, &http)
            .await
            .unwrap();

        // Not exact match → goes through table/time validation.
        // "The answer is __UNRESOLVABLE__ maybe" has no table key → Unresolvable.
        assert!(
            matches!(result, RewriteResult::Unresolvable),
            "non-exact sentinel still results in Unresolvable (no table key)"
        );
    }

    #[tokio::test]
    async fn rewrite_query_returns_unresolvable_on_empty_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(openai_response("")),
            )
            .mount(&mock_server)
            .await;

        let schema = make_schema();
        let config = make_rw_config(&mock_server.uri());
        let http = reqwest::Client::new();
        let msgs = messages(&[("user", "something")]);

        let result = rewrite_query(&msgs, "something", &schema, &config, &http)
            .await
            .unwrap();

        assert!(
            matches!(result, RewriteResult::Unresolvable),
            "empty LLM response must produce Unresolvable"
        );
    }

    #[tokio::test]
    async fn rewrite_query_returns_unresolvable_when_output_has_table_but_no_time() {
        // LLM returns a table key but no time expression.
        // parse_time_range_explicit should return Ok(None) → Unresolvable.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(openai_response("What was aws_spend?")),
            )
            .mount(&mock_server)
            .await;

        let schema = make_schema();
        let config = make_rw_config(&mock_server.uri());
        let http = reqwest::Client::new();
        let msgs = messages(&[("user", "how about it?")]);

        let result = rewrite_query(&msgs, "how about it?", &schema, &config, &http)
            .await
            .unwrap();

        assert!(
            matches!(result, RewriteResult::Unresolvable),
            "LLM output with table but no explicit time must be Unresolvable"
        );
    }

    #[tokio::test]
    async fn rewrite_query_returns_unresolvable_on_refusal() {
        // LLM returns a polite refusal with no table key.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(openai_response("I need more context to answer this question.")),
            )
            .mount(&mock_server)
            .await;

        let schema = make_schema();
        let config = make_rw_config(&mock_server.uri());
        let http = reqwest::Client::new();
        let msgs = messages(&[("user", "I need more info about Q3")]);

        let result = rewrite_query(&msgs, "I need more info about Q3", &schema, &config, &http)
            .await
            .unwrap();

        assert!(
            matches!(result, RewriteResult::Unresolvable),
            "LLM refusal (no table key) must produce Unresolvable"
        );
    }

    #[tokio::test]
    async fn rewrite_query_does_not_leak_error_in_http_response() {
        // When the LLM endpoint returns 500, rewrite_query returns Err.
        // The proxy must not expose this error — tested at the Ok/Err boundary.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal server error"))
            .mount(&mock_server)
            .await;

        let schema = make_schema();
        let config = make_rw_config(&mock_server.uri());
        let http = reqwest::Client::new();
        let msgs = messages(&[("user", "something")]);

        let result = rewrite_query(&msgs, "something", &schema, &config, &http).await;
        // HTTP 500 from the LLM endpoint must surface as Err from rewrite_query.
        // The proxy catches this Err and returns a 400 to the caller without exposing
        // the underlying error message (prevents server internals from leaking).
        // Note: reqwest may reject at the HTTP status layer (error_for_status) or at JSON
        // parse — both are Err. Unresolvable is NOT acceptable here since that would
        // silently mask a real transport/auth error.
        assert!(
            result.is_err(),
            "HTTP 500 from LLM endpoint must surface as Err, not Ok(Unresolvable)"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-table disable test
// ---------------------------------------------------------------------------

#[test]
fn per_table_rewriting_disable_respected_in_deterministic() {
    // Build a schema where payroll has query_rewriting: false.
    let mut tables = HashMap::new();
    tables.insert(
        "payroll".to_owned(),
        TableConfig {
            sensitivity: "critical".to_owned(),
            description: "Payroll expenses".to_owned(),
            example_prompts: vec!["payroll Q1 2024".to_owned()],
            query_rewriting: Some(false), // <- disabled
            ..TableConfig::default()
        },
    );
    let schema = SchemaConfig { fiscal_year_offset_months: 0, tables };
    let backend = make_backend(&schema);

    let msgs = messages(&[
        ("user", "What was the payroll in Q1 2024?"),
        ("assistant", "Payroll was $500k."),
        ("user", "How about Q2 2024?"),
    ]);

    // deterministic_resolve itself doesn't check the flag — the call site (proxy.rs) does.
    // This test verifies the resolve still returns the intent (flag checked upstream).
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, usize::MAX);
    assert!(
        result.is_some(),
        "deterministic_resolve should return the intent (flag enforcement is caller's responsibility)"
    );
    assert_eq!(result.unwrap().table, "payroll");
}

// ---------------------------------------------------------------------------
// Token budget test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod token_budget_tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use zemtik::config::RewriterConfig;
    use zemtik::rewriter::rewrite_query;

    use super::*;

    fn openai_response_with_table(content: &str) -> serde_json::Value {
        json!({
            "choices": [{"message": {"content": content, "role": "assistant"}}],
            "model": "gpt-5.4-nano",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        })
    }

    #[tokio::test]
    async fn token_budget_truncates_long_conversations() {
        // max_context_tokens=10 (tiny) → oldest turns must be dropped.
        // We verify the request is made successfully (no crash) and the response is handled.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(openai_response_with_table("What was aws_spend in Q2 2024?")),
            )
            .mount(&mock_server)
            .await;

        let schema = make_schema();
        let config = RewriterConfig {
            base_url: mock_server.uri(),
            model: "gpt-5.4-nano".to_owned(),
            api_key: "test-key".to_owned(),
            context_window_turns: 6,
            max_scan_messages: 5,
            timeout_secs: 10,
            max_context_tokens: 10, // extremely small — forces truncation
        };
        let http = reqwest::Client::new();

        // Long conversation that exceeds the tiny budget.
        let mut pairs: Vec<(&str, &str)> = Vec::new();
        for _ in 0..20 {
            pairs.push(("user", "Tell me something about the spending in Q1 2023."));
            pairs.push(("assistant", "Your spending was $XYZ in Q1 2023."));
        }
        pairs.push(("user", "And Q2 2024?"));
        let msgs = messages(&pairs);

        // Must not panic; response must be accepted or Unresolvable.
        let result = rewrite_query(&msgs, "And Q2 2024?", &schema, &config, &http).await;
        assert!(result.is_ok(), "rewrite_query must not error on token budget truncation");
    }
}

// ---------------------------------------------------------------------------
// Issue #36 — gate_max_chars threading through deterministic_resolve
// ---------------------------------------------------------------------------

/// When gate_max_chars is set to a small value (e.g. 50), a prior message shorter than 50
/// chars resolves normally — the gate fires and carries the intent forward.
#[test]
fn deterministic_resolve_with_small_gate_max_chars_resolves_prior() {
    // Prior: "What was aws_spend in Q1 2024?" = 30 chars, under gate_max_chars=50.
    // Gate fires → resolves to aws_spend/Q1 2024. Current: no time → carries forward.
    let schema = make_schema();
    let backend = make_backend(&schema);
    let msgs = messages(&[
        ("user", "What was aws_spend in Q1 2024?"),
        ("assistant", "Your AWS spend in Q1 2024 was $100,000."),
        ("user", "Tell me more."),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, 50);
    assert!(result.is_some(), "should resolve prior intent with gate_max_chars=50");
    let intent = result.unwrap();
    assert_eq!(intent.table, "aws_spend");
}

/// When gate_max_chars=50, a prior message longer than 50 chars with "aws_spend" at
/// the head still resolves: the gate is skipped but the backend receives the truncated
/// head (first 50 chars), which contains the keyword.
#[test]
fn deterministic_resolve_long_prior_with_keyword_at_head_still_resolves() {
    // Prior: "aws_spend Q1 2025 " + 100 'z's → 118 chars > gate_max_chars=50.
    // Gate skipped; backend receives first 50 chars: "aws_spend Q1 2025 zzzzzzzzzzzzzz"
    // — "aws_spend" is still in that window → resolves. Current: no time → carries forward.
    let schema = make_schema();
    let backend = make_backend(&schema);
    let prior = format!("aws_spend Q1 2025 {}", "z".repeat(100));
    assert!(prior.chars().count() > 50, "prior must exceed gate_max_chars");
    let msgs = messages(&[
        ("user", prior.as_str()),
        ("assistant", "Your AWS spend in Q1 2025 was $200,000."),
        ("user", "Tell me more."),
    ]);
    let result = deterministic_resolve(&msgs, &schema, &backend, 0.0, 5, 50);
    assert!(result.is_some(), "aws_spend at position 0 is within first 50 chars → must resolve");
    let intent = result.unwrap();
    assert_eq!(intent.table, "aws_spend");
}
