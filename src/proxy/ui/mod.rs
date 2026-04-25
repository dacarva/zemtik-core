use crate::receipts;

/// Format a signed integer as a dollar amount with thousands separators.
///
/// Examples: `1234567` → `"$1,234,567"`, `-500` → `"-$500"`.
fn format_currency(n: i64) -> String {
    let s = n.unsigned_abs().to_string();
    let formatted: String = s.chars().rev().enumerate()
        .flat_map(|(i, c)| if i > 0 && i % 3 == 0 { vec![',', c] } else { vec![c] })
        .collect::<String>().chars().rev().collect();
    if n < 0 { format!("-${}", formatted) } else { format!("${}", formatted) }
}

/// Extract the table key from a human_summary string like `"Aggregated N rows from 'table_key' into..."`.
fn extract_table_from_summary(s: &str) -> Option<String> {
    let start = s.find("from '")?;
    let rest = &s[start + 6..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_owned())
}

/// Render the receipt detail page for a single audit record.
pub(in crate::proxy) fn render_verify_page(r: &receipts::Receipt, readable: Option<&serde_json::Value>) -> String {
    let (badge_color, status_label) = match r.proof_status.as_str() {
        s if s.starts_with("VALID") => ("#22c55e", "VALID"),
        "FAST_LANE_ATTESTED" => ("#3b82f6", "FAST LANE ATTESTED"),
        "general_lane" => ("#8b5cf6", "GENERAL LANE"),
        "general_lane_rate_limited" => ("#f59e0b", "RATE LIMITED"),
        _ => ("#ef4444", "INVALID"),
    };

    let subtitle = match r.proof_status.as_str() {
        "general_lane" | "general_lane_rate_limited" =>
            "Audit evidence — non-data query forwarded directly to LLM; no database records accessed",
        _ => "Audit evidence — no raw records were transmitted to the LLM",
    };

    // Parse evidence_json for richer data (v9+). Fall back to ZK bundle readable inputs.
    let ev: Option<serde_json::Value> = r.evidence_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    let aggregate_display = ev
        .as_ref()
        .and_then(|v| v.get("aggregate"))
        .and_then(|v| v.as_i64())
        .map(format_currency)
        .or_else(|| readable
            .and_then(|v| v.get("verified_aggregate"))
            .and_then(|v| v.as_u64())
            .map(|n| format_currency(n as i64)))
        .unwrap_or_else(|| "—".to_owned());

    let table_display = ev
        .as_ref()
        .and_then(|v| v.get("engine_used"))
        .and_then(|_| {
            ev.as_ref()
                .and_then(|v| v.get("human_summary"))
                .and_then(|v| v.as_str())
                .and_then(extract_table_from_summary)
        })
        .or_else(|| readable
            .and_then(|v| v.get("category_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned()))
        .unwrap_or_else(|| "—".to_owned());

    let engine_label = ev
        .as_ref()
        .and_then(|v| v.get("engine_used"))
        .and_then(|v| v.as_str())
        .unwrap_or(&r.engine_used);

    let human_summary_html = ev
        .as_ref()
        .and_then(|v| v.get("human_summary"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| format!(
            r#"<div class="summary-box"><strong>Summary</strong><p>{}</p></div>"#,
            html_escape(s)
        ))
        .unwrap_or_default();

    let checks_html = ev
        .as_ref()
        .and_then(|v| v.get("checks_performed"))
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .map(|checks| {
            let items: String = checks.iter()
                .filter_map(|c| c.as_str())
                .map(|c| format!("<li><code>{}</code></li>", html_escape(c)))
                .collect();
            format!(r#"<div class="checks"><strong>Checks Performed</strong><ol>{}</ol></div>"#, items)
        })
        .unwrap_or_default();

    let reason_row = ev
        .as_ref()
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| format!(r#"<tr><td>Routing Reason</td><td>{}</td></tr>"#, html_escape(s)))
        .unwrap_or_default();

    let zk_coverage_row = ev
        .as_ref()
        .and_then(|v| v.get("zk_coverage"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| format!(r#"<tr><td>ZK Coverage</td><td>{}</td></tr>"#, html_escape(s)))
        .unwrap_or_default();

    let attestation_row = ev
        .as_ref()
        .and_then(|v| v.get("attestation_hash"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|h| format!(
            r#"<tr><td>Attestation Hash</td><td class="mono">{}</td></tr>"#,
            html_escape(h)
        ))
        .unwrap_or_default();

    let proof_row = if !r.circuit_hash.is_empty() || r.proof_hash.is_some() {
        format!(
            r#"<tr><td>Circuit Hash</td><td class="mono">{}</td></tr>
  <tr><td>bb Version</td><td class="mono">{}</td></tr>"#,
            html_escape(&r.circuit_hash),
            html_escape(&r.bb_version),
        )
    } else {
        String::new()
    };

    let anonymizer_html = ev
        .as_ref()
        .and_then(|v| v.get("anonymizer"))
        .filter(|a| !a.is_null())
        .map(|a| {
            let entities_found = a.get("entities_found").and_then(|v| v.as_u64()).unwrap_or(0);
            let dropped = a.get("dropped_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
            let injected = a.get("tokens_injected").and_then(|v| v.as_u64()).unwrap_or(0);
            let types = a.get("entity_types")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|t| t.as_str())
                    .map(|t| format!("<code>{}</code>", html_escape(t)))
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_else(|| "—".to_owned());
            format!(
                r#"<div class="anon-box">
  <strong>PII Anonymized</strong>
  <p>{injected} token{ip} injected from input; {dropped} token{dp} not echoed by LLM.</p>
  <p>{entities_found} entit{plural} detected and stripped before forwarding to LLM.</p>
  <p>Types: {types}</p>
</div>"#,
                injected = injected,
                ip = if injected == 1 { "" } else { "s" },
                dropped = dropped,
                dp = if dropped == 1 { "" } else { "s" },
                entities_found = entities_found,
                plural = if entities_found == 1 { "y" } else { "ies" },
                types = types,
            )
        })
        .unwrap_or_default();

    // Pretty-print evidence JSON for the raw block
    let evidence_json_pretty = ev
        .as_ref()
        .and_then(|v| serde_json::to_string_pretty(v).ok())
        .map(|s| format!(
            r#"<details class="json-block">
  <summary>Evidence Pack JSON</summary>
  <pre><code>{}</code></pre>
</details>"#,
            html_escape(&s)
        ))
        .unwrap_or_default();

    let back_link = r#"<p class="back-link"><a href="/receipts">← All receipts</a></p>"#;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zemtik Receipt — {id}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 760px; margin: 48px auto; padding: 0 24px; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 4px; }}
  .subtitle {{ color: #666; font-size: 0.9rem; margin-bottom: 32px; }}
  .badge {{ display: inline-block; padding: 6px 18px; border-radius: 6px; font-weight: 700;
            font-size: 1.1rem; color: white; background: {badge_color}; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.95rem; margin-bottom: 24px; }}
  td {{ padding: 10px 0; border-bottom: 1px solid #e5e5e5; vertical-align: top; }}
  td:first-child {{ font-weight: 600; width: 200px; color: #444; }}
  .mono {{ font-family: monospace; font-size: 0.85rem; word-break: break-all; }}
  .summary-box {{ background: #f0f9ff; border-left: 3px solid #3b82f6; padding: 12px 16px; margin-bottom: 20px; border-radius: 0 6px 6px 0; font-size: 0.95rem; }}
  .summary-box p {{ margin: 6px 0 0; color: #444; }}
  .checks {{ margin-bottom: 20px; font-size: 0.95rem; }}
  .checks ol {{ margin: 8px 0 0 0; padding-left: 20px; color: #444; }}
  .checks li {{ padding: 2px 0; }}
  .json-block {{ margin-top: 24px; border: 1px solid #e5e5e5; border-radius: 6px; overflow: hidden; }}
  .json-block summary {{ padding: 10px 16px; background: #f8f8f8; cursor: pointer; font-weight: 600; font-size: 0.9rem; }}
  .json-block pre {{ margin: 0; padding: 16px; background: #1a1a1a; color: #e8e8e8; font-size: 0.82rem; overflow-x: auto; }}
  .footer {{ margin-top: 32px; font-size: 0.8rem; color: #999; }}
  .back-link {{ margin-bottom: 24px; font-size: 0.9rem; }}
  .back-link a {{ color: #3b82f6; text-decoration: none; }}
  .anon-box {{ background: #fdf4ff; border-left: 3px solid #8b5cf6; padding: 12px 16px; margin-bottom: 20px; border-radius: 0 6px 6px 0; font-size: 0.95rem; }}
  .anon-box p {{ margin: 6px 0 0; color: #444; }}
  .anon-box code {{ background: #ede9fe; padding: 1px 4px; border-radius: 3px; font-size: 0.82rem; }}
  @media print {{ .footer, .back-link, .json-block {{ display: none; }} }}
</style>
</head>
<body>
{back_link}
<h1>Zemtik Cryptographic Receipt</h1>
<p class="subtitle">{subtitle}</p>

<div class="badge">{status_label}</div>

{human_summary_html}
{anonymizer_html}

<table>
  <tr><td>Receipt ID</td><td class="mono">{id}</td></tr>
  <tr><td>Verified Aggregate</td><td><strong>{aggregate_display}</strong></td></tr>
  <tr><td>Table</td><td>{table_display}</td></tr>
  <tr><td>Engine</td><td>{engine_label}</td></tr>
  <tr><td>Proof Status</td><td>{proof_status}</td></tr>
  {reason_row}
  {zk_coverage_row}
  {attestation_row}
  {proof_row}
  <tr><td>Generated At</td><td>{created_at}</td></tr>
  <tr><td>Raw Rows to LLM</td><td><strong>0</strong></td></tr>
  <tr><td>Query Hash</td><td class="mono">{prompt_hash}</td></tr>
</table>

{checks_html}

{evidence_json_pretty}

<p class="footer">
  Verify this receipt independently: <code>zemtik verify &lt;bundle.zip&gt;</code> (ZK SlowLane only)<br>
  Requires only the <code>bb</code> binary (Barretenberg ≥ v4).
</p>
</body>
</html>"#,
        back_link = back_link,
        id = html_escape(&r.id),
        badge_color = badge_color,
        status_label = status_label,
        human_summary_html = human_summary_html,
        subtitle = subtitle,
        aggregate_display = html_escape(&aggregate_display),
        table_display = html_escape(&table_display),
        engine_label = html_escape(engine_label),
        proof_status = html_escape(&r.proof_status),
        reason_row = reason_row,
        zk_coverage_row = zk_coverage_row,
        attestation_row = attestation_row,
        proof_row = proof_row,
        created_at = html_escape(&r.created_at),
        prompt_hash = html_escape(&r.prompt_hash),
        checks_html = checks_html,
        anonymizer_html = anonymizer_html,
        evidence_json_pretty = evidence_json_pretty,
    )
}

/// Render the paginated receipts list page.
pub(in crate::proxy) fn render_receipts_list(list: &[receipts::Receipt], total: usize, page_size: usize) -> String {
    let rows: String = if list.is_empty() {
        r#"<tr><td colspan="5" style="text-align:center;color:#999;padding:32px 0">No receipts yet. Send a query through the proxy to generate one.</td></tr>"#.to_owned()
    } else {
        list.iter().map(|r| {
            let ev: Option<serde_json::Value> = r.evidence_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());

            let aggregate_cell = ev
                .as_ref()
                .and_then(|v| v.get("aggregate"))
                .and_then(|v| v.as_i64())
                .map(format_currency)
                .unwrap_or_else(|| "—".to_owned());

            let table_cell = ev
                .as_ref()
                .and_then(|v| v.get("human_summary"))
                .and_then(|v| v.as_str())
                .and_then(extract_table_from_summary)
                .unwrap_or_else(|| "—".to_owned());

            let (badge_color, badge_label) = match r.proof_status.as_str() {
                s if s.starts_with("VALID") => ("#22c55e", "ZK VALID"),
                "FAST_LANE_ATTESTED" => ("#3b82f6", "FastLane"),
                s if s.contains("general") => ("#6b7280", "General"),
                _ => ("#ef4444", "—"),
            };

            // Truncate timestamp to date + time without nanoseconds
            let ts_short = r.created_at.get(..19).unwrap_or(&r.created_at);

            format!(
                r#"<tr>
  <td class="mono small"><a href="/verify/{id}">{id_short}…</a></td>
  <td><span class="badge" style="background:{badge_color}">{badge_label}</span></td>
  <td>{table_cell}</td>
  <td><strong>{aggregate_cell}</strong></td>
  <td class="small">{ts_short}</td>
</tr>"#,
                id = html_escape(&r.id),
                id_short = html_escape(r.id.get(..8).unwrap_or(&r.id)),
                badge_color = html_escape(badge_color),
                badge_label = html_escape(badge_label),
                table_cell = html_escape(&table_cell),
                aggregate_cell = html_escape(&aggregate_cell),
                ts_short = html_escape(ts_short),
            )
        }).collect()
    };

    let showing = list.len();
    let truncated = total > page_size;
    let count_line = if truncated {
        format!(
            r#"Showing {showing} most recent of {total} receipt(s) total <a class="refresh" href="/receipts">↻ Refresh</a>"#,
            showing = showing,
            total = total,
        )
    } else {
        format!(
            r#"{total} receipt(s) total <a class="refresh" href="/receipts">↻ Refresh</a>"#,
            total = total,
        )
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zemtik — Receipts</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 48px auto; padding: 0 24px; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 4px; }}
  .subtitle {{ color: #666; font-size: 0.9rem; margin-bottom: 28px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
  th {{ text-align: left; padding: 8px 0; border-bottom: 2px solid #e5e5e5; color: #444; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; }}
  td {{ padding: 10px 8px 10px 0; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }}
  tr:hover td {{ background: #fafafa; }}
  a {{ color: #3b82f6; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.78rem; font-weight: 700; color: white; }}
  .mono {{ font-family: monospace; }}
  .small {{ font-size: 0.85rem; color: #666; }}
  .count {{ color: #666; font-size: 0.85rem; margin-bottom: 16px; }}
  .refresh {{ float: right; font-size: 0.85rem; color: #3b82f6; }}
</style>
</head>
<body>
<h1>Zemtik — Audit Trail</h1>
<p class="subtitle">Every query intercepted by this proxy. Click a receipt to see the full evidence pack.</p>
<p class="count">{count_line}</p>
<table>
<thead>
  <tr>
    <th>Receipt ID</th>
    <th>Engine</th>
    <th>Table</th>
    <th>Aggregate</th>
    <th>Timestamp</th>
  </tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"#,
        count_line = count_line,
        rows = rows,
    )
}

/// Render a 404-style HTML page when a receipt ID is not found in the local DB.
pub(in crate::proxy) fn render_not_found(id: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Receipt not found</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:80px auto;padding:0 24px;color:#1a1a1a;}}</style>
</head>
<body>
<h1>Receipt not found</h1>
<p>No receipt with ID <code>{}</code> exists in this Zemtik instance.</p>
<p style="color:#999;font-size:0.9rem">The bundle may have been generated on a different machine or the receipts database may have been reset.</p>
</body>
</html>"#,
        html_escape(id)
    )
}

/// Escape HTML special characters to prevent XSS in rendered pages.
pub(in crate::proxy) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
