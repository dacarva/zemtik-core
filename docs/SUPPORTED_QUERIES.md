# Supported Queries — v1 Contract

## Supported patterns

| Pattern | Example | Notes |
|---------|---------|-------|
| `Q[1-4] YYYY [table]` | "Q1 2026 AWS spend" | Quarter + year + table name or alias |
| `[table] spend YYYY` | "payroll expenses Q2 2025" | Table name first, then quarter/year |
| Table alias | "cloud spend Q3 2024" | Aliases configured in schema_config.json |

## Unsupported in v1

- **Multi-table queries**: "What was payroll vs AWS spend?" — only the first table found is processed. Response includes a note: "Note: only processed [table] — multi-table queries not yet supported."
- **Relative dates**: "last quarter", "this year", "last month" — use explicit `Q[1-4] YYYY` or `YYYY` instead.
- **Aggregations other than SUM**: averages, min/max, percentiles.
- **Client filtering**: all queries run against client 123 in the demo dataset.

## Fiscal year offset

Set `fiscal_year_offset_months` in `schema_config.json` to shift calendar quarter boundaries.

Example: `fiscal_year_offset_months: 9` with Q1 2026 → processes Oct 2025 – Dec 2025.

Formula: `fiscal_start = calendar_start - offset_months` (year-wrap handled automatically).

## Table sensitivity routing

| Sensitivity | Engine | Latency |
|-------------|--------|---------|
| `low` | FastLane (BabyJubJub attestation) | < 50ms |
| `critical` | ZK SlowLane (UltraHonk proof) | ~17-20s |

Unknown tables default to ZK SlowLane (fail-secure).

## FAQ

**What happens if my table isn't listed in schema_config.json?**
The query is routed to ZK SlowLane as a fail-secure fallback. Add the table to schema_config.json to enable FastLane routing.

**What if no table is identified in my prompt?**
The request is rejected with HTTP 400. Check that your prompt references a table name or alias from schema_config.json.

**How do I configure table aliases?**
Edit `~/.zemtik/schema_config.json`. Add an `aliases` array to any table entry:
```json
"aws_spend": { "sensitivity": "low", "aliases": ["AWS", "amazon", "cloud spend"] }
```
