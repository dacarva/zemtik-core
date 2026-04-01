# Supported Queries — v1 Contract

**Document type:** Reference
**Audience:** Developers and product teams building on top of the Zemtik proxy
**Goal:** Know exactly what query shapes work, what doesn't, and what happens at the boundary

---

## Supported time expressions

The `DeterministicTimeParser` recognizes the following patterns anywhere in the prompt. Matching is case-insensitive.

| Pattern | Example prompt | Resolves to |
|---------|---------------|-------------|
| `Q[1-4] YYYY` | "Q1 2024 AWS spend" | Jan 1–Mar 31 2024 |
| `H[1-2] YYYY` | "H1 2025 payroll" | Jan 1–Jun 30 2025 |
| `FY YYYY` | "FY 2024 cloud costs" | Full fiscal year (with offset applied) |
| `MMM YYYY` | "March 2024 expenses" | Mar 1–31 2024 |
| `YYYY` | "payroll 2023" | Jan 1–Dec 31 2023 |
| `YTD` / `year to date` | "YTD vendor invoices" | Jan 1 current year → today |
| `this quarter` | "this quarter AWS" | Current quarter start → today |
| `last quarter` | "last quarter spend" | Previous full quarter |
| `this month` | "this month payroll" | Current calendar month start → today |
| `last month` | "last month payroll" | Previous full calendar month |
| `past N days` | "past 90 days travel" | Rolling N-day window ending now |

### Fiscal year offset

When `fiscal_year_offset_months` is set in `schema_config.json`, quarter boundaries shift accordingly.

Example with `fiscal_year_offset_months: 9` (fiscal year starts October):

| Quarter in prompt | Date range resolved |
|------------------|-------------------|
| Q1 FY2025 | Oct 1 2024 – Dec 31 2024 |
| Q2 FY2025 | Jan 1 2025 – Mar 31 2025 |
| Q3 FY2025 | Apr 1 2025 – Jun 30 2025 |
| Q4 FY2025 | Jul 1 2025 – Sep 30 2025 |

---

## Supported table references

Tables are matched by:

1. The table key exactly (e.g., `aws_spend`)
2. Any string in the `aliases` array (case-insensitive substring match)
3. Semantic similarity to `description` and `example_prompts` (embedding backend only)

Examples for the default `schema_config.example.json`:

| Prompt fragment | Matched table |
|----------------|--------------|
| "AWS spend" | `aws_spend` |
| "amazon costs" | `aws_spend` |
| "cloud spend" | `aws_spend` |
| "payroll" | `payroll` |
| "salary expenses" | `payroll` (via embedding) |
| "employee compensation" | `payroll` (via embedding) |
| "travel" | `travel` |
| "T&E" | `travel` (via alias) |

---

## Unsupported in v1

### Multi-table queries

Queries that reference more than one table are not supported. Only the highest-confidence table match is processed.

| Prompt | Behavior |
|--------|---------|
| "Compare payroll vs AWS spend Q1 2024" | Processes only the first matched table |
| "Total payroll and travel for 2024" | Processes only one table |

The proxy silently processes only the highest-confidence match. No note is added to the response.

### Aggregation types

Only `SUM(amount)` is supported. The circuit and engine both implement exactly one aggregation.

| Aggregation | Supported |
|-------------|---------|
| SUM | Yes |
| COUNT | No |
| AVG / MEAN | No |
| MIN / MAX | No |
| Percentiles | No |

### Client filtering

All queries run against `client_id = 123` in the demo dataset. Per-client filtering is not available in v1.

### Ambiguous time expressions

Time expressions that do not match any recognized pattern cause `TimeRangeAmbiguous`, which routes conservatively to ZK SlowLane.

| Expression | Recognized? |
|------------|------------|
| "Q1 2024" | Yes |
| "last quarter" | Yes |
| "before the acquisition" | No — `TimeRangeAmbiguous` → ZK SlowLane |
| "previously" | No — `TimeRangeAmbiguous` → ZK SlowLane |
| "last year" | No — `TimeRangeAmbiguous` → ZK SlowLane (use `2024` instead) |
| "current year" | No — `TimeRangeAmbiguous` → ZK SlowLane (use `YTD` instead) |
| "in the old fiscal year" | No — `TimeRangeAmbiguous` → ZK SlowLane |

---

## Routing by table sensitivity

| Sensitivity | Engine | Proof type | Typical latency |
|-------------|--------|-----------|-----------------|
| `low` | FastLane | BabyJubJub attestation | < 50ms |
| `critical` | ZK SlowLane | UltraHonk proof | ~17–20s |
| Unknown table | ZK SlowLane | UltraHonk proof | ~17–20s |

The routing decision and confidence score are included in every response's `evidence` object and stored in `receipts.db`.

---

## Error reference

| Condition | HTTP status | Error message |
|-----------|------------|--------------|
| No table identified in prompt | 400 | `"no table identified in prompt"` |
| No messages in request body | 400 | `"no messages in request body"` |
| Empty prompt | 400 | `"empty prompt"` |
| Table matched but not in circuit map | 500 | `"table not mapped to circuit category"` |
| `bb verify` fails | 500 | `"proof verification failed"` |

---

## FAQ

**What happens if my table isn't listed in `schema_config.json`?**

The query is routed to ZK SlowLane as a fail-secure fallback. The ZK slow lane will fail if the table key also has no entry in the circuit category map. Add the table to `schema_config.json` to ensure correct routing.

**What if no table is identified?**

The request is rejected with HTTP 400. Check that the prompt references a table name, alias, or a phrase similar to the `example_prompts` in `schema_config.json`.

**How do I add or change table aliases?**

Edit `~/.zemtik/schema_config.json` and restart the proxy. See [How to Add a Table](HOW_TO_ADD_TABLE.md).

**Why is my low-sensitivity table going to ZK SlowLane?**

The intent confidence score is below the threshold (`ZEMTIK_INTENT_THRESHOLD`, default 0.65). Add more `example_prompts` to the table entry and restart. See [Intent Engine](INTENT_ENGINE.md) for details.

**How do I see what route a query took?**

Check the `evidence.engine` field in the response JSON, or run `cargo run -- list` to view recent receipts with their routing decisions.
