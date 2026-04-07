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
| `this quarter` | "this quarter AWS" | Current quarter start → end |
| `last quarter` / `prior quarter` | "last quarter spend" | Previous full quarter |
| `this month` | "this month payroll" | Current calendar month start → end |
| `last month` / `prior month` | "last month payroll" | Previous full calendar month |
| `last year` / `prior year` | "last year AWS spend" | Full prior calendar year |
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

Three aggregation functions are supported. Each routes differently based on `sensitivity`.

| Aggregation | FastLane (low) | ZK SlowLane (critical) | Notes |
|-------------|---------------|----------------------|-------|
| SUM | Yes | Yes | Sums a numeric column |
| COUNT | Yes | Yes | Counts matching rows (non-null `value_column`; use a PK or non-nullable column for ZK path) |
| AVG | No | Yes — composite | Two sequential ZK proofs (SUM + COUNT) + BabyJubJub attestation for division. Response includes `sum_proof_hash`, `count_proof_hash`, and `avg_evidence_model: "zk_composite+attestation"`. Latency: ~40-120s. |
| MIN / MAX | No | No (Phase 2) | |
| Percentiles | No | No | |

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
| "last year" | **Yes** — resolves to prior calendar year |
| "prior year" | **Yes** — resolves to prior calendar year |
| "prior quarter" | **Yes** — resolves to previous full quarter |
| "prior month" | **Yes** — resolves to previous full calendar month |
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
| Table key is empty, non-ASCII, or >93 bytes | 500 | `"cannot hash table key '...' (key must be ≤93 bytes after lowercasing)"` |
| `bb verify` fails | 500 | `"proof verification failed"` |
| More than 500 matching rows (ZK path) | 422 | `"Too many matching rows (N=...). ZK SlowLane supports up to 500 transactions per query. Narrow the time range or set sensitivity to 'low' to use FastLane instead."` |
| COUNT table with nullable `value_column` (ZK path) | Runtime 422 | Circuit counts all padded rows that match time/category filters regardless of null semantics — use a primary key or NOT NULL column for `value_column` to avoid incorrect counts |
| AVG query with no matching rows (COUNT=0) | 422 | `"AVG: no matching transactions in the queried time period. The COUNT step returned 0. Check that the time range and table key match existing data."` |
| Unrecognized `agg_fn` value in schema_config.json | Exit 1 | serde parse error — valid values are `"SUM"`, `"COUNT"`, `"AVG"` (case-sensitive, uppercase) |
| Circuit compilation timeout on first ZK request | 504 | `"ZK circuit compilation timed out. This is expected on first use (~30-120s). Retry the request."` |

---

## FAQ

**What happens if my table isn't listed in `schema_config.json`?**

The query is routed to ZK SlowLane as a fail-secure fallback. Any table key that is valid ASCII and ≤93 bytes can be processed by the ZK slow lane — the circuit uses Poseidon BN254 hashing of the table name, so no hardcoded category mapping is needed. Add the table to `schema_config.json` to ensure correct routing and sensitivity classification.

**What if no table is identified?**

The request is rejected with HTTP 400. Check that the prompt references a table name, alias, or a phrase similar to the `example_prompts` in `schema_config.json`.

**How do I add or change table aliases?**

Edit `~/.zemtik/schema_config.json` and restart the proxy. See [How to Add a Table](HOW_TO_ADD_TABLE.md).

**Why is my low-sensitivity table going to ZK SlowLane?**

The intent confidence score is below the threshold (`ZEMTIK_INTENT_THRESHOLD`, default 0.65). Add more `example_prompts` to the table entry and restart. See [Intent Engine](INTENT_ENGINE.md) for details.

**How do I see what route a query took?**

Check the `evidence.engine` field in the response JSON, or run `cargo run -- list` to view recent receipts with their routing decisions.

**What is the difference between FastLane attestation and a ZK proof?**

Both paths guarantee that **zero raw rows are sent to OpenAI**. The difference is in the strength of the correctness guarantee:

| | FastLane (`attestation_hash`) | ZK SlowLane (`proof_hash`) |
|---|---|---|
| What is produced | BabyJubJub EdDSA signature over `(aggregate, query_descriptor)` | UltraHonk ZK proof over the Noir circuit |
| Circuit constraint | None — the prover is not bound by a circuit | Yes — `assert(eddsa_verify(...))` + aggregate computation; a wrong aggregate has no valid witness |
| Malicious operator | Could sign an arbitrary value with the key | Cannot produce a valid proof for a wrong aggregate without breaking the signature assumption |
| Offline verification | Not possible with `bb verify` | `cargo run -- verify <bundle.zip>` replays `bb verify` |
| Latency | < 50ms | ~17–20s on CPU |
| Use case | Non-sensitive aggregates (e.g., public revenue totals) | Sensitive aggregates where correctness must be cryptographically proven |

In short: FastLane is fast and private; ZK SlowLane is fast, private, *and* verifiably correct. The right choice depends on whether the aggregate itself is sensitive and whether you need a proof that survives external audit.
