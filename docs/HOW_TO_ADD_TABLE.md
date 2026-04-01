# How to Add a Table to Zemtik

**Document type:** How-to guide
**Audience:** Developers configuring Zemtik for their data schema
**Goal:** Register a new data table so the proxy can route natural-language queries against it

---

## Prerequisites

- Zemtik proxy running and responding to requests (see [Getting Started](GETTING_STARTED.md))
- `~/.zemtik/schema_config.json` exists (copy from `schema_config.example.json` if not)
- You know whether the table contains sensitive data (determines FastLane vs ZK SlowLane routing)

---

## Step 1 — Choose a table key and sensitivity

Pick a short, lowercase, underscore-separated key. This key must match how Zemtik identifies the data in its internal circuit mapping.

> **Important:** The ZK SlowLane only supports tables with a corresponding entry in `schema_key_to_category_code` inside `src/db.rs`. Currently mapped tables are: `aws_spend`, `payroll`, `travel`. For any other key, ZK SlowLane will return an error. If you need ZK support for a new table, contact the Zemtik team or see the architecture docs for adding a circuit category code.

Choose sensitivity based on your data classification policy:

| Sensitivity | Engine | Description |
|-------------|--------|-------------|
| `"low"` | FastLane | BabyJubJub attestation, no ZK proof. Sub-50ms. Use for non-critical operational data. |
| `"critical"` | ZK SlowLane | Full UltraHonk proof. ~17–20s. Use for PII, financials, legally sensitive data. |

---

## Step 2 — Add the table to `schema_config.json`

Open `~/.zemtik/schema_config.json` and add an entry under `"tables"`:

```json
{
  "fiscal_year_offset_months": 0,
  "tables": {
    "aws_spend": { ... },
    "payroll":   { ... },

    "vendor_invoices": {
      "sensitivity": "low",
      "aliases": ["vendors", "invoices", "AP"],
      "description": "Accounts payable — vendor invoice amounts by category and date.",
      "example_prompts": [
        "What was our total vendor spend last quarter?",
        "Show me invoice totals for Q2 2025",
        "How much did we pay in vendor invoices this year?",
        "What are our accounts payable for H1 2024?",
        "Give me a vendor payment summary for Q3"
      ]
    }
  }
}
```

### Field guidance

**`sensitivity`** — **Important:** The ZK SlowLane only works for tables with a matching entry in the circuit's category code map (`aws_spend`, `payroll`, `travel`). Setting `"critical"` for any other table will result in HTTP 500 on every request to that table, because the ZK circuit has no category code for it. For any new table that is not in the circuit map, use `"low"` (FastLane) until circuit support is added. See Step 1 above for details.

**`aliases`** — Add the terms users will actually type. Include abbreviations and synonyms. The intent engine matches these case-insensitively as substrings.

```json
"aliases": ["vendors", "invoices", "AP", "accounts payable", "vendor payments"]
```

**`description`** — One sentence describing the content. Used by the embedding backend to build a semantic index. Be specific; vague descriptions reduce matching accuracy.

```json
"description": "Accounts payable — vendor invoice amounts categorized by supplier type and payment date."
```

**`example_prompts`** — Representative queries a real user would ask. Five or more examples improve accuracy. Include different phrasings of the same intent.

```json
"example_prompts": [
  "What was our total vendor spend last quarter?",
  "Show me invoice totals for Q2 2025",
  "How much did we pay vendors in 2024?",
  "What are our AP costs for H1 2024?",
  "Give me a vendor payment summary by quarter",
  "How much was spent on vendor invoices in Q3 2025?"
]
```

---

## Step 3 — Restart the proxy

The schema index is built once at startup. Changes to `schema_config.json` require a restart:

```bash
# Stop the running proxy (Ctrl+C), then:
cargo run -- proxy
```

The embedding backend logs the indexed tables on startup:

```
[INTENT] Indexed 4 tables: aws_spend, payroll, travel, vendor_invoices
```

---

## Step 4 — Verify the new table is matched

Send a test query:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "What were our vendor invoices for Q2 2025?"}]
  }'
```

Check the `evidence` field in the response:

```json
"evidence": {
  "engine": "FastLane",
  "zemtik_confidence": 0.87,
  ...
}
```

If `zemtik_confidence` is below `0.65` (the default threshold), the query falls through to ZK SlowLane. Improve matching by adding more `example_prompts` or more specific `aliases`.

---

## Troubleshooting

### Confidence is low (`< 0.65`)

Add more example prompts that match how your users phrase queries. The embedding backend learns from these examples — five is the minimum, ten is better.

### "No table identified" error (HTTP 400)

The intent engine could not match any table. Check that:

- The prompt includes a recognizable keyword from `aliases` or `example_prompts`
- The proxy was restarted after editing `schema_config.json`
- The `description` field is present and accurate

### ZK SlowLane returns an error for my new table

The ZK circuit currently supports three category codes: `aws_spend` (2), `payroll` (1), `travel` (3). Tables not in this map cannot use the ZK slow lane. Route the table to FastLane (`"sensitivity": "low"`) or file an issue requesting a new category code.

### The regex backend doesn't match my table

`ZEMTIK_INTENT_BACKEND=regex` matches by substring against table keys and aliases. Make sure at least one alias matches a distinct word in the user's query.

---

## Fiscal year offset

If your organization uses a non-calendar fiscal year, set `fiscal_year_offset_months` at the top level:

```json
{
  "fiscal_year_offset_months": 9,
  "tables": { ... }
}
```

This shifts all quarter boundaries by 9 months (fiscal year starts October 1). The offset applies to all tables.

See [Supported Queries](SUPPORTED_QUERIES.md) for the full time expression reference.
