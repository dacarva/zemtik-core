# Troubleshooting

**Document type:** Reference  
**Audience:** On-site integrators and support engineers  
**Use when:** Something is broken at a customer site and you need a fast diagnosis

---

## Quick symptom → cause → fix table

| Symptom | Cause | Fix |
|---------|-------|-----|
| Every query returns `$0.00` or `0` | Demo `client_id=123` with no matching rows in customer DB | Set `"skip_client_id_filter": true` in `schema_config.json` |
| JS client hangs indefinitely | `stream: true` sent to standard proxy — not supported | Set `stream: false` in client config |
| HTTP 400 `NoTableIdentified` | Prompt alias mismatch in `schema_config.json` | Add aliases matching how users phrase queries |
| HTTP 400 `RewritingFailed` (hint: `unresolvable`) | Rewriter enabled but cannot determine table or time from conversation history | Add more context to prior messages, or use Workaround A/B/C in SUPPORTED_QUERIES.md |
| HTTP 400 `RewritingFailed` (hint: `timeout`) | LLM rewriter call timed out | Increase `ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS` (default: 10) |
| HTTP 500 on critical-sensitivity tables | `nargo` or `bb` not on PATH | Set `ZEMTIK_SKIP_CIRCUIT_VALIDATION=1` (FastLane-only) or `INSTALL_ZK_TOOLS=true` |
| HTTP 500 `QueryFailed` | Wrong `physical_table`, `value_column`, or `timestamp_column` | Verify column names match actual DB schema |
| DB connection refused at startup | Wrong `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, or `DATABASE_URL` | Check credentials and network reachability |

---

## Detailed diagnosis

### Symptom: 0-row aggregate

**What you see:** Response includes `evidence.aggregate: 0` and `evidence.row_count: 0`. No error returned.

**Root cause:** The `client_id` filter is enabled (default) and the customer's database has no rows with `client_id = 123`. The demo data uses `client_id=123`; most production tables don't.

**Fix:**
```json
{
  "tables": {
    "your_table": {
      "skip_client_id_filter": true
    }
  }
}
```

**Verify:** Restart proxy. Check startup logs for the validation block — row count should be non-zero.

---

### Symptom: Client hangs or stream parse error

**What you see:** LangChain / Vercel AI SDK client hangs indefinitely, or throws a streaming parse error.

**Root cause:** The LLM library defaults to `stream: true`. Zemtik standard mode does not support streaming — responses must buffer the full ZK proof before being sent.

**Fix:** Set `stream: false` in the client:

```python
# LangChain
llm = ChatOpenAI(streaming=False, base_url="http://localhost:4000/v1")
```

```typescript
// Vercel AI SDK
const result = await generateText({ model, stream: false });
```

**Note:** Tunnel mode (`ZEMTIK_MODE=tunnel`) does support streaming — the guard only applies in standard mode.

---

### Symptom: HTTP 400 `NoTableIdentified`

**What you see:**
```json
{"error": {"type": "zemtik_intent_error", "code": "NoTableIdentified", "hint": "..."}}
```

**Root cause:** The intent engine could not match the prompt to any table in `schema_config.json`. Usually an alias mismatch.

**Fix:**
1. Check what aliases are configured: `cat ~/.zemtik/schema_config.json | jq '.tables | to_entries[] | {key: .key, aliases: .value.aliases}'`
2. Add aliases that match how your users phrase queries:
```json
{
  "tables": {
    "your_table": {
      "aliases": ["revenue", "transactions", "sales"],
      "example_prompts": ["What was our revenue in Q1?", "Show me total sales this year."]
    }
  }
}
```
3. Restart proxy (schema is loaded at startup).

---

### Symptom: HTTP 400 `RewritingFailed`

**What you see:**
```json
{"error": {"type": "zemtik_intent_error", "code": "RewritingFailed", "hint": "unresolvable", "message": "..."}}
```
or
```json
{"error": {"type": "zemtik_intent_error", "code": "RewritingFailed", "hint": "timeout", "message": "..."}}
```

**Root cause (hint: `unresolvable`):** `ZEMTIK_QUERY_REWRITER=1` is set, but the rewriter could not determine the table or time range from the conversation history. The deterministic pass scanned the prior messages (up to `ZEMTIK_QUERY_REWRITER_SCAN_MESSAGES`, default 5) and found no usable table reference. The LLM fallback also failed to produce a resolvable query.

**Fix (hint: `unresolvable`):**
- Ensure at least one prior user message contains the table name, alias, or a phrase matching `example_prompts` in `schema_config.json`.
- Increase `ZEMTIK_QUERY_REWRITER_SCAN_MESSAGES` to scan further back in long conversations.
- If the conversation structure cannot be changed, use Workaround A, B, or C from [SUPPORTED_QUERIES.md](SUPPORTED_QUERIES.md) instead of relying on the rewriter.

**Root cause (hint: `timeout`):** The LLM rewrite call did not complete within `ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS` (default: 10 seconds). The deterministic pass does not have a timeout — this error only occurs when the LLM fallback is reached.

**Fix (hint: `timeout`):**
```bash
ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS=20 cargo run -- proxy
```

If timeouts persist, check network latency to the configured `ZEMTIK_OPENAI_BASE_URL` and confirm `OPENAI_API_KEY` has capacity.

---

### Symptom: HTTP 500 on critical-sensitivity tables

**What you see:** `{"error": {"type": "zemtik_pipeline_error", "message": "..."}}`

**Root cause:** ZK tools (`nargo`, `bb`) not on PATH. Critical-sensitivity tables require the ZK SlowLane.

**Fix (option A — use FastLane-only mode):**
```bash
ZEMTIK_SKIP_CIRCUIT_VALIDATION=1 docker compose up
```
Change table `"sensitivity"` from `"critical"` to `"low"` in `schema_config.json` if ZK proofs are not required for this pilot.

**Fix (option B — install ZK tools):**
```bash
docker compose build --build-arg INSTALL_ZK_TOOLS=true
docker compose up
```

---

### Symptom: HTTP 500 `QueryFailed`

**What you see:**
```json
{"error": {"type": "zemtik_db_error", "code": "QueryFailed", "message": "Database query failed — check server logs for details.", "hint": "Check that physical_table, value_column, and timestamp_column match your schema."}}
```

**Root cause:** The database rejected the query — wrong column name, table name, or RLS policy.

**Diagnosis:**
```bash
# Check what query zemtik is constructing by looking at startup validation logs
# or running ZEMTIK_VALIDATE_ONLY=1
docker compose run --rm zemtik-proxy env ZEMTIK_VALIDATE_ONLY=1
```

**Fix:** Compare `physical_table`, `value_column`, `timestamp_column` in `schema_config.json` against actual column names in your database:
```sql
SELECT column_name, data_type FROM information_schema.columns
WHERE table_name = 'your_physical_table_name';
```

---

### Symptom: DB connection refused at startup

**What you see:** Startup logs show `connection_failed` or `connection_timeout` in the validation block.

**Root cause:** Wrong credentials, wrong host, or network policy blocking the connection.

**Diagnosis:**
```bash
# Test connectivity directly
psql $DATABASE_URL -c "SELECT 1"

# Or for Supabase
curl -H "apikey: $SUPABASE_SERVICE_KEY" "$SUPABASE_URL/rest/v1/"
```

**Note:** A connection failure at startup is a **WARNING** — the proxy starts anyway. Queries will fail at request time if the DB is unreachable.

---

## Startup validation block

At startup, zemtik prints a validation summary:

```text
[ZEMTIK] Schema validation
  └ acme_transactions: 14,823 rows — OK
  └ acme_invoices: 0 rows — WARNING: empty table
  └ ZK tools: nargo=✓ bb=✗ (MISSING)
```

Run validation without starting the server:
```bash
docker compose run --rm zemtik-proxy env ZEMTIK_VALIDATE_ONLY=1
```

Exit code 0 = all clear. Exit code 1 = warnings to fix before the demo.

Skip validation entirely (e.g. during local development):
```bash
ZEMTIK_SKIP_DB_VALIDATION=1 docker compose up
```

---

## Startup events log

Each startup validation appends structured events to `~/.zemtik/startup_events.jsonl`. Review after a deployment:

```bash
tail -n 20 ~/.zemtik/startup_events.jsonl | jq .
```
