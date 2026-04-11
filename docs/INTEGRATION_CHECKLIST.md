# Integration Checklist

**Document type:** Executable checklist  
**Audience:** DBAs and integrators connecting zemtik to a production database  
**Use when:** Setting up zemtik before a customer demo or pilot go-live

Print this page. Check each item. Run each curl command and verify the expected output.

---

## Pre-flight: what you need

- [ ] `OPENAI_API_KEY` — your OpenAI API key
- [ ] `DATABASE_URL` — Postgres connection string: `postgresql://user:pass@host:5432/dbname`
- [ ] `schema_config.json` — configured with your table name, columns, and example prompts
- [ ] Docker or a built `zemtik` binary

---

## Step 0 — Validate schema before starting

```bash
docker compose run --rm zemtik-proxy env ZEMTIK_VALIDATE_ONLY=1
```

**Expected output:**
```text
[ZEMTIK] Schema validation
  └ your_table: N rows — OK
  └ ZK tools: nargo=✓ bb=✓
[VALIDATE] Schema validation passed. Ready to start.
```

- [ ] Exit code 0
- [ ] Row count is non-zero for all tables

If you see `WARNING: empty table` → data seeding issue or wrong `physical_table` name.

---

## Step 1 — Start the proxy

```bash
DATABASE_URL=postgresql://... OPENAI_API_KEY=sk-... docker compose up
```

- [ ] Proxy starts without hard errors
- [ ] Startup logs show `[ZEMTIK] Schema validation` block

---

## Step 2 — Health check

```bash
curl -s http://localhost:4000/health | jq .
```

**Expected:**
```json
{
  "status": "ok",
  "schema_validation": {
    "status": "ok",
    "tables": [{"table_key": "...", "row_count": N, "status": "ok"}]
  }
}
```

- [ ] `status: "ok"`
- [ ] `schema_validation.status` is `"ok"` (not `"warnings"`)

---

## Step 3 — Test intent matching

```bash
curl -s -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5.4-nano","stream":false,"messages":[{"role":"user","content":"YOUR TEST QUERY HERE"}]}' \
  | jq '{status: .choices[0].message.content, evidence: .evidence}'
```

Replace `"YOUR TEST QUERY HERE"` with a query your users will actually ask.

**Expected:**
```json
{
  "status": "Your aggregate result from gpt-5.4-nano...",
  "evidence": {
    "aggregate": 12345,
    "row_count": 847,
    "data_exfiltrated": 0
  }
}
```

- [ ] HTTP 200
- [ ] `evidence.aggregate` is non-zero
- [ ] `evidence.data_exfiltrated` is 0
- [ ] Response makes sense for the time period queried

---

## Step 4 — Test streaming rejection (standard mode)

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5.4-nano","stream":true,"messages":[{"role":"user","content":"test"}]}'
```

- [ ] Returns `400` (not a hang)

---

## Step 5 — Test error message quality

```bash
curl -s -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5.4-nano","stream":false,"messages":[{"role":"user","content":"tell me a joke"}]}' \
  | jq .error
```

**Expected:**
```json
{
  "type": "zemtik_intent_error",
  "code": "NoTableIdentified",
  "hint": "Add aliases matching your users' phrasing...",
  "doc_url": "..."
}
```

- [ ] `error.code` is `"NoTableIdentified"` (not a raw error string)
- [ ] `error.hint` is actionable

---

## Step 6 — Verify audit trail (tunnel mode only)

If running in `ZEMTIK_MODE=tunnel`:

```bash
curl -s http://localhost:4000/tunnel/audit \
  -H "Authorization: Bearer $ZEMTIK_DASHBOARD_API_KEY" \
  | jq '{count: .count, first: .records[0]}'
```

- [ ] `count > 0` after at least one request
- [ ] `match_status` is `"matched"` or `"unmatched"` (not `"error"`)

---

## Step 7 — Check startup events log

```bash
tail -n 5 ~/.zemtik/startup_events.jsonl | jq .
```

- [ ] File exists
- [ ] `status` is `"ok"` for all tables
- [ ] `row_count` matches expected data volume

---

## Go/no-go criteria

| Check | Status |
|-------|--------|
| Startup validation: all tables OK | ☐ |
| /health returns status: ok | ☐ |
| Test query returns non-zero aggregate | ☐ |
| stream:true returns 400 (not hang) | ☐ |
| Error responses include code + hint | ☐ |

**All 5 checked = ready for demo.**

---

## If something fails

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — 6-symptom reference with fixes.
