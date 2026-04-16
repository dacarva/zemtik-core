# Getting Started with Zemtik Core

**Document type:** Tutorial
**Audience:** Developers integrating Zemtik for the first time
**Goal:** Run the full ZK pipeline locally and send your first privacy-preserving query to OpenAI

```mermaid
flowchart LR
    App["Your App\n(any OpenAI client)"]
    Proxy["Zemtik Proxy\nlocalhost:4000"]
    OpenAI["OpenAI API\napi.openai.com"]

    App -->|"POST /v1/chat/completions\nno code changes required"| Proxy
    Proxy -->|"aggregate only\ndata_exfiltrated: 0"| OpenAI
    OpenAI -->|"LLM response\n+ evidence block"| App
```

---

## Option A — Docker Quick Start (recommended)

No Rust toolchain, no nargo, no bb required. Runs in under 2 minutes.

```bash
# 1. Set your OpenAI API key
export OPENAI_API_KEY=sk-...

# 2. Start the proxy
docker compose up --build

# 3. Verify
curl http://localhost:4000/health

# 4. Query (change the endpoint from api.openai.com to localhost:4000)
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-5.4-nano","messages":[{"role":"user","content":"What was our total AWS spend for Q1 2024?"}]}'
```

The response includes `evidence.data_exfiltrated: 0` — a cryptographic receipt showing no raw records were sent to OpenAI. See [COMPLIANCE_RECEIPT.md](COMPLIANCE_RECEIPT.md) for field descriptions.

**Using your own data:** `docker-compose.yml` already mounts `schema_config.example.json` with demo tables (aws\_spend, payroll, travel, and more). Replace that mount with your own `schema_config.json`. The demo dataset uses the `transactions` table with `client_id=123`.

---

## Option B — Build from Source

By the end of this section you will have:

1. Built Zemtik Core from source
2. Run the CLI demo — 500 transactions processed through a ZK circuit, result sent to OpenAI
3. Started the proxy and made your first OpenAI-compatible request with zero raw data exfiltration

> **What you will not do:** configure your own database tables or connect to Supabase. Those are covered in the how-to guides after you have the basics working.

---

## Prerequisites (for Build from Source)

You need three tools on your `PATH` before starting. Install them in this order.

### 1. Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Verify:

```bash
rustc --version   # rustc 1.70.0 or later
```

### 2. Nargo (Noir toolchain)

Zemtik's ZK circuit is written in Noir. The `nargo` CLI compiles and executes it.

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup --version 1.0.0-beta.19
```

Verify:

```bash
nargo --version   # nargo version = 1.0.0-beta.19
```

### 3. Barretenberg (`bb`)

`bb` generates and verifies UltraHonk proofs. Install via `bbup`, which `noirup` installs alongside `nargo`:

```bash
bbup
```

Verify:

```bash
bb --version   # 4.0.0-nightly (or compatible v4)
```

> **Note:** On first use, `bb` downloads a Structured Reference String (SRS) of ~1GB from Aztec's CDN. This is a one-time download to `~/.bb/`.

---

## Step 1 — Clone and configure

```bash
git clone https://github.com/zemtik/zemtik-core.git
cd zemtik-core
cp .env.example .env
```

Open `.env` and set your OpenAI API key:

```bash
OPENAI_API_KEY=sk-...your-key-here...
```

> **Model:** The CLI pipeline uses `gpt-5.4-nano` (current OpenAI model). To use a different model, set `ZEMTIK_OPENAI_MODEL` before running: `ZEMTIK_OPENAI_MODEL=gpt-4o-mini cargo run`.

All other `.env` values have safe defaults for local development.

---

## Step 2 — Build

```bash
cargo build --release
```

The first build downloads and compiles all Rust dependencies. This takes 2–5 minutes.

---

## Step 3 — Run the CLI demo

```bash
cargo run
```

The first run compiles the Noir circuit (~10 seconds). Subsequent runs skip this step.

You will see output in these phases:

```
[DB]   Initializing in-memory SQLite ledger... OK (500 transactions for client 123)
[KMS]  Signing 10 batches of 50 transactions with BabyJubJub EdDSA... OK
[NOIR] Writing Prover.toml (10 batches)... OK
[NOIR] Circuit already compiled, skipping nargo compile
[NOIR] Executing circuit (10 batches x EdDSA + aggregation)...
[NOIR] Verified aggregate AWS Infrastructure spend = $2805600
[NOIR] Generating UltraHonk proof (bb v4, CRS auto-download)...
[AI]   Querying gpt-5.4-nano with ZK-verified payload...
       Payload: { category: "AWS Infrastructure", total_spend_usd: 2805600, ... }
```

Followed by the final result:

```
══════════════════════════════════════════════════════
  ZEMTIK RESULT (total time: ~20s)
══════════════════════════════════════════════════════
  Category : AWS Infrastructure
  Period   : Q1 2024
  Aggregate: $2805600
  ZK Proof : VALID
  Raw rows sent to OpenAI: 0
══════════════════════════════════════════════════════
```

**What just happened:**

- 500 transaction rows were processed entirely inside your machine
- A Poseidon commitment tree was built over each batch of 50 rows
- The bank's BabyJubJub key signed each commitment
- A Noir ZK circuit verified every signature and summed the matching rows
- Barretenberg generated an UltraHonk proof (728k gates) and verified it locally
- Only three fields were sent to OpenAI: `category`, `total_spend_usd`, `data_provenance`
- The audit record is at `audit/<timestamp>.json`

---

## Step 4 — Start the proxy

The proxy is a drop-in replacement for `api.openai.com`. No application code changes are needed — just redirect the base URL.

First, copy the schema config template:

```bash
cp schema_config.example.json ~/.zemtik/schema_config.json
```

Then start the proxy:

```bash
cargo run -- proxy
```

> **First start:** The embedding backend downloads the BGE-small-en ONNX model (~130MB) to `~/.zemtik/models/` before serving requests. This takes 30–120 seconds depending on your connection. The proxy logs `[INTENT] Downloading model...` while this happens. Subsequent starts skip the download.
>
> To skip the download entirely, use the regex backend instead: `ZEMTIK_INTENT_BACKEND=regex cargo run -- proxy`

You will see:

```
[PROXY] Listening on http://127.0.0.1:4000
[PROXY] Point your app to http://localhost:4000 instead of api.openai.com
```

---

## Step 5 — Send your first proxy request

> **What you're about to see — FastLane.** The example `schema_config.example.json` sets `aws_spend` to `"sensitivity": "low"`, so this query routes through **FastLane** — the sub-50ms path that runs a direct database aggregate and attests the result with BabyJubJub EdDSA. No ZK proof is generated. The response `evidence` object will show `"engine": "FastLane"` and an `attestation_hash` (a cryptographic receipt binding the aggregate to your signing key and the exact query parameters). To see the ZK SlowLane in action, proceed to Step 6.

In a separate terminal:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "What was our AWS spend in Q1 2024?"}]
  }'
```

The response is a standard OpenAI Chat Completions JSON with one addition: a top-level `evidence` field:

```json
{
  "id": "chatcmpl-...",
  "choices": [...],
  "evidence": {
    "engine": "FastLane",
    "attestation_hash": "a3f9...",
    "actual_row_count": 47,
    "data_exfiltrated": 0,
    "zemtik_confidence": 0.91,
    "receipt_id": "rec_...",
    "evidence_version": 3,
    "human_summary": "Aggregated 47 rows from 'aws_spend' into a single SUM attested by Zemtik (BabyJubJub EdDSA). No individual records left the institution's infrastructure.",
    "checks_performed": ["intent_classification", "schema_sensitivity_check", "aggregate_only_enforcement", "babyjubjub_attestation"]
  }
}
```

**`attestation_hash` explained:** SHA-256 of the BabyJubJub EdDSA signature produced by `attest_fast_lane()` over the aggregate result plus the resolved query and metric configuration: category name, time range, aggregate, row count, timestamp, resolved table and column settings, `agg_fn`, `metric_label`, and the effective client scope. It cryptographically binds this specific aggregate result to your institution's signing key. The hash is returned in the response `evidence` object and included in the `EvidencePack`; the FastLane receipt path in `src/proxy.rs` writes `proof_hash: None`, so FastLane does not persist `attestation_hash` in `receipts.db`.

> **FastLane does not generate a ZK proof.** The `attestation_hash` confirms that *someone with your signing key* produced this aggregate, but there is no circuit constraint proving the aggregate was computed from real database rows. See [Architecture](ARCHITECTURE.md#4-fastlane-engine_fastrs) for the full trust model.

The proxy logs in the server terminal show the routing decision:

```
[PROXY] Intent: table=aws_spend confidence=0.91 time=Q1 2024
[PROXY] Route:  FastLane (sensitivity=low)
[PROXY] Result: $2805600 — attestation_hash=a3f9...
```

---

## Step 5.5 — Multi-turn follow-up with the query rewriter

By default, Zemtik extracts intent from the last user message only. Enable the hybrid query rewriter to resolve follow-up questions that omit the table name or time range:

```bash
ZEMTIK_QUERY_REWRITER=1 cargo run -- proxy
```

With the rewriter enabled, send a two-turn conversation. Turn 1 establishes the table and time context; Turn 2 references only a new time expression:

```bash
# Turn 1 — explicit query (full context)
curl -s -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5.4-nano","messages":[{"role":"user","content":"aws_spend in Q1 2024"}]}'

# Turn 2 — follow-up with only a time expression
curl -s -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [
      {"role": "user",      "content": "aws_spend in Q1 2024"},
      {"role": "assistant", "content": "AWS spend was $12,345."},
      {"role": "user",      "content": "How about Q2 2024?"}
    ]
  }'
```

The Turn 2 response includes `rewrite_method: "deterministic"` in the evidence envelope, confirming the table was carried forward from the prior message without an LLM call:

```json
"evidence": {
  "engine": "FastLane",
  "attestation_hash": "b7e2...",
  "data_exfiltrated": 0,
  "rewrite_method": "deterministic"
}
```

If the deterministic pass cannot determine the table or time, the rewriter falls back to an LLM call and sets `rewrite_method: "llm"`. If neither path succeeds, the request returns HTTP 400 `RewritingFailed`. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and [CONFIGURATION.md](CONFIGURATION.md#query-rewriting-v0100) for tuning options.

> **Data residency:** when `rewrite_method: "llm"`, the full conversation history in the request body was sent to the OpenAI endpoint configured by `ZEMTIK_OPENAI_BASE_URL`. Review the data residency section in [CONFIGURATION.md](CONFIGURATION.md#data-residency) before enabling the LLM fallback in production.

---

## Step 6 — Try a critical table

Query payroll (sensitivity = `critical`) to see the ZK slow lane in action:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "Total payroll expenses for Q1 2024"}]
  }'
```

This time the proxy runs the full ZK pipeline. The response includes:

```json
"evidence": {
  "engine": "ZkSlowLane",
  "proof_hash": "7b2c...",
  "data_exfiltrated": 0
}
```

The server terminal shows the ZK pipeline stages. Expect ~17–20s for proof generation.

---

## Step 6.5 — Try COUNT and AVG on critical tables

The ZK SlowLane now supports COUNT and AVG aggregations, not just SUM. Add these entries to your `~/.zemtik/schema_config.json` under `"tables"`:

> **Note on `timestamp_column`:** The engine compares timestamps as UNIX epoch seconds (`u64`). Ensure the column in your database stores epoch seconds, not human-readable date strings. If your table uses a date column, add a computed column or view that converts it (e.g. `EXTRACT(EPOCH FROM hire_date)::bigint`).

```json
"headcount_low": {
  "sensitivity": "low",
  "description": "FastLane headcount from HR records. Uses physical_table to query 'employees' on Supabase (Supabase only — SQLite always queries 'transactions').",
  "physical_table": "employees",
  "value_column": "employee_id",
  "timestamp_column": "hire_date_epoch",
  "category_column": null,
  "agg_fn": "COUNT",
  "metric_label": "headcount",
  "skip_client_id_filter": true,
  "example_prompts": [
    "How many employees were hired in Q1 2024?",
    "What is the headcount for this quarter?"
  ]
},
"avg_deal_size": {
  "sensitivity": "critical",
  "description": "ZK-verified average M&A deal size.",
  "physical_table": "transactions",
  "value_column": "amount",
  "timestamp_column": "timestamp",
  "category_column": "category_name",
  "agg_fn": "AVG",
  "metric_label": "avg_deal_value_usd",
  "skip_client_id_filter": false,
  "example_prompts": [
    "What was the average deal size last quarter?",
    "Show me average transaction value for Q1 2024"
  ]
}
```

Restart the proxy (`Ctrl+C`, then `cargo run -- proxy`), then query:

**COUNT on a critical table:**

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "How many employees were hired in Q1 2024?"}]
  }'
```

Response `evidence` field:

```json
"evidence": {
  "evidence_version": 3,
  "engine": "ZkSlowLane",
  "proof_hash": "9a1b...",
  "actual_row_count": 47,
  "data_exfiltrated": 0,
  "human_summary": "Computed COUNT over 47 rows from 'employee_records' inside a zero-knowledge circuit (UltraHonk proof). Raw records never left the institution's infrastructure. Proof is independently verifiable offline via `zemtik verify <bundle.zip>`.",
  "checks_performed": ["intent_classification", "schema_sensitivity_check", "babyjubjub_signing", "poseidon_commitment", "ultrahonk_proof", "bb_verify_local"]
}
```

**AVG on a critical table** (runs two ZK proofs sequentially, ~40-120s):

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "What was the average deal size in Q1 2024?"}]
  }'
```

Response `evidence` field:

```json
"evidence": {
  "evidence_version": 3,
  "engine": "ZkSlowLane",
  "sum_proof_hash": "7b2c...",
  "count_proof_hash": "a3f9...",
  "avg": 56200,
  "sum": 2810000,
  "count": 50,
  "actual_row_count": 50,
  "avg_evidence_model": "zk_composite+attestation",
  "data_exfiltrated": 0,
  "human_summary": "Computed AVG over 50 rows from 'deals' inside a zero-knowledge circuit (UltraHonk proof). Raw records never left the institution's infrastructure. Proof is independently verifiable offline via `zemtik verify <bundle.zip>`.",
  "checks_performed": ["intent_classification", "schema_sensitivity_check", "babyjubjub_signing", "poseidon_commitment", "ultrahonk_proof", "bb_verify_local"]
}
```

**Understanding the AVG evidence model:** AVG runs two independent ZK proofs — one for the SUM of all matching rows, one for the COUNT. Both proofs are verifiable with `zemtik verify <bundle.zip>`. The final division (`avg = sum / count`) is attested with a BabyJubJub EdDSA signature over the result. This is the same trust model as FastLane for the division step, with full UltraHonk guarantees on both operands.

> **Latency note:** The first AVG or COUNT query on a new table compiles the ZK circuit (~30-120s). The proxy logs `[PROXY] Compiling circuit...` while this happens. Subsequent requests reuse the compiled artifact. Set `ZEMTIK_INTENT_BACKEND=regex` if you want to skip the embedding model download on first proxy start.

---

---

## Streaming

The proxy does **not** support `stream: true`. Set `stream: false` in your client configuration.

All responses are returned as a single buffered JSON object after pipeline completion. If `stream: true` is detected in the request body, the proxy returns HTTP 400 immediately:

```json
{
  "error": {
    "type": "zemtik_config_error",
    "code": "StreamingNotSupported",
    "message": "Set stream: false in your client configuration.",
    "hint": "The ZK pipeline must complete before any part of the response can be sent.",
    "doc_url": "https://github.com/dacarva/zemtik-core/blob/main/docs/GETTING_STARTED.md#streaming"
  }
}
```

**LangChain / Vercel AI SDK:** these libraries default to `stream: true`. Override explicitly:

```python
# LangChain
llm = ChatOpenAI(streaming=False, base_url="http://localhost:4000/v1")
```

```typescript
// Vercel AI SDK
const result = await generateText({ model, stream: false });
```

> **Tunnel mode** supports streaming — `stream: true` passes through to OpenAI unmodified. The streaming guard only applies in standard proxy mode.
>
> **General Passthrough** also supports streaming (v0.11.0+) — when `ZEMTIK_GENERAL_PASSTHROUGH=1`, `stream: true` is allowed for non-data queries. `zemtik_meta` is NOT injected into the SSE body; use the `X-Zemtik-Meta` response header instead.

---

## Option C — Mixed Session (data + general queries)

Real conversations mix data queries ("What was Q1 spend?") and general follow-ups
("Can you explain that?"). To handle both in the same session:

1. Enable General Passthrough:
```bash
export ZEMTIK_GENERAL_PASSTHROUGH=1
docker compose up --build   # or restart if already running
```

2. Send a data query (handled by ZK/FastLane as normal):
```bash
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-5.4-nano","messages":[{"role":"user","content":"Q1 2024 aws_spend total"}]}'
```

3. Send a follow-up general query in the same session — now succeeds:
```bash
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-5.4-nano","messages":[{"role":"user","content":"Can you summarize that for a non-technical audience?"}]}'
```

The general query response will include `zemtik_meta.engine_used: "general_lane"`
and `zk_coverage: "none"` — confirming that no ZK verification was applied (and none
was needed, since no raw data was queried). (`zemtik_meta` is the GeneralLane
equivalent of the `evidence` field used by ZK/FastLane responses — a separate
top-level key injected only when `engine_used: "general_lane"`.)

> **Note on ZEMTIK_QUERY_REWRITER:** GeneralLane works with or without the query
> rewriter enabled. If `ZEMTIK_QUERY_REWRITER=1` is set, the proxy first attempts to
> resolve follow-up queries as data queries (adding ~1s latency) before routing to
> GeneralLane. Without the rewriter, general queries go to GeneralLane immediately.

---

## Bring Your Own Database (5-step guide)

This section is for integrators connecting zemtik to their own Postgres database.

### Step 0 — Validate before starting

Run schema validation without starting the server:

```bash
docker compose run --rm zemtik-proxy env ZEMTIK_VALIDATE_ONLY=1
```

This prints a block like:

```text
[ZEMTIK] Schema validation
  └ acme_transactions: 14,823 rows — OK
  └ acme_invoices: 0 rows — WARNING: empty table
  └ ZK tools: nargo=✓ bb=✓
```

Exit code 0 = all clear. Exit code 1 = warnings to fix. Run this before the customer demo.

### Step 1 — Create `schema_config.json`

Copy the example and configure your table:

```bash
cp schema_config.example.json ~/.zemtik/schema_config.json
```

Edit the table key, `physical_table`, `value_column`, `timestamp_column`:

```json
{
  "tables": {
    "company_transactions": {
      "sensitivity": "low",
      "physical_table": "financial_transactions",
      "value_column": "amount_usd",
      "timestamp_column": "ts_epoch",
      "skip_client_id_filter": true,
      "description": "Company financial transaction ledger",
      "example_prompts": ["What was our revenue in Q1 2025?"]
    }
  }
}
```

### Step 2 — Handle client_id (single-tenant)

If your database does not have a `client_id` column, set `"skip_client_id_filter": true`. Without this, every query returns 0 rows because it filters for `client_id = 123` (the demo default).

### Step 3 — Handle timestamps

The `timestamp_column` must store **UNIX epoch seconds** (integer). For PostgreSQL `timestamp`/`timestamptz` columns, create a generated column:

```sql
ALTER TABLE financial_transactions
  ADD COLUMN ts_epoch BIGINT GENERATED ALWAYS AS
    (EXTRACT(EPOCH FROM created_at)::BIGINT) STORED;
```

### Step 4 — Choose your build profile

The default image uses regex-based intent matching. Pick the profile that matches your needs:

| Profile | Command | Size | Intent matching | ZK proofs |
|---------|---------|------|----------------|-----------|
| Default | `docker compose build` | ~150MB | Regex (exact table key) | No |
| Embed | `docker compose build --build-arg BUILD_FEATURES=embed --build-arg BUILDER_IMAGE=ubuntu:24.04 --build-arg RUNTIME_IMAGE=ubuntu:24.04` | ~450MB | Semantic (BGE-small-en ONNX) | No |
| ZK | `docker compose build --build-arg INSTALL_ZK_TOOLS=true` | ~450MB | Regex | Yes |
| Full | All args above combined | ~750MB | Semantic | Yes |

The embed profile requires ubuntu:24.04 base images — ONNX Runtime needs glibc 2.38+, which Debian Bookworm (2.36) does not provide.

On first proxy start, the embed profile downloads the BGE-small-en model (~130MB) to `~/.zemtik/models/`. Set `ZEMTIK_INTENT_BACKEND=regex` to skip the download and force regex matching.

Or set `ZEMTIK_SKIP_CIRCUIT_VALIDATION=1` to use FastLane-only mode without installing ZK tools.

### Step 5 — Smoke-test

```bash
# 1. Start the proxy
DATABASE_URL=postgresql://user:pass@host/db docker compose up

# 2. Check startup logs for validation block
# 3. Send a test query
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5.4-nano","stream":false,"messages":[{"role":"user","content":"What was our revenue in Q1 2025?"}]}'
```

### Common problems

| Symptom | Cause | Fix |
|---------|-------|-----|
| 0-row aggregate | `client_id=123` default, no matching rows | Set `skip_client_id_filter: true` in schema_config.json |
| Streaming hang | `stream: true` not supported in standard mode | Set `stream: false` |
| `NoTableIdentified` 400 | Alias mismatch in schema_config.json | Add aliases matching your users' phrasing |
| ZK tools absent | nargo/bb not on PATH | Set `ZEMTIK_SKIP_CIRCUIT_VALIDATION=1` or `INSTALL_ZK_TOOLS=true` |
| Column not found | `physical_table` or `value_column` name mismatch | Fix in schema_config.json, check DB schema |
| DB connection refused | Wrong `SUPABASE_URL` or `DATABASE_URL` | Verify credentials, test connectivity |

---

## What's next

- **Configure your own tables** — [How to Add a Table](HOW_TO_ADD_TABLE.md)
- **Understand the routing and engines** — [Architecture](ARCHITECTURE.md)
- **Review all configuration options** — [Configuration Reference](CONFIGURATION.md)
- **Understand supported query patterns** — [Supported Queries](SUPPORTED_QUERIES.md)
- **Troubleshoot issues on-site** — [Troubleshooting](TROUBLESHOOTING.md)
