# Getting Started with Zemtik Core

**Document type:** Tutorial
**Audience:** Developers integrating Zemtik for the first time
**Goal:** Run the full ZK pipeline locally and send your first privacy-preserving query to OpenAI

---

By the end of this tutorial you will have:

1. Built Zemtik Core from source
2. Run the CLI demo — 500 transactions processed through a ZK circuit, result sent to OpenAI
3. Started the proxy and made your first OpenAI-compatible request with zero raw data exfiltration

> **What you will not do in this tutorial:** configure your own database tables or connect to Supabase. Those are covered in the how-to guides after you have the basics working.

---

## Prerequisites

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

> **Demo model:** The CLI pipeline uses `gpt-5.4-nano` as the model name. This is a placeholder used in the POC. For the OpenAI API call to succeed, update `MODEL` in `src/openai.rs` (or set the model in your proxy request) to a real model name such as `gpt-4o-mini`.

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
    "evidence_version": 2
  }
}
```

**`attestation_hash` explained:** SHA-256 of the BabyJubJub EdDSA signature over `(table_key, start_time, end_time, aggregate, row_count, timestamp)`. It cryptographically binds this specific aggregate result to your institution's signing key. It is stored in `receipts.db` for audit purposes.

> **FastLane does not generate a ZK proof.** The `attestation_hash` confirms that *someone with your signing key* produced this aggregate, but there is no circuit constraint proving the aggregate was computed from real database rows. See [Architecture](ARCHITECTURE.md#4-fastlane-engine_fastrs) for the full trust model.

The proxy logs in the server terminal show the routing decision:

```
[PROXY] Intent: table=aws_spend confidence=0.91 time=Q1 2024
[PROXY] Route:  FastLane (sensitivity=low)
[PROXY] Result: $2805600 — attestation_hash=a3f9...
```

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
  "evidence_version": 2,
  "engine": "ZkSlowLane",
  "proof_hash": "9a1b...",
  "actual_row_count": 47,
  "data_exfiltrated": 0
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
  "evidence_version": 2,
  "engine": "ZkSlowLane",
  "sum_proof_hash": "7b2c...",
  "count_proof_hash": "a3f9...",
  "avg": 56200,
  "sum": 2810000,
  "count": 50,
  "actual_row_count": 50,
  "avg_evidence_model": "zk_composite+attestation",
  "data_exfiltrated": 0
}
```

**Understanding the AVG evidence model:** AVG runs two independent ZK proofs — one for the SUM of all matching rows, one for the COUNT. Both proofs are verifiable with `zemtik verify <bundle.zip>`. The final division (`avg = sum / count`) is attested with a BabyJubJub EdDSA signature over the result. This is the same trust model as FastLane for the division step, with full UltraHonk guarantees on both operands.

> **Latency note:** The first AVG or COUNT query on a new table compiles the ZK circuit (~30-120s). The proxy logs `[PROXY] Compiling circuit...` while this happens. Subsequent requests reuse the compiled artifact. Set `ZEMTIK_INTENT_BACKEND=regex` if you want to skip the embedding model download on first proxy start.

---

## What's next

- **Configure your own tables** — [How to Add a Table](HOW_TO_ADD_TABLE.md)
- **Understand the routing and engines** — [Architecture](ARCHITECTURE.md)
- **Review all configuration options** — [Configuration Reference](CONFIGURATION.md)
- **Understand supported query patterns** — [Supported Queries](SUPPORTED_QUERIES.md)
