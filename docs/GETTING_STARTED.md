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

## Switching to Anthropic (Claude)

If your deployment requires Anthropic Claude instead of OpenAI, update three env vars and restart. No client code changes required — Zemtik translates OpenAI-format requests to Anthropic format internally.

**In your `.env` file:**

```bash
ZEMTIK_LLM_PROVIDER=anthropic
ZEMTIK_ANTHROPIC_API_KEY=sk-ant-...your-key-here...
ZEMTIK_ANTHROPIC_MODEL=claude-sonnet-4-6   # or your required version

# Required when using Anthropic — protects the proxy from unauthorized use.
# Any client reaching :4000 would otherwise get free API calls billed to your account.
ZEMTIK_PROXY_API_KEY=your-strong-random-secret
```

Verify at startup: the validation block shows `llm_provider: anthropic` and `llm_model: claude-sonnet-4-6`.

**Send a request:**

```bash
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ZEMTIK_PROXY_API_KEY" \
  -d '{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"What was our total AWS spend for Q1 2024?"}]}'
```

A successful response includes `"llm_provider": "anthropic"` and `"data_exfiltrated": 0` in the `evidence` block.

**Model substitution:** Zemtik replaces any non-Claude model name in your request (e.g. `gpt-5.4-nano`) with the value of `ZEMTIK_ANTHROPIC_MODEL`. Your client code does not need to change. The actual model used is recorded in `zemtik_meta.resolved_model` in every response.

**Auth asymmetry:** When using Anthropic, Zemtik uses `ZEMTIK_ANTHROPIC_API_KEY` for all outbound Claude calls. The `Authorization: Bearer` header your client sends to Zemtik is validated against `ZEMTIK_PROXY_API_KEY` — it is **not** forwarded to Anthropic. This is expected behavior.

**Check the configured model:**

```bash
curl -H "Authorization: Bearer $ZEMTIK_PROXY_API_KEY" http://localhost:4000/v1/models
# → {"object":"list","data":[{"id":"claude-sonnet-4-6","owned_by":"anthropic",...}]}
```

---

## Adding a Future Provider (e.g., Gemini)

Zemtik uses the `LlmBackend` trait (`src/llm_backend.rs`) to isolate provider-specific logic from the proxy. Adding a new provider — Gemini, Mistral, Bedrock, or any OpenAI-compatible endpoint — requires four steps and touches three files.

### Step 1 — Implement `LlmBackend`

Create `src/llm_backend_gemini.rs` (or add a struct to `llm_backend.rs`) and implement the trait:

```rust
use crate::llm_backend::LlmBackend;

pub struct GeminiBackend {
    client: reqwest::Client,
    api_key: String,      // from ZEMTIK_GEMINI_API_KEY
    model: String,        // from ZEMTIK_GEMINI_MODEL
    base_url: String,     // e.g. https://generativelanguage.googleapis.com
}

impl LlmBackend for GeminiBackend {
    fn complete<'a>(
        &'a self,
        body: &'a serde_json::Value,
        _api_key: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<(u16, serde_json::Value)>> {
        Box::pin(async move {
            // 1. Translate OpenAI message format → Gemini generateContent format
            let gemini_body = translate_to_gemini(body)?;

            // 2. Call Gemini API (key goes in query param or x-goog-api-key header)
            let url = format!(
                "{}/v1beta/models/{}:generateContent?key={}",
                self.base_url, self.model, self.api_key
            );
            let resp = self.client.post(&url).json(&gemini_body).send().await?;

            let status = resp.status();
            if !status.is_success() {
                let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| {
                    serde_json::json!({"error": {"type": "upstream_error"}})
                });
                return Ok((status.as_u16(), body));
            }

            let resp_body: serde_json::Value = resp.json().await?;

            // 3. Normalize to OpenAI response shape (same pattern as AnthropicBackend)
            let text = extract_gemini_text(&resp_body)?;
            let normalized = serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "object": "chat.completion",
                "model": self.model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "_zemtik_resolved_model": self.model,
            });
            Ok((200, normalized))
        })
    }
    // Optionally implement forward_raw() for streaming
}
```

Key invariants to follow (same as `AnthropicBackend`):

- Use `self.api_key` (operator key) for outbound calls — **never** the incoming `_api_key` argument.
- Return `_zemtik_resolved_model` in the normalized body; the proxy strips and injects it into `zemtik_meta.resolved_model`.
- Check `!status.is_success()` before parsing the body to handle non-JSON error payloads from the upstream (gateways sometimes return HTML 502).
- Return `(501, ...)` for any Gemini-specific capability (e.g., function calling, grounding) not yet supported instead of silently returning a 500.

### Step 2 — Wire into `config.rs`

Add new config fields alongside the existing Anthropic fields:

```rust
// src/config.rs
pub gemini_api_key: Option<String>,   // ZEMTIK_GEMINI_API_KEY
pub gemini_model: String,             // ZEMTIK_GEMINI_MODEL (default: gemini-2.0-flash)
pub gemini_base_url: String,          // ZEMTIK_GEMINI_BASE_URL
```

Populate them from env vars in the config loading block, following the same pattern as `anthropic_api_key`.

### Step 3 — Add the match arm in `proxy.rs`

In `build_llm_backend()` (or equivalent factory function in `proxy.rs`), add a match arm:

```rust
"gemini" => {
    let api_key = config.gemini_api_key.clone()
        .ok_or_else(|| anyhow!("ZEMTIK_GEMINI_API_KEY required when llm_provider=gemini"))?;
    Box::new(GeminiBackend::new(client, api_key, config.gemini_model.clone(), config.gemini_base_url.clone()))
}
```

At startup, follow the same hard-error pattern as Anthropic: if `llm_provider=gemini` and `ZEMTIK_GEMINI_API_KEY` is unset, refuse to start with a clear error. Do not silently fall back.

### Step 4 — Add env vars to `.env.example` and `CLAUDE.md`

Add to `.env.example`:

```bash
# Gemini backend (set ZEMTIK_LLM_PROVIDER=gemini to activate)
# ZEMTIK_GEMINI_API_KEY=AIza...
# ZEMTIK_GEMINI_MODEL=gemini-2.0-flash
# ZEMTIK_GEMINI_BASE_URL=https://generativelanguage.googleapis.com
```

Add to the env vars table in `CLAUDE.md` so future maintainers know the keys exist.

### OpenAI-compatible endpoints (simpler path)

If the provider exposes an OpenAI-compatible API (Together AI, Groq, Fireworks, local Ollama, etc.), no new backend struct is needed. Just use `OpenAiBackend` with a custom base URL:

```bash
ZEMTIK_LLM_PROVIDER=openai
ZEMTIK_OPENAI_BASE_URL=https://api.together.xyz
ZEMTIK_OPENAI_MODEL=meta-llama/Llama-3-70b-chat-hf
# Client's Bearer token is forwarded as-is (BYOK model)
```

This works because `OpenAiBackend` does not translate formats — it forwards the request verbatim to `${ZEMTIK_OPENAI_BASE_URL}/v1/chat/completions`.

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

## Step 4.5 — Anonymizer (PII tokenization)

This step is optional. Skip to Step 5 if you do not need PII masking.

The anonymizer replaces sensitive entities (names, organizations, locations) with opaque tokens of the form `[[Z:xxxx:n]]` before the prompt leaves the proxy. The LLM sees only tokens. The proxy deanonymizes the response before returning it to the caller, so your application receives plain text as normal.

Scope: single-turn only. The vault that maps tokens back to real values is cleared after each request. Multi-turn vault persistence is planned for Phase 2-3.

### Prerequisites — start the sidecar

The anonymizer runs a Python gRPC sidecar (GLiNER + Presidio) for entity recognition. The sidecar is not included in `docker-compose.yml` and must be started separately.

```bash
# Build the sidecar image (one-time)
# Must be run from the repo root (zemtik-core/) — the Dockerfile does
# COPY sidecar/ . which requires the repo root as the build context.
docker build -f sidecar/Dockerfile -t zemtik-sidecar .

# Run the sidecar (gRPC on port 50051)
docker run -p 50051:50051 zemtik-sidecar
```

The sidecar loads the GLiNER model on startup. Allow ~30 seconds before sending requests.

### Enable in the proxy

Add these three environment variables before starting the proxy:

```bash
export ZEMTIK_ANONYMIZER_ENABLED=true
export ZEMTIK_ANONYMIZER_SIDECAR_ADDR=http://127.0.0.1:50051
export ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true   # recommended: tokenizes structured PII if sidecar is unreachable

cargo run -- proxy
```

**Note on intent extraction:** When the anonymizer replaces PII (e.g. `"Jose Garcia"` → `[[Z:a1b2:0]]`), intent extraction runs on the **original** prompt to preserve embedding quality. Non-data queries that reference people (e.g. `"who is Jose Garcia?"`) will return `NoTableIdentified` — enable `ZEMTIK_GENERAL_PASSTHROUGH=1` to route those through the general lane instead.

### Verify it works

Send a query that contains a person name:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "What was Alice Johnson Q1 2024 AWS spend?"}]
  }'
```

The response includes a `zemtik_meta.anonymizer` block confirming what was found and tokenized:

```json
"zemtik_meta": {
  "anonymizer": {
    "entities_found": 1,
    "entity_types": ["PERSON"],
    "sidecar_used": true,
    "sidecar_ms": 48,
    "dropped_tokens": 0
  }
}
```

`dropped_tokens` counts tokens the deanonymizer could not resolve. A value of `0` means the response was fully deanonymized.

> ⚠️ **Check `sidecar_used`:** If `sidecar_used: false` appears in the block, the sidecar was unreachable and only regex patterns were active. PERSON, ORG, and LOCATION detection requires the sidecar. Named entities in the prompt were not anonymized. Verify the sidecar is running with `docker ps` and that `ZEMTIK_ANONYMIZER_SIDECAR_ADDR=http://127.0.0.1:50051` is set correctly.

### Preview anonymization without calling OpenAI

Use `POST /v1/anonymize/preview` to inspect what the anonymizer would produce for a given prompt, without running the ZK pipeline or calling OpenAI:

```bash
curl -X POST http://localhost:4000/v1/anonymize/preview \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "Contact Bob Smith at bob@acme.com"}]}'
```

The response shows the tokenized messages alongside the anonymizer audit metadata.

### Regex fallback

When `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true` and the sidecar is unreachable, the proxy falls back to a regex engine that tokenizes structured PII (emails, IDs, phone numbers). PERSON, ORG, and LOCATION entities require the sidecar and are skipped in fallback mode. The `sidecar_used` field in `zemtik_meta.anonymizer` will be `false` when the fallback runs.

> **Phase 1 limitations**
>
> - **Single-turn vault only.** The vault that maps tokens to original values is cleared after each request (removed via `scopeguard::defer!`). Tokens assigned in turn N are NOT available in turn N+1 — each request starts with a fresh vault. If you send a multi-turn conversation where the prior assistant message contains deanonymized text, that text will be re-anonymized on the next request.
> - Multi-turn vault persistence and shared-session deanonymization are Phase 2-3 features.
> - The sidecar is not in `docker-compose.yml`. You must start it manually as shown above.

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
  "human_summary": "Computed COUNT over 47 rows from 'headcount_low' inside a zero-knowledge circuit (UltraHonk proof). Raw records never left the institution's infrastructure. Proof is independently verifiable offline via `zemtik verify <bundle.zip>`.",
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
  "proof_hash": "7b2c...",
  "actual_row_count": 50,
  "data_exfiltrated": 0,
  "human_summary": "Computed AVG over 50 rows from 'deals' using two sequential zero-knowledge circuits (SUM + COUNT, each UltraHonk proof), then attested the division result with BabyJubJub EdDSA. Raw records never left the institution's infrastructure. Both proofs are independently verifiable offline via `zemtik verify <bundle.zip>`.",
  "checks_performed": ["intent_classification", "schema_sensitivity_check", "babyjubjub_signing", "poseidon_commitment", "ultrahonk_proof", "bb_verify_local", "ultrahonk_proof", "bb_verify_local", "babyjubjub_attestation"]
}
```

**Understanding the AVG evidence model:** AVG runs two independent ZK proofs — one for the SUM of all matching rows, one for the COUNT. Both proofs are verifiable with `zemtik verify <bundle.zip>`. The final division (`avg = sum / count`) is attested with a BabyJubJub EdDSA signature over the result. This is the same trust model as FastLane for the division step, with full UltraHonk guarantees on both operands.

> **Latency note:** The first AVG or COUNT query on a new table compiles the ZK circuit (~30-120s). The proxy logs `[PROXY] Compiling circuit...` while this happens. Subsequent requests reuse the compiled artifact. Set `ZEMTIK_INTENT_BACKEND=regex` if you want to skip the embedding model download on first proxy start.

---

## Step 7 — View your audit trail

Every query sent through the proxy (Steps 5 and 6) produces a receipt in the local SQLite database at `~/.zemtik/receipts.db`. Three ways to inspect it:

### `zemtik list`

```bash
zemtik list
```

Expected output after at least one proxy query:

```
Receipt ID                              Engine                Status                  Conf      Created At
------------------------------------------------------------------------------------------------------------------------
3f7a1c2e-...                            fast_lane             FAST_LANE_ATTESTED      0.91      2026-04-16T10:23:44Z

1 receipt(s) total.
```

Docker users:

```bash
docker compose exec zemtik zemtik list
```

> No receipts appear until at least one proxy query has been sent (Steps 5 or 6).

### `/receipts` — browser audit list

Open a full audit trail of every query the proxy has handled:

```
http://localhost:4000/receipts
```

The page shows up to 100 most recent receipts with a "Showing N of M total" banner at the top. Each row displays a truncated receipt ID (linked to the detail page), engine badge (`ZK VALID` / `FastLane` / `General`), table name, aggregate with thousands separators, and timestamp. Refreshes on each page load.

### `/verify/{receipt_id}` — browser receipt detail

Copy the `receipt_id` from the `evidence` block in any Step 5 or Step 6 response, then open it in a browser:

```
http://localhost:4000/verify/<receipt_id>
```

For receipts generated by v0.13.4 or later (which store a full `evidence_json` snapshot in `receipts.db`), the page shows:

- **Proof status badge** — `VALID` (ZK SlowLane) or `FAST LANE ATTESTED` (FastLane)
- **Verified aggregate** — formatted with thousands separators (e.g. `$2,805,600`)
- **Table** — extracted from `human_summary`
- **Summary** — the `human_summary` plain-language description from the Evidence Pack
- **Checks Performed** — ordered list of every cryptographic check that ran
- **Attestation Hash** — the BabyJubJub EdDSA attestation hash (FastLane) or circuit/bb metadata (ZK SlowLane)
- **Evidence Pack JSON** — collapsible raw JSON accordion with the full `EvidencePack`
- **Back link** — returns to `/receipts`

For receipts from before v0.13.4 (no `evidence_json` column), the page falls back to reading the ZK bundle file and displays proof status, aggregate, and category from the bundle's `public_inputs_readable.json`.

Works in both source and Docker modes. The host and port match wherever the proxy is bound (`ZEMTIK_BIND_ADDR`).

### Proxy logs

**Source build:** Logs are already streaming in the terminal running `cargo run -- proxy`. Look for `[PROXY]`-prefixed lines — the same output shown in Step 5.

**Docker:** Stream proxy stdout with:

```bash
docker compose logs -f
```

### CLI pipeline audit files

Step 3 (`cargo run`) writes a complete JSON audit record to `audit/<timestamp>.json`. See the "What just happened" bullets in Step 3 for a breakdown of every field in that file.

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

## MCP Attestation Proxy (Claude Desktop)

Zemtik ships an MCP server (`zemtik mcp` / `zemtik mcp-serve`) that wraps every tool call with BabyJubJub EdDSA attestation. This lets Claude Desktop users run audited, SSRF-safe tool execution without routing chat through the Zemtik proxy.

### Available tools

| Tool | Description |
|------|-------------|
| `zemtik_fetch` | HTTP GET a URL with SSRF guard (blocks private IPs, IMDS, RFC 1918) |
| `zemtik_read_file` | Read a file with key-file protection and 10 MB cap |
| `zemtik_analyze` | Tokenize PII before Claude reasons on it (requires `ZEMTIK_ANONYMIZER_ENABLED=1`) |

### Quick start (Docker)

```bash
# In .env
ZEMTIK_MCP_API_KEY=$(openssl rand -hex 32)
ZEMTIK_ANONYMIZER_ENABLED=true   # enables zemtik_analyze tool

# Start MCP server + anonymizer sidecar
ZEMTIK_ANONYMIZER_ENABLED=true docker compose --profile anonymizer --profile mcp up -d

# Verify health
curl http://localhost:4001/mcp/health
```

### Claude Desktop integration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "zemtik-docker": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:4001/mcp"]
    }
  }
}
```

Fully quit and relaunch Claude Desktop. The tools appear in the composer tool list.

### `zemtik_analyze` — PII soft enforcement

When `ZEMTIK_ANONYMIZER_ENABLED=1`, `zemtik_analyze` is exposed and Claude Desktop is steered via the MCP `instructions` string to call it before reasoning on user-pasted documents.

**What it does:**
- Accepts raw text (max 100 KB)
- Runs through the GLiNER/Presidio anonymizer sidecar (regex fallback if sidecar unavailable)
- Returns `{"anonymized_text": "...", "entities_found": N, "entity_types": [...]}`
- Attests the transformation (`sha256(raw)` + `sha256(tokenized)`) with BabyJubJub EdDSA
- Persists an audit record in `mcp_audit.db`

**Constraints:**
- Tokens (`[[Z:xxxx:n]]`) are stable **within one call only** — vault is discarded after each invocation and never returned to Claude
- Regex fallback covers structured PII only (emails, IBANs, LATAM IDs) — not PERSON/ORG names

**Test prompt for Claude Desktop:**
```
Summarize this contract: "Juan Carlos López (CC 1020304050) from Bogotá
agrees to pay $5,200,000 COP starting March 1, 2024."
```
Expected: Claude calls `zemtik_analyze` first, then summarizes using only `[[Z:...:n]]` tokens.

**Verify the audit trail:**
```bash
curl -s -H "Authorization: Bearer $ZEMTIK_MCP_API_KEY" http://localhost:4001/mcp/audit
```

### Why Claude Desktop chat is NOT anonymized

Claude Desktop sends chat directly to `api.anthropic.com` — it bypasses the Zemtik proxy entirely. `zemtik_analyze` is soft enforcement: Claude follows the instruction but a user can type a normal message to bypass it.

For hard enforcement (all traffic anonymized), use a web client (e.g. Open WebUI) pointed at the Zemtik proxy on `localhost:4000` with `ZEMTIK_ANONYMIZER_ENABLED=true`.

---

## What's next

- **Configure your own tables** — [How to Add a Table](HOW_TO_ADD_TABLE.md)
- **Understand the routing and engines** — [Architecture](ARCHITECTURE.md)
- **Review all configuration options** — [Configuration Reference](CONFIGURATION.md)
- **Understand supported query patterns** — [Supported Queries](SUPPORTED_QUERIES.md)
- **Troubleshoot issues on-site** — [Troubleshooting](TROUBLESHOOTING.md)
