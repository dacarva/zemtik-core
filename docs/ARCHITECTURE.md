# Zemtik Architecture

**Document type:** Explanation + Reference  
**Audience:** Bank CISOs, enterprise security architects, and technical evaluators  
**Goal:** Understand how Zemtik guarantees zero raw data exfiltration to external AI systems  

**Scope note:** This document is aligned with **v0.8.0** (see `CHANGELOG.md`). The ZK slow-lane cryptography described here is unchanged in spirit from earlier releases; middleware around intent extraction, routing, and FastLane landed in v0.3.0–v0.4.0. v0.5.x adds timing instrumentation, Poseidon caching, outgoing prompt hash tracking, sidecar manifests, and a configurable `bb verify` timeout. v0.6.0 adds Supabase FastLane connector, configurable bind/CORS, multi-client support, `bb` process kill on timeout, and hardened Supabase defaults. v0.7.0 adds the universal FastLane engine: any table in `schema_config.json` with `"sensitivity": "low"` automatically routes through FastLane; `AggFn` enum (SUM/COUNT); new `TableConfig` fields (`value_column`, `timestamp_column`, `category_column`, `agg_fn`, `metric_label`, `skip_client_id_filter`, `physical_table`); `attest_fast_lane()` public API; `signing_version: 2`; and fixes ISSUE-001 (`DB_BACKEND=sqlite` ignored when Supabase creds were set). v0.8.0 (Universal ZK Engine) adds `AggFn::Avg` (ZK composite: two sequential proofs + attestation), mini-circuit layout (`circuit/sum/`, `circuit/count/`, `circuit/lib/`), variable row-count padding with sentinel transactions, `actual_row_count` field replacing `row_count`, `evidence_version: 2` on all proxy responses, receipts DB v5 migration, and per-agg pipeline locks (SUM and COUNT run concurrently).

---

## The Problem Zemtik Solves

Financial institutions accumulate petabytes of transaction data that could generate competitive intelligence through AI analysis. The obstacle is contractual, regulatory, and fiduciary: raw ledger data cannot leave the enterprise perimeter. Sending individual transactions to a third-party LLM violates data residency rules, client confidentiality agreements, and in many jurisdictions, financial privacy law.

Existing workarounds (on-premises LLMs, data anonymization, synthetic data) involve substantial infrastructure cost, accuracy loss, or both.

Zemtik takes a different approach: **compute the answer locally, prove the computation was honest (or attest it on a lighter path), and send only the aggregate and provenance metadata to the LLM.**

---

## Core Guarantee

> **Zero raw transaction rows are transmitted to OpenAI at any point in the pipeline.**

What reaches the model is a deliberately small JSON summary: at minimum the aggregate metric, the category or table label, and a provenance tag (`ZEMTIK_VALID_ZK_PROOF` on the ZK path, `ZEMTIK_FAST_LANE_ATTESTATION` on FastLane). The proxy **merges a top-level `evidence` object** into the Chat Completions JSON returned to the client (serialized `EvidencePack` plus `engine` and `intent` summaries for tooling). The substituted user message to OpenAI still carries the same aggregate payload as before. None of these structures contain row-level ledger fields.

The mathematical mechanism for the **ZK slow lane** is described below. The **FastLane** path uses the same BabyJubJub EdDSA signing machinery over commitments, but skips full UltraHonk proof generation; it is gated to non-critical tables by policy in `schema_config.json`.

---

## Architecture Overview (ZK Slow Lane)

The diagram below is the trust boundary for **critical** queries: batches of signed transactions stay inside the perimeter until reduced to a single verified sum.

```
Bank Perimeter
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  ┌──────────────┐    sign     ┌───────────────────────┐    │
│  │  Transaction │ ──────────► │  Bank KMS (Mock)       │    │
│  │  DB (SQLite  │             │  BabyJubJub EdDSA      │    │
│  │  or Supabase)│             │  Poseidon hash tree    │    │
│  └──────────────┘             └───────────┬───────────┘    │
│         │                                 │                 │
│         │ raw rows (private)              │ signature       │
│         ▼                                 ▼                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Noir ZK Circuit                          │   │
│  │                                                       │   │
│  │  1. Verify EdDSA signature over transaction hash      │   │
│  │     assert(eddsa_verify(bank_pub_key, sig, hash))     │   │
│  │                                                       │   │
│  │  2. Aggregate: SUM(amount) WHERE category matches     │   │
│  │     AND timestamp IN [start, end]                     │   │
│  │                                                       │   │
│  │  Private witness: 10 batches × 50 rows, EdDSA/batch   │   │
│  │  Public output: verified aggregate (Field)            │   │
│  └──────────────────────────────────────────────────────┘   │
│                             │                               │
│                             │ $158,100  (one number)        │
└─────────────────────────────┼───────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  OpenAI API         │
                   │  (Chat Completions) │
                   │                     │
                   │  Payload (example): │
                   │  { category,        │
                   │    total_spend_usd, │
                   │    data_provenance }│
                   └─────────────────────┘
```

---

## Operational Modes

| Mode | Command | Role |
|------|---------|------|
| CLI pipeline | `cargo run` (default) | One-shot demo: seed 500 txs → batch sign → `nargo execute` → optional UltraHonk proof → OpenAI |
| Proxy | `cargo run -- proxy` | Axum server (default `:4000`): intercepts `POST /v1/chat/completions`, runs intent → router → FastLane or ZK slow lane |
| Verify | `cargo run -- verify <bundle.zip>` | Offline `bb verify` on a portable proof bundle |
| List | `cargo run -- list` | Prints recent rows from `~/.zemtik/receipts.db` (includes `intent_confidence` where present) |

External toolchain on PATH: **Noir** `nargo` (1.0.0-beta.19), **Barretenberg** `bb` (v4.x / UltraHonk; project docs use `v4.0.0-nightly`).

---

## Proxy Data Flow (v0.3+)

Natural-language prompts are interpreted **without calling an LLM** for routing. v0.4.0 adds an embedding-based matcher; v0.3.0 regex logic remains available as fallback.

```
POST /v1/chat/completions (user prompt)
  → Intent extraction (intent.rs: IntentBackend trait, no LLM)
      ├── EmbeddingBackend (default): fastembed + BGE-small-en ONNX, cosine similarity
      │     over schema index (table keys, aliases, descriptions, example_prompts)
      │     → DeterministicTimeParser (time_parser.rs) for time range
      │     → low confidence / ambiguous time → secure fallback toward ZK SlowLane
      └── RegexBackend (ZEMTIK_INTENT_BACKEND=regex or embed init failure):
            keyword / substring matching against schema
  → Routing (router.rs: sensitivity from schema_config.json)
      ├── FastLane: DB aggregate — SUM or COUNT (SQLite or Supabase) → BabyJubJub attestation → EvidencePack → OpenAI
      └── ZK SlowLane (critical tables or unknown table): full batch ZK pipeline → OpenAI
```

**Configuration:** `schema_config.json` lives at `~/.zemtik/schema_config.json` in normal deployments; `schema_config.example.json` is the template. Embedding mode expects each table to include `description` and `example_prompts`; missing fields warn and fall back to `RegexBackend`.

**Environment (intent):** `ZEMTIK_INTENT_BACKEND` (`embed` | `regex`, case-insensitive), `ZEMTIK_INTENT_THRESHOLD` (default cosine threshold 0.65).

---

## Source Module Map (`src/`)

| Module | Responsibility |
|--------|------------------|
| `main.rs` | CLI routing: pipeline, `proxy`, `verify`, `list` |
| `proxy.rs` | HTTP proxy, FastLane / ZK dispatch, receipt headers |
| `intent.rs` | `IntentBackend` trait, `RegexBackend`, dispatch to embed backend |
| `intent_embed.rs` | `EmbeddingBackend`, schema index, cosine match |
| `time_parser.rs` | `DeterministicTimeParser` (quarters, FY, months, relative, YTD, etc.) |
| `router.rs` | `FastLane` vs `ZkSlowLane` from table sensitivity |
| `engine_fast.rs` | FastLane: generic `aggregate_table()` (SUM or COUNT) → `attest_fast_lane()` (`signing_version: 2`) |
| `evidence.rs` | `EvidencePack` for both engines |
| `db.rs` | SQLite / Supabase, seeding, signing, `aggregate_table()` / `query_aggregate_table()` (generic SUM/COUNT; `sum_by_category` deprecated v0.7.0), category codes for circuit |
| `prover.rs` | `nargo` / `bb` subprocess pipeline |
| `verify.rs` / `bundle.rs` | Bundle ZIP + offline verification |
| `openai.rs` | Chat Completions client |
| `config.rs` | Layered config + schema load |
| `receipts.rs` | SQLite receipts (v5: adds `actual_row_count`; v3: `outgoing_prompt_hash`; v2: `engine_used`, `proof_hash`, `data_exfiltrated`, `intent_confidence`) |
| `keys.rs` | BabyJubJub key at `~/.zemtik/keys/bank_sk` (0600) |
| `types.rs` | `IntentResult`, `Route`, `EngineResult`, `EvidencePack`, … |
| `audit.rs` | JSON audit records under `audit/` |

Layered config order: defaults → `~/.zemtik/config.yaml` → env (`ZEMTIK_*`, `OPENAI_API_KEY`, `DB_BACKEND`, …) → CLI flags (`--port`, `--circuit-dir`).

---

## Component Deep-Dive

### 1. Configuration and schema (`config.rs`)

Runtime paths and API keys are merged from the layers above. Proxy mode **requires** a valid `schema_config.json` so tables have sensitivity, aliases, and fiscal-year settings. The embedding backend additionally indexes human-readable `description` and `example_prompts` per table.

### 2. Intent and time (`intent.rs`, `intent_embed.rs`, `time_parser.rs`)

- **Embedding path:** Builds a fixed schema index at startup, embeds the user prompt, returns the best-matching table key with a **confidence** score (`IntentResult.confidence`). Evaluated against `eval/labeled_prompts.json` via `cargo run --bin intent-eval --features eval` (release CI gate; see CHANGELOG for accuracy thresholds).
- **Regex path:** Deterministic keyword-style matching, no ONNX.
- **Time:** Parsed from the same prompt string; unrecognized time phrases yield `TimeRangeAmbiguous` and conservative routing.

Confidence flows into `EvidencePack.zemtik_confidence` and the `receipts` table (`intent_confidence`).

### 3. Routing (`router.rs`)

Each table declares sensitivity (e.g. `critical` vs `low`). **Critical** (and unknown tables, fail-secure) use the ZK slow lane. **Non-critical** tables use FastLane.

### 4. FastLane (`engine_fast.rs`)

Computes `SUM(value_column)` or `COUNT(value_column)` (controlled by `AggFn` in `TableConfig`) for the resolved category and time window. Works against both the **in-memory SQLite ledger** (`DB_BACKEND=sqlite`) and **Supabase PostgREST** (`DB_BACKEND=supabase`). The generic `aggregate_table()` / `query_aggregate_table()` functions accept any table defined in `schema_config.json` with `"sensitivity": "low"` — no code change required to add tables. `attest_fast_lane()` signs the `(aggregate, row_count)` pair with BabyJubJub EdDSA (`signing_version: 2`); **no UltraHonk proof**. Fully concurrent; does not hold the global ZK `pipeline_lock`.

### 5. The Bank Ledger (`src/db.rs`)

`DB_BACKEND` selects storage:

- **`sqlite`** (default): in-memory SQLite for development and CLI demo. FastLane uses this in local/dev mode.
- **`supabase`**: PostgreSQL via PostgREST + direct Postgres for DDL.

Production expectation: a read-only adapter to the bank’s real ledger.

**Schema (both backends):**

```sql
CREATE TABLE transactions (
    id        BIGINT PRIMARY KEY,
    client_id BIGINT NOT NULL,
    amount    BIGINT NOT NULL,    -- in USD
    category  BIGINT NOT NULL,    -- 1=Payroll, 2=AWS, 3=Coffee
    timestamp BIGINT NOT NULL     -- UNIX seconds
);
```

The POC seeds **500** transactions (10 batches × 50) for `client_id = 123` across Q1 2024. Both backends share `generate_seed_transactions()` so hashes and proofs stay reproducible.

### 6. The Bank KMS Mock (`src/db.rs`, batch signing)

Before use in the circuit, transaction batches are signed with **BabyJubJub EdDSA** and **Poseidon** commitments (same construction as the original POC). The commitment tree is documented in the Noir section below.

### 7. The ZK Circuits (`circuit/`)

Mini-circuit layout (v0.8.0). Three Noir packages:

| Directory | Purpose |
|-----------|---------|
| `circuit/sum/` | SUM mini-circuit — computes `SUM(amount)` per batch; used by SUM and AVG queries |
| `circuit/count/` | COUNT mini-circuit — computes `COUNT(non-null rows)` per batch; used by COUNT and AVG queries |
| `circuit/lib/` | Shared Noir library — Poseidon tree construction, EdDSA verify wrapper |

**Each mini-circuit** (Noir 1.0.0-beta.19) processes **`BATCH_COUNT` = 10** batches of **`TX_COUNT` = 50** transactions (500 rows total, padded with sentinel transactions when the actual result set is smaller). Each batch has its own Poseidon commitment and EdDSA signature (`BatchInput`).

**Public inputs (both circuits):** `target_category_hash`, `start_time`, `end_time`, `bank_pub_key_x`, `bank_pub_key_y`.  
**Private inputs:** `batches: [BatchInput; 10]` (rows + `sig_s`, `sig_r8_x`, `sig_r8_y` per batch).  
**Return value (public):** single `Field` — the aggregate across all 10 batches (total sum or total count).

Per batch: reconstruct 4-level Poseidon tree → `eddsa_verify::<PoseidonHasher>` → branchless masked accumulation over the 50 rows.

**AVG composite:** `proxy.rs` runs the SUM circuit then the COUNT circuit sequentially (under separate per-agg locks), then computes `avg = sum / count` in Rust and signs the triple `(sum, count, avg)` with BabyJubJub. The response includes `sum_proof_hash`, `count_proof_hash`, and `avg_evidence_model: "zk_composite+attestation"`.

### 8. The Noir Pipeline (`src/prover.rs`)

| Command | Purpose |
|---------|---------|
| `nargo compile` | ACIR bytecode |
| `nargo execute` | Witness + full constraint satisfaction |
| `bb prove` (UltraHonk) | ZK proof |
| `bb verify` | Verifies proof + VK |

`nargo execute` alone is a complete soundness check for the constraints; proof generation may be skipped or fail on CRS limits while execute still succeeds.

### 9. Receipts, Bundles, and Verify (`receipts.rs`, `bundle.rs`, `verify.rs`)

ZK slow lane writes portable ZIP bundles under `~/.zemtik/receipts/` and rows in `receipts.db` (engine used, proof hash, prompt/request hashes, `intent_confidence` in v2, `outgoing_prompt_hash` in v3). Bundles at `bundle_version >= 2` include a `manifest.json` sidecar (SHA-256 of `public_inputs_readable.json`); `zemtik verify` enforces manifest presence for these bundles. **`cargo run -- verify`** replays `bb verify` on a bundle. The HTTP proxy also exposes a receipt viewer route for bundle ids (see `proxy.rs`).

### 10. The OpenAI Client (`src/openai.rs` and proxy injection)

**CLI pipeline** sends a JSON payload including `period_start` / `period_end` and `data_provenance: "ZEMTIK_VALID_ZK_PROOF"` (see `openai.rs`).

**Proxy FastLane** replaces the last user message with a summary that includes an **`evidence`** object: engine name, `attestation_hash`, `schema_config_hash`, aggregate, `actual_row_count`, `receipt_id`, `zemtik_confidence`, `outgoing_prompt_hash`, `evidence_version: 2`, and `data_exfiltrated: 0`.

**Proxy ZK slow lane** injects the same compact summary into the last user message for the model, and adds the same top-level **`evidence`** object on the HTTP response as FastLane (ZK `proof_hash`, `engine_used`, `intent`, `outgoing_prompt_hash`, etc.). `outgoing_prompt_hash` is `None` when `fully_verifiable=false` (no proof artifact exists). Receipt metadata captures `proof_hash`, confidence, and `outgoing_prompt_hash` server-side.

In all cases, individual transaction amounts, timestamps, and client identifiers stay out of the outbound LLM payload.

---

---

## Data Ingestion & Aggregation: From SQL to Zero-Knowledge

This section walks through exactly what happens when Zemtik processes a real query against a real database — from the SQL schema through to the payload sent to the LLM. No magic.

### Step 0: Schema Conformance

v1 requires your table to expose five columns with these exact names and types. Additional columns (PII, metadata, signatures) are harmlessly ignored.

```sql
-- Your enterprise table. Zemtik only touches the five columns below.
CREATE TABLE transactions (
    id            BIGINT PRIMARY KEY,
    client_id     BIGINT        NOT NULL,  -- tenant / cost-centre identifier
    amount        BIGINT        NOT NULL,  -- integer currency units (e.g. USD cents)
    category_name VARCHAR(93)   NOT NULL,  -- must match a key in schema_config.json
    timestamp     BIGINT        NOT NULL,  -- UNIX epoch seconds

    -- Everything below is ignored by Zemtik's query — it never appears in SELECT
    user_name     TEXT,                    -- PII: never read, never signed, never sent
    description   TEXT,                    -- free-text: same
    db_signature  TEXT                     -- your own DB-level integrity field: same
);
```

The `category_name` values must match the keys you declare in `schema_config.json`. Zemtik converts each key to a BN254 field element via `poseidon_of_string(key)` — trim + lowercase → three 31-byte chunks → `bn254::hash_3`. The Noir circuit receives this hash as a public input and uses it to filter rows without ever seeing the string itself.

**The only SQL Zemtik executes is:**

```sql
-- FastLane (aggregate only — no rows ever leave the DB layer):
-- Query shape is controlled by TableConfig: agg_fn (SUM/COUNT), value_column,
-- timestamp_column, category_column, and skip_client_id_filter.
-- Example for a SUM table with category and client_id filters:
SELECT SUM(amount), COUNT(*)
FROM   transactions
WHERE  category_name = $1          -- only when category_column is set
  AND  timestamp     >= $2         -- UNIX seconds from DeterministicTimeParser
  AND  timestamp     <= $3
  AND  client_id     = $4;         -- omitted when skip_client_id_filter=true

-- ZK SlowLane (fetches rows for private-witness construction):
SELECT amount, category_name, timestamp
FROM   transactions
WHERE  client_id = $1
ORDER  BY id
LIMIT  500;                        -- hard limit: circuit accepts exactly 500 rows
```

### Step 1 (Fast Lane) — "What is the total marketing spend last quarter?"

Concretely, this is what executes at each layer.

**1. Intent extraction** (`src/intent.rs`, `src/intent_embed.rs`)

The proxy receives `POST /v1/chat/completions` with `"content": "What is the total marketing spend last quarter?"`.

- EmbeddingBackend encodes the prompt via BGE-small-en ONNX and runs cosine similarity over the schema index.
- `DeterministicTimeParser` (`src/time_parser.rs`) extracts `"last quarter"` → Q4 2025 → `(1727740800, 1735689599)` Unix seconds.
- Returns: `IntentResult { table: "marketing", time_range: (1727740800, 1735689599), confidence: 0.89 }`

**2. Routing** (`src/router.rs`)

```rust
// schema_config.json: "marketing": { "sensitivity": "low", ... }
decide_route(&intent, &schema) // → Route::FastLane
```

**3. Database query** (`src/db.rs::aggregate_table`)

The query is built dynamically from `TableConfig` (`value_column`, `timestamp_column`, `category_column`, `agg_fn`). For a SUM table with a category column this looks like:

```sql
SELECT SUM(amount), COUNT(*)
FROM   transactions
WHERE  category_name = 'marketing'
  AND  timestamp >= 1727740800
  AND  timestamp <= 1735689599
  AND  client_id = 123;
-- → (41200000, 47)   -- $412,000.00 in cents; 47 matching rows
```

For a COUNT table with `skip_client_id_filter: true` and no `category_column` (e.g. `new_hires`), the query omits those filters and uses `COUNT(employee_id)` instead.

Individual rows, `user_name`, and `description` are **never fetched**.

**4. Attestation** (`src/engine_fast.rs::attest_fast_lane`)

```
SHA-256("marketing" || 1727740800_le || 1735689599_le || 41200000_le || 47_le || now_le)
  → 32-byte payload hash

BabyJubJub EdDSA sign(bank_sk, payload_hash)
  → (sig_r8_x, sig_r8_y, sig_s)

attestation_hash = SHA-256(sig_r8_x || sig_r8_y || sig_s)
```

**5. OpenAI payload (what actually crosses the perimeter)**

```json
{
  "role": "user",
  "content": "The verified aggregate for marketing (Q4 2025) is $412,000.\nEvidence: { \"engine\": \"fastlane\", \"aggregate\": 412000, \"row_count\": 47, \"data_exfiltrated\": 0, \"attestation_hash\": \"a3f9...\" }"
}
```

What is **not** in the payload: no `user_name`, no individual transaction amounts, no timestamps, no account identifiers.

Total latency: **< 50 ms**.

---

### Step 2 (ZK Slow Lane) — "What is the total payroll this quarter?"

**1. Intent + routing**

Same extraction as above. `schema_config.json` has `"payroll": { "sensitivity": "critical" }`.

```rust
decide_route(&intent, &schema) // → Route::ZkSlowLane
```

**2. Fetch private witnesses** (`src/db.rs::query_transactions`)

```sql
SELECT amount, category_name, timestamp
FROM   transactions
WHERE  client_id = 123
ORDER  BY id
LIMIT  500;
-- Returns up to 500 rows — the hard circuit limit.
-- If your query window contains > 500 rows the pipeline will error.
-- See SCALING.md for the production multi-batch path.
```

Rows stay **inside the Rust process** as in-memory structs. They are private witnesses — never written to disk, never sent over the network.

**3. Category hash** (`src/db.rs::poseidon_of_string`)

```
"payroll"
  → trim + lowercase → b"payroll" (7 bytes)
  → zero-pad to 3 × 31-byte chunks: [chunk0=b"payroll\x00...", chunk1=0, chunk2=0]
  → bn254::hash_3([chunk0, chunk1, chunk2])
  → Field(0x1d3f...)   ← target_category_hash (PUBLIC input to circuit)
```

**4. Batch signing** — 500 rows → 10 batches of 50 (`src/db.rs::sign_transaction_batches`)

For each batch:

```
L1: hash_3([amount_i, category_hash_i, timestamp_i])  × 50 rows
L2: hash_5([L1[0..4]]),  hash_5([L1[5..9]]),  …       × 10
L3: hash_5([L2[0..4]]),  hash_5([L2[5..9]])            × 2
L4: hash_2([L3[0], L3[1]])                             → batch_commitment

sig = EdDSA_sign(bank_sk, batch_commitment)
    → (sig_s, sig_r8_x, sig_r8_y)
```

**5. Witness file** (`src/prover.rs::generate_batched_prover_toml`) — written to a temp run directory, never persisted to `~/.zemtik/`

```toml
# Public inputs — visible to the verifier
target_category_hash = "8029374..."
start_time           = "1735689600"
end_time             = "1743465599"
bank_pub_key_x       = "11559732..."
bank_pub_key_y       = "17671386..."

# Private inputs — hidden from the verifier, never leave the process
[[batches]]
sig_s    = "2819374..."
sig_r8_x = "9182736..."
sig_r8_y = "1029384..."

[[batches.transactions]]
amount    = "12500000"    # $125,000.00 in cents
category  = "8029374..."  # poseidon_of_string("payroll") — same as target
timestamp = "1735689601"

[[batches.transactions]]
amount    = "7500000"     # $75,000.00
category  = "8029374..."
timestamp = "1735689602"
# ... 48 more rows in this batch; 9 more batches follow
```

**6. Noir circuit** (`circuit/src/main.nr`)

For each of the 10 batches, `process_batch()`:

1. Rebuilds the identical 4-level Poseidon commitment tree from the private transaction rows.
2. Runs `assert(eddsa_verify(bank_pub_key_x, bank_pub_key_y, sig_s, sig_r8_x, sig_r8_y, batch_commitment))`. If the data was tampered with, this assertion fails and no valid witness exists.
3. Accumulates a branchless masked sum:
   ```noir
   total += if (tx.category == target_category_hash)
               & (tx.timestamp >= start_time)
               & (tx.timestamp <= end_time)
            { tx.amount as Field } else { 0 };
   ```

`main()` sums the 10 partial aggregates and returns a single public `Field`.

**7. Proof generation**

```bash
nargo execute   # constraint check + witness; returns aggregate as hex
bb prove        # UltraHonk proof (728k gates, ~17s on CPU)
bb verify       # local soundness check before forwarding to OpenAI
```

**8. OpenAI payload (what actually crosses the perimeter)**

```json
{
  "role": "user",
  "content": "The ZK-verified aggregate for payroll (Q1 2025) is $4,250,000.\nEvidence: { \"engine\": \"zk_slowlane\", \"aggregate\": 4250000, \"data_exfiltrated\": 0, \"proof_hash\": \"7c3a...\" }"
}
```

**What the verifier (and OpenAI) learns:** the aggregate ($4,250,000), the category name, the time range, and the proof hash. **What stays private:** every individual payroll amount, every employee's `user_name`, every transaction timestamp, the batch signatures, and the private key.

---

### Step 3: Database Connectivity — What "Supabase" Actually Means

Zemtik v1 supports two `DB_BACKEND` values:

| `DB_BACKEND` | What it connects to | Use case |
|---|---|---|
| `sqlite` (default) | In-memory SQLite seeded with 500 demo rows | Local development, CLI demo |
| `supabase` | Your PostgreSQL via PostgREST REST API | Integration testing, early production |

**`DB_BACKEND=supabase` is not a raw Postgres connection.** It speaks the PostgREST HTTP protocol. Required env vars:

```bash
SUPABASE_URL=https://your-project.supabase.co   # PostgREST base URL
SUPABASE_SERVICE_KEY=eyJhbGci...                # Service-role JWT (Supabase dashboard → Settings → API)
```

If you are running your own Postgres (not Supabase), you need PostgREST deployed in front of it. The Zemtik Rust process never opens a raw Postgres socket in v1.

**Schema conformance:** The five required columns (`id`, `client_id`, `amount`, `category_name`, `timestamp`) must exist with those exact names. Zemtik does not do schema introspection or column aliasing. If your table uses `category_code` instead of `category_name`, you must add the column or rename it before connecting.

> **Roadmap:** A native `sqlx`-based Postgres connector (`DB_BACKEND=postgres`) that accepts a `DATABASE_URL` and a column-mapping config is planned for v2. Until then, self-hosted PostgREST is the integration path for non-Supabase deployments.

---

## Data Flow: CLI Pipeline (Default `cargo run`)

```
1. `AppConfig::load()` (config layers + paths)

2. `db::init_db()` → `query_transactions(client 123)` → 500 rows, 10 batches of 50

3. `keys::load_or_generate_key()`

4. `db::sign_transaction_batches()` (BabyJubJub EdDSA per batch)

5. `prover::generate_batched_prover_toml()`

6. `prover::compile_circuit()` (cached)

7. `prover::execute_circuit()` (constraint check + aggregate)

8. `prover::generate_proof()` + `prover::verify_proof()` (UltraHonk, CRS-dependent)

9. `bundle::generate_bundle()` + `receipts::insert_receipt()` when fully verifiable

10. `openai::query_openai(...)` (aggregate-only payload)

11. `audit::write_audit_record(...)`
```

Proxy mode replaces steps 2–10 with: **parse Chat Completions body → intent → router →** either FastLane handler or the same ZK pipeline as above keyed off extracted `IntentResult` (category + time range).

---

## Cryptographic Security Properties

### Soundness (ZK path)

A dishonest prover cannot forge a valid proof for a wrong aggregate without breaking the signature assumption on the Poseidon commitment: the witness must match a bank-signed message hash.

### Zero-knowledge

The proof reveals nothing about private rows beyond what public inputs and the aggregate imply.

### Completeness

Honest prover with valid signed data matching public inputs can produce a witness; proof generation additionally requires a sufficient CRS / `bb` environment.

### FastLane caveat

FastLane provides cryptographic attestation over the aggregate path, not a succinct ZK proof. Policy (`schema_config.json`) decides which queries are acceptable on that path.

---

## Technology Stack

| Component | Technology | Notes |
|-----------|------------|--------|
| ZK circuit | Noir | 1.0.0-beta.19 |
| Proof system | Barretenberg UltraHonk | `bb` v4.x (nightly in CI / README) |
| EdDSA (Noir) | noir-lang/eddsa | vendored constraints |
| Orchestrator | Rust | edition 2021 |
| DB | rusqlite / Supabase | `DB_BACKEND` |
| Signing | babyjubjub-rs, poseidon-rs | BN254-aligned |
| HTTP | axum, reqwest | Proxy + OpenAI |
| Intent (embed) | fastembed 5, BGE-small-en ONNX | Optional feature `embed`; `regex-only` build skips |
| Eval | `intent-eval` binary | Feature `eval`; labeled prompts in `eval/labeled_prompts.json` |

---

## Known Limitations

1. **CRS / proof generation:** The full 500-transaction circuit (10 signed batches) is large; local SRS may be insufficient for `bb prove`. `nargo execute` still validates all constraints. Production should pin SRS or use a proving service.

2. **Deterministic demo key:** Bank key is generated or loaded from disk for demos; production should use an HSM or KMS.

3. **Fixed batch geometry:** `TX_COUNT` and `BATCH_COUNT` are compile-time constants (currently 50 × 10 = 500 rows). Changing capacity requires recompiling the circuit and regenerating artifacts.

4. **Query expressiveness:** ZK SlowLane supports SUM, COUNT, and AVG (composite). AVG runs two sequential proofs (~40–120s). MIN/MAX, GROUP BY, and multi-table JOINs require new circuit variants and are not supported.

5. **Public inputs sidecar:** Human-readable metadata in bundles is not separately committed inside the circuit (documented in verifier UX); rely on `bb verify` for proof / VK / binary public inputs.

6. **`bb verify` process cleanup:** `ZEMTIK_VERIFY_TIMEOUT_SECS` (default 120s) bounds how long the proxy waits for `bb verify`. A timeout returns HTTP 504 and kills and reaps the `bb` child process (fixed in v0.6.0 via `poll_child_with_timeout`). (Resolved: unbounded wait prior to v0.5.2; orphaned process prior to v0.6.0.)

7. **Universal category hash (Sprint 2):** The circuit uses a Poseidon BN254 hash of the table key string instead of a hardcoded integer code. Any table defined in `schema_config.json` can run the ZK slow lane without a code change. The hash is computed by `poseidon_of_string()` in `db.rs` and verified cross-language against Noir `bn254::hash_3`.

8. **FastLane data source:** FastLane supports two backends. With `DB_BACKEND=sqlite` (default), it queries the in-memory seeded SQLite ledger via `aggregate_table()`. With `DB_BACKEND=supabase` (and `SUPABASE_URL` + `SUPABASE_SERVICE_KEY` set), it queries PostgREST via `query_aggregate_table()` and signs the aggregate. The Supabase path is now fully generic (SUM/COUNT, any table) as of v0.7.0. Note: `DB_BACKEND=supabase` must be set explicitly — having Supabase credentials without this env var keeps the SQLite path active (ISSUE-001 fix, v0.7.0).

9. **Embedding model:** First proxy start may download ~130MB ONNX to `~/.zemtik/models/`; air-gapped deploys can set `ZEMTIK_INTENT_BACKEND=regex`.

---

## Running the POC

```bash
# Prerequisites: nargo 1.0.0-beta.19, bb v4 (UltraHonk), Rust stable
cp .env.example .env
# Set OPENAI_API_KEY in .env or ~/.zemtik/config.yaml

cargo build --release

# Default: full CLI ZK pipeline (500 txs, Q1 2024, aws_spend category)
cargo run

# OpenAI-compatible proxy (needs ~/.zemtik/schema_config.json)
cargo run -- proxy

# Offline bundle check
cargo run -- verify path/to/bundle.zip

# Receipt ledger
cargo run -- list
```

**Typical CLI output shape:** `[DB]` ledger init, `[KMS]` batch signing, `[NOIR]` compile/execute, optional `[NOIR] Generating UltraHonk proof (bb v4, CRS auto-download)...`, `[AI]` with aggregate-only payload and `Raw rows sent to OpenAI: 0`.

For supported natural-language patterns in proxy mode, see `docs/SUPPORTED_QUERIES.md`.
