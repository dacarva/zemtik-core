# Zemtik Architecture

**Document type:** Explanation + Reference  
**Audience:** Bank CISOs, enterprise security architects, and technical evaluators  
**Goal:** Understand how Zemtik guarantees zero raw data exfiltration to external AI systems  

**Scope note:** This document is aligned with **v0.6.0** (see `CHANGELOG.md`). The ZK slow-lane cryptography described here is unchanged in spirit from earlier releases; middleware around intent extraction, routing, and FastLane landed in v0.3.0–v0.4.0. v0.5.x adds timing instrumentation, Poseidon caching, outgoing prompt hash tracking, sidecar manifests, and a configurable `bb verify` timeout. v0.6.0 adds Supabase FastLane connector, configurable bind/CORS, multi-client support, `bb` process kill on timeout, and hardened Supabase defaults.

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
      ├── FastLane: in-memory SQLite sum → BabyJubJub attestation → EvidencePack → OpenAI
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
| `engine_fast.rs` | FastLane SUM + attestation |
| `evidence.rs` | `EvidencePack` for both engines |
| `db.rs` | SQLite / Supabase, seeding, signing, `sum_by_category`, category codes for circuit |
| `prover.rs` | `nargo` / `bb` subprocess pipeline |
| `verify.rs` / `bundle.rs` | Bundle ZIP + offline verification |
| `openai.rs` | Chat Completions client |
| `config.rs` | Layered config + schema load |
| `receipts.rs` | SQLite receipts (v3: adds `outgoing_prompt_hash`; v2: `engine_used`, `proof_hash`, `data_exfiltrated`, `intent_confidence`) |
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

Computes `SUM(amount)` for the resolved category and time window against the **demo in-memory SQLite ledger** (same seed data as the CLI demo). Produces a BabyJubJub attestation over the result; **no UltraHonk proof**. Fully concurrent; does not hold the global ZK `pipeline_lock`.

### 5. The Bank Ledger (`src/db.rs`)

`DB_BACKEND` selects storage:

- **`sqlite`** (default): in-memory SQLite for development, FastLane, and CLI demo.
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

### 7. The ZK Circuit (`circuit/src/main.nr`)

Noir 1.0.0-beta.19. One ACIR program processes **`BATCH_COUNT` = 10** batches of **`TX_COUNT` = 50** transactions (500 rows total). Each batch has its own Poseidon commitment and EdDSA signature (`BatchInput`).

**Public inputs:** `target_category`, `start_time`, `end_time`, `bank_pub_key_x`, `bank_pub_key_y`.  
**Private inputs:** `batches: [BatchInput; 10]` (rows + `sig_s`, `sig_r8_x`, `sig_r8_y` per batch).  
**Return value (public):** single `Field`, the sum of per-batch aggregates.

Per batch: reconstruct 4-level Poseidon tree → `eddsa_verify::<PoseidonHasher>` → branchless masked sum over the 50 rows.

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

**Proxy FastLane** replaces the last user message with a summary that includes an **`evidence`** object: engine name, `attestation_hash`, `schema_config_hash`, aggregate, `row_count`, `receipt_id`, `zemtik_confidence`, `outgoing_prompt_hash`, and `data_exfiltrated: 0`.

**Proxy ZK slow lane** injects the same compact summary into the last user message for the model, and adds the same top-level **`evidence`** object on the HTTP response as FastLane (ZK `proof_hash`, `engine_used`, `intent`, `outgoing_prompt_hash`, etc.). `outgoing_prompt_hash` is `None` when `fully_verifiable=false` (no proof artifact exists). Receipt metadata captures `proof_hash`, confidence, and `outgoing_prompt_hash` server-side.

In all cases, individual transaction amounts, timestamps, and client identifiers stay out of the outbound LLM payload.

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

4. **Query expressiveness:** Circuit is SUM with category + time window; other aggregates need new circuits.

5. **Public inputs sidecar:** Human-readable metadata in bundles is not separately committed inside the circuit (documented in verifier UX); rely on `bb verify` for proof / VK / binary public inputs.

6. **`bb verify` process cleanup:** `ZEMTIK_VERIFY_TIMEOUT_SECS` (default 120s) bounds how long the proxy waits for `bb verify`. A timeout returns HTTP 504 and kills and reaps the `bb` child process (fixed in v0.6.0 via `poll_child_with_timeout`). (Resolved: unbounded wait prior to v0.5.2; orphaned process prior to v0.6.0.)

7. **Universal category hash (Sprint 2):** The circuit uses a Poseidon BN254 hash of the table key string instead of a hardcoded integer code. Any table defined in `schema_config.json` can run the ZK slow lane without a code change. The hash is computed by `poseidon_of_string()` in `db.rs` and verified cross-language against Noir `bn254::hash_3`.

8. **FastLane data source:** FastLane uses the in-memory seeded SQLite ledger, not Supabase (see `CHANGELOG` / `CLAUDE.md`).

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
