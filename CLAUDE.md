# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming → invoke office-hours
- Bugs, errors, "why is this broken", 500 errors → invoke investigate
- Ship, deploy, push, create PR → invoke ship
- QA, test the site, find bugs → invoke qa
- Code review, check my diff → invoke review
- Update docs after shipping → invoke document-release
- Weekly retro → invoke retro
- Design system, brand → invoke design-consultation
- Visual audit, design polish → invoke design-review
- Architecture review → invoke plan-eng-review
- Write Rust code → invoke rust-best-practices
- Write zk circuits in Noir - → invoke noir-idioms

## Testing conventions

Write tests in the `tests/` directory, not inline in `src/`. Inline `#[cfg(test)]` modules are only acceptable when tests must access private functions or types that cannot be exposed. In all other cases, add tests to the appropriate `tests/test_<module>.rs` file (or create one if it doesn't exist). New test files follow the naming convention `test_<module>.rs` and import via `use zemtik::<module>::<item>`.

## Commands

```bash
# Build
cargo build --release

# Run (CLI pipeline mode — default)
cargo run

# Run proxy mode (OpenAI-compatible HTTP server on :4000)
cargo run -- proxy

# Verify a proof bundle offline
cargo run -- verify <bundle.zip>

# List recent receipts
cargo run -- list

# Tests
cargo test

# Install binary to ~/.local/bin and set up ~/.zemtik/
./install.sh
```

External tools required on PATH: `nargo` (Noir 1.0.0-beta.19), `bb` (Barretenberg v4.0.0-nightly).

## Architecture

Zemtik Core is a **Rust + Noir ZK middleware** that enforces zero-knowledge proofs on enterprise data before allowing LLM queries. It runs in three modes:

| Mode | Entry point | What it does |
|------|-------------|--------------|
| CLI pipeline | `cargo run` | One-shot: seed 500 txs → sign → prove → verify → call OpenAI |
| Proxy | `cargo run -- proxy` | Axum HTTP server on `:4000`; intercepts `POST /v1/chat/completions`, extracts intent → routes to FastLane or ZK SlowLane → forwards sanitized request |
| Verify | `cargo run -- verify <bundle.zip>` | Offline bundle verification via `bb verify` |
| List | `cargo run -- list` | List recent receipts from `~/.zemtik/receipts.db` |

### Proxy Data Flow (v0.4+)

```
POST /v1/chat/completions (user prompt)
  → Intent extraction (intent.rs — IntentBackend trait dispatch, no LLM)
      ├── EmbeddingBackend (default): fastembed BGE-small-en ONNX, cosine similarity
      │     → DeterministicTimeParser (time_parser.rs) for time range extraction
      │     → confidence < threshold or low margin → Err(NoTableIdentified) → ZK SlowLane
      │     → unrecognized time token → Err(TimeRangeAmbiguous) → ZK SlowLane
      └── RegexBackend (fallback if model unavailable): keyword/.contains() matching
  → Routing decision (router.rs — schema_config.json sensitivity)
      ├── FastLane (low sensitivity): DB sum → BabyJubJub attestation → EvidencePack
      └── ZK SlowLane (critical sensitivity):
            Raw Transactions (private witnesses, never leave the host)
              → BabyJubJub EdDSA signing (per batch of 50)
              → Noir circuit: Poseidon commitment verification + aggregation
              → UltraHonk proof (bb v4 / Barretenberg)
              → Proof verified locally ✓
              → Aggregate only → OpenAI
```

### Source Modules (`src/`)

| File | Role |
|------|------|
| `main.rs` | Pipeline orchestrator; CLI arg parsing; routes to proxy / verify / list / pipeline |
| `proxy.rs` | Axum HTTP server; `POST /v1/chat/completions` interception; FastLane + ZK dispatch |
| `intent.rs` | `IntentBackend` trait + `RegexBackend` (fallback); dispatches to embedding or regex backend |
| `intent_embed.rs` | `EmbeddingBackend` (fastembed + BGE-small-en ONNX, CPU-only); schema index builder; cosine similarity |
| `time_parser.rs` | `DeterministicTimeParser` — Q/H/FY/MMM/relative/YTD patterns; unrecognized → `TimeRangeAmbiguous` |
| `router.rs` | Routing decision: `schema_config.json` sensitivity → `FastLane` or `ZkSlowLane` |
| `engine_fast.rs` | FastLane: DB SUM → BabyJubJub attestation (no ZK, fully concurrent) |
| `evidence.rs` | Builds `EvidencePack` for both engine paths (attestation_hash or proof_hash) |
| `db.rs` | DB abstraction (SQLite + Supabase); transaction seeding; EdDSA signing; `sum_by_category` |
| `prover.rs` | Subprocess management for `nargo compile`, `nargo execute`, `bb generate` |
| `verify.rs` | Proof bundle extraction + `bb verify` invocation |
| `bundle.rs` | ZIP bundle creation for portable proofs |
| `openai.rs` | OpenAI Chat Completions API client |
| `config.rs` | Layered config + `SchemaConfig` / `TableConfig` loading from `schema_config.json` |
| `receipts.rs` | SQLite receipts ledger (CRUD + v3 migration: adds `outgoing_prompt_hash`; v2: `engine_used`, `proof_hash`, `data_exfiltrated`, `intent_confidence`) |
| `keys.rs` | BabyJubJub key generation + persistence (`~/.zemtik/keys/bank_sk`, mode 0600) |
| `types.rs` | Shared types: `Transaction`, `AuditRecord`, `IntentResult`, `Route`, `EngineResult`, … |
| `audit.rs` | JSON audit record writer → `audit/` directory |

### ZK Circuit (`circuit/`)

Written in Noir. Verifies Poseidon commitments for each signed batch and aggregates the result. Vendored EdDSA library lives in `vendor/eddsa/`.

### Configuration

Layered resolution order (later overrides earlier):

1. Hardcoded defaults (`~/.zemtik/` subdirs: `circuit/`, `runs/`, `keys/`, `receipts/`, `receipts.db`, `zemtik.db`)
2. YAML file (`~/.zemtik/config.yaml`)
3. Environment variables (`ZEMTIK_*` prefix, plus `OPENAI_API_KEY`, `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `DB_BACKEND`, `ZEMTIK_INTENT_BACKEND` (`embed`|`regex`), `ZEMTIK_INTENT_THRESHOLD`, `ZEMTIK_VERIFY_TIMEOUT_SECS` (default 120), `ZEMTIK_CLIENT_ID` (default 123), `ZEMTIK_BIND_ADDR` (default `127.0.0.1:4000`), `ZEMTIK_CORS_ORIGINS` (comma-separated; `*` for wildcard))
4. CLI flags (`--port`, `--circuit-dir`)

Copy `.env.example` to `.env` and set `OPENAI_API_KEY` at minimum for end-to-end runs.

### Database backends

- **SQLite** (default) — auto-seeded in-memory on first run; path `~/.zemtik/zemtik.db`
- **Supabase** — set `DB_BACKEND=supabase`; schema in `supabase/migrations/`; set `SUPABASE_AUTO_CREATE_TABLE=1` to create the table on startup (default: `false`); set `SUPABASE_AUTO_SEED=1` to insert 500 demo rows (default: `false` — prevents accidental writes to client production databases)

### Release / CI

GitHub Actions (`release.yml`) runs the intent eval gate (`cargo run --bin intent-eval --features eval`) before cross-compiling for `x86_64-linux`, `aarch64-darwin` on version tags (`v*`). Archives include binary + `install.sh` + `config.example.yaml`. (`aarch64-linux` and `x86_64-darwin` removed in v0.6.0 due to `ort-sys` ABI mismatch.)

## Key constraints and known gaps

- CLI pipeline query is hardcoded (500 txs, client 123, `aws_spend`, Q1 2024). Proxy mode supports natural-language queries via `schema_config.json`-defined tables.
- `schema_config.json` required in proxy mode — copy `schema_config.example.json` to `~/.zemtik/schema_config.json`. Tables must include `description` and `example_prompts` fields for the embedding backend.
- FastLane always uses the in-memory seeded SQLite ledger (Supabase FastLane connector deferred to v2).
- The ZK slow lane supports any table key via Poseidon BN254 hashing (Sprint 2). No code change needed — just add the table to `schema_config.json` with `"sensitivity": "critical"`.
- `bb verify` has a configurable timeout (`ZEMTIK_VERIFY_TIMEOUT_SECS`, default 120s); returns HTTP 504 on expiry. On timeout, the `bb` child process is killed and reaped (fixed in v0.6.0).
- `--no-verify` hook bypass and force-push to main are never acceptable.
- Public inputs sidecar is not cryptographically committed (known limitation, tracked).
- EmbeddingBackend downloads BGE-small-en model (~130MB) on first proxy start to `~/.zemtik/models/`. Set `ZEMTIK_INTENT_BACKEND=regex` to skip. First start can take 30–120s.
- `IntentBackend` trait: `index_schema(&mut self, schema)` called once at startup; `match_prompt(&self, prompt, k)` returns sorted `Vec<(table_key, score)>`. Add new backends by implementing this trait.
