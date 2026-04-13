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

Integration tests live in `tests/integration_proxy.rs` (proxy/FastLane/ZK routing, CORS, `/health`) and `tests/integration_tunnel.rs` (tunnel mode: FORK 1 passthrough, FORK 2 background verification, audit endpoints, match status, dashboard auth). Both spin up the full Axum router with a mock OpenAI server and require `ZEMTIK_SKIP_CIRCUIT_VALIDATION=1`. Run them with `cargo test --test integration_proxy` and `cargo test --test integration_tunnel`.

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

# List recent tunnel audit records (tunnel mode only)
cargo run -- list-tunnel

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
| Tunnel | `ZEMTIK_MODE=tunnel cargo run -- proxy` | Transparent passthrough proxy; forwards every request to OpenAI unmodified (FORK 1) while running ZK verification in the background (FORK 2) and logging a comparison audit record. No customer impact. |
| Verify | `cargo run -- verify <bundle.zip>` | Offline bundle verification via `bb verify` |
| List | `cargo run -- list` | List recent receipts from `~/.zemtik/receipts.db` |
| List-tunnel | `cargo run -- list-tunnel` | List recent tunnel audit records from `~/.zemtik/tunnel_audit.db` |

### Proxy Data Flow (v0.8+)

```
POST /v1/chat/completions (user prompt)
  → Intent extraction (intent.rs — IntentBackend trait dispatch, no LLM)
      ├── EmbeddingBackend (default): fastembed BGE-small-en ONNX, cosine similarity
      │     → DeterministicTimeParser (time_parser.rs) for time range extraction
      │     → confidence < threshold or low margin → Err(NoTableIdentified) → ZK SlowLane
      │     → unrecognized time token → Err(TimeRangeAmbiguous) → ZK SlowLane
      └── RegexBackend (fallback if model unavailable): keyword/.contains() matching
  → Routing decision (router.rs — schema_config.json sensitivity)
      ├── FastLane (low sensitivity): DB aggregate (SUM or COUNT) → BabyJubJub attestation → EvidencePack
      └── ZK SlowLane (critical sensitivity):
            Raw Transactions (private witnesses, never leave the host)
              → BabyJubJub EdDSA signing (per batch of 50)
              → Noir mini-circuit: Poseidon commitment verification + SUM or COUNT aggregation
                  (circuit/sum/ for SUM/AVG, circuit/count/ for COUNT; shared lib in circuit/lib/)
              → UltraHonk proof (bb v4 / Barretenberg)
              → Proof verified locally ✓
              → AVG: two sequential proofs (SUM + COUNT) + BabyJubJub attestation for division
              → Aggregate only → OpenAI; response includes evidence_version: 2, actual_row_count
```

### Source Modules (`src/`)

| File | Role |
|------|------|
| `main.rs` | Pipeline orchestrator; CLI arg parsing; routes to proxy / verify / list / list-tunnel / pipeline |
| `proxy.rs` | Axum HTTP server; `POST /v1/chat/completions` interception; FastLane + ZK dispatch; tunnel mode routing |
| `tunnel.rs` | Tunnel mode handlers: `handle_tunnel` (FORK 1 + FORK 2 dispatch), `handle_audit`, `handle_audit_csv`, `handle_summary`, `handle_tunnel_passthrough`; `TunnelAuditRecord` persistence; diff computation |
| `intent.rs` | `IntentBackend` trait + `RegexBackend` (fallback); dispatches to embedding or regex backend |
| `intent_embed.rs` | `EmbeddingBackend` (fastembed + BGE-small-en ONNX, CPU-only); schema index builder; cosine similarity |
| `time_parser.rs` | `DeterministicTimeParser` — Q/H/FY/MMM/relative/YTD patterns; unrecognized → `TimeRangeAmbiguous` |
| `router.rs` | Routing decision: `schema_config.json` sensitivity → `FastLane` or `ZkSlowLane` |
| `engine_fast.rs` | FastLane: generic `aggregate_table()` (SUM or COUNT) → BabyJubJub attestation `attest_fast_lane()` (no ZK, fully concurrent); `signing_version: 2` |
| `evidence.rs` | Builds `EvidencePack` for both engine paths (attestation_hash or proof_hash) |
| `db.rs` | DB abstraction (SQLite + Supabase); transaction seeding; EdDSA signing; `aggregate_table()` / `query_aggregate_table()` (generic SUM/COUNT; `sum_by_category` deprecated since v0.7.0) |
| `prover.rs` | Subprocess management for `nargo compile`, `nargo execute`, `bb generate` |
| `verify.rs` | Proof bundle extraction + `bb verify` invocation |
| `bundle.rs` | ZIP bundle creation for portable proofs |
| `openai.rs` | OpenAI Chat Completions API client |
| `config.rs` | Layered config + `SchemaConfig` / `TableConfig` loading from `schema_config.json`; `AggFn` enum (SUM/COUNT/AVG); identifier validation; `use_supabase_fast_lane()` |
| `startup.rs` | Startup validation: Postgres column+row checks per table, ZK tools detection, formatted validation block, `ZEMTIK_VALIDATE_ONLY` exit path, startup events JSONL log |
| `receipts.rs` | SQLite receipts ledger (CRUD + v5 migration: adds `actual_row_count`; v3: `outgoing_prompt_hash`; v2: `engine_used`, `proof_hash`, `data_exfiltrated`, `intent_confidence`) |
| `keys.rs` | BabyJubJub key generation + persistence (`~/.zemtik/keys/bank_sk`, mode 0600) |
| `types.rs` | Shared types: `Transaction`, `AuditRecord`, `IntentResult`, `Route`, `EngineResult`, … |
| `audit.rs` | JSON audit record writer → `audit/` directory |

### ZK Circuit (`circuit/`)

Mini-circuit layout introduced in v0.8.0. Three subdirectories:

- `circuit/sum/` — SUM circuit (used by SUM and AVG queries)
- `circuit/count/` — COUNT circuit (used by COUNT and AVG queries)
- `circuit/lib/` — Shared Noir library (Poseidon helpers, EdDSA wrappers)

Each mini-circuit verifies Poseidon commitments per signed batch and computes its respective aggregate. The vendored EdDSA library lives in `vendor/eddsa/`. AVG runs both circuits sequentially and combines results with a BabyJubJub attestation.

### Configuration

Layered resolution order (later overrides earlier):

1. Hardcoded defaults (`~/.zemtik/` subdirs: `circuit/`, `runs/`, `keys/`, `receipts/`, `receipts.db`, `zemtik.db`)
2. YAML file (`~/.zemtik/config.yaml`)
3. Environment variables (`ZEMTIK_*` prefix, plus `OPENAI_API_KEY`, `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `DB_BACKEND`, `ZEMTIK_INTENT_BACKEND` (`embed`|`regex`), `ZEMTIK_INTENT_THRESHOLD`, `ZEMTIK_VERIFY_TIMEOUT_SECS` (default 120), `ZEMTIK_CLIENT_ID` (default 123), `ZEMTIK_BIND_ADDR` (default `127.0.0.1:4000`), `ZEMTIK_CORS_ORIGINS` (comma-separated; `*` for wildcard), `ZEMTIK_OPENAI_BASE_URL` (default `https://api.openai.com`; override in tests/dev), `ZEMTIK_OPENAI_MODEL` (default `gpt-5.4-nano`; `gpt-5.4-nano` is a real OpenAI model, not a placeholder), `ZEMTIK_SKIP_CIRCUIT_VALIDATION` (`1`|`true`; skips nargo/bb circuit dir check — required in Docker and integration tests), `ZEMTIK_SKIP_DB_VALIDATION` (`1`|`true`; skips startup schema validation — use when `DATABASE_URL` is not available), `ZEMTIK_VALIDATE_ONLY` (`1`|`true`; run startup schema validation then exit 0/1 — pre-demo config check, no server started), `ZEMTIK_MODE` (`standard`|`tunnel`; default `standard`), `ZEMTIK_TUNNEL_API_KEY` (required when `ZEMTIK_MODE=tunnel`; hard startup error if unset), `ZEMTIK_TUNNEL_MODEL` (default: `ZEMTIK_OPENAI_MODEL`), `ZEMTIK_TUNNEL_TIMEOUT_SECS` (default 180), `ZEMTIK_TUNNEL_SEMAPHORE_PERMITS` (default 50), `ZEMTIK_DASHBOARD_API_KEY` (protects `/tunnel/audit` and `/tunnel/summary`; warning if unset in tunnel mode), `ZEMTIK_TUNNEL_AUDIT_DB_PATH` (default `~/.zemtik/tunnel_audit.db`), `ZEMTIK_TUNNEL_DEBUG_PREVIEWS` (`0`|`1`; default `0` — when enabled, stores 500-char plaintext snippets of original LLM responses in the audit DB; disable in production to avoid persisting customer output), `ZEMTIK_QUERY_REWRITER` (`1`|`true`; default `false` — enable hybrid query rewriter for multi-turn proxy mode), `ZEMTIK_QUERY_REWRITER_MODEL` (default: `ZEMTIK_OPENAI_MODEL`), `ZEMTIK_QUERY_REWRITER_TURNS` (default 6 — conversation turns included in LLM rewrite context), `ZEMTIK_QUERY_REWRITER_SCAN_MESSAGES` (default 5 — max prior messages scanned by deterministic_resolve), `ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS` (default 10 — per-request timeout for LLM rewrite call), `ZEMTIK_QUERY_REWRITER_MAX_CONTEXT_TOKENS` (default 2000 — token budget for LLM context, estimated via char/4), `ZEMTIK_GENERAL_PASSTHROUGH` (`1`|`true`; default `false` — enables General Passthrough lane; non-data queries that fail intent extraction are forwarded to OpenAI with a receipt and zemtik_meta block instead of returning 400), `ZEMTIK_GENERAL_MAX_RPM` (default `0` — max requests/minute for the general lane; `0` = unlimited; per-instance, not cluster-wide; 429 with GeneralLaneBudgetExceeded on breach))
4. CLI flags (`--port`, `--circuit-dir`)

Copy `.env.example` to `.env` and set `OPENAI_API_KEY` at minimum for end-to-end runs.

### Database backends

- **SQLite** (default) — auto-seeded in-memory on first run; path `~/.zemtik/zemtik.db`
- **Supabase** — set `DB_BACKEND=supabase`; schema in `supabase/migrations/`; set `SUPABASE_AUTO_CREATE_TABLE=1` to create the table on startup (default: `false`); set `SUPABASE_AUTO_SEED=1` to insert 500 demo rows (default: `false` — prevents accidental writes to client production databases)

### Release / CI

Two GitHub Actions workflows:

- **`ci.yml`** — runs on every push/PR: `cargo test` (unit + integration), `cargo clippy`, and a Docker build smoke-test. Integration tests require `ZEMTIK_SKIP_CIRCUIT_VALIDATION=1` (no nargo/bb in CI).
- **`release.yml`** — runs on version tags (`v*`): intent eval gate (`cargo run --bin intent-eval --features eval`), cross-compile for `x86_64-linux` + `aarch64-darwin`, Docker multi-platform publish to GHCR. Archives include binary + `install.sh` + `config.example.yaml`. (`aarch64-linux` and `x86_64-darwin` removed in v0.6.0 due to `ort-sys` ABI mismatch.)

## Key constraints and known gaps

- CLI pipeline query is hardcoded (500 txs, client 123, `aws_spend`, Q1 2024). Proxy mode supports natural-language queries via `schema_config.json`-defined tables.
- `schema_config.json` required in proxy mode — copy `schema_config.example.json` to `~/.zemtik/schema_config.json`. Tables must include `description` and `example_prompts` fields for the embedding backend.
- FastLane supports both `DB_BACKEND=sqlite` (in-memory seeded ledger) and `DB_BACKEND=supabase` (PostgREST). The Supabase path uses the generic `query_aggregate_table()` introduced in v0.7.0. `DB_BACKEND=supabase` must be set explicitly — Supabase credentials alone do not activate the Supabase path (ISSUE-001 fix).
- The ZK slow lane supports any table key via Poseidon BN254 hashing (Sprint 2). No code change needed — just add the table to `schema_config.json` with `"sensitivity": "critical"`.
- `bb verify` has a configurable timeout (`ZEMTIK_VERIFY_TIMEOUT_SECS`, default 120s); returns HTTP 504 on expiry. On timeout, the `bb` child process is killed and reaped (fixed in v0.6.0).
- `--no-verify` hook bypass and force-push to main are never acceptable.
- Public inputs sidecar is not cryptographically committed (known limitation, tracked).
- EmbeddingBackend downloads BGE-small-en model (~130MB) on first proxy start to `~/.zemtik/models/`. Set `ZEMTIK_INTENT_BACKEND=regex` to skip. First start can take 30–120s.
- `IntentBackend` trait: `index_schema(&mut self, schema)` called once at startup; `match_prompt(&self, prompt, k)` returns sorted `Vec<(table_key, score)>`. Add new backends by implementing this trait.
- **Testing model:** All curl examples, test payloads, and end-to-end tests use `gpt-5.4-nano` (the current default in `src/openai.rs`). `gpt-5.4-nano` is a real OpenAI model (the latest as of 2026-04). Do NOT use `gpt-4o` or other model names in test commands — they won't match the proxy fallback and will pass through unmodified. The model name is configurable via `ZEMTIK_OPENAI_MODEL` env var (see `src/openai.rs`).
- **Tunnel mode (`ZEMTIK_MODE=tunnel`):** `ZEMTIK_TUNNEL_API_KEY` is a **hard startup error** if unset — proxy refuses to start. This is intentional: verification calls must be billed to zemtik's account, not the pilot customer's. `TunnelMatchStatus` has six variants: `Matched`, `Diverged` (diff outside tolerance), `Unmatched`, `Error`, `Timeout`, `Backpressure`. The `Diverged` variant was added in v0.9.0 — it distinguishes "verification ran but values don't agree" from "verification couldn't run at all". See `src/types.rs:TunnelMatchStatus`.
