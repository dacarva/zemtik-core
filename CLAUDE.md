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
| Proxy | `cargo run -- proxy` | Axum HTTP server on `:4000`; intercepts `POST /v1/chat/completions`, runs ZK pipeline, forwards sanitized request |
| Verify | `cargo run -- verify <bundle.zip>` | Offline bundle verification via `bb verify` |
| List | `cargo run -- list` | List recent receipts from `~/.zemtik/receipts.db` |

### ZK Data Flow

```
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
| `main.rs` | Pipeline orchestrator; CLI arg parsing; routes to proxy / verify / pipeline |
| `proxy.rs` | Axum HTTP server; `POST /v1/chat/completions` interception |
| `db.rs` | DB abstraction (SQLite + Supabase); transaction seeding; EdDSA signing |
| `prover.rs` | Subprocess management for `nargo compile`, `nargo execute`, `bb generate` |
| `verify.rs` | Proof bundle extraction + `bb verify` invocation |
| `bundle.rs` | ZIP bundle creation for portable proofs |
| `openai.rs` | OpenAI Chat Completions API client |
| `config.rs` | Layered config: defaults → `~/.zemtik/config.yaml` → `ZEMTIK_*` env vars → CLI flags |
| `receipts.rs` | SQLite receipts ledger (CRUD) |
| `keys.rs` | BabyJubJub key generation + persistence (`~/.zemtik/keys/bank_sk`, mode 0600) |
| `types.rs` | Shared types: `Transaction`, `AuditRecord`, `SignatureData`, … |
| `audit.rs` | JSON audit record writer → `audit/` directory |

### ZK Circuit (`circuit/`)

Written in Noir. Verifies Poseidon commitments for each signed batch and aggregates the result. Vendored EdDSA library lives in `vendor/eddsa/`.

### Configuration

Layered resolution order (later overrides earlier):

1. Hardcoded defaults (`~/.zemtik/` subdirs: `circuit/`, `runs/`, `keys/`, `receipts/`, `receipts.db`, `zemtik.db`)
2. YAML file (`~/.zemtik/config.yaml`)
3. Environment variables (`ZEMTIK_*` prefix, plus `OPENAI_API_KEY`, `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `DB_BACKEND`)
4. CLI flags (`--port`, `--circuit-dir`)

Copy `.env.example` to `.env` and set `OPENAI_API_KEY` at minimum for end-to-end runs.

### Database backends

- **SQLite** (default) — auto-seeded in-memory on first run; path `~/.zemtik/zemtik.db`
- **Supabase** — set `DB_BACKEND=supabase`; schema in `supabase/migrations/`; auto-creates table if `SUPABASE_AUTO_CREATE_TABLE=1`

### Release / CI

GitHub Actions (`release.yml`) cross-compiles for `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin` on version tags (`v*`). Archives include binary + `install.sh` + `config.example.yaml`.

## Key constraints and known gaps

- Query is hardcoded (500 txs, client 123, AWS spend, Q1 2024) — no dynamic query support yet.
- `bb verify` subprocess has no timeout in proxy mode (potential deadlock risk).
- `--no-verify` hook bypass and force-push to main are never acceptable.
- Public inputs sidecar is not cryptographically committed (known limitation, tracked).
