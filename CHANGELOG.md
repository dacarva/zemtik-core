# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-03-31

### Added
- **Embedding-based intent engine** — `src/intent_embed.rs` introduces `EmbeddingBackend` using fastembed + BGE-small-en (ONNX, CPU-only). Replaces brittle regex matching with cosine similarity over a schema index built from table keys, aliases, descriptions, and example prompts. Zero external API calls during intent extraction.
- **`IntentBackend` trait** — `src/intent.rs` now dispatches intent extraction through a trait (`EmbeddingBackend` or `RegexBackend`). `RegexBackend` wraps the v0.3 regex logic as an offline fallback if the ONNX model is unavailable.
- **Deterministic time parser** — `src/time_parser.rs` handles `Q[1-4] YYYY`, `H[1-2] YYYY`, `FY YYYY`, `MMM YYYY`, `last/this quarter/month`, `YTD`, `past N days`, and bare `YYYY`. Unrecognized time-signaling words (e.g. "recently") return `TimeRangeAmbiguous` → ZK SlowLane.
- **Confidence scores** — `IntentResult.confidence: f32` propagated through EvidencePack (`zemtik_confidence` field) and receipts DB (`intent_confidence` column, v2 migration).
- **`ZEMTIK_INTENT_BACKEND` env var** — switch between `embed` (default) and `regex` at runtime without recompiling. Useful for air-gapped deploys and CI unit tests.
- **`ZEMTIK_INTENT_THRESHOLD` env var** — configures cosine similarity threshold (default 0.65).
- **Intent eval harness** — `eval/intent_eval.rs` binary with 235 labeled prompts (aws_spend, payroll, travel tables). Measures table accuracy ≥95%, zero false-FastLane on adversarial slice, time-range accuracy ≥90%. Run: `cargo run --bin intent-eval --features eval`.
- **Release eval CI gate** — `.github/workflows/release.yml` now runs the eval harness before building release artifacts. Release fails if accuracy gates are not met.
- **Extended `schema_config.example.json`** — all tables now include `description` and `example_prompts` fields required by the embedding index.
- **LazyLock regexes** — all regexes in `time_parser.rs` compiled once at startup.

### Changed
- `schema_config.json` tables now require `description` (string) and `example_prompts` (array) fields when running with the embedding backend. Missing fields log a warning and fall back to `RegexBackend`.
- `receipts` table migrated to v2 schema: adds `intent_confidence REAL` column (additive, non-breaking).
- `cargo run -- list` output now includes the `intent_confidence` column.
- Intent rejections stored as `first 100 chars + SHA-256 prefix` to avoid persisting raw PII in `intent_rejections` table.
- FastLane receipts now record `prompt_hash` and `request_hash` (previously empty strings).

### Fixed
- Case-insensitive schema key lookup in `schema_key_to_category_code` (fixes routing for uppercase/mixed-case table names from external schema configs).
- March 2024 end timestamp in test suite.
- fastembed v5 API compatibility in `EmbeddingBackend`.
- Prompt truncation now happens at Unicode char boundary instead of byte offset (prevents panic on multi-byte UTF-8 input).
- `ZEMTIK_INTENT_BACKEND` comparison is now case-insensitive.
- Fiscal year offset now applied to `last quarter` and `this quarter` expressions (previously ignored).
- `past N days` capped at 36500 days to prevent `chrono::Duration` overflow.
- Embedding index build failure now panics at startup (previously silently returned 400 for all requests).
- Time parser now recognizes `last year` / `prior year` → prior calendar year; `prior quarter` / `prior month` as aliases for `last quarter` / `last month`. Previously these triggered `TimeRangeAmbiguous` and routed all matching prompts to ZK SlowLane unnecessarily.
- `schema_config.example.json` example prompts expanded to cover indirect vocabulary (HR costs, headcount, wages, cloud billing, expense reports, etc.). Eval accuracy: 72.9% → 98.8% (168/170 labeled prompts).

## [0.3.0] - 2026-03-30

### Added
- **Routing engine** — `src/intent.rs` extracts structured intent (table, time range) from natural-language prompts using regex/keyword matching against `schema_config.json`. No LLM involved in routing decisions.
- **FastLane path** — `src/engine_fast.rs` runs a BabyJubJub EdDSA attestation pipeline for non-critical tables (sub-50ms vs full ZK). FastLane queries are fully concurrent; ZK slow-lane requests are still serialized via `pipeline_lock`.
- **ZK routing** — `src/router.rs` routes each request deterministically: `critical` sensitivity tables always go to ZK SlowLane, all others to FastLane. Unknown tables fail secure to ZK.
- **EvidencePack** — `src/evidence.rs` builds a unified evidence record for both engine paths, recording `engine_used`, `attestation_hash` (FastLane) or `proof_hash` (ZK), `schema_config_hash`, and `data_exfiltrated: 0`.
- **Schema config** — `schema_config.json` (loaded from `~/.zemtik/schema_config.json`) defines table sensitivity, aliases, and fiscal year offset. Required in proxy mode; `schema_config.example.json` ships as a template.
- **`list` subcommand** — `cargo run -- list` prints recent receipts from `~/.zemtik/receipts.db` with full `proof_status` output.
- **Supported queries doc** — `docs/SUPPORTED_QUERIES.md` documents natural-language query patterns recognized by the intent extractor.
- **Test suite expansion** — 51 integration tests across 10 test files covering all new modules (intent extraction, routing, FastLane engine, evidence, receipts migration).

### Changed
- Proxy `POST /v1/chat/completions` now runs intent extraction → routing → engine dispatch instead of always running the ZK pipeline. ZK slow-lane path is unchanged for critical tables.
- `receipts` table migrated to v1 schema: adds `engine_used`, `proof_hash`, `data_exfiltrated` columns via idempotent `PRAGMA user_version`-gated migration.
- `transactions.category_name` seeded with schema-config-compatible keys (`aws_spend`, `payroll`, `travel`) to align with intent extractor output.
- `QueryParams.category_name` changed from `&'static str` to `String` to support runtime-extracted values.
- Intent extraction is deterministic: when a prompt matches multiple tables, the highest-sensitivity table (critical > low) wins.

### Fixed
- ZK slow lane now uses extracted intent (category, time range) instead of hardcoded Q1 2024 AWS values.
- `schema_key_to_category_code` returns an error (not a silent CAT_AWS fallback) for unknown tables.
- HTML dashboard escapes single quotes (`&#39;`) in addition to `&`, `<`, `>`, `"`.

## [0.2.1] - 2026-03-27

### Added
- **Distribution** — `install.sh` one-shot installer, `demo/demo.sh` end-to-end walkthrough,
  `demo/README.md` 30-minute deploy guide, `demo/sample_transactions.csv` (500 deterministic rows),
  `config.example.yaml` reference config with all supported fields documented
- **Config system** (`src/config.rs`) — layered config (defaults → `~/.zemtik/config.yaml` → env
  vars → CLI flags); tilde expansion for all path fields; `AppConfig::load` replaces scattered
  `std::env::var` lookups; 5 unit tests covering all override layers
- **`--version` / `-V` flag** — `zemtik --version` prints `zemtik 0.2.1` and exits cleanly
- **GitHub Actions release pipeline** (`.github/workflows/release.yml`) — triggered on `v*` tags;
  cross-compiles for x86_64/aarch64 Linux+macOS; multiarch OpenSSL setup for `aarch64-unknown-linux-gnu`
- **Test coverage** lifted from 57% to 93%: 11 new unit tests across `db.rs`, `prover.rs`, and `keys.rs`
  covering `fr_to_decimal`, `compute_tx_commitment`, `hex_output_to_u64`, `generate_batched_prover_toml`,
  `read_proof_artifacts`, and key generation

### Fixed
- **`bank_sk` file permissions** — signing key now written with mode `0600` (owner-only) instead of
  umask-derived `0644`; prevents local users from reading the bank signing key
- **`openai_api_key` in config** — `openai_api_key` field in `config.yaml` now actually used at
  runtime (proxy falls back to it after Authorization header and `OPENAI_API_KEY` env var;
  CLI pipeline passes it directly to `query_openai`)
- **`anyhow::ensure!` in `sign_transaction_batches`** — replaced `assert_eq!` with `anyhow::ensure!`
  to return a proper error instead of panicking in a blocking thread context
- **Proof run directory cleanup** — `RunDirGuard` (RAII `Drop` impl) in both `main.rs` and `proxy.rs`
  ensures per-run work directories are removed on all exit paths including errors
- **Bundle audit trail** — proxy now discards bundle and removes its ZIP file if `insert_receipt`
  fails, so no orphaned bundles are emitted without a DB record
- **Request/prompt hashes** — `generate_bundle` in proxy now receives actual `request_hash` /
  `prompt_hash` instead of `None, None`
- **`demo/README.md` circuit copy** — fixed double-nesting bug (`cp -r circuit` → `cp -r circuit/.`)

## [0.2.0] - 2026-03-26

### Added
- **Verifier flow** — independent proof bundle verification for ZK receipts
  - `src/bundle.rs` — generates portable proof bundle ZIPs at `~/.zemtik/receipts/<uuid>.zip`
    (circuit artifacts, proof, public inputs, metadata, bb version tag)
  - `src/receipts.rs` — SQLite receipts ledger at `~/.zemtik/receipts.db` for
    `insert_receipt` / `get_receipt` CRUD
  - `src/verify.rs` — `verify_bundle` / `run_verify_cli` for offline proof verification
    via `bb verify`; checks bb version compatibility (major/minor), validates required files
  - `zemtik verify <bundle.zip>` CLI subcommand — verifies any bundle independently
    without Zemtik infrastructure
  - `GET /verify/:id` proxy route — human-readable cryptographic receipt page with
    proof status badge and metadata transparency disclaimer
- **Security hardening** (ISSUE-001 follow-up)
  - Zip bomb protection: entry count limit (64) and extracted-bytes limit (32 MiB)
  - Directory entry handling: ZIP directory entries silently skipped during extraction
    (prevents regression where standard ZIP tools adding directory entries broke extraction)
  - `bb --version` exit code verified before version parsing
  - `html_escape` applied consistently to all receipt page fields including `id` and `circuit_hash`
- **Metadata transparency disclaimer** in both CLI output and receipt page
  — clearly marks self-reported sidecar fields (aggregate, timestamp, raw_rows) as
  NOT committed to the ZK circuit, per adversarial review finding
- `src/types.rs` — `AuditRecord`, `BundleResult`, `VerifyResult`, `Receipt` shared types
- `TODOS.md` — initial tracking of known gaps (CIRCUIT_DIR config, CI/CD release pipeline,
  integration test coverage for bb-dependent paths, etc.)
- Unit test coverage: `parse_bb_version` (5 cases), receipts CRUD (insert/get/duplicate),
  zip-slip regression (ISSUE-001), directory-entry regression

### Fixed
- `proxy.rs:544` — `.unwrap()` on first signed batch replaced with proper `context()` error
  (was a panic if zero transactions matched the query)

## [0.1.0] - 2026-03-25

### Added
- Initial open source release (MIT)
- Axum proxy interceptor (`--proxy` mode) — transparent drop-in for `api.openai.com`
  that runs ZK proof pipeline before forwarding to OpenAI
- ZK pipeline: DB query → EdDSA batch signing → Noir circuit execution (UltraHonk/bb)
- CLI pipeline mode (default) — runs end-to-end proof generation and audit record
- `src/proxy.rs` — Axum HTTP proxy with `pipeline_lock` for serialized proof generation
- `src/openai.rs` — OpenAI API client
- `src/audit.rs` — JSON audit record writer
- `src/db.rs` — PostgreSQL transaction queries + EdDSA batch signing
- `src/prover.rs` — Noir circuit execution + Barretenberg proof generation
