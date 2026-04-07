# Changelog

All notable changes to this project will be documented in this file.

## [0.8.0] - 2026-04-07

### Added
- **COUNT and AVG on ZK SlowLane** — `"agg_fn": "COUNT"` now routes to a dedicated ZK circuit for `sensitivity: "critical"` tables. `"agg_fn": "AVG"` runs two sequential ZK proofs (SUM + COUNT) and attests the division with BabyJubJub. Both produce independently verifiable bundles.
- **Variable row count (padding)** — ZK SlowLane now handles queries matching fewer than 500 rows. Rows are padded with signed sentinel transactions (amount=0, excluded by predicate filter). `actual_row_count` in the response shows the pre-padding count. Queries matching more than 500 rows return HTTP 422 with a remedy message.
- **`AggFn::Avg`** — New variant in the `AggFn` enum. AVG is valid in `schema_config.json` as `"agg_fn": "AVG"`. Invalid agg_fn values are caught at config parse time (serde error with valid values listed).
- **`evidence_version: 2`** — All proxy responses now include `evidence_version: 2` in the evidence object. Enables downstream parsers to distinguish v1 (single proof, `row_count`) from v2 (actual_row_count, AVG dual-proof) response shapes.
- **`actual_row_count` field** — Replaces the ambiguous `row_count` in v2 responses. Shows how many real (pre-padding) transactions were included. Auditors compare this against their expected dataset size.
- **mini-circuits** (`circuit/sum/`, `circuit/count/`) — Shared commitment logic extracted to `circuit/lib/commitment.nr`. Each aggregation has its own Nargo project. Startup log shows compiled status per circuit.
- **schema_config.example.json** — Added `headcount_critical` (COUNT+critical) and `avg_deal_size` (AVG+critical) example entries.
- **Receipts DB v5 migration** — Adds `actual_row_count` column (nullable, backward-compatible).

### Fixed
- **COUNT+critical no longer rejected at startup** — Previously Zemtik refused to start if a critical table used COUNT. Now it compiles and routes to the ZK COUNT circuit.
- **>500 row error message** — Now includes the row count and a remedy: "Narrow the time range or set sensitivity to 'low'."
- **Proxy startup logs circuit availability** — Each mini-circuit is checked and logged on startup. Missing or uncompiled circuits are flagged before the first request.

### Docs
- `docs/SUPPORTED_QUERIES.md` — Aggregation table and error reference updated for COUNT/AVG.
- `docs/GETTING_STARTED.md` — Step 6.5: COUNT and AVG copy-paste examples with expected response shapes.
- `docs/HOW_TO_ADD_TABLE.md` — New `agg_fn` field guidance with AVG evidence model explanation.
- `docs/CONFIGURATION.md` — TableConfig reference updated with all fields.
- `docs/INDUSTRY_USE_CASES.md` — COUNT+critical and AVG+critical guidance updated across all verticals.

### Migration notes
- **`schema_config.json`** — Existing tables without `agg_fn` continue to work (default: `"SUM"`). No changes required.
- **`receipts.db`** — Migrates automatically on startup (v4 → v5). No action required.
- **`evidence` response shape** — `row_count` is deprecated in v2. Use `actual_row_count`. Existing parsers reading `row_count` will get `null` on new responses and should migrate.

## [0.7.0] - 2026-04-06

### Added
- **Universal FastLane engine** — any table in `schema_config.json` with `sensitivity: "low"` now routes through FastLane automatically. Previously only the hardcoded `aws_spend` table was supported. Add new tables by declaring them in the schema — no code changes required.
- **Generic `aggregate_table()` and `query_aggregate_table()`** — SQLite and Supabase paths both accept `AggFn::Sum` or `AggFn::Count`, `value_column`, `timestamp_column`, and optional `category_column`. Any numeric table can be aggregated and attested.
- **`AggFn` enum** — `schema_config.json` now accepts `"agg_fn": "SUM"` or `"agg_fn": "COUNT"` per table. COUNT tables return the number of matching rows; SUM tables return the aggregate value. COUNT + `sensitivity: "critical"` is rejected at startup (ZK circuit only supports SUM).
- **New `TableConfig` fields** — `value_column`, `timestamp_column`, `category_column`, `agg_fn`, `metric_label`, `skip_client_id_filter`, `physical_table` (Supabase table name override). All column and table names are validated against `[a-zA-Z0-9_]` at startup.
- **`attest_fast_lane()`** — new public function that signs a pre-computed `(aggregate, row_count)` pair. Separates the signing step from the DB query step, enabling the Supabase path to sign PostgREST results using the same attestation format as SQLite.
- **`signing_version: 2`** — FastLane receipts now record `signing_version = 2` in the receipts DB, enabling future offline verifiers to distinguish v1 (category-only) from v2 (full TableConfig) attestation formats.
- **`schema_config.example.json` updated** — includes a `new_hires` example table demonstrating COUNT aggregation with `skip_client_id_filter: true`.

### Fixed
- **FastLane respects `DB_BACKEND=sqlite` even when Supabase credentials are set** — previously, the proxy would route to Supabase FastLane whenever `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` were present, regardless of `DB_BACKEND`. Now only `DB_BACKEND=supabase` activates the Supabase path. This closes ISSUE-001 (regression where dev environments with Supabase creds set hit the Supabase backend unintentionally).
- **`DB_BACKEND` value is now case-insensitive** — `DB_BACKEND=Supabase` and `DB_BACKEND=SUPABASE` are now treated the same as `DB_BACKEND=supabase`. Previously any case other than lowercase silently fell through to SQLite.
- **`note` field no longer silently overwritten** — when `category_column` is `null` and `row_count == 0`, the "no category support" note takes priority over the "no rows matched" note. Previously the second `map.insert` would silently drop the first note.
- **Failed receipt writes now logged** — if `receipts::insert_receipt` returns an error, the proxy logs `[WARN] FastLane: failed to write audit receipt` instead of silently discarding the error. Broken audit trails are now visible to operators.
- **Identifier safety checks promoted to runtime** — column and table name guards in `aggregate_table()` use `anyhow::ensure!` instead of `debug_assert!`, so they run in both debug and release builds.
- **`skip_client_id_filter` emits startup warning** — tables with `skip_client_id_filter: true` now log `[WARN]` at proxy startup, alerting operators that queries will aggregate across all tenants in Supabase.

## [0.6.0] - 2026-04-06

### Added
- **Supabase FastLane connector** — `query_sum_by_category` queries PostgREST with stable pagination (`order=id`) and handles all page sizes, string amounts, and null amounts. Enables Supabase as the aggregation backend in the ZK slow lane.
- **Configurable bind address** — `ZEMTIK_BIND_ADDR` env var (default `127.0.0.1:4000`) allows the proxy to bind to any address. The startup message reflects the actual listening address.
- **Configurable CORS origins** — `ZEMTIK_CORS_ORIGINS` env var (comma-separated; `*` for wildcard) replaces the hardcoded localhost-only CORS policy. Mixing `*` with specific origins uses the wildcard policy.
- **Multi-client support** — `ZEMTIK_CLIENT_ID` env var (default `123`) and per-table `client_id` override in `schema_config.json` enable multi-tenant Supabase deployments.
- **`/health` endpoint** — `GET /health` returns `{"status":"ok","version":"..."}` and probes Supabase connectivity when `SUPABASE_URL` is configured.
- **MessageContent normalization** — proxy now handles both plain-string `content` and the content-parts array format sent by openai-python v1.x and other modern SDKs.

### Fixed
- **`bb` process kill on timeout** — `verify_proof` and `bb verify` offline now kill and reap the `bb` child process on timeout instead of abandoning it. Eliminates zombie processes and resource leaks after timeout.
- **Supabase auto-seed/DDL now opt-in** — `SUPABASE_AUTO_CREATE_TABLE` and `SUPABASE_AUTO_SEED` default to `false` (previously `true`). Set to `1` explicitly for local dev. Prevents demo rows from being silently inserted into client production databases.
- **Supabase pagination sum overflow** — aggregate overflow now returns a hard error instead of silently dropping amounts (was `checked_add.unwrap_or(old_value)`).
- **CORS wildcard race** — CORS wildcard (`*`) correctly activates even when mixed with specific origins in `ZEMTIK_CORS_ORIGINS`. Previously required the vec to be exactly `["*"]`.
- **Empty prompt rejection** — requests with `null`, missing, or empty `content` fields now return HTTP 400 instead of silently routing to the expensive ZK slow lane.
- **Release matrix** — removed `aarch64-unknown-linux-gnu` and `x86_64-apple-darwin` from CI cross-compilation (broken by `ort-sys@2.0.0-rc.11` ABI mismatch). `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` remain.

## [0.5.2] - 2026-04-05

### Added
- **Sidecar manifest** — bundles now include `manifest.json` with a SHA-256 hash of `public_inputs_readable.json`, making the sidecar tamper-evident. `zemtik verify` enforces manifest presence for `bundle_version >= 2`; older bundles skip the check.
- **Outgoing prompt hash** — `outgoing_prompt_hash` (SHA-256 of the financial payload JSON sent to the LLM) is now tracked in `EvidencePack`, receipts DB, and bundle `request_meta.json`. Visible in `zemtik verify` output and `zemtik list`. This is a Rust-layer commitment; circuit-level commitment is planned for Sprint 3.
- **Configurable `bb verify` timeout** — `ZEMTIK_VERIFY_TIMEOUT_SECS` env var (default 120) controls how long the proxy waits for `bb verify` before returning HTTP 504. Prevents indefinite hangs in the ZK slow lane.

### Fixed
- **OpenAI error propagation** — HTTP error responses from OpenAI now include the full response body and status code in the error message. `query_openai` accepts an optional `base_url` override for integration testing via wiremock.
- **Typed `ProxyError`** — `ProxyError` is now an enum (`Internal` → HTTP 500, `Timeout` → HTTP 504) instead of a tuple struct. ZK slow lane timeout returns 504; internal errors return 500.
- **`outgoing_prompt_hash` correctness** — hash is set to `None` in receipts when `fully_verifiable=false` (no proof artifact exists to match against). Serialization errors now propagate instead of silently producing a hash of an empty string.
- **Test reliability** — env-var tests for `ZEMTIK_VERIFY_TIMEOUT_SECS` serialized with a static mutex (ISSUE-001) to prevent data races in parallel test execution.

## [0.5.1] - 2026-04-05

### Performance
- **Poseidon cache** — `poseidon_of_string()` now uses a thread-local `HashMap` cache. A ZK request for 500 transactions (10 batches × 50 txs, all sharing 3-5 category names) drops from ~1001 Poseidon hash computations to 3-5. Cache is keyed on the normalized (trimmed + lowercased) input; validation still runs on every miss.
- **Per-step timing breakdown** — CLI pipeline now prints elapsed time for each major step (DB init, EdDSA signing, Prover.toml generation, `nargo execute`, `bb prove+verify`, bundle + receipt, OpenAI query) and a total at the end. Useful for profiling which step dominates wall-clock time in CI and on new hardware.

---

## [0.5.0] - 2026-04-02

**Breaking change:** Circuit VK has changed. Proof bundles generated before v0.5.0 are not verifiable with this version. Re-run the ZK pipeline to generate new bundles. Also fixes missed `Cargo.toml` version bump from v0.4.1.

### Added
- **Universal ZK circuit** — Any table key in `schema_config.json` now works with ZK SlowLane, not just the three hardcoded demo tables. No code change needed to add new tables.
- **Poseidon BN254 category hash** — `poseidon_of_string()` in `db.rs` computes a cross-language-compatible Poseidon BN254 hash of any table name string (3×31-byte big-endian chunk encoding). Verified to match Noir's `bn254::hash_3` output for `"aws_spend"`.
- **`Transaction.category_name: String`** — New field on the shared Transaction type. DB queries now fetch `category_name` from the `transactions` ledger. Used as the input to `poseidon_of_string` at the ZK witness boundary.
- **`tests/test_poseidon_compat.rs`** — 8 cross-language compatibility tests: canonicalization (trim + lowercase), empty string rejection, non-ASCII rejection, oversized input error, max-length boundary, non-zero hash assertion, collision resistance, and exact value match against Noir output.

### Changed
- **`target_category: u64` → `target_category_hash: String`** throughout `QueryParams`, `ZkPublicInputs`, `Prover.toml` header, sidecar JSON (`public_inputs_readable.json`), and audit records.
- **Noir circuit** — `Transaction.category: Field` (was `u64`); `main()` signature is now `target_category_hash: pub Field` (was `target_category: pub u64`). Circuit VK has changed — bundles generated before v0.5.0 must be regenerated.
- **`schema_key_to_category_code()` removed** — Function hardcoded only 3 tables. Replaced everywhere by `poseidon_of_string(&intent.table)`.
- **`/verify` receipt page** — Category column now reads `category_name` from the bundle sidecar instead of a hardcoded `u64 → name` lookup.
- **Gate count** — v0.5.0 baseline: **274,462 ACIR opcodes** (measured 2026-04-02). No change vs Sprint 1.

### Fixed
- Stale docs in `HOW_TO_ADD_TABLE.md`, `README.md`, `CLAUDE.md`, `ARCHITECTURE.md` that still said ZK SlowLane only works for `aws_spend`, `payroll`, `travel`.
- Misleading error message in `proxy.rs` that said "not recognized in schema_config" on `poseidon_of_string` failure (corrected to: "key must be ≤93 bytes after lowercasing").
- `poseidon_of_string` now rejects empty strings and non-ASCII table keys with descriptive errors instead of silently producing incorrect hashes.

---

## [0.4.1] - 2026-04-02

### Fixed
- **FastLane executor blocking** — `ledger_db` and `receipts_db` changed from `tokio::sync::Mutex` to `std::sync::Mutex`. FastLane DB sum now runs inside `spawn_blocking` so the Tokio executor is never blocked by synchronous SQLite operations. All `receipts_db` lock sites use synchronous scoped locking with poison recovery.
- **BabyJubJub sign failure (~25% of runs)** — SHA-256 attestation hash is now reduced `mod BN254_FIELD_ORDER` before signing. The field order is parsed once at startup via `LazyLock` instead of per-request.
- **Unified attestation always signed** — `EngineResult::EmptyResult` removed. Zero-row results now return `Ok(FastLaneResult{row_count:0})` with a cryptographically signed receipt, making zero-spend attestations indistinguishable-in-format from positive results and binding them to the installation key.
- **`RE_BARE_YEAR` false match on non-year numbers** — regex narrowed from `20\d{2}` to `20[1-9][0-9]` (2010–2099). Phrases like "we have 2000 employees" no longer silently route to a year-2000 time window.
- **`/verify/:id` badge for FastLane receipts** — `FAST_LANE_ATTESTED` now renders a blue "FAST LANE ATTESTED" badge instead of the red INVALID badge.

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
- ONNX intent extraction wrapped in `tokio::task::spawn_blocking` to avoid blocking the Tokio executor on CPU-bound embedding work.
- `CorsLayer::permissive()` replaced with localhost-only origin allowlist (`localhost:4000`, `127.0.0.1:4000`).
- `fiscal_year_offset_months` validated to `0..=11` at schema load time; negative values and out-of-range values now produce a clear startup error.
- `ZEMTIK_INTENT_THRESHOLD` env var clamped to `[0.01, 1.0]`; out-of-range values now produce a clear error instead of silently accepting them.
- `month_start_unix` / `month_end_unix` now panic loudly on invalid date inputs instead of silently returning Unix epoch (1970-01-01), which was a silent data-corruption sink.

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
