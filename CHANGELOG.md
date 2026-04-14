# Changelog

All notable changes to this project will be documented in this file.

## [0.13.0] - 2026-04-14

### Added
- **MCP Attestation Proxy** (`zemtik mcp` / `zemtik mcp-serve`) — every file read and HTTP fetch Claude makes on your data is signed with BabyJubJub EdDSA and written to a tamper-evident audit record in `~/.zemtik/mcp_audit.db`. Zero latency impact via FORK 1+2 pattern.
- **STDIO mode** (`zemtik mcp`): Claude Desktop spawns Zemtik as a subprocess. Audit records are best-effort with a 1-second async signing timeout.
- **SSE mode** (`zemtik mcp-serve`): Streamable HTTP server on `ZEMTIK_MCP_BIND_ADDR` (default `127.0.0.1:4001`) with `GET /mcp/audit`, `/mcp/summary`, `/mcp/health` endpoints. Bearer token auth via `ZEMTIK_MCP_API_KEY`.
- **`zemtik_read_file` tool**: file read with P0 deny for `~/.zemtik/` (signing key protection), 10 MB cap, allowlist enforcement in SSE mode (`ZEMTIK_MCP_ALLOWED_PATHS`).
- **`zemtik_fetch` tool**: HTTP fetch with domain allowlist enforcement in SSE mode (`ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS`). Bypass events are audited with `mode=bypass_blocked` or `mode=bypass_stdio`.
- **`docs/MCP_ATTESTATION.md`**: compliance doc covering audit schema, BabyJubJub signature verification (Rust + Python), tunnel vs governed mode, key management, and security boundaries.
- **`install.sh` MCP wrapper**: creates `~/.zemtik/bin/zemtik-mcp` and prints the exact JSON block for `claude_desktop_config.json`.

### Changed
- **`check_mcp_auth` now denies on unconfigured key** — previous allow-all default inverted to deny-all. Startup validation in `run_mcp_serve` ensures the key is always set before any requests are served.
- **`mcp_audit.db` uses WAL mode** — prevents dropped audit records under concurrent FORK 2 writes in SSE mode.
- **`allowed_paths` canonicalized at construction time** — tilde and symlink components in `ZEMTIK_MCP_ALLOWED_PATHS` are resolved at startup, not per-request.
- **`pending_fork2` handles drained on push** — completed `JoinHandle`s are pruned before pushing new ones, preventing unbounded memory growth in long-running SSE deployments.
- **Key seed wrapped in `Zeroizing`** — the 32-byte BabyJubJub key seed copy materialized in each FORK 2 `spawn_blocking` call is now zeroed on drop.

### Fixed (security)
- **Symlink bypass of key-file protection** (`fix(mcp)` commit 17861a0): `zemtik_home` is now canonicalized at construction time. On macOS, `/var/folders` is a symlink to `/private/var/folders`; without canonicalization, `starts_with()` silently passed for symlinked paths into `~/.zemtik/`.
- **SSE mode with empty `ZEMTIK_MCP_ALLOWED_PATHS` now denies all reads** (commit 118f438) — empty allowlist was previously allow-all instead of deny-all in SSE mode.
- **Non-allowlisted `zemtik_fetch` domains blocked in SSE mode** (commit 81d6bf1) — previously only logged, now returns an error and writes a bypass audit record.
- **Startup warning when SSE mode binds to non-loopback address** (commit 6005bd4).

## [0.12.0] - 2026-04-14

### Added
- **Stage 1 audit trail integrity** — proof bundles now carry a cryptographic chain of custody from the bank signing key to the manifest.
- **ed25519 manifest signing**: `bundle_version=3` bundles include `manifest_sig` — a 64-byte ed25519 signature over the JCS-canonical (RFC 8785) manifest JSON. Key derived via HKDF-SHA256(bank_sk, info="zemtik-manifest-signing-v1"). `manifest_key_id` is SHA-256(raw verifying key bytes).
- **`GET /public-key`** endpoint (unauthenticated): returns `ed25519_manifest_pub` (hex), `manifest_key_id` (hex), `babyjubjub_pub_x`, `babyjubjub_pub_y`. Auditors can retrieve the verifying key and independently check manifest signatures.
- **`outgoing_prompt_hash` ZK circuit input**: SHA-256(original user prompt) with top 2 bits masked to fit BN254 field — now a public input to both the SUM and COUNT circuits. Binds the proof to the exact prompt that triggered it. Circuit enforces `assert(outgoing_prompt_hash != 0)` (probability of collision ~2^-254).
- **Receipts DB v8 migration**: adds `manifest_key_id TEXT` column to the receipts ledger.
- **BJJ public key precomputed at startup**: `bjj_pub_x` and `bjj_pub_y` computed once from `bank_sk` and stored in `ProxyState` — no per-request scalar multiplication.

### Changed
- **v3 public inputs layout** (7 fields, 224 bytes): adds `outgoing_prompt_hash` at index 5 (bytes 160–192); `verified_aggregate` moves to index 6 (bytes 192–224). v1/v2 bundles (192 bytes, 6 fields) continue to verify unchanged.
- **`cross_verify_sidecar`** updated for v3 field layout: aggregate is now read from bytes 216–224 in v3 bundles.

### Fixed (security)
- **Bundle demotion attack**: `bundle_version` is now derived from the binary size of `public_inputs` (224 bytes → v3 forced; 192 bytes → v1/v2 trusted from claim) rather than from the untrusted `request_meta.json`. Claiming `bundle_version < 3` for a 224-byte inputs file is a hard integrity failure.
- **JCS truncation attack**: manifest reconstruction now uses `bail!` for every required field (algorithm, bundle_version, created_at, proof_hash, public_inputs_hash, request_meta_hash, sidecar_hash, vk_hash). A missing field is a hard bundle rejection — no silent partial-manifest reconstruction.
- **`manifest_key_id` fingerprint**: was SHA-256(hex-encoded string); corrected to SHA-256(raw verifying key bytes) — standard auditor convention.

### Tests
- **`test_keys.rs`**: 4 new tests for `derive_manifest_signing_keypair` — deterministic derivation, sign/verify roundtrip, unique-per-seed, tampered-payload rejection.
- **`test_verify.rs`**: 7 new v3 bundle tests — valid manifest sig passes, tampered sig rejected, tampered request_meta rejected, demotion attack detected, v3 cross_verify sidecar passes, v3 cross_verify OPH mismatch detected.
- **`src/proxy.rs`**: 4 new tests for `compute_prompt_hash_field` — known-answer, empty string non-zero, different prompts differ, deterministic.
- **`src/verify.rs`**: 2 new inline tests for v3 `cross_verify_sidecar`.

## [0.11.0] - 2026-04-13

### Added
- **GeneralLane**: non-data query passthrough via `ZEMTIK_GENERAL_PASSTHROUGH=1`. When intent extraction fails to match any configured table (after rewriter exhaustion), requests are forwarded to OpenAI with a receipt and `zemtik_meta` response block instead of returning HTTP 400.
- **`ZEMTIK_GENERAL_MAX_RPM`**: per-instance rate limiter for the general lane (default: 0/unlimited). Sliding 60-second window; returns HTTP 429 `GeneralLaneBudgetExceeded` on breach.
- **`zemtik_meta` field** in GeneralLane JSON responses: `{ engine_used, zk_coverage, reason, receipt_id }`. `reason` is `"no_table_match"` (NoTableIdentified) or `"time_range_ambiguous"` (TimeRangeAmbiguous).
- **`X-Zemtik-Meta` header**: URL-encoded JSON of `zemtik_meta` — primary metadata signal for streaming responses.
- **`general_queries_today`** and **`intent_failures_today`** counters in `/health` response.
- **Receipts DB v7 migration**: composite index `idx_receipts_engine_created` on `(engine_used, created_at)` for `/health` counter queries.
- **Streaming passthrough for GeneralLane**: when `ZEMTIK_GENERAL_PASSTHROUGH=1` and `stream: true`, general queries are forwarded as SSE. `zemtik_meta` is NOT injected into the SSE body; use `X-Zemtik-Meta` header instead.

### Changed (behavioral)
- **`X-Zemtik-Engine: <lane>` header** is now present on ALL proxy responses (FastLane, ZK SlowLane, GeneralLane). Previously absent on ZK SlowLane responses without a committed bundle. Clients that validate response headers should allow this header.
- **NoTableIdentified 400 hint** updated to mention `ZEMTIK_GENERAL_PASSTHROUGH=1` as the opt-in for non-data queries.
- **CORS `expose_headers`** now includes `x-zemtik-engine` and `x-zemtik-meta` so cross-origin clients can read them.
- **Shared SSE helper** extracted from `tunnel.rs` to `proxy.rs` (`is_hop_by_hop`, `stream_openai_passthrough`) to avoid duplication.

### Fixed
- **GeneralLane 429 audit trail**: rate-limited requests now write a receipt with `proof_status = "general_lane_rate_limited"` so they appear in audit logs and `general_queries_today`.
- **`Retry-After` header on 429**: GeneralLane rate-limit responses now include `Retry-After: N` computed from the sliding window oldest entry.
- **Upstream `Content-Type` passthrough**: GeneralLane non-streaming responses now forward the upstream `Content-Type` instead of hardcoding `application/json`.
- **Streaming task timeout**: `stream_openai_passthrough` now applies a 60s per-chunk timeout — stalled upstream connections release the connection pool entry instead of hanging indefinitely.
- **Receipts v7 migration tests**: updated assertions to match schema version 7; added `test_migration_v6_to_v7_adds_index`.
- **Daily counter tests**: `count_engine_today` and `count_intent_failures_today` now have direct unit tests including old-timestamp boundary cases.
- **Config tests**: `ZEMTIK_GENERAL_PASSTHROUGH` and `ZEMTIK_GENERAL_MAX_RPM` now have dedicated parse and validation tests.

## [0.10.0] - 2026-04-12

### Added
- **Hybrid query rewriter** (`ZEMTIK_QUERY_REWRITER=1`) — resolves multi-turn follow-up queries that fail standalone intent extraction. Two-step pipeline: (1) deterministic resolve scans prior user messages and carries forward table + time; (2) LLM rewriter fallback calls `gpt-5.4-nano` with conversation history. Feature is off by default; all failures remain fail-secure (HTTP 400).
- **New env vars**: `ZEMTIK_QUERY_REWRITER`, `ZEMTIK_QUERY_REWRITER_MODEL`, `ZEMTIK_QUERY_REWRITER_TURNS`, `ZEMTIK_QUERY_REWRITER_SCAN_MESSAGES`, `ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS`, `ZEMTIK_QUERY_REWRITER_MAX_CONTEXT_TOKENS`.
- **Per-table rewriter override**: `query_rewriting` field in `schema_config.json` per table — absent (follow global), `true` (force enable), `false` (fail-secure disable).
- **`rewrite_method` in evidence envelope**: `"deterministic"` or `"llm"` injected into `body.evidence.rewrite_method` for rewritten requests. Absent for direct-extraction requests.
- **Receipts DB v6 migration**: adds `rewrite_method TEXT` and `rewritten_query TEXT` columns (backward compatible — existing rows get `NULL`).
- **`RewritingFailed` error code**: returned when rewriting fails. Two distinct hints: `unresolvable` (table or time cannot be determined) and `timeout` (LLM rewriter timed out; increase `ZEMTIK_QUERY_REWRITER_TIMEOUT_SECS`).
- **Startup WARN**: `ZEMTIK_QUERY_REWRITER=1` with `ZEMTIK_MODE=tunnel` emits a warning — rewriter has no effect in tunnel mode.
- **`zemtik list` rewriting summary**: footer line showing direct / deterministic / llm request counts when any rewritten requests are present.

### Changed
- **Documentation overhaul** — replaced all ASCII art diagrams (9 diagrams across 8 files) with GitHub-native Mermaid diagrams. Added 7 new diagrams covering startup validation, CI/CD pipeline, config resolution, and verification flow.
- **`docs/ARCHITECTURE.md`** — updated scope note to v0.9.1; added `startup.rs` and `tunnel.rs` to source module map; new sections: Startup Validation, Structured Error Codes, Security Hardening (S1/S2/S3), CI/CD Pipeline, Health Endpoint.
- **`README.md`** — replaced 38-line ASCII "How It Works" and tunnel mode diagrams with Mermaid flowcharts; updated project file tree to include `startup.rs`.
- **`docs/TUNNEL_MODE.md`** — replaced ASCII data flow with `sequenceDiagram`; fixed audit record `id` type (UUID string, not integer); fixed dead link (`debug/MANUAL_TUNNEL_QA.md` → `INTEGRATION_CHECKLIST.md`).
- **`docs/INTENT_ENGINE.md`** — added full intent extraction flowchart; fixed `TimeRangeAmbiguous` routing (routes to HTTP 400, not ZK SlowLane — 5 locations corrected).
- **`docs/CONFIGURATION.md`** — added config resolution flowchart; added v0.9.1 env vars (`ZEMTIK_SKIP_DB_VALIDATION`, `ZEMTIK_VALIDATE_ONLY`); updated routing rules table with rewriter entries.
- **`docs/SUPPORTED_QUERIES.md`** — fixed `TimeRangeAmbiguous` error description (was incorrectly documented as routing to ZK SlowLane).
- **`docs/SCALING.md`** — replaced 3 ASCII recursive proof/aggregation/batch diagrams with Mermaid.
- **`docs/GETTING_STARTED.md`** — added orientation flowchart.
- **`docs/INTEGRATION_CHECKLIST.md`** — added verification flow diagram.
- **`docs/TROUBLESHOOTING.md`** — updated quick table with `StreamingNotSupported` error code.

### Fixed
- **SEC-3**: internal ZK pipeline error messages are no longer leaked in HTTP response bodies. Replaced with `"Internal pipeline error — see server logs for details."`.
- **ISSUE-001**: `deterministic_resolve` now returns `None` for context-dependent time phrases (`same period`, `same quarter`, `same month`, `last year`) instead of applying a year-level time pivot. These phrases trigger LLM rewriter fallback (or HTTP 400 if rewriter disabled).

### Upgrading to v0.10.0

Receipts DB v6 migration adds two nullable columns to the `receipts` table (`rewrite_method`, `rewritten_query`). The migration runs automatically at startup — no action required. All rows created before v0.10.0 have `NULL` in these columns.

`ZEMTIK_QUERY_REWRITER` is off by default. Existing deployments are unaffected. To opt in:
1. Set `ZEMTIK_QUERY_REWRITER=1`.
2. Review the data residency note in [docs/CONFIGURATION.md](docs/CONFIGURATION.md#data-residency) before enabling the LLM fallback path in production. The LLM rewrite call sends conversation history to `ZEMTIK_OPENAI_BASE_URL`.
3. Add `"query_rewriting": false` to any table in `schema_config.json` where you want to prevent conversation history from being sent externally, even if the global flag is on.

---

## [0.9.1] - 2026-04-11

### Added
- **Startup schema validation** — on proxy start, zemtik validates each table in `schema_config.json` against the connected Postgres database (if `DATABASE_URL` is set). Prints a formatted block showing row counts and any warnings. SQLite mode skips validation (demo-only). Set `ZEMTIK_SKIP_DB_VALIDATION=1` to suppress.
- **`ZEMTIK_VALIDATE_ONLY=1`** — run full startup validation, print results, then exit 0 (all OK) or exit 1 (any warning). Enables pre-demo validation: `docker compose run --rm zemtik-proxy env ZEMTIK_VALIDATE_ONLY=1`
- **Streaming guard** — `stream: true` in standard proxy mode now returns HTTP 400 with `error.code: StreamingNotSupported` immediately, instead of hanging. Tunnel mode is unaffected (streaming passes through).
- **Structured error bodies** — all 400/500 responses now include `error.type`, `error.code`, `error.hint`, and `error.doc_url` fields. Error codes: `NoTableIdentified`, `StreamingNotSupported`, `InvalidRequest`, `QueryFailed`.
- **`/health` schema_validation field** — `/health` now includes `schema_validation.status`, `schema_validation.tables`, and `schema_validation.zk_tools` from the startup validation run.
- **Startup events log** — appends JSONL events to `~/.zemtik/startup_events.jsonl` after each startup validation. Enables post-deployment review.
- **`docs/TROUBLESHOOTING.md`** — 6-symptom → cause → fix reference for on-site use.
- **`docs/INTEGRATION_CHECKLIST.md`** — 7-step executable checklist with curl commands + expected outputs.
- **"Streaming" and "Bring Your Own Database" sections** in `docs/GETTING_STARTED.md`.
- **"Conversation patterns" section** in `docs/SUPPORTED_QUERIES.md` — explains multi-turn limitation with three workarounds.
- **`ZemtikErrorCode` enum** in `src/types.rs` — typed error codes with `Display` impl.
- **`.github/CODEOWNERS`** — requires owner review for any CI/CD workflow changes.

### Fixed
- **S1 — Security:** Removed `danger_accept_invalid_certs(true)` from `ensure_supabase_table()` in `src/db.rs`. Supabase uses valid CA-signed certs — bypassing TLS verification was unnecessary and created MitM risk at customer deployments.
- **S2 — Security:** Table key (used as SQL identifier in startup validation) is now validated with `is_safe_identifier` in `validate_schema_config`. Previously, a malformed `schema_config.json` key could inject arbitrary SQL into the startup Postgres count query.
- **S3 — Security:** DB error strings are no longer echoed in HTTP 500 response bodies. Raw Postgres errors (which include table/column names and constraint details) are logged server-side only; the API response says "check server logs."
- **`ZEMTIK_VALIDATE_ONLY=1` + `ZEMTIK_SKIP_CIRCUIT_VALIDATION=1`** — when circuit validation is suppressed, `VALIDATE_ONLY` no longer exits 1 due to missing nargo/bb. Both flags now stack correctly.
- **`/health` `schema_validation.status`** — now reports `"warnings"` when ZK tools (nargo/bb) are missing, instead of silently reporting `"ok"`.
- **client_id=123 warning** — when demo default `client_id=123` returns 0 rows and `skip_client_id_filter=false`, a warning is logged pointing to the fix. Now uses the parsed config value (catches YAML-configured `client_id`, not just env var).
- **Test safety:** `startup_validation_skipped_when_env_set` now uses `#[serial]` to prevent undefined behavior from concurrent `set_var`/`remove_var` in parallel test execution.

### Changed
- `schema_config.example.json` — default `skip_client_id_filter` changed to `true` for `aws_spend` and `travel` tables (single-tenant is the common case for new integrations).
- Dockerfile ZK tool installation now uses pinned release tarballs instead of `curl | bash @main` (S3 security fix).
- Tunnel integration tests now run in CI alongside proxy tests.

### Upgrading to v0.9.1

New `[ZEMTIK] Schema validation` output appears in startup logs. This is intentional.

- **Warnings at startup** = real config issues to fix (empty table, missing table, missing ZK tools). Fix them or set `ZEMTIK_SKIP_DB_VALIDATION=1` to suppress.
- **Both suppression flags** stack correctly: `ZEMTIK_SKIP_DB_VALIDATION=1 ZEMTIK_SKIP_CIRCUIT_VALIDATION=1` → clean startup with no validation output.

---

## [0.9.0] - 2026-04-09

### Added
- **Tunnel mode** (`ZEMTIK_MODE=tunnel`) — transparent verification proxy that forwards all requests to OpenAI immediately (FORK 1) while running ZK proof verification in the background (FORK 2). Zero latency impact on the pilot customer.
- **`/tunnel/audit`** endpoint — JSON audit log of every request with match status, diff detection, ZK aggregate vs LLM response comparison. Protected by `ZEMTIK_DASHBOARD_API_KEY`.
- **`/tunnel/audit/csv`** — CSV export of audit records for compliance review.
- **`/tunnel/summary`** — aggregate metrics (total requests, matched rate, diff rate, avg latency).
- **`zemtik list-tunnel`** CLI command — inspect tunnel audit records from the command line.
- **`x-zemtik-receipt-id`** response header — correlates each request with its audit record ID.
- **Streaming support** — `stream:true` requests are fully supported; SSE chunks are teed to the client and accumulated for FORK 2 verification after the stream ends.
- **`docs/TUNNEL_MODE.md`** — full documentation for tunnel mode setup, configuration, and audit endpoints.
- **`TunnelMatchStatus::Diverged`** — audit records now distinguish between `matched` (ZK agrees with LLM) and `diverged` (ZK detects discrepancy).

### Changed
- `ProxyState` fields made `pub(crate)` to support the tunnel module.
- `run_fast_lane_engine()` and `run_zk_pipeline()` extracted as `pub(crate)` functions usable by tunnel FORK 2.
- `handle_health` now includes `mode`, `tunnel_semaphore_available`, `tunnel_semaphore_capacity`, and `tunnel_backpressure_count` fields in tunnel mode.

### Fixed
- `ZEMTIK_TUNNEL_API_KEY` missing in tunnel mode is now a hard startup error (prevents silent billing of the pilot customer's key).
- `handle_tunnel_passthrough` now forwards unrecognized routes transparently to the upstream OpenAI base URL, preserving the tunnel mode design goal of zero customer impact.
- Dashboard auth defaults to `401` when `ZEMTIK_DASHBOARD_API_KEY` is not configured (was silently allowing all requests).
- Dashboard API key comparison now uses constant-time equality to prevent timing-oracle attacks.
- Regex in `compute_diff` now compiled once at startup via `LazyLock` (was re-compiled per request).
- `ZEMTIK_TUNNEL_SEMAPHORE_PERMITS=0` and `ZEMTIK_TUNNEL_TIMEOUT_SECS` < 10 are now rejected at startup.
- Backpressure events now write a `Backpressure` audit record to the DB.
- CSV export now strips leading formula-injection characters (`=`, `+`, `-`, `@`) from field values.

## [0.8.2] - 2026-04-08

### Added
- **Docker support** — multi-stage `Dockerfile` (Rust 1.88 builder + Debian bookworm-slim runtime). Default image builds FastLane-only (~150MB); set `INSTALL_ZK_TOOLS=true` at build time for ZK SlowLane support (~450MB). Docker Hub/GHCR release automation added to `release.yml`.
- **`docker-compose.yml`** — demo deployment with all required env vars pre-configured. Includes comments for both FastLane (default) and ZK SlowLane variants.
- **CI pipeline** — `.github/workflows/ci.yml` runs unit tests, integration tests, clippy (`-D warnings`), and a Docker build on every push/PR. Integration tests use `ZEMTIK_SKIP_CIRCUIT_VALIDATION=1` so they run without nargo/bb.
- **Integration test suite** — `tests/integration_proxy.rs` spins up a real Axum server on an ephemeral port with a WireMock OpenAI stub and in-memory SQLite. Covers FastLane SUM and COUNT roundtrips, `/health`, passthrough for unsupported model, ambiguous-prompt 400, empty-prompt 400, and `schema_config`-missing 500.
- **`ZEMTIK_OPENAI_BASE_URL`** and **`ZEMTIK_OPENAI_MODEL`** env vars — override OpenAI endpoint and model at runtime; used in integration tests to point at a mock server.
- **`ZEMTIK_SKIP_CIRCUIT_VALIDATION`** env var — skip nargo/bb circuit-dir checks at proxy startup; required for Docker and integration tests.
- **`build_proxy_router()`** public function extracted from `run_proxy()` — allows integration tests to spin up a server on an ephemeral port without binding to a real address.

### Fixed
- **Clippy warnings resolved** — 13 pre-existing warnings suppressed or fixed (`too_many_arguments`, `is_multiple_of`, `.to_string()`). CI now enforces `-D warnings` from day one.
- **`render_verify_page` XSS** — `category` and `aggregate` fields in the `/verify/:id` HTML receipt page were not HTML-escaped; both now wrapped with `html_escape()`.
- **`circuit_dir_for(AggFn::Sum)` in CLI pipeline** — the CLI pipeline hardcodes a SUM query but was passing the root `circuit_dir` to nargo; now correctly resolves the `circuit/sum/` sub-directory.

## [0.8.1] - 2026-04-07

### Docs
- **README — FastLane documented as a first-class concept.** Added "Two Lanes: FastLane vs ZK SlowLane" section explaining when each path runs, the performance difference (< 50ms vs ~17–20s), and the security tradeoff (attestation-only vs UltraHonk proof). Added explicit warning that FastLane does not generate a ZK proof and is an honest-prover model only.
- **README — "How It Works" diagram forked.** Diagram now shows both execution paths (FastLane and ZK SlowLane) branching at the routing decision, making the two-lane architecture visible at a glance.
- **README — "How FastLane Works" section added.** Parallel to the existing "How the ZK Proof Works" section. Covers the DB aggregate query, `attest_fast_lane()` signature construction (`signing_version: 2`), `attestation_hash` semantics, and the offline verification limitation.
- **README — Trust Model updated.** FastLane and ZK SlowLane now have separate trust model paragraphs; the stronger trust requirement for FastLane (no circuit constraint) is called out explicitly.
- **README — Industry table legend added.** Footnote below the "Where Zemtik Applies" table explains the "FastLane or ZK" column and maps each option to the `schema_config.json` sensitivity field.
- **docs/ARCHITECTURE.md — FastLane section expanded.** Component 4 ("FastLane") now includes an attestation mechanics walkthrough, `signing_version: 2` explanation, latency context, and explicit note that no UltraHonk proof is generated. Cryptographic Security Properties section expanded with a dedicated FastLane caveat block.
- **docs/GETTING_STARTED.md — FastLane explained before first proxy example.** Step 5 now includes a short description of FastLane, the meaning of `attestation_hash`, and why the response shows `engine: "FastLane"` instead of `engine: "ZkSlowLane"`.
- **docs/SUPPORTED_QUERIES.md — FAQ entry added.** "What is the difference between FastLane attestation and a ZK proof?" answers the most common point of confusion for evaluators.

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
