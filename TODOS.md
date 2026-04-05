# TODOS

## P1 — Gating questions (blocking implementation)

### SF client demand confirmation (feat/routing-engine, before implementation)
- **What:** Ask SF client before starting implementation week: "If Zemtik could answer your standard analytics queries in under a second while keeping payroll/M&A ZK-verified, would that change how often your team uses it?"
- **Why:** The design doc flags this as the gating question for the routing engine. The answer determines whether the feature solves a real blocker or a hypothetical problem. Build decision should be confirmed, not assumed.
- **Pros:** Eliminates the risk of building the wrong feature.
- **Cons:** 1-3 day delay waiting for response.
- **Effort:** S (human) → S (CC+gstack)
- **Priority:** P1 — do this before writing a line of routing engine code
- **Depends on:** Nothing

---

## P2 — Blocking for productized distribution

### ~~CIRCUIT_DIR configurable~~ ✓ DONE (feat/distribution-improvement, 2026-03-27)
- `--circuit-dir <path>` CLI flag and `ZEMTIK_CIRCUIT_DIR` env var added to `config.rs`.
  Layered config system (defaults → YAML → env → CLI) resolves paths with tilde expansion.

### ~~Per-run work directories for ZK pipeline~~ ✓ DONE (feat/distribution-improvement, 2026-03-27)
- `prover::prepare_run_dir` creates `~/.zemtik/runs/{uuid}/` per proof run.
  RAII `RunDirGuard` (Drop impl) cleans up on all exit paths in both `main.rs` and `proxy.rs`.

### ~~Installation-specific signing key (replace hardcoded BANK_SK_SEED)~~ ✓ DONE (feat/distribution-improvement, 2026-03-27)
- `keys::load_or_generate_key` generates a random 32-byte BabyJubJub private key on first run,
  written to `~/.zemtik/keys/bank_sk` with mode `0600`. Public key fingerprint logged at startup.

---

## P3 — Tech debt, non-blocking

### Migrate CLI arg parsing to clap
- **What:** Replace manual `args.get(1)` / `args.get(2)` arg parsing with `clap`.
- **Why:** Works today with 2 subcommands (`--proxy`, `verify`). Will break cleanly at 3+ subcommands (`list`, `export`, `config`). Manual parsing is error-prone and produces no `--help`.
- **Effort:** S (human) → S (CC+gstack)
- **Trigger:** feat/verifier-flow adds `verify` as 2nd subcommand. Migrate before adding a 3rd.
- **Depends on:** feat/verifier-flow merged

### ~~bb verify timeout (prevents proxy deadlock)~~ ✓ DONE (fix/pipeline-timing-instrumentation v0.5.2)
- `ZEMTIK_VERIFY_TIMEOUT_SECS` (default 120) controls the timeout. Proxy returns HTTP 504 on expiry.
- **Known gap:** `bb` is abandoned (not killed) on timeout — see "Kill abandoned bb on timeout" P3 item below.

### Kill abandoned `bb` on timeout (DoS hardening)
- **What:** Switch from `Command::output()` (blocking) to `Child` + `child.kill()` so the `bb` process is actually killed when the timeout fires, not just abandoned.
- **Why:** The current timeout returns 504 to the client but leaves the `bb` child process running indefinitely. Under load, repeated timed-out ZK requests stack orphaned `bb` processes + temp directories, eventually exhausting process table and disk. Flagged by adversarial review (v0.5.2, two models).
- **How to apply:** Use `Command::spawn()` → `Child`. On timeout, call `child.kill().ok()` and `child.wait().ok()`. Clean up temp dirs only after the child exits.
- **Effort:** S (human ~2h) → S (CC+gstack ~15min)
- **Priority:** P3 (current timeout mitigates deadlock; kill is a hardening step)

### Integration tests for bb-dependent paths
- **What:** Integration tests for `verify_bundle` happy path, `generate_bundle`, and `run_verify_cli` that require the `bb` binary.
- **Why:** Unit tests cover parse logic and DB CRUD (63% coverage). The ZK proof round-trip paths are excluded because they require `bb` — a gap noted in Step 3.4 of the ship audit.
- **How to apply:** Add a `tests/integration/` directory, conditionally run with `#[cfg(feature = "integration")]` or behind `RUN_INTEGRATION_TESTS=1` env guard. Require `bb` to be in PATH.
- **Effort:** M (human) → M (CC+gstack)

### Cross-verify sidecar metadata against binary public_inputs
- **Status:** PROMOTED TO P2 — moved to feat/distribution-improvement scope (2026-03-27 CEO review + Codex outside voice)
- **What:** Parse the binary `public_inputs` file in the bundle and verify it matches `public_inputs_readable.json` (aggregate value, category, time range). Currently `bb verify` only checks the proof/vk/public_inputs binary — the human-readable JSON is self-reported.
- **Why:** An attacker could craft a bundle with a valid proof for aggregate=0 but set `"verified_aggregate": 9999999` in the sidecar JSON. The CLI and receipt page would display the fake number as if verified. Promoted because the SF pitch claims "cryptographic receipt" — that claim is only honest if the displayed aggregate is proof-bound.
- **How to apply:** In `verify_bundle`, after extracting the bundle, parse `public_inputs` as raw field elements (BN254 scalars) and compare each against the corresponding field in `public_inputs_readable.json`. Return an error if they diverge.
- **Effort:** M (human) → M (CC+gstack)

---

## Post-distribution TODOS (added 2026-03-27, CEO review feat/distribution-improvement)

### install.zemtik.dev — hosted, signed install script (P2, post-canal-qualification)
- **What:** Host install.sh at install.zemtik.dev with HTTPS + GPG-signed binaries. Enables `curl -sSL https://install.zemtik.dev | bash` as the onboarding URL.
- **Why:** Deferred from feat/distribution-improvement. GitHub Release artifact is sufficient for the SF demo. This becomes important when the SF commits to being a multi-client channel and starts deploying for other accounting firms — they will want a branded URL, not a GitHub link.
- **How to apply:** Set up DNS, SSL, CDN. Host install.sh (with arch detection) + sha256sums. Add GPG signing step to GitHub Actions release pipeline. The per-platform tarballs already exist on GitHub Releases — this just adds a universal entry point.
- **Effort:** M (human) → M (CC+gstack)
- **Depends on:** SF qualifying question answered affirmatively. feat/distribution-improvement merged.

### ~~`zemtik list` subcommand~~ ✓ DONE (feat/routing-engine, 2026-03-30)
- `cargo run -- list` implemented in main.rs via `receipts::list_receipts()`. Displays receipt_id, created_at, proof_status, engine_used fields.

### config.yaml schema versioning (P2, before second release)
- **What:** Add a `version: 1` field to config.yaml. On load, validate and emit a migration message if the schema version has changed.
- **Why:** If the config schema changes in a future release (new required field), SF engineers with existing installs will get a confusing startup failure with no guidance. Added as a result of feat/distribution-improvement establishing config.yaml as the canonical config format.
- **How to apply:** Add `schema_version: u32` to AppConfig. If absent or mismatched on load, print migration instructions and exit 1 with instructions to re-run install.sh or manually update config.yaml.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** feat/distribution-improvement merged. Ship before any breaking config schema change.

### Artifact version compatibility matrix (P2, before second client)
- **What:** Each GitHub Release encodes a version tuple `(nargo_version, bb_version, circuit_acir_hash)` in a `versions.json` file inside the tarball. On startup, zemtik checks that the loaded artifacts match the expected tuple and exits with a clear error if not.
- **Why:** A MAJOR version bump in bb makes all existing proofs unverifiable. Without a startup check, zemtik silently fails or generates unverifiable proofs after an upgrade. Identified by Codex outside voice (feat/distribution-improvement eng review, 2026-03-26).
- **How to apply:** Write `versions.json` during CI/CD release build. On proxy startup, load and validate. Return `Err("artifact version mismatch: expected nargo=X.Y.Z, found ...")` with remediation instructions.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** feat/distribution-improvement merged. Must ship before second client.

### Release integrity: sha256sums + GPG signing (P2, post-canal-qualification)
- **What:** Each GitHub Release includes a `SHA256SUMS` file covering all platform tarballs. Optionally, GPG-sign the checksums file. The install.sh verifies the checksum before executing binaries.
- **Why:** Zemtik distributes cryptographic tooling. An SF engineer evaluating it for compliance use will ask how they can verify the binary is legitimate. Without checksums, the answer is "trust us" — which undermines the product's core value proposition. Identified by Codex outside voice (2026-03-26).
- **How to apply:** Add `sha256sum` step to GitHub Actions release workflow. Update install.sh to download and verify SHA256SUMS before proceeding. GPG signing can wait for post-canal-qualification.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** feat/distribution-improvement merged (provides the release pipeline to extend).

---

## feat/intent-engine TODOs (added 2026-03-30, plan-ceo-review)

### Multi-turn context extraction for intent (P2, post-feat/intent-engine)
- **What:** Extend `proxy.rs:166` to concatenate the last N user messages before passing to `extract_intent`, not just the last message. Also handle structured content arrays (`[{"type":"text","text":"..."}]`) which currently yield an empty prompt string.
- **Why:** An analyst typing 'Q1 2024' as a follow-up to 'AWS spend' gets `NoTableIdentified` today — intent is split across turns. Flagged by Codex outside voice during CEO review. Structured content gap also flagged by Codex outside voice during feat/intent-engine eng review (2026-03-30) — many OpenAI SDK clients send structured content, making routing accuracy claims hollow for those clients.
- **Pros:** Improves routing accuracy for conversational use and for SDK clients that use structured message content. Stays local. No new dependencies.
- **Cons:** May over-weight stale context from earlier turns. Needs a window size parameter.
- **Context:** Current `proxy.rs:166` only extracts the last user message content if it's a plain string. Multi-turn context and structured message parts are dropped.
- **Effort:** S (human: ~2h / CC: ~10min)
- **Depends on:** feat/intent-engine merged.

### ONNX model integrity check at load time (P2, before second client)
- **What:** Compute SHA-256 of the downloaded BGE-small-en model file and store alongside it. Verify checksum on subsequent loads before ONNX runtime init.
- **Why:** The model binary downloads from the fastembed hub without integrity verification. For a ZK middleware marketing 'cryptographic safety,' a supply-chain attack on the ML model is a trust inconsistency. Severity: low for SF demo, medium for any enterprise with a security review.
- **Pros:** Closes a supply-chain gap. `sha2` already in `Cargo.toml`. Simple to implement.
- **Cons:** ~50ms startup overhead for 130MB file check. Checksum must be published alongside model updates.
- **Effort:** S (human: ~2h / CC: ~10min)
- **Depends on:** feat/intent-engine merged (provides the model download flow to extend).

### Schema hot-reload via SIGHUP (P3, post-v1)
- **What:** On SIGHUP, rebuild the embedding index from `schema_config.json` without proxy restart. Use Arc-swap pattern to atomically replace the `Arc<dyn IntentBackend>` in `ProxyState`.
- **Why:** Right now schema changes require a proxy restart. Operational friction for enterprise environments where table sensitivity changes frequently.
- **Pros:** Zero-downtime schema updates. Pairs well with external secret rotation flows.
- **Cons:** Requires careful coordination with `pipeline_lock` (ZK requests must not see a partially rebuilt index). Arc-swap is the clean pattern but adds complexity.
- **Context:** The design doc explicitly deferred this. Confirmed deferred in CEO review (2026-03-30). Revisit when second client onboards.
- **Effort:** M (human: ~3 days / CC: ~30min)
- **Depends on:** feat/intent-engine merged.

### Default time range is wall-clock dependent (P3, post-v1)
- **What:** Prompts with no time expression (e.g. "what is our total AWS spend?") default to the current calendar year. Add a `default_time_range` config option (e.g., `"full_history"`, `"current_year"`, or an explicit range) so behavior is deterministic across deployments.
- **Why:** Receipts generated from identical prompts in January vs December cover different data periods. For a system producing cryptographic receipts, this creates a reproducibility gap — two receipts with the same prompt but different timestamps silently represent different data. Surfaced by Codex outside voice during feat/intent-engine eng review (2026-03-30).
- **Pros:** Makes receipt interpretation unambiguous. Needed for audit trails. Simple config addition.
- **Cons:** Changing the default would be a breaking behavior change for existing users. Only add as an opt-in initially.
- **Context:** Existing behavior (default to current year) is inherited from the initial intent.rs. Not urgent for SF demo but becomes relevant when compliance teams review receipts.
- **Effort:** S (human: ~1h / CC: ~10min)
- **Depends on:** feat/intent-engine merged (provides DeterministicTimeParser where this config would be applied).

---

## feat/routing-engine TODOs (added 2026-03-30, plan-eng-review)

### ~~Evaluate evidence.rs vs. bundle.rs overlap~~ ✓ DONE (feat/routing-engine, 2026-03-30)
- FastLane Evidence Pack is JSON-only (no ZIP, no proof.bin). ZK bundles use ZIP with proof.bin/vk.bin/public_inputs. Formats are incompatible; evidence.rs as a separate module is the correct call.

### db.rs::sum_by_category integer overflow guard (P3)
- **What:** Add an explicit overflow check in sum_by_category: if the returned aggregate < 0, return Err(SumOverflow) instead of propagating a negative value.
- **Why:** SQLite SUM silently wraps to -1 on integer overflow. For financial data (if amounts are in dollars not cents), a large bank's Q1 data could theoretically overflow i64::MAX. FastLane would return an incorrect aggregate with no error, and the Evidence Pack would silently record wrong data.
- **Pros:** 2 lines of code. Prevents a silent correctness bug when real data is connected.
- **Cons:** None. Trivial to implement.
- **Context:** Not urgent for the synthetic PoC (500 seeded transactions with small amounts). Becomes a real risk when Supabase/real DB is connected. Implement alongside sum_by_category.
- **Depends on:** db.rs::sum_by_category implemented (this PR).

### ~~EvidencePack: include key_id for EmptyResult responses~~ ✓ DONE (fix/critical-bugs-v040, 2026-04-02)
- `EngineResult::EmptyResult` removed. All FastLane results (including row_count=0) return `Ok(FastLaneResult)` with a signed unified attestation. Zero-result receipts are now cryptographically bound to the installation key.

### ~~intent.rs: compile regexes once~~ ✓ DONE (feat/intent-engine, v0.4.0)
- `time_parser.rs` uses `std::sync::LazyLock` for all regexes (compiled once at first use). `RegexBackend` uses `str::contains()` — no `Regex::new()` calls in the hot path.

### run_zk_pipeline: reuse ledger DB instead of re-initializing (P3)
- **What:** `run_zk_pipeline` calls `db::init_db()` on every ZK request, re-seeding the demo SQLite in-memory DB each time. Share the existing `ledger_db` from `ProxyState`.
- **Why:** Found by Claude adversarial review (feat/routing-engine, 2026-03-30). Wastes CPU on every ZK slow-lane request; creates correctness risk if `pipeline_lock` is ever bypassed with concurrent ZK requests.
- **WARNING (Sprint 2):** `ProxyState.ledger_db` is always an in-memory SQLite connection (seeded via `init_ledger_sqlite`). `run_zk_pipeline` calls `db::init_db()` which can select Supabase when `DB_BACKEND=supabase`. Passing `ledger_db` directly to ZK would silently use the wrong backend in Supabase mode. Before implementing: either add a Supabase FastLane connector (Sprint 2 scope) or document that this reuse only applies to SQLite mode.
- **Effort:** S (human) → S (CC+gstack)

### ~~run_fast_lane blocks async executor while holding ledger_db lock~~ ✓ DONE (fix/critical-bugs-v040, 2026-04-02)
- `ledger_db` and `receipts_db` changed from `tokio::sync::Mutex<Connection>` to `std::sync::Mutex<Connection>`. FastLane call wrapped in `spawn_blocking(Arc::clone(&state))`. All `.lock().await` call sites replaced with `.lock().unwrap_or_else(|e| e.into_inner())`.

### ~~RE_BARE_YEAR captures non-year numbers~~ ✓ DONE (fix/critical-bugs-v040, 2026-04-02)
- Changed `\b(20\d{2})\b` → `\b(20[1-9][0-9])\b` (range 2010–2099). "2000 employees" no longer matches. Regression test `bare_year_ignores_non_year_numbers` added.

### ~~Add test for "May 2024" month name parsing~~ ✓ DONE (fix/critical-bugs-v040, 2026-04-02)
- `fn may_2024()` test added to `tests/test_time_parser.rs`, asserting `start = 1714521600`, `end = 1717199999`.

### Exact table key substring bypasses embedding threshold (P3, INVESTIGATE)
- **What:** In `extract_intent_with_backend`, rule 2 (substring gate) gives confidence `1.0` and skips all embedding + margin checks when exactly one table key or alias appears verbatim in the prompt. A user who knows any table key (e.g., `aws_spend`) can craft prompts that always route to FastLane regardless of what the embedding would score.
- **Why:** Found by Claude adversarial review (feat/intent-engine, 2026-04-01). Whether this is a bug or intentional depends on whether table keys are considered public. For an internal enterprise tool they typically are, so the risk is low. Worth reviewing before external clients onboard.
- **How to apply:** Decide: should exact-key substring matches still require embedding score ≥ threshold to confirm? Or document that table keys are public and the bypass is acceptable.
- **Effort:** S (human: ~1h / CC: ~10min)
- **Depends on:** feat/intent-engine merged.

### RE_BARE_YEAR historical range limitation (P3, post-v1)
- **What:** `RE_BARE_YEAR` regex is restricted to `20[1-9][0-9]` (2010–2099) to prevent false matches like "2000 employees". Pre-2010 historical data queries (2000–2009) will fall through to the current-year default with no error.
- **Why:** Sprint 1 (fix/critical-bugs-v040) narrowed the range from 2000–2099 to 2010–2099 to close the silent mismatch bug. The right long-term fix is a context-aware time parser that only treats 4-digit numbers as years when adjacent to financial context words.
- **How to apply:** Either expand the regex with context anchors (e.g., `\b(20[0-9]{2})\b(?=\s*(spending|spend|payroll|travel|cost|budget))`), or replace RE_BARE_YEAR with a proper NLP time expression parser in v2.
- **Effort:** S (human: ~2h / CC: ~15min)
- **Depends on:** Sprint 1 merged.

### intent.rs v2: multi-table query support (P3, post-v1)
- **What:** Extend intent.rs to extract multiple table names from a single query and apply the cross-sensitivity OR rule across all extracted tables.
- **Why:** v1 extracts only the first table match. A query like "What was Q1 payroll vs AWS spend?" would only process the first table found. The cross-sensitivity OR rule (if ANY table is critical → ZK SlowLane) is architecturally correct but unreachable in v1 for multi-table queries. v1 behavior: extract first table, add a note in the response: "Note: only processed [table] — multi-table queries not yet supported."
- **Pros:** Unlocks the full OR rule. Enables comparative analytics queries (payroll vs AWS in one shot).
- **Cons:** Multi-table output requires either two separate Evidence Packs or a new combined format. Schema for combined Evidence Pack needs design.
- **Context:** v1 single-table is a conscious shortcut. The router.rs OR rule is implemented correctly but only exercised in unit tests with simulated multi-table intent. Real user queries will need this in v2.
- **Depends on:** feat/routing-engine merged (provides the single-table v1 foundation).

### /verify page: show aggregate and category for FastLane receipts (P3, before v1)
- **What:** `/verify/:id` renders aggregate and category from `public_inputs_readable.json` inside the bundle ZIP. FastLane receipts have no bundle ZIP — `bundle_path` is empty, so aggregate and category show "—" on the verify page.
- **Why:** Found by Codex outside voice during fix/critical-bugs-v040 eng review (2026-04-02). FastLane attestation is the primary path for low-sensitivity tables. Auditors hitting `/verify/:id` for a FastLane receipt see no meaningful data beyond the badge and receipt ID.
- **How to apply:** Option A: store `aggregate` and `category_name` directly in the receipts table (schema migration). Option B: derive them from the `EvidencePack` JSON stored in the response (no schema change but requires storing the payload). Option A is cleaner — add `aggregate i64` and `category_name TEXT` columns to the receipts table with a v3 migration, populate on insert in `handle_fast_lane`.
- **Effort:** S (human: ~2h / CC: ~15min)
- **Depends on:** fix/critical-bugs-v040 merged.

---

## feat/zk-universalization TODOs (added 2026-04-02, plan-ceo-review)

### ~~poseidon_of_string: strings > 93 bytes not supported~~ ✓ DONE (feat/zk-universalization, 2026-04-02)
- `anyhow::ensure!(s.len() <= 93, ...)` added at top of `poseidon_of_string` in `db.rs`.
- `oversized_input_returns_error` and `max_length_input_succeeds` tests added in `tests/test_poseidon_compat.rs`.

### ~~poseidon_of_string: empty string and non-ASCII keys not guarded~~ ✓ DONE (worktree-ethereal-twirling-finch, 2026-04-02)
- Added `ensure!(!s.is_empty(), ...)` and `ensure!(s.is_ascii(), ...)` to `poseidon_of_string` in `db.rs`.
- Tests `empty_string_returns_error` and `non_ascii_input_returns_error` added in `tests/test_poseidon_compat.rs`.

### Supabase `category_name` column: existing tables not migrated (P2)
- **What:** Sprint 2 adds `category_name` to the Supabase SELECT query (`query_supabase`). Any Supabase `transactions` table created before Sprint 2 lacks the column — every ZK request on Supabase backend will fail with a PostgREST column-not-found error until the column is added.
- **Why:** Found by adversarial review (2026-04-02). `ensure_supabase_table()` creates the table with `category_name` if it doesn't exist, but never ALTERs an existing table to add the column.
- **How to apply:** Add a Supabase migration (`supabase/migrations/YYYYMMDDHHMMSS_add_category_name.sql`) that runs `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS category_name TEXT DEFAULT ''`. Also add a note to `GETTING_STARTED.md` / `CONFIGURATION.md` about re-running migrations after Sprint 2 upgrade.
- **Effort:** XS (human: ~30min / CC: ~10min)
- **Priority:** P2 — blocks any Supabase user who upgrades from Sprint 1
- **Depends on:** worktree-ethereal-twirling-finch (Sprint 2) merged.

### category_name DB / schema_config mismatch produces silent ZK undercount (P3)
- **What:** `poseidon_of_string(tx.category_name)` computes the witness hash from the DB value. `poseidon_of_string(intent.table)` computes the target hash from the schema_config key. If these strings differ (e.g., DB stores "AWS" but schema key is "aws_spend"), the circuit comparison always returns 0 matches — the proof is valid but the aggregate is silently 0.
- **Why:** Found by Codex outside voice during feat/zk-universalization eng review (2026-04-02). The `contains_key(&intent.table)` guardrail in proxy.rs checks that the table exists in schema_config, but does not validate that the category_name values already in the DB match the schema key. The demo DB is seeded from code so this risk is minimal today, but customer-loaded data could have inconsistencies.
- **How to apply:** In `sign_transactions` or `compute_tx_commitment`, validate that `tx.category_name` is present in `schema_config.tables` keys before hashing. Alternatively: add a startup validation step that queries the DB for distinct `category_name` values and checks them against `schema_config.tables`. Return a clear error if any DB category_name has no corresponding schema key.
- **Effort:** S (human: ~1h / CC: ~15min)
- **Priority:** P3 — not blocking Sprint 2, relevant before second enterprise client onboards
- **Depends on:** feat/zk-universalization (Sprint 2) merged.

---

## Commercial Readiness Sprint TODOs (added 2026-04-05, plan-ceo-review)

### Kill bb prove (generate_proof) on timeout (P3)
- **What:** Add timeout + kill to `prover.rs::generate_proof` — the `bb prove` subprocess has no timeout guard. If `bb prove` hangs, the process runs indefinitely and is never killed.
- **Why:** `generate_proof` (`prover.rs`) uses `std::process::Command::output()` with no timeout — the same pattern that `verify_proof` had before the Commercial Readiness Sprint fix. `bb prove` is typically slower than `bb verify` and more likely to hang on machine sleep/CRS download stall. Flagged by outside voice (plan-ceo-review, 2026-04-05).
- **How to apply:** Same pattern as the Commit 5 fix: `Command::spawn()` + polling loop with `child.try_wait()` + `child.kill().ok()` + `child.wait().ok()` on timeout. Add `ZEMTIK_PROVE_TIMEOUT_SECS` env var (or reuse `ZEMTIK_VERIFY_TIMEOUT_SECS`; they can share the same default).
- **Effort:** S (human: ~1h / CC: ~15min)
- **Priority:** P3 — not a pilot blocker; current timeout mitigates the proxy deadlock for verify. Implement in Pilot Week 1 hardening.
- **Depends on:** Commercial Readiness Sprint (v0.6.0) merged.

### Proxy auth middleware: require explicit caller authentication (P2, before second pilot)
- **What:** Add authentication middleware so only authorized callers can use the proxy when it is bound to a non-localhost address. Options: `ZEMTIK_API_KEY` header check, mTLS, or IP allowlist.
- **Why:** When `ZEMTIK_BIND_ADDR=0.0.0.0`, the proxy falls back to the server's `OPENAI_API_KEY` env var if no `Authorization` header is provided. Any machine on the LAN can use the server's OpenAI key without authentication. Found by Codex outside voice (plan-eng-review, 2026-04-05).
- **How to apply:** Add an Axum middleware layer that checks a `ZEMTIK_PROXY_API_KEY` header on all routes when `bind_addr` is non-localhost. Return `401 Unauthorized` if the key is missing or invalid. For localhost-only deployments, skip the check.
- **Effort:** S (human: ~2h / CC: ~15min)
- **Priority:** P2 — required before installing on any untrusted network. For the v0.6.0 pilot, the CDO deploys on an internal LAN — document that `OPENAI_API_KEY` must NOT be set on the server (require callers to pass their own key).
- **Depends on:** Commercial Readiness Sprint (v0.6.0) merged.

### table_name field in TableConfig (P3, Pilot Week 1)
- **What:** Add `table_name: Option<String>` to `TableConfig` in `config.rs`. If set, use this as the Supabase table name in `query_sum_by_category` instead of the schema_config key.
- **Why:** Currently, `query_sum_by_category` queries `/rest/v1/{table}` where `{table}` is the schema_config key. This means the Supabase table MUST be named identically to the schema_config key. A CDO with a table named `bank_transactions` and a schema key `aws_spend` would need to rename their table. Found by Codex outside voice (plan-eng-review, 2026-04-05).
- **How to apply:** `TableConfig { ..., table_name: Option<String> }`. In `query_sum_by_category`, use `table_config.table_name.as_deref().unwrap_or(schema_key)` as the PostgREST table name.
- **Effort:** XS (human: ~30min / CC: ~10min)
- **Priority:** P3 — v0.6.0 pilots can name their Supabase table to match the schema key. Add before second client if table naming flexibility is needed.
- **Depends on:** Commercial Readiness Sprint (v0.6.0) merged.

### Restore aarch64-linux-gnu and x86_64-apple-darwin CI targets (P3)
- **What:** Re-add `aarch64-unknown-linux-gnu` and `x86_64-apple-darwin` to the `release.yml` build matrix. Currently removed because `ort-sys@2.0.0-rc.11` does not provide prebuilt ONNX Runtime for Intel Mac and its cross-compilation from x86_64 picks up aarch64 OpenSSL for the build script linker (ABI mismatch).
- **Why:** Removed 2026-04-05 to unblock v0.6.0 release. `x86_64-linux` and `aarch64-apple-darwin` cover the CDO pilot use case. Intel Mac and aarch64-Linux ARM servers would benefit from coverage.
- **How to apply:** Option A: migrate from `ort` to `ort-tract` backend in `fastembed` — pure Rust, no prebuilt dependencies, cross-compiles cleanly. Option B: use `cargo-cross` with Docker images for aarch64-linux-gnu. Option C: when `ort-sys` adds prebuilt support for these targets, re-add them.
- **Effort:** M (human: ~1 day / CC: ~30min) for Option A; S for Option C.
- **Priority:** P3 — no active CDO/accounting pilot uses Intel Mac or aarch64-Linux.
- **Depends on:** v0.6.0 merged.
