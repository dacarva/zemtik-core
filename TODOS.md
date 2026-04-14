# TODOS

## ~~P1 — Integration test suite (added 2026-04-07, QA post-mortem)~~ **Completed: v0.8.2 (2026-04-08)**

### ~~End-to-end proxy integration tests (P1, before next sprint)~~
- **Completed:** `tests/integration_proxy.rs` — 7 integration tests covering FastLane SUM/COUNT, `/health`, passthrough, ambiguous-prompt 400, empty-prompt 400, missing schema 500. CI pipeline runs them on every push. See `feat/integration-test-and-docker`.

---

## DX additions — fix/integration-issues DX review (2026-04-10)

These items were added during `/plan-devex-review` of the pilot readiness plan.
All target v0.9.1. Ordered by pilot-blocking priority.

### ZEMTIK_VALIDATE_ONLY=1 env var (P1, v0.9.1)
- **What:** If `ZEMTIK_VALIDATE_ONLY=1` is set at startup, run full schema validation, print results as a block, exit 0 (all OK) or exit 1 (any WARNING). Enables pre-demo validation: `docker compose run --rm zemtik-proxy env ZEMTIK_VALIDATE_ONLY=1`
- **Why:** Zemtik engineer can validate schema_config.json before the customer demo starts — not discover failures live on-site. Like `nginx -t`.
- **Pros:** Zero new commands to learn (env var). Enables CI validation of schema_config.json.
- **Cons:** Minimal — ~20 lines in main.rs/proxy.rs.
- **Context:** Add to INTEGRATION_GUIDE.md as step 0 in the BYODB flow.
- **Effort:** S (CC: ~5 min)

### Startup validation block log format (P1, v0.9.1)
- **What:** Print schema validation as a single formatted block instead of interleaved log lines:
  ```text
  [ZEMTIK] Schema validation
  └ acme_transactions: 14,823 rows — OK
  └ acme_invoices: 0 rows — WARNING: empty table
  ```
- **Why:** In Docker, interleaved log lines scroll past. The Zemtik engineer can't narrate the validation result to the customer's IT team if they can't find it in the log stream.
- **Pros:** Scannable. Customer-readable. Narrate-able.
- **Effort:** XS (CC: ~5 min)

### example_prompts startup validation (P2, v0.9.1)
- **What:** During startup schema validation, warn if any table in schema_config.json has an absent or empty `example_prompts` field. Warning: "table X: example_prompts missing — embedding backend will fall back to regex matching (lower intent accuracy)."
- **Why:** A Zemtik engineer adding a new table for a future pilot and forgetting example_prompts gets silent regex fallback. No error. Queries route incorrectly with no indication why.
- **Effort:** XS (CC: ~5 min)

### Startup event log (~/.zemtik/startup_events.jsonl) (P2, v0.9.1)
- **What:** At each startup validation step, append a JSONL event: `{"ts": "ISO", "table": "...", "status": "ok|warning", "row_count": N, "warnings": [...]}`. One file, one entry per table per startup.
- **Why:** After a customer deployment, the Zemtik team can review exactly what happened and when. Structured data beats memory. Enables learning across pilot deployments.
- **Effort:** S (CC: ~10 min)

### Structured DB error 500 (P1, v0.9.1)
- **What:** The `EngineResult::DbError` path in proxy.rs:504 returns a raw 500. Add structured body: `{"error": {"type": "zemtik_db_error", "code": "QueryFailed", "message": "<db error>", "hint": "Check physical_table, value_column, timestamp_column against your schema."}}`.
- **Why:** If the customer's Postgres rejects a query (RLS, wrong column, network blip), the Zemtik engineer sees nothing useful. Pilot-blocking if this happens mid-demo.
- **Effort:** S (CC: ~10 min)

### TROUBLESHOOTING.md (P1, v0.9.1)
- **What:** New `docs/TROUBLESHOOTING.md` — 6-entry symptom → cause → fix table covering: 0-row aggregate, streaming hang, NoTableIdentified, ZK tools absent, column not found, DB connection refused.
- **Why:** During a live customer deployment the Zemtik engineer needs to diagnose fast. Currently they'd grep through 10 docs files. One reference doc eliminates that.
- **Effort:** S (CC: ~15 min doc writing)

### v0.9.1 upgrade note in CHANGELOG.md (P1, v0.9.1)
- **What:** Add a brief "Upgrading to v0.9.1" section: what's new, what WARNINGs to expect at startup, what they mean. Existing customers who upgrade and have misconfigured schema_config.json will see new WARNINGs they've never seen before.
- **Why:** Without context, a Zemtik engineer upgrading a customer deployment might think the proxy is broken when it logs a startup warning for the first time.
- **Effort:** XS (CC: ~5 min)

---

## DX debt — added from feat/universal-zk-engine DX review (2026-04-07)

### Structured JSON error responses (P3, v2)
- **What:** Migrate proxy error strings to a structured `{ "error": { "type": "...", "code": "...", "message": "...", "doc_url": "..." } }` shape (Stripe API pattern). Currently errors are plain strings.
- **Why:** Platform engineers parsing responses programmatically can't distinguish error types without regex. Affects every integration that handles errors gracefully.
- **Pros:** Cleaner client integration, debuggable error types, linkable to docs.
- **Cons:** Breaking change to the error response shape — requires a versioned rollout.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** evidence_version field already added (v2 responses)

### Pre-built binary with compiled ZK circuits (P2, post-sprint)
- **What:** Compile `circuit/sum/` and `circuit/count/` mini-circuits in the GitHub Actions release pipeline and include the compiled artifacts in the tarball.
- **Why:** The first request for a COUNT or AVG query triggers circuit compilation (~30-120s). The proxy logs `[PROXY] Compiling circuit...` but platform engineers watching a demo think the proxy is hung. Pre-compiled artifacts eliminate this entirely.
- **Pros:** First-request latency drops to proof generation only (~17s). Champion-tier DX for demo environments.
- **Cons:** Increases tarball size (~5-15MB per circuit). CI build time increases by ~2min.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** ~~feat/universal-zk-engine merged~~ ✓ UNBLOCKED (v0.8.0, 2026-04-07) — mini-circuits exist at circuit/sum/ and circuit/count/

### AVG evidence model explainer page (P3, post-sprint)
- **What:** A standalone `docs/AVG_EVIDENCE.md` that explains the ZK composite evidence model for AVG: why there are two proof hashes, what the BabyJubJub attestation covers, and how to verify each component. Target audience: compliance officer reviewing audit bundles.
- **Why:** The `avg_evidence_model: "zk_composite+attestation"` field tells engineers there's a mixed model, but compliance officers reading the bundle need plain language. Missing this doc means the compliance officer asks the engineer, who has to invent an explanation on the spot.
- **Pros:** Compliance officer can self-serve during bundle review. Reduces demo prep time.
- **Cons:** Needs updating if the AVG pipeline changes (e.g., full ZK AVG circuit in Phase 2).
- **Effort:** S (human) → S (CC+gstack)
- **Context:** Link this doc from `request_meta.json` inside AVG proof bundles as `"evidence_model_docs": "https://github.com/zemtik/zemtik-core/blob/main/docs/AVG_EVIDENCE.md"`.
- **Depends on:** feat/universal-zk-engine merged

---

## DX additions — query rewriting DX review (2026-04-12)

Added from `/plan-devex-review` of the query rewriting plan (worktree-worktree-greedy-drifting-reddy).

### Deterministic-only rewriting mode (P2, v1.0)

- **What:** Add `ZEMTIK_QUERY_REWRITER_LLM_FALLBACK=0` — enables deterministic context propagation (`deterministic_resolve`) without LLM rewrite fallback. When set, failing queries that the deterministic path can't resolve return 400 (no LLM call made).
- **Why:** The LLM rewriter sends prior conversation turns to an external LLM endpoint. For deployments with strict data residency requirements where query text cannot leave the proxy boundary, the LLM fallback is unacceptable. The deterministic path is zero-cost, stays within the proxy boundary, and handles the majority of simple time-only follow-ups.
- **Pros:** Data residency compliance without disabling rewriting entirely. The deterministic path covers ~70% of multi-turn cases at zero cost.
- **Cons:** ~5 LOC config change + docs update. Table-switching follow-ups ("And for payroll?") won't resolve without LLM.
- **Context:** The data residency note in CONFIGURATION.md (DX Fix 9) mentions this as option (a). Engineering work is minimal — it's a conditional check at the `rewrite_query` call site in `proxy.rs`.
- **Effort:** XS (CC: ~15 min)
- **Depends on:** query rewriting feature shipped

---

## Tunnel Mode deferred items — added from feat/tunnel-mode (2026-04-08)

### Drift alert webhook (P3, v2)
- **What:** `ZEMTIK_TUNNEL_WEBHOOK_URL` — POST a JSON payload to this URL whenever `diff_detected=true` exceeds a configurable threshold rate (e.g. `ZEMTIK_TUNNEL_ALERT_DIFF_RATE_THRESHOLD=0.1`).
- **Why:** Today, divergence is only visible via `/tunnel/summary` or `list-tunnel`. A pilot customer's ops team needs a push notification when Zemtik would have caught a real discrepancy, so they can investigate proactively.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** tunnel mode shipped (feat/tunnel-mode)

### Audit durability on container restart (P3, v2)
- **What:** Document and default `ZEMTIK_TUNNEL_AUDIT_DB_PATH` to a named Docker volume path so `tunnel_audit.db` survives container recreates (similar to the `receipts.db` volume added in v0.8.2).
- **Why:** Currently `tunnel_audit.db` is written to `~/.zemtik/tunnel_audit.db` inside the container. If the container is recreated without a volume mount, all audit history is lost. The docker-compose.yml currently has a commented section but no volume is declared.
- **Effort:** XS (human) → XS (CC+gstack)
- **Depends on:** tunnel mode shipped

### Interactive HTML dashboard at /tunnel/dashboard (P3, v2)
- **What:** A single-page HTML dashboard served at `/tunnel/dashboard` (no JS framework) showing a live table of audit records, match/diff rates, and a simple timeline chart.
- **Why:** The JSON API at `/tunnel/audit` is sufficient for engineers but not for a pilot customer's manager who wants a weekly screenshot for a status update.
- **Effort:** M (human) → S (CC+gstack)
- **Depends on:** tunnel mode shipped

---

## ~~Stage 1 — Audit Trail Integrity (2026-04-14)~~ **Completed: v0.12.0-dev**

- ed25519 manifest signing, `outgoing_prompt_hash` as ZK circuit public input, bundle_version=3, GET /public-key endpoint, `manifest_key_id` in receipts.
- All 10 manual QA checks passed. 285 unit + integration tests green.
- Bundle-demotion-attack (flip bundle_version 3→2): blocked by public_inputs size check (224 vs 192 bytes). Incidental but effective defense.
- Known gap: v2 `outgoing_prompt_hash` display in `zemtik verify` shows "Circuit public input #6" even though for v2 it's sidecar-sourced. Cosmetic only.
- Known gap: CLI pipeline passes `outgoing_prompt_hash=0` to nargo execute — breaks with v3 circuit (assert(outgoing_prompt_hash != 0)). CLI pipeline must be updated to hash the hardcoded query before passing it as a witness.
- Known gap: `verify_bundle` in offline mode requires the prover's local `~/.zemtik/keys/bank_sk` to reconstruct the ed25519 verifying key. Auditors running `zemtik verify` on a third-party bundle need a portable verifying-key sidecar or the `GET /public-key` endpoint. Tracked for Stage 2.

---

## DX additions — GeneralLane DX review (2026-04-13)

Added from `/plan-devex-review` of fix/general-queries.

### ~~intent_failures_today counter approach (P1, v0.11.0)~~ **Completed: v0.11.0 (2026-04-13)**

- **What:** `intent_failures_today: u64` and `general_queries_today: u64` added to `/health` response. Uses `count_engine_today("general_lane")` and `count_intent_failures_today()` — both backed by the v7 composite index. Intent failures use the existing `intent_rejections` table (no new DB writes on error paths).
- **Completed:** fix/general-queries PR.

---

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

### ~~Migrate CLI arg parsing to clap~~ ✓ DONE (main.rs already uses clap, 2026-04-08)
- `use clap::{Parser, Subcommand}` in main.rs. `Commands` enum with `Proxy`, `Verify`, `List` variants. `feat/tunnel-mode` adds `ListTunnel`.

### ~~bb verify timeout (prevents proxy deadlock)~~ ✓ DONE (fix/pipeline-timing-instrumentation v0.5.2)
- `ZEMTIK_VERIFY_TIMEOUT_SECS` (default 120) controls the timeout. Proxy returns HTTP 504 on expiry.
- **Known gap:** `bb` is abandoned (not killed) on timeout — see "Kill abandoned bb on timeout" P3 item below.

### ~~Kill abandoned `bb` on timeout (DoS hardening)~~ ✓ DONE (v0.6.0, 2026-04-06)
- `poll_child_with_timeout` in `prover.rs` kills and reaps `bb` on timeout. Applied to both `verify_proof` (prover.rs) and `verify_bundle` (verify.rs). **Completed:** v0.6.0 (2026-04-06)

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

### /health endpoint: Supabase probe DoS and timing oracle (P2, before non-localhost deploy)
- **What:** Rate-limit `GET /health` and move the Supabase liveness probe to a background ticker. The current `/health` fires a live PostgREST request on every call — unauthenticated (per TODOS P2 auth middleware TODO), enabling DoS via sustained polling that exhausts Supabase rate limits.
- **Why:** Found by Claude adversarial review (v0.6.0 pre-landing). Any LAN attacker can exhaust Supabase API quota by looping `GET /health`. Also provides a timing oracle for Supabase key validity. For `127.0.0.1` deployments the attack surface is minimal.
- **How to apply:** A) Add a background health-check task (tokio interval) that caches the last probe result. Return the cached result instantly. B) Rate-limit to 1 req/sec per IP. Full fix requires auth middleware.
- **Effort:** S (human: ~1h / CC: ~15min)
- **Priority:** P2 — low risk for localhost-only deployments; required before `ZEMTIK_BIND_ADDR=0.0.0.0`.
- **Depends on:** Proxy auth middleware TODO.

### ZK slow lane re-initializes DB on every request (P2)
- **What:** `run_zk_pipeline` calls `db::init_db()` on every ZK slow lane request (proxy.rs:~1004). `init_db()` conditionally runs `ensure_supabase_table()` DDL and seeds 500 rows. Two concurrent ZK requests can double-seed (race between `supabase_is_empty` check and insertion). Even with `SUPABASE_AUTO_SEED=0`, calling `init_db()` per request is wasteful.
- **Why:** Found by Claude adversarial review (v0.6.0 pre-landing). Concurrent ZK requests on a fresh Supabase table can double-seed data.
- **How to apply:** Move DB initialization to `ProxyState` startup. Pass the initialized `DbBackend` through `Arc<ProxyState>`. Already done for `ledger_db` (SQLite), extend to Supabase backend.
- **Effort:** M (human: ~2h / CC: ~20min)
- **Priority:** P2 — low risk with `SUPABASE_AUTO_SEED=0` (new default), but the per-request `init_db` is still an unnecessary overhead.
- **Depends on:** Commercial Readiness Sprint (v0.6.0) merged.

### init_supabase bypasses AppConfig (P3)
- **What:** `init_supabase()` and `ensure_supabase_table()` in `db.rs` read `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` directly from `std::env::var`, bypassing the layered `AppConfig`. If a user sets these in `config.yaml`, the proxy's intent/routing path (which reads from `AppConfig`) works correctly, but `init_supabase` at startup still requires the env vars.
- **Why:** Found by Claude adversarial review (v0.6.0 pre-landing). The two code paths can diverge: YAML config works for queries but startup fails if env vars are absent.
- **How to apply:** Pass `AppConfig` (or at minimum `supabase_url: Option<String>`, `supabase_service_key: Option<String>`) into `init_db()` / `init_supabase()`.
- **Effort:** S (human: ~1h / CC: ~15min)
- **Priority:** P3 — affects only users who set Supabase credentials via YAML (not common; env vars are the documented path).
- **Depends on:** Commercial Readiness Sprint (v0.6.0) merged.

### Restore aarch64-linux-gnu and x86_64-apple-darwin CI targets (P3)
- **What:** Re-add `aarch64-unknown-linux-gnu` and `x86_64-apple-darwin` to the `release.yml` build matrix. Currently removed because `ort-sys@2.0.0-rc.11` does not provide prebuilt ONNX Runtime for Intel Mac and its cross-compilation from x86_64 picks up aarch64 OpenSSL for the build script linker (ABI mismatch).
- **Why:** Removed 2026-04-05 to unblock v0.6.0 release. `x86_64-linux` and `aarch64-apple-darwin` cover the CDO pilot use case. Intel Mac and aarch64-Linux ARM servers would benefit from coverage.
- **How to apply:** Option A: migrate from `ort` to `ort-tract` backend in `fastembed` — pure Rust, no prebuilt dependencies, cross-compiles cleanly. Option B: use `cargo-cross` with Docker images for aarch64-linux-gnu. Option C: when `ort-sys` adds prebuilt support for these targets, re-add them.
- **Effort:** M (human: ~1 day / CC: ~30min) for Option A; S for Option C.
- **Priority:** P3 — no active CDO/accounting pilot uses Intel Mac or aarch64-Linux.
- **Depends on:** v0.6.0 merged.

---

## P2 — FastLane verifier path (added by /plan-ceo-review 2026-04-06)

### FastLane attestation signature storage + offline verifier

- **What:** Store BabyJubJub signature bytes (`sig.r_b8.x`, `sig.r_b8.y`, `sig.s`) in `receipts.db`
  alongside `attestation_hash`. Add `zemtik verify-fastlane <receipt_id>` CLI command that
  re-derives the payload from stored receipt fields and verifies the signature against the stored
  public key.
- **Why:** Currently, FastLane receipts store only `attestation_hash` — the hash of the signature
  bytes. An auditor cannot verify the signature without the original bytes. The claim "auditor can
  verify how it was computed" is incomplete until the raw signature is stored. Detected by Codex
  outside voice during /plan-ceo-review (2026-04-06) on feat/universal-fast-engine.
- **Pros:** Makes the FastLane attestation fully auditable, on par with ZK bundle verification.
  Required for enterprise compliance use cases (e.g., SOC 2 evidence chain).
- **Cons:** receipts.db schema change (add 3 columns). Requires v3 migration in `receipts.rs`.
  Adds `verify-fastlane` as a 3rd CLI subcommand (migrate arg parsing to clap first — see P3).
- **Context:** The `signing_version: 2` field added in feat/universal-fast-engine enables the
  verifier to distinguish old (v1) from new (v2) receipt formats. Build the verifier against v2.
- **Effort:** S (human) → S (CC+gstack)
- **Priority:** P2 — blocking for enterprise audit compliance pitch
- **Depends on:** feat/universal-fast-engine merged (signing_version: 2 format)

---

## P3 — Intent subcategory extraction (added by /plan-ceo-review 2026-04-06)

### Intent engine: extract subcategory value from prompt

- **What:** Extend `IntentResult` to carry an optional `category_value: Option<String>` separate
  from `category_name` (the table key). When present, use `category_value` as the filter value
  for `category_column` instead of the table key.
- **Why:** Currently `category_name = table_key` always (e.g., "aws_spend"). A user asking
  "AWS spend on EC2" or "headcount for Engineering department" cannot get subcategory results —
  the intent engine has no mechanism to extract "EC2" or "Engineering" from the prompt.
  Detected during /plan-ceo-review (2026-04-06) cross-referencing intent.rs:182-189.
- **Pros:** Enables rich subcategory filtering without code changes — only prompt + schema_config.
  Unlocks the full power of `category_column` as designed.
- **Cons:** Requires training data or LLM-assisted extraction in the intent engine. Complex
  disambiguation (is "for Engineering" a category or a recipient?). Embedding approach may not
  generalize without per-table example subcategory values in schema_config.json.
- **Context:** `category_column` in TableConfig already supports this at the DB layer — the gap
  is purely in the intent extraction layer.
- **Effort:** L (human) → M (CC+gstack)
- **Priority:** P3 — non-blocking, ZK universalization is higher priority
- **Depends on:** feat/universal-fast-engine merged

---

## P4 — category_column=null → explicit HTTP 400 when prompt implies category filtering (added by /plan-eng-review 2026-04-06)

### Fail-secure response when category filtering is unsupported

- **What:** When `category_column: null` and the user prompt implies category-level filtering (e.g., "AWS spend on EC2"), return HTTP 400 with a clear error instead of silently returning the whole-table aggregate + LLM note.
- **Why:** Currently the system silently falls back to a whole-table aggregate and relies on a payload note to prevent the LLM from hallucinating category precision. This is the wrong failure mode — an auditor-grade system should reject unsupported queries explicitly, not let them through with a warning. Detected during /plan-eng-review (2026-04-06) via Codex outside voice (Issue #5).
- **Pros:** Makes the system fail-secure. No ambiguity about what the query returned. Prevents misleading receipts where the attestation says "category: new_hires" but the data is the entire table.
- **Cons:** Requires the intent engine to detect whether a prompt implies subcategory filtering (separate from P3). Cannot be implemented until P3 (intent subcategory extraction) is complete — without knowing whether the user asked for a category vs the whole table, we cannot distinguish "how many new hires?" (whole table fine) from "how many hires in Engineering?" (would need subcategory filter).
- **Context:** The payload note approach (current) is acceptable for the CDO pilot. The 400 approach is the production-grade behavior. Build after P3 is shipped.
- **Effort:** S (human) → S (CC+gstack) — 1 proxy.rs check + 1 test
- **Priority:** P4 — non-blocking, requires P3
- **Depends on:** P3 (intent subcategory extraction) merged

---

## P2 — feat/universal-zk-engine (added by /plan-ceo-review 2026-04-07)

### AVG over Supabase operates on two independent dataset snapshots

- **What:** In AVG mode, `run_zk_pipeline` is called twice (SUM + COUNT). Each call invokes `db::init_db()` separately. For SQLite (demo), this is deterministic (seeded data). For Supabase (production), the two calls hit the live DB at different timestamps — if a transaction is inserted between the SUM call and the COUNT call, the SUM and COUNT operate on different datasets. The AVG will be mathematically inconsistent (numerator from N+1 rows, denominator from N rows).
- **Why:** Found by Codex adversarial review during /plan-ceo-review (2026-04-07). The `avg_pipeline_lock` prevents concurrent ZK requests but does not prevent changes in the external Supabase database.
- **Pros of fixing:** AVG is cryptographically consistent — both proofs are over the exact same dataset. Required for compliance use cases where auditors may check SUM/COUNT proofs independently.
- **Cons:** Requires passing a pre-fetched transaction set to both pipeline runs (instead of letting each call `init_db()`). Requires `run_zk_pipeline` to accept pre-fetched data as a parameter.
- **Context:** The demo uses SQLite (deterministic, seeded). For the first demo, document this as a known limitation in `request_meta.json` as `"avg_snapshot_model": "sequential_independent"`. Fix before shipping Supabase AVG to production.
- **Effort:** M (human: ~2h / CC: ~20min) — refactor `run_zk_pipeline` to accept pre-fetched TransactionBatch
- **Priority:** P2 — blocking for production Supabase AVG; non-blocking for SQLite demo
- **Depends on:** feat/universal-zk-engine merged

---

### AVG queries produce two independent receipts — AVG value not visible in `zemtik list`

- **What:** `handle_avg` inserts two receipts into the receipts DB: one for the SUM bundle (aggregate = raw SUM value) and one for the COUNT bundle (aggregate = row count). `zemtik list` shows these as two independent ZK SlowLane queries. The actual AVG value (SUM / COUNT) is not recorded anywhere in the receipts ledger or the `/verify` page. A compliance officer reviewing the audit trail cannot find the AVG query.
- **Why:** Found by Claude subagent adversarial review during /plan-eng-review (2026-04-07). The bundle metadata includes `avg_bundle_pair_id` linking the two bundles, but there is no consolidated receipt. The `zemtik list` UX is misleading for AVG.
- **Pros of fixing:** Full audit trail — compliance officer runs `zemtik list` and sees one AVG entry with the computed value, referencing both the SUM and COUNT proof bundles.
- **Cons:** Requires a new `engine_used = 'zk_slow_lane_avg'` type, a new receipt insert with `sum_bundle_id` + `count_bundle_id` + `avg_value`, and updates to `zemtik list` display formatting.
- **Context:** For the first demo, the compliance officer is told to verify both bundles separately and compute the AVG manually. The `avg_bundle_pair_id` in each bundle's `request_meta.json` links them. Document this limitation in the demo script.
- **Effort:** S (human: ~1h / CC: ~15min) — new engine_used type, one INSERT, list display update
- **Priority:** P2 — non-blocking for demo; required for production audit trail
- **Depends on:** feat/universal-zk-engine merged

---

## P1 — Docker ZK tools hash pinning (added 2026-04-08, ship review feat/integration-test-and-docker)

- **What:** The `Dockerfile` installs nargo (via `noirup`) and bb (via `bbup`) using `curl | bash` when `INSTALL_ZK_TOOLS=true`. Neither installer URL is pinned to a content hash. A compromised installer would execute arbitrary code as root inside the builder layer, tainting the final image binary.
- **Why:** Supply-chain integrity for the ZK path. The FastLane-only image (default) is unaffected, but the ZK SlowLane variant (`INSTALL_ZK_TOOLS=true`) is exposed. At the time of shipping, this path is documented as experimental/advanced, so risk is low. Needs a proper fix before the ZK path is recommended to enterprise customers.
- **How to fix:** Pin the installer scripts with `sha256sum -c` before executing, or copy pre-built, hash-verified binaries from a trusted artifact registry (e.g., GitHub Release asset with verified SHA) rather than running shell-pipe installers as root.
- **Effort:** S (human: ~1h / CC: ~15min) — update Dockerfile RUN commands, add sha256 verification
- **Priority:** P1 — fix before marketing the ZK SlowLane Docker path to customers

---

## Tunnel mode — post-pilot improvements (added 2026-04-08, feat/tunnel-mode CEO review)

### Drift alert webhook (P2, post-pilot week 2)

- **What:** POST to `ZEMTIK_TUNNEL_WEBHOOK_URL` when `diff_rate_last_N > threshold` (configurable). Payload JSON with `{n_requests, diff_rate, threshold, sample_record}`. Customer connects to Slack, PagerDuty, or their own system.
- **Why:** Pilot customer needs proactive alerts when ZK-verified numbers diverge from unverified OpenAI responses. Without this, they do manual polling of `/tunnel/audit`. Transforms zemtik from a passive audit tool into an active data quality monitor.
- **Pros:** Turns a 4-week eval into an active monitoring setup. Bridges toward production adoption.
- **Cons:** Requires background aggregation task, HTTP client in tunnel.rs, new config fields. ~150 LOC.
- **Context:** Decision made during CEO review: defer until pilot customer is onboarded and explicitly requests it. Do not build for a user who doesn't exist yet.
- **Effort:** M (human: ~3h) → S (CC+gstack: ~30min)
- **Priority:** P2 — build in week 2 of pilot if requested
- **Depends on:** `ZEMTIK_MODE=tunnel` shipped and running for a pilot customer

### Tunnel audit durability on restart (P3)

- **What:** At startup in tunnel mode, if `tunnel_audit` and `receipts` tables exist, check if any receipts with `created_at` in the last 180s have no matching `tunnel_audit` entry. Log: `[WARN] N tunnel audit records may be missing due to process restart`.
- **Why:** When zemtik restarts mid-flight (FORK 2 in progress), audit records for those requests are silently lost. For a compliance pilot, silent gaps in the audit trail undermine trust. A visible warning at startup makes the gap explicit and auditable.
- **Pros:** 5 minutes of code, changes a silent gap into a visible + logged gap.
- **Cons:** Adds startup latency if `tunnel_audit` is large (~10ms for 1000 records).
- **Context:** Raised by Codex outside voice review. Shutdown/restart story was not in the original spec.
- **Effort:** S (human: ~30min) → XS (CC+gstack: ~5min)
- **Priority:** P3 — not blocking for pilot launch; add before marketing tunnel mode broadly
- **Depends on:** tunnel mode shipped

### Migration v6 downgrade documentation (P3, before second customer)

- **What:** Add a note to release notes and TUNNEL_MODE.md: "The `tunnel_audit` table (migration v6) is one-way. Back up your `~/.zemtik/receipts.db` before downgrading zemtik to a version before tunnel mode."
- **Why:** Silent data loss on downgrade is worse than a downgrade failure. A compliance pilot customer will have audit records they need to retain.
- **Effort:** XS (human: ~5min / CC: ~2min)
- **Priority:** P3 — add before shipping to second customer
- **Depends on:** tunnel mode shipped (migration v6 merged)

### Semaphore permits in /health (P3)

- **What:** Add `"tunnel_semaphore_available_permits": N` to the `/health` JSON response when running in tunnel mode.
- **Why:** A platform engineer monitoring the proxy can see backpressure building up before it starts dropping FORK 2 tasks. Currently /health has no visibility into tunnel mode state.
- **Pros:** ~5 LOC. Enables proactive scaling decisions.
- **Cons:** Minor: slightly increases /health response size.
- **Effort:** XS (human: ~15min / CC: ~5min)
- **Priority:** P3 — not blocking for pilot, useful for week 2+ monitoring
- **Depends on:** tunnel mode shipped

---

## Integration Validation deferred items — added from fix/integration-issues (2026-04-10)

### PostgREST smoke-test at startup

See canonical entry below: [PostgREST smoke-test at startup (P2, v0.9.2)](#postgrest-smoke-test-at-startup-p2-v092). Duplicate removed.

### x-zemtik-warning response header (P3, v2)
- **What:** When the proxy emits a startup warning (client_id=123, schema_validation warnings, ZK tools absent), include a `x-zemtik-warning: <code>` response header on subsequent chat completions responses. Clients can inspect this header programmatically during integration testing.
- **Why:** Current warnings are log-only. An API caller running automated integration tests cannot observe warnings without reading server logs. A response header gives immediate, programmatic signal.
- **Pros:** No breaking change. Additive header. Enables automated integration test assertions on warning paths.
- **Cons:** Slightly increases response size. Requires deciding which warnings propagate to per-request headers (startup warnings vs. per-query).
- **Context:** Identified during eng review. Particularly useful for testing client_id=123 warning path (log-only today, no HTTP observable signal).
- **Effort:** S (human: ~1h / CC: ~10min)
- **Priority:** P3 — post-pilot, DX improvement
- **Depends on:** fix/integration-issues merged

---

### HTML dashboard /tunnel/audit (P2, post-pilot)

- **What:** `GET /tunnel/audit` with `Accept: text/html` (or no `Accept` header) returns an HTML page with a sortable table of audit records. Similar to the existing `/verify/{id}` HTML page.
- **Why:** If the pilot customer wants to share audit results with non-technical stakeholders (compliance officer, CFO), a navigable HTML table is more convincing than a raw JSON blob.
- **Pros:** ~100 LOC. Reuses existing HTML templating pattern from verify.rs. High perceived value, low effort.
- **Cons:** Content negotiation adds a small amount of complexity to handle_tunnel_audit.
- **Context:** Deferred from initial pilot launch per CEO review. Build in week 2 if customer requests it.
- **Effort:** S (human: ~2h / CC: ~20min)
- **Priority:** P2 — build in week 2 of pilot if requested
- **Depends on:** tunnel mode shipped, pilot customer onboarded

---

## PostgREST smoke-test at startup (P2, v0.9.2)

- **What:** After Postgres column/row validation, if `DB_BACKEND=supabase`, fire a `GET {SUPABASE_URL}/rest/v1/{table}?select={value_column}&limit=1` against each table via PostgREST. Record result (200 vs 4xx/5xx) in startup event log and print to the formatted validation block.
- **Why:** `startup.rs` validates the Postgres direct connection only. FastLane queries go through PostgREST (SUPABASE_URL). A table can pass startup validation and still fail every query at runtime if PostgREST has RLS, auth, or aggregate permission issues. This gap has caused silent failures in past sessions (prior learning: `startup-validation-postgrest-gap`).
- **Pros:** Catches RLS/PostgREST auth misconfiguration before the demo starts. Pairs with `ZEMTIK_VALIDATE_ONLY=1` for pre-demo smoke-test.
- **Cons:** Makes startup slower when Supabase is configured (~1 HTTP call per table). Add `ZEMTIK_SKIP_POSTGREST_VALIDATION` env var to suppress for offline environments.
- **Context:** Start in `validate_table()` in `startup.rs` — that function already owns per-table validation and writes to the event log. PostgREST check follows the same pattern: call, record result, print summary line.
- **Depends on / blocked by:** Requires `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` to be set. Skip gracefully if absent (sqlite path).
- **Effort:** S (human: ~2h / CC: ~20min)
- **Priority:** P2 — required before standard-mode pilot launch

---

## GeneralLane post-launch TODOs (added 2026-04-13, plan-ceo-review fix/general-queries)

### Per-table general_passthrough override (P3)
- **What:** Add `general_passthrough: bool` field to `TableConfig` in `schema_config.json`. When false, GeneralLane is blocked for requests that partially matched this table (intent identified the table but routing failed).
- **Why:** Operators with sensitive tables want GeneralLane opt-out at table granularity without disabling it globally.
- **Pros:** Defense-in-depth for sensitive schemas.
- **Cons:** Only applies to partial-match cases where intent resolved a table. Cannot apply when intent fails entirely (NoTableIdentified) — the full-miss case that GeneralLane primarily handles. Needs redesign to clarify semantics before implementing.
- **Context:** Rejected from fix/general-queries PR (Codex found it logically broken for the primary use case). Revisit if an operator requests it with a concrete partial-match scenario.
- **Effort:** S (human: ~2h / CC: ~10min)
- **Priority:** P3
- **Depends on:** fix/general-queries merged, operator feedback on real use cases

### Cluster-aware GeneralLane rate limiting (P2)
- **What:** Move `ZEMTIK_GENERAL_MAX_RPM` from per-instance `VecDeque<Instant>` sliding window to a Redis-backed sliding window.
- **Why:** Replicated Zemtik deployments (multiple proxy instances behind a load balancer) get N × MAX_RPM effective throughput. Per-instance limiting is only accurate for single-instance deployments.
- **Pros:** Accurate cluster-wide enforcement. Required for production multi-instance deployments.
- **Cons:** New external dependency (Redis). Adds operational complexity (Redis availability becomes a proxy dependency).
- **Context:** v1 GeneralLane rate limiter is per-instance by design. Acceptable for single-instance pilots. Block for multi-instance production launch.
- **Effort:** M (human: ~4h / CC: ~20min + Redis dep)
- **Priority:** P2 — block for multi-instance production

### GeneralLane adversarial intent-miss threat model (P3)
- **What:** Document and optionally implement detection for prompts that deliberately cause intent classifier miss to force routing into GeneralLane when `ZEMTIK_GENERAL_PASSTHROUGH=1`.
- **Why:** BGE-small-en (the embedding backend) is not adversarially robust. An attacker who knows `ZEMTIK_GENERAL_PASSTHROUGH=1` could craft prompts that always fail intent extraction to reach OpenAI without ZK verification — potentially extracting data-adjacent information via the general lane.
- **Pros:** Closes a known attack surface for operators who have enabled passthrough.
- **Cons:** Hard to implement well without false positives. Most Zemtik deployments are enterprise-internal, reducing exposure. The receipt audit trail is the primary mitigation today.
- **Context:** Raised during fix/general-queries eng review (outside voice). Applies only when `ZEMTIK_GENERAL_PASSTHROUGH=1`. A basic mitigation could be a second-pass similarity check against known data patterns before allowing GeneralLane to fire.
- **Effort:** M (human: ~4h / CC: ~20min)
- **Priority:** P3 — non-blocking, mitigated by opt-in flag and receipt audit trail
- **Depends on:** fix/general-queries merged

### GeneralLane idempotency key support (P3)
- **What:** Support `Idempotency-Key` request header to deduplicate rapid retries. Same key within a TTL window returns the cached receipt_id and skips a second forward to OpenAI.
- **Why:** Network retries or client double-submits write two receipts and forward twice. Audit trail shows duplicate entries; operator billed twice.
- **Pros:** Clean audit trail. Prevents duplicate OpenAI billing on retries.
- **Cons:** Requires in-memory cache or DB lookup per GeneralLane request. Cache TTL adds state to the rate limiter. More complexity than the value warrants in v1.
- **Context:** Added as P3 during fix/general-queries review. No operator has reported duplicate receipt issues yet.
- **Effort:** M (human: ~3h / CC: ~15min)
- **Priority:** P3

---

## Completed — v0.9.1 (2026-04-11)

All items below shipped in `fix/integration-issues` → PR merged to main.

- **ZEMTIK_VALIDATE_ONLY=1 env var** — pre-demo schema validation (`nginx -t` for zemtik). Exit 0/1 based on warnings.
- **Startup validation block log format** — formatted `[ZEMTIK] Schema validation` block at startup.
- **example_prompts startup validation** — warns when `example_prompts` is missing, signals regex fallback.
- **Startup event log (`~/.zemtik/startup_events.jsonl`)** — JSONL audit trail of every startup validation run.
- **Structured DB error 500** — `EngineResult::DbError` now returns structured JSON with `type`, `code`, `hint`, `doc_url`. Raw DB error strings no longer exposed in HTTP responses (S3 security fix).
- **TROUBLESHOOTING.md** — 6-symptom diagnostic reference for on-site deployments.
- **v0.9.1 upgrade note** — CHANGELOG.md upgrade section explaining new startup warnings.
- **S2 security fix** — table key validated with `is_safe_identifier` in `validate_schema_config` (SQL injection in startup Postgres count query).
- **VALIDATE_ONLY + SKIP_CIRCUIT_VALIDATION** — both flags now stack correctly; VALIDATE_ONLY no longer exits 1 when circuit validation is suppressed.
- **`/health` status_summary** — reports `"warnings"` when ZK tools are absent, not `"ok"`.
- **Test safety** — `startup_validation_skipped_when_env_set` uses `#[serial]` to prevent env var race in parallel tests.

---

## BN254 field encoding + HKDF safety (P2, before second Aztec demo)

Added from `/plan-eng-review` of the Audit Trail Integrity plan (worktree-groovy-yawning-creek).

### SHA-256 → BN254 truncation safety
- **What:** SHA-256 produces 256 bits; BN254 scalar field is ~254 bits (2^254 - delta). Truncating the 2 MSBs is safe for nearly all inputs but can produce `value == 0` or `value >= field_modulus` in extreme edge cases. Add a check: if truncated value >= BN254_FIELD_ORDER or == 0, return Err with a clear message ("prompt hash encoding out of BN254 range — retry or report this input").
- **Why:** The Aztec engineer will inspect the public input encoding during review. A panic or silent wrong value would undermine the cryptographic credibility of the commitment.
- **Context:** The field modulus is `21888242871839275222246405745257275088548364400416034343698204186575808495617` (BN254 scalar field). SHA-256 of any 256-bit random input has probability ~2^-254 of landing out of range — extremely rare but worth a runtime guard.
- **Effort:** XS (CC: ~5 min)

### HKDF derive_manifest_signing_key() error handling
- **What:** `derive_manifest_signing_key()` should return `anyhow::Result<ed25519_dalek::SigningKey>` instead of unwrapping HKDF expand. If `hk.expand()` fails (e.g., bad OKM length), it would panic in the hot path.
- **Why:** Hard startup error is acceptable (matches ZEMTIK_TUNNEL_API_KEY pattern), but panic is not. Use `hk.expand(...)?.` and propagate as startup error.
- **Context:** HKDF expand can only fail if the output length exceeds 255 * HashLen. For SHA-256 with 32-byte output this will never fail in practice — but the guard is cheap and the Aztec engineer will check error handling.
- **Effort:** XS (CC: ~2 min)
