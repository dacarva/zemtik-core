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

### bb verify timeout (prevents proxy deadlock)
- **What:** Add a timeout to the `Command::new("bb").args(["verify", ...]).output()` call in `verify_bundle`.
- **Why:** `bb` can hang indefinitely (CRS download, stalled network, native deadlock). In proxy mode, the hung `bb` holds `pipeline_lock` forever, deadlocking all subsequent requests. Found by Claude adversarial review (feat/verifier-flow, 2026-03-26).
- **How to apply:** Spawn `bb verify` as a child process, set a deadline (e.g., 60s), and kill it if it exceeds the limit. Return an error to the caller.
- **Effort:** S (human) → S (CC+gstack)

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

### EvidencePack: include key_id for EmptyResult responses (P2, before production)
- **What:** When FastLane returns `EngineResult::EmptyResult` (no rows match), the EvidencePack currently has empty `key_id` and both `proof_hash`/`attestation_hash` as None. A verifier cannot determine which key attested the zero-spend result.
- **Why:** Found by Claude adversarial review (feat/routing-engine, 2026-03-30). A forged zero-result EvidencePack with empty key_id is indistinguishable from a genuine one. Fix: compute and sign the query hash even when row_count=0, record the key_id and attestation_hash.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** feat/routing-engine merged.

### ~~intent.rs: compile regexes once~~ ✓ DONE (feat/intent-engine, v0.4.0)
- `time_parser.rs` uses `std::sync::LazyLock` for all regexes (compiled once at first use). `RegexBackend` uses `str::contains()` — no `Regex::new()` calls in the hot path.

### run_zk_pipeline: reuse ledger DB instead of re-initializing (P3)
- **What:** `run_zk_pipeline` calls `db::init_db()` on every ZK request, re-seeding the demo SQLite in-memory DB each time. Share the existing `ledger_db` from `ProxyState`.
- **Why:** Found by Claude adversarial review (feat/routing-engine, 2026-03-30). Wastes CPU on every ZK slow-lane request; creates correctness risk if `pipeline_lock` is ever bypassed with concurrent ZK requests.
- **Effort:** S (human) → S (CC+gstack)

### intent.rs v2: multi-table query support (P3, post-v1)
- **What:** Extend intent.rs to extract multiple table names from a single query and apply the cross-sensitivity OR rule across all extracted tables.
- **Why:** v1 extracts only the first table match. A query like "What was Q1 payroll vs AWS spend?" would only process the first table found. The cross-sensitivity OR rule (if ANY table is critical → ZK SlowLane) is architecturally correct but unreachable in v1 for multi-table queries. v1 behavior: extract first table, add a note in the response: "Note: only processed [table] — multi-table queries not yet supported."
- **Pros:** Unlocks the full OR rule. Enables comparative analytics queries (payroll vs AWS in one shot).
- **Cons:** Multi-table output requires either two separate Evidence Packs or a new combined format. Schema for combined Evidence Pack needs design.
- **Context:** v1 single-table is a conscious shortcut. The router.rs OR rule is implemented correctly but only exercised in unit tests with simulated multi-table intent. Real user queries will need this in v2.
- **Depends on:** feat/routing-engine merged (provides the single-table v1 foundation).
