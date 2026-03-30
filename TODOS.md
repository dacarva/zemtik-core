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

### intent.rs: compile regexes once (P3)
- **What:** `Regex::new(...)` is called inside `extract_intent`, which runs on every proxy request. Move to `std::sync::LazyLock` or `once_cell::sync::Lazy`.
- **Why:** Found by Claude adversarial review (feat/routing-engine, 2026-03-30). Regex compilation is expensive (~microseconds) and wasteful on the hot path.
- **Effort:** XS (human) → XS (CC+gstack)

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
