# TODOS

## P2 — Blocking for productized distribution

### CIRCUIT_DIR configurable
- **What:** Make `CIRCUIT_DIR` (currently hardcoded as `"circuit"`) configurable via env var (`ZEMTIK_CIRCUIT_DIR`) or CLI flag.
- **Why:** The binary only works when executed from the repo root. Any distribution outside the repo (GitHub Releases, global install) will break because the circuit artifacts won't be at `./circuit/`.
- **How to apply:** Accept `--circuit-dir <path>` flag or read `ZEMTIK_CIRCUIT_DIR` env var. Pass through to all `prover.rs` functions.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** feat/verifier-flow merged (don't add this mid-feature)

### Per-run work directories for ZK pipeline
- **What:** Give each proof run its own isolated temp dir instead of the shared `circuit/Prover.toml` + `circuit/proofs/proof/` paths.
- **Why:** `Mutex<()>` in ProxyState serializes only the proxy process. A concurrent CLI run, second proxy instance, or direct `nargo execute` call still clobbers the shared paths. Identified by Codex in feat/verifier-flow eng review (2026-03-26).
- **How to apply:** Pass a `work_dir: PathBuf` parameter through all `prover.rs` functions. Each proof run writes to `~/.zemtik/runs/{uuid}/` instead of `circuit/`.
- **Effort:** M (human) → M (CC+gstack)
- **Depends on:** feat/verifier-flow merged. Blocking before multi-user / multi-tenant deployment.

### Installation-specific signing key (replace hardcoded BANK_SK_SEED)
- **What:** Replace the deterministic demo seed `[0x01..0x20]` in `db.rs` with a per-installation key generated at first run and stored in `~/.zemtik/keys/bank_sk`.
- **Why:** Anyone with the repo source can mint receipts indistinguishable from a real Zemtik install. Until keys are installation-specific, third-party verification has no evidentiary value beyond the demo. Identified by Codex in feat/verifier-flow eng review (2026-03-26).
- **How to apply:** On first `zemtik --proxy` startup, check for `~/.zemtik/keys/bank_sk`. If missing, generate a random BabyJubJub private key, write it, and log the public key fingerprint. Derive `BANK_SK_SEED` from this file at runtime.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** GitHub Releases / productized install. Must ship before first real client.

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

### `zemtik list` subcommand (P3)
- **What:** List receipts in ~/.zemtik/receipts/ with UUID, date, aggregate, proof status.
- **Why:** Enabled by feat/distribution-improvement (per-install receipts DB). The SF engineer can show Cecilia the historical list of proofs generated by her installation.
- **How to apply:** Add `list` subcommand to clap CLI. Query receipts.db, format as table.
- **Effort:** S (human) → S (CC+gstack)
- **Depends on:** feat/distribution-improvement merged (provides ~/.zemtik/receipts.db).

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
