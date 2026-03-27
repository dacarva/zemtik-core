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
