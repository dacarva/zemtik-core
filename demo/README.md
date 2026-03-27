# Zemtik 30-Minute Deploy Walkthrough

Deploy Zemtik from source on a fresh machine with zero prerequisites beyond Rust and the Barretenberg prover.

## Prerequisites

| Tool | Install |
|------|---------|
| Rust 1.75+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Nargo (Noir) | `curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install \| bash && noirup` |
| bb (Barretenberg) | `curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install \| bash && bbup` |
| OpenAI API key | Set `OPENAI_API_KEY` in your shell or `.env` |

## Step 1 — Build (~5 min)

```sh
git clone https://github.com/dacarva/zemtik-core
cd zemtik-core
cargo build --release
```

## Step 2 — Install (~1 min)

```sh
sh install.sh
# Restart your shell, or:
export PATH="$PATH:$HOME/.local/bin"
```

This creates `~/.zemtik/` and installs the binary.

## Step 3 — Circuit files (handled by install.sh)

`install.sh` automatically copies `circuit/` and `vendor/` to `~/.zemtik/`.
No manual step needed.

If you skipped `install.sh` or are using a custom `ZEMTIK_CIRCUIT_DIR`, copy manually:

```sh
cp -r circuit/. ~/.zemtik/circuit/
mkdir -p ~/.zemtik/vendor && cp -r vendor/. ~/.zemtik/vendor/
```

The circuit directory contains the Noir source and gets compiled on first run.

## Step 4 — Set your API key (~1 min)

```sh
export OPENAI_API_KEY=sk-...
# Or add to ~/.zemtik/config.yaml:
#   openai_api_key: sk-...
```

## Step 5 — Run the demo (~20 min, most time is proof generation)

```sh
sh demo/demo.sh
```

This runs the full pipeline:
1. Seeds 500 transactions into an in-memory SQLite ledger
2. Signs all batches with BabyJubJub EdDSA using your installation key
3. Writes `~/.zemtik/circuit/Prover.toml` with all inputs
4. Compiles the Noir circuit (first run, ~30s)
5. Executes the circuit and generates a UltraHonk ZK proof (~10-15 min)
6. Verifies the proof and generates a bundle ZIP in `~/.zemtik/receipts/`
7. Verifies the bundle with `zemtik verify`

## Step 6 — Start the proxy

```sh
zemtik --proxy
# Listening on http://localhost:4000
```

Point your OpenAI client to `http://localhost:4000` instead of `api.openai.com`:

```python
import os
import openai
client = openai.OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url="http://localhost:4000/v1",
)
```

Every chat completion request automatically runs the ZK pipeline and appends a cryptographic receipt.

## Verifying a receipt

```sh
zemtik verify ~/.zemtik/receipts/<bundle-id>.zip
```

Or view in browser: `http://localhost:4000/verify/<bundle-id>`

## Configuration

Copy `config.example.yaml` to `~/.zemtik/config.yaml` to customise paths and port.

Environment variables take precedence:
- `ZEMTIK_PROXY_PORT` — port for the proxy server
- `ZEMTIK_CIRCUIT_DIR` — path to the compiled Noir circuit
- `ZEMTIK_KEYS_DIR` — path to the bank signing key
- `OPENAI_API_KEY` — forwarded to OpenAI

## Sample transactions

`demo/sample_transactions.csv` contains the 500 deterministic demo transactions.
These are the same rows used by the in-memory SQLite backend.
