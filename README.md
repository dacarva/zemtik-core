# Zemtik

> ZK middleware that eliminates enterprise data exfiltration to AI systems.

Every time a company queries an LLM with internal data, it creates a **shadow copy** of proprietary records on third-party infrastructure. For financial institutions, healthcare providers, and defense contractors, this isn't a policy problem—it's a legal one. Raw transaction rows, patient records, or classified queries cannot leave the enterprise perimeter.

Zemtik solves this at the infrastructure layer: **compute the answer locally inside a Zero-Knowledge circuit, prove the computation was honest, and send only the proven number to the model.** Zero raw rows ever leave the perimeter.

---

## How It Works

Zemtik runs as a local proxy on `localhost:4000`. Point your application at it instead of `api.openai.com`—no code changes required.

```
Your Application
      │
      │  POST /v1/chat/completions
      │  (normal OpenAI request with raw query)
      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Zemtik Proxy (localhost:4000)               │
│                                                             │
│  ┌──────────────┐    sign     ┌───────────────────────┐    │
│  │  Transaction │ ──────────► │  Bank KMS (Mock)       │    │
│  │  DB (SQLite  │             │  BabyJubJub EdDSA      │    │
│  │  or Supabase)│             │  Poseidon hash tree    │    │
│  └──────────────┘             └───────────┬───────────┘    │
│          │ raw rows (private witness)      │ signature       │
│          └─────────────────┬──────────────┘                 │
│                            ▼                                 │
│               Noir ZK Circuit (UltraHonk)                    │
│               · Verify EdDSA signature over tx hash          │
│               · SUM(amount) WHERE category AND time range    │
│                            │                                 │
│                            │  $2,805,600  ◄── only this      │
└────────────────────────────┼─────────────────────────────────┘
                             │  crosses the boundary
                             ▼
                    OpenAI API
                    { spend: 2805600,
                      provenance: "ZEMTIK_ZK" }
```

The raw transaction rows are **private witnesses** inside the ZK circuit. The verifier—and OpenAI—sees only the cryptographically proven aggregate.

---

## Measured Performance

Numbers from a real run (`audit/2026-03-25T17-46-43Z.json`), not projections:

| Metric | Value |
|--------|-------|
| Transactions processed | 500 (10 batches × 50) |
| Circuit execution | 2.4s |
| Full pipeline (DB → proof → AI response) | ~20s |
| Proof scheme | UltraHonk (Barretenberg v4) |
| Proof status | **VALID** — generated and independently verified |
| Raw rows sent to LLM | **0** |

---

## Quick Start

**Prerequisites:**

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.70+ | [rustup.rs](https://rustup.rs) |
| Nargo (Noir) | 1.0.0-beta.19 | `noirup --version 1.0.0-beta.19` |
| Barretenberg (`bb`) | v4.0.0-nightly | `bbup` (resolved automatically from Nargo version) |

```bash
git clone https://github.com/zemtik/zemtik-core.git
cd zemtik-core
cp .env.example .env
# Add your OPENAI_API_KEY to .env
```

### Option A — CLI pipeline (batch demo)

Runs the full 500-transaction ZK pipeline once and prints the verified result:

```bash
cargo run
```

**Expected output:**

```
╔══════════════════════════════════════════════════╗
║   Zemtik: ZK Middleware POC (Rust + Noir + AI)   ║
╚══════════════════════════════════════════════════╝

[DB]   Initializing in-memory SQLite ledger... OK (500 transactions for client 123)
[KMS]  Signing 10 batches of 50 transactions with BabyJubJub EdDSA... OK
       pub_key_x = 11559732...32435791
[NOIR] Writing Prover.toml (10 batches)... OK
[NOIR] Circuit already compiled, skipping nargo compile
[NOIR] Executing circuit (10 batches x EdDSA + aggregation)...
[NOIR] Verified aggregate AWS Infrastructure spend = $2805600
[NOIR] Generating UltraHonk proof (bb v4, CRS auto-download)...
[AI]   Querying gpt-5.4-nano with ZK-verified payload...
       Payload: { category: "AWS Infrastructure", total_spend_usd: 2805600, provenance: "ZEMTIK_VALID_ZK_PROOF" }

══════════════════════════════════════════════════════
  ZEMTIK RESULT (total time: 20.34s)
══════════════════════════════════════════════════════
  Category : AWS Infrastructure
  Period   : Q1 2024
  Aggregate: $2805600
  ZK Proof : VALID (ZK proof generated and verified)
  Raw rows sent to OpenAI: 0
══════════════════════════════════════════════════════
```

The first run compiles the Noir circuit (~10s). Subsequent runs skip compilation.

### Option B — Proxy mode (drop-in OpenAI replacement)

Start the proxy server once. Your application needs no changes—just point it at `localhost:4000`:

```bash
cargo run -- proxy
```

```
╔══════════════════════════════════════════════════╗
║   Zemtik Proxy — ZK Middleware for Enterprise AI ║
╚══════════════════════════════════════════════════╝

[PROXY] Listening on http://127.0.0.1:4000
[PROXY] Intercepts POST /v1/chat/completions → intent extraction → FastLane or ZK SlowLane → forwards to OpenAI
[PROXY] Point your app to http://localhost:4000 instead of api.openai.com
```

Then call it like any OpenAI endpoint:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "Analyze our Q1 AWS spend"}]
  }'
```

Zemtik intercepts the request, runs the full ZK pipeline against the transaction database, replaces the user message with the ZK-verified aggregate, and forwards the sanitized request to OpenAI. The raw transactions never leave the process.

---

## How the ZK Proof Works

**Step 1 — Bank KMS signs each batch.** The bank's BabyJubJub private key signs a Poseidon Merkle commitment to each 50-transaction batch. This ties the raw data to a cryptographic identity—any tampering with the data invalidates the signature.

**Step 2 — Noir circuit verifies signatures and aggregates.** The circuit receives the raw transactions as *private witnesses* (hidden from the verifier). It reconstructs the Poseidon commitment tree, verifies the EdDSA signature with `assert(eddsa_verify(...))`, and computes `SUM(amount) WHERE category = AWS AND timestamp IN [Q1_start, Q1_end]`. If any assertion fails, no valid witness exists and no proof can be generated—a dishonest prover cannot forge a valid proof.

**Step 3 — UltraHonk proof generation.** Barretenberg generates a succinct proof over the circuit (728,283 gates). The proof reveals nothing about individual transaction amounts, timestamps, or client identifiers. The verifier learns only: "the holder of the bank private key signed this dataset, and the AWS spend in Q1 was $2,805,600."

The payload sent to OpenAI contains exactly three data fields:

```json
{
  "category": "AWS Infrastructure",
  "total_spend_usd": 2805600,
  "data_provenance": "ZEMTIK_VALID_ZK_PROOF"
}
```

---

## Project Structure

```
zemtik-core/
├── src/
│   ├── main.rs           # Pipeline orchestrator + CLI subcommand routing
│   ├── proxy.rs          # Axum proxy server (localhost:4000); FastLane + ZK dispatch
│   ├── intent.rs         # IntentBackend trait dispatch (EmbeddingBackend or RegexBackend)
│   ├── intent_embed.rs   # EmbeddingBackend: fastembed BGE-small-en ONNX, cosine similarity
│   ├── time_parser.rs    # DeterministicTimeParser: Q/H/FY/month/relative/YTD → Unix range
│   ├── router.rs         # Routing decision (schema_config sensitivity → FastLane or ZK)
│   ├── engine_fast.rs    # FastLane: DB sum → BabyJubJub attestation (sub-50ms)
│   ├── evidence.rs       # EvidencePack builder for both engine paths
│   ├── db.rs             # DB backend (SQLite / Supabase) + BabyJubJub KMS + sum_by_category
│   ├── prover.rs         # nargo / bb subprocess pipeline
│   ├── openai.rs         # OpenAI Chat Completions client (CLI mode)
│   ├── audit.rs          # Audit record writer
│   ├── receipts.rs       # Receipts ledger (CRUD + v3 migration: outgoing_prompt_hash; v2: engine_used, intent_confidence)
│   ├── keys.rs           # BabyJubJub key generation + persistence
│   ├── config.rs         # Layered config + SchemaConfig loading
│   ├── lib.rs            # Library crate root (for eval harness and integration tests)
│   └── types.rs          # Shared types
├── circuit/
│   ├── Nargo.toml     # eddsa = { path = "../vendor/eddsa" }, poseidon v0.2.6
│   └── src/
│       └── main.nr    # ZK circuit: EdDSA verify + SUM aggregation
├── vendor/eddsa/      # Vendored EdDSA library (noir-lang/eddsa, -59% gates)
├── supabase/
│   └── migrations/    # SQL schema for Supabase backend
├── eval/
│   ├── intent_eval.rs   # Intent eval harness (235 labeled prompts, CI gate)
│   └── labeled_prompts.json
├── docs/
│   ├── ARCHITECTURE.md     # Full component breakdown and data flow
│   ├── CONFIGURATION.md    # All config fields, env vars, schema_config.json format
│   ├── GETTING_STARTED.md  # End-to-end setup guide
│   ├── HOW_TO_ADD_TABLE.md # Add a new table to the schema (step-by-step)
│   ├── INTENT_ENGINE.md    # How EmbeddingBackend + DeterministicTimeParser work
│   ├── SCALING.md          # Recursive proofs, production path, why remote proving breaks ZK
│   └── SUPPORTED_QUERIES.md # v1 query contract: supported patterns, error reference
└── .env.example
```

---

## Audit Trail

Every pipeline run writes a timestamped JSON record to `audit/` containing the complete evidence chain for compliance review:

```
audit/
  2026-03-25T17-46-43Z.json   (41 KB)
```

Each record contains:
- **`pipeline`** — transaction count, query parameters, verified aggregate, proof status, circuit execution time
- **`zk_proof`** — hex-encoded proof and verification key; all public inputs committed to by the proof
- **`openai_request`** — the exact payload sent to the model (no raw rows)
- **`openai_response`** — model response, version, and token usage
- **`privacy_attestation`** — explicit record: `raw_rows_transmitted: 0`

An auditor can independently verify the proof from the audit record:

```bash
echo "<proof_hex>" | xxd -r -p > proof
echo "<vk_hex>"   | xxd -r -p > vk
bb verify -p proof -k vk
```

---

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| ZK circuit | Noir | 1.0.0-beta.19 |
| Proof backend | Barretenberg (UltraHonk) | v4.0.0-nightly |
| Signature scheme | BabyJubJub EdDSA + Poseidon | BN254 |
| Proxy / orchestrator | Rust + Axum | 1.70+ / 0.8 |
| Database | SQLite (in-memory) or Supabase (PostgREST) | — |
| AI inference | OpenAI gpt-5.4-nano | Chat Completions API |

---

## Known Limitations (POC)

- **CLI pipeline query is hardcoded** — 500 transactions, client 123, `aws_spend`, Q1 2024. Proxy mode supports natural-language queries against tables defined in `schema_config.json`.
- **FastLane uses demo data** — FastLane always reads from the in-memory seeded SQLite ledger. Supabase FastLane connector is deferred to v2.
- **Circuit category mapping** — Since Sprint 2, the ZK slow lane supports any table key via Poseidon BN254 hashing. No code change is needed to add new tables — just add them to `schema_config.json` with `"sensitivity": "critical"`.
- **Single query type** — `SUM(amount) WHERE category AND time_range`. COUNT, AVG, and multi-dimensional filters require new circuit variants.
- **Proving infrastructure** — The current setup uses local CPU proving. For sub-second proofs at scale, GPU/FPGA hardware is required—and it must remain on-prem (remote proving exposes the private witness).

See [docs/SCALING.md](docs/SCALING.md) for the full production path.

---

## Zemtik Enterprise

This repository is the MIT-licensed core layer. The commercial product adds:

| Feature | Description |
|---------|-------------|
| **Map-Reduce ZK aggregator** | Horizontal proof generation across distributed workers — scales from 500 to 500,000+ transactions while keeping all private witnesses inside the perimeter |
| **CISO dashboard** | Real-time visibility into every AI query: what data was queried, what was transmitted, proof verification status, SOC2-ready audit exports |
| **SSO / RBAC** | Active Directory, Okta, and SAML integration; per-team query authorization policies |
| **LLM fallback routing** | Automatic failover across model providers; query-type-aware routing (e.g., financial queries → GPT, code → Claude) |
| **On-prem GPU proving** | Hardware-accelerated proof generation for sub-second latency at enterprise scale |

**Contact:** [david@zemtik.com](mailto:david@zemtik.com)

---

## Docs

- [Architecture](docs/ARCHITECTURE.md) — Full component breakdown, data flow, cryptographic security properties
- [Intent Engine](docs/INTENT_ENGINE.md) — How embedding-based routing and the time parser work
- [Supported Queries](docs/SUPPORTED_QUERIES.md) — v1 query contract: time expressions, table matching, error reference
- [Configuration](docs/CONFIGURATION.md) — All config fields, env vars, schema_config.json format
- [Getting Started](docs/GETTING_STARTED.md) — End-to-end setup guide
- [How to Add a Table](docs/HOW_TO_ADD_TABLE.md) — Step-by-step guide to adding a new table
- [Scaling](docs/SCALING.md) — Recursive proofs vs aggregation; why remote proving breaks the privacy guarantee

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Zemtik Contributors
