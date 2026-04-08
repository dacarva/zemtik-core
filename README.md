# Zemtik

> A Rust proxy that intercepts LLM prompts, queries your local database, computes an aggregate inside a Zero-Knowledge circuit, and sends only the proven number to the model. Zero raw rows leave the perimeter.

Every time a company queries an LLM with internal data, it creates a **shadow copy** of proprietary records on third-party infrastructure. For financial institutions, healthcare providers, and defense contractors, this isn't a policy problem—it's a legal one. Raw transaction rows, patient records, or classified queries cannot leave the enterprise perimeter.

Zemtik solves this at the infrastructure layer: **compute the answer locally inside a Zero-Knowledge circuit, prove the computation was honest, and send only the proven number to the model.** Zero raw rows ever leave the perimeter.

---

## Quick Start (Docker)

The fastest way to run Zemtik. No Rust toolchain or ZK tools required.

```bash
# 1. Set your OpenAI API key
export OPENAI_API_KEY=sk-...

# 2. Start the proxy (binds to localhost:4000)
docker compose up --build

# 3. Verify it's running
curl http://localhost:4000/health

# 4. Send a query — the magic moment: data_exfiltrated is always 0
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "Q1 2024 client_portfolios total"}]
  }'
```

The response includes an `evidence` block with `data_exfiltrated: 0` and `attestation_hash` — a cryptographic receipt you can show to auditors. See [docs/COMPLIANCE_RECEIPT.md](docs/COMPLIANCE_RECEIPT.md) for field descriptions.

To use your own data: mount a custom `schema_config.json` — see the commented volume in `docker-compose.yml`.

> **POC status (v0.8.0):** This is a working proof-of-concept, not a production product. Current hard limits: ZK circuit is fixed at 500 transactions per query; database connectivity requires a Supabase/PostgREST adapter (raw Postgres connector planned for v2); the signing key is file-based at `~/.zemtik/keys/bank_sk` (HSM integration planned for v2). See [Known Limitations](#known-limitations-poc) before evaluating for production use.

---

## How It Works

Zemtik runs as a local proxy on `localhost:4000`. Point your application at it instead of `api.openai.com` — the HTTP interface is OpenAI-compatible, so no client-side code changes are required. Server-side setup requires a conforming database schema and `schema_config.json` (see [Getting Started](docs/GETTING_STARTED.md)).

```
Your Application
      │
      │  POST /v1/chat/completions
      │  (natural-language query)
      ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Zemtik Proxy (localhost:4000)                    │
│                                                                      │
│      Intent extraction + routing (schema_config.json sensitivity)    │
│                               │                                      │
│         ┌─────────────────────┴──────────────────────────┐           │
│    sensitivity: "low"                    sensitivity: "critical"      │
│         ▼                                               ▼            │
│  ┌─────────────────────┐               ┌────────────────────────┐   │
│  │      FastLane        │               │      ZK SlowLane        │   │
│  │                     │               │                        │   │
│  │  DB aggregate query  │               │  Transaction DB        │   │
│  │  (SUM or COUNT)      │               │  (raw rows as private  │   │
│  │        │             │               │  witnesses — never sent)│   │
│  │        ▼             │               │        │               │   │
│  │  BabyJubJub EdDSA   │               │        ▼               │   │
│  │  sign(aggregate +   │               │  BabyJubJub batch sign │   │
│  │  query descriptor)  │               │  + Noir ZK Circuit     │   │
│  │  ── NO ZK PROOF ──  │               │  + UltraHonk proof     │   │
│  │  < 50ms             │               │  (~17s on CPU)         │   │
│  └──────────┬──────────┘               └────────────┬───────────┘   │
│             │ attestation_hash                       │ proof_hash    │
└─────────────┼───────────────────────────────────────┼───────────────┘
              │                                       │
              └────────────────┬──────────────────────┘
                               │  aggregate only — zero raw rows
                               ▼
                          OpenAI API
                          { aggregate, provenance:
                            "ZEMTIK_FAST_LANE" or "ZEMTIK_ZK" }
```

In both paths, raw transaction rows **never leave the Zemtik process**. Which path runs is determined by the `sensitivity` field in `schema_config.json`. See [Two Lanes: FastLane vs ZK SlowLane](#two-lanes-fastlane-vs-zk-slowlane) below.

> **KMS note:** `~/.zemtik/keys/bank_sk` is a 32-byte file (mode 0600) that acts as the BabyJubJub signing key. The ZK circuit's soundness guarantee — `assert(eddsa_verify(...))` — holds only if this key is genuinely controlled by the institution. A compromised file means a compromised attestation. Production deployments must replace this with an HSM or KMS (v2 roadmap).

---

## Two Lanes: FastLane vs ZK SlowLane

Zemtik routes each query to one of two execution paths based on the `"sensitivity"` field you configure per table in `schema_config.json`.

### FastLane (`"sensitivity": "low"`)

FastLane is designed for aggregates that are not themselves sensitive — for example, total e-commerce revenue by category, public-facing headcount by department, or any metric where the aggregate number is safe to share.

1. Zemtik queries the database for the aggregate (`SUM` or `COUNT`) directly. **No raw rows are fetched.**
2. BabyJubJub EdDSA signs the result together with a query descriptor (table, columns, time range, aggregation function).
3. The `attestation_hash` and aggregate are forwarded to OpenAI.

**Latency:** < 50ms.

> **Warning — FastLane does not generate a Zero-Knowledge proof.** There is no circuit constraint preventing a malicious operator from signing an arbitrary aggregate value. The privacy guarantee is that raw rows never leave the Zemtik process; the correctness guarantee relies on trusting the Zemtik binary and the confidentiality of `~/.zemtik/keys/bank_sk`. Use FastLane only for tables where the aggregate is non-sensitive and an honest-prover model is acceptable.

### ZK SlowLane (`"sensitivity": "critical"`)

ZK SlowLane is required for tables where even an aggregate could reveal sensitive information — payroll totals, patient counts, classified procurement figures, or anything subject to data-residency regulation.

1. Raw rows are fetched as **private witnesses** — they stay inside the Rust process and are never written to disk or sent over the network.
2. Each batch of 50 rows is signed with BabyJubJub EdDSA over a Poseidon commitment tree.
3. A Noir ZK circuit verifies every signature and computes the aggregate. The circuit is a mathematical constraint: a dishonest prover cannot produce a valid proof for a wrong aggregate without breaking the signature assumption.
4. Barretenberg generates an UltraHonk proof. The `proof_hash` is included in the response and can be independently verified offline.

**Latency:** ~17–20s on CPU. See [docs/SCALING.md](docs/SCALING.md) for the GPU/FPGA path.

### Choosing the right lane

| | FastLane | ZK SlowLane |
|---|---|---|
| Raw rows sent to OpenAI | Never | Never |
| Aggregate is sensitive | No — if yes, use ZK | Yes |
| Cryptographic proof of correct computation | No | Yes — UltraHonk |
| AVG supported | No | Yes (composite: SUM + COUNT proofs) |
| Latency | < 50ms | ~17–20s |
| Config (`schema_config.json`) | `"sensitivity": "low"` | `"sensitivity": "critical"` |

Unknown tables that are not in `schema_config.json` always route to ZK SlowLane (fail-secure).

---

## Where Zemtik Applies

Zemtik addresses a specific problem: **your data contains rows you cannot send to an LLM, but your business needs answers from those rows.** The pattern recurs across industries wherever regulation, privilege, or competitive sensitivity governs data residency.

| Industry | Regulation | What stays private | FastLane or ZK |
|----------|-----------|-------------------|----------------|
| **Healthcare** | HIPAA §164.502 | Patient identifiers, individual claim amounts | ZK — PHI in any row |
| **Legal** | Attorney-client privilege | Matter IDs, attorney-client assignments | ZK — reveals client relationships |
| **Insurance** | GDPR Art. 9, CCPA | Policy holder IDs, individual payouts | ZK — special category data |
| **E-commerce** | CCPA, PCI DSS | Customer IDs, purchase history, payment data | FastLane — aggregates are non-sensitive |
| **Government / Defense** | FAR, FedRAMP | Contractor identities, program funding | ZK — may be classified |
| **Pharma / Biotech** | SEC Reg S-K (MNPI) | Trial IDs, per-compound pipeline spend | ZK — material non-public |
| **Fintech / Crypto** | MiCA, FATF Travel Rule | Wallet addresses, transaction counterparties | ZK — Travel Rule compliance |

> **FastLane vs ZK column:** FastLane = BabyJubJub attestation, no ZK proof, < 50ms, set `"sensitivity": "low"` in `schema_config.json`. ZK = Noir + UltraHonk proof, ~17–20s, set `"sensitivity": "critical"`. Both guarantee zero raw rows reach the LLM. See [Two Lanes: FastLane vs ZK SlowLane](#two-lanes-fastlane-vs-zk-slowlane) for the full tradeoff.

In every case the integration is the same: map your table's columns in `schema_config.json`, point Zemtik at a PostgREST endpoint, and send natural-language queries. The proxy returns a cryptographically attested aggregate. Zero raw rows cross the perimeter.

> **Full integration guides for all seven industries** — including real SQL schemas, complete `schema_config.json` entries, and column mapping for common database patterns — are in [docs/INDUSTRY_USE_CASES.md](docs/INDUSTRY_USE_CASES.md).

---

## v1 Capability Boundary

Before reading further, understand what Zemtik v1 does **not** do:

| Capability | v1 status |
|---|---|
| Connect to arbitrary Postgres directly | Not supported — requires Supabase/PostgREST in front of your DB |
| ZK-prove queries with > 500 matching rows | Not supported — circuit is fixed at 500 rows (10 batches × 50) |
| AVG, multi-table JOINs, GROUP BY | COUNT supported on FastLane and ZK SlowLane (`"agg_fn": "COUNT"`). AVG supported via ZK composite proof — two sequential proofs (SUM + COUNT) plus BabyJubJub attestation for the division step (`"agg_fn": "AVG"`). JOINs and GROUP BY not supported. |
| Sub-second ZK proofs | Not supported — local CPU proving takes ~17s (GPU/FPGA required at scale) |
| Eliminate need to trust the Zemtik process | Not possible — the binary reads the signing key and constructs witnesses |

---

## Measured Performance

Numbers from a real run (`audit/2026-03-25T17-46-43Z.json`), not projections:

| Metric | Value |
|--------|-------|
| Transactions processed | 500 (10 batches × 50) — **hard circuit limit; queries matching > 500 rows will error** |
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

**Step 1 — Zemtik KMS signs each batch.** The BabyJubJub private key at `~/.zemtik/keys/bank_sk` signs a Poseidon Merkle commitment to each 50-transaction batch. This ties the raw data to a cryptographic identity — any tampering with the data invalidates the signature.

**Step 2 — Noir circuit verifies signatures and aggregates.** The circuit receives the raw transactions as *private witnesses* (hidden from the verifier). It reconstructs the Poseidon commitment tree, verifies the EdDSA signature with `assert(eddsa_verify(...))`, and computes `SUM(amount) WHERE category = AWS AND timestamp IN [Q1_start, Q1_end]`. If any assertion fails, no valid witness exists and no proof can be generated — a dishonest prover cannot forge a valid proof.

**Step 3 — UltraHonk proof generation.** Barretenberg generates a succinct proof over the circuit (728,283 gates). The proof reveals nothing about individual transaction amounts, timestamps, or client identifiers. The verifier learns only: "the holder of the signing key signed this dataset, and the AWS spend in Q1 was $2,805,600."

The payload sent to OpenAI contains exactly three data fields:

```json
{
  "category": "AWS Infrastructure",
  "total_spend_usd": 2805600,
  "data_provenance": "ZEMTIK_VALID_ZK_PROOF"
}
```

The HTTP response to the caller includes an `evidence` object at the top level (`evidence_version: 2`, introduced in v0.8.0). It contains the `actual_row_count` of matching rows (replacing the old `row_count` field), the `proof_hash` or `attestation_hash`, engine name, intent confidence, and `data_exfiltrated: 0`.

### Trust Model

**ZK SlowLane:** The ZK proof provides a mathematical guarantee that **if** the signing key is legitimate and **if** the circuit's public inputs are correct, then the aggregate is valid. It does **not** eliminate the need to trust:

1. **The Zemtik binary itself** — it reads the signing key, constructs witnesses from raw rows, and controls what gets signed.
2. **The key file** (`~/.zemtik/keys/bank_sk`) — anyone who reads this file can produce valid proofs for arbitrary data. Production requires an HSM.
3. **The database query results** — Zemtik trusts that the DB returns the correct rows; it does not verify DB-level integrity independently.

**FastLane:** The trust requirement is higher than ZK SlowLane. Because there is no circuit constraint, a malicious operator with access to the signing key could attest an arbitrary aggregate without querying the database at all. FastLane is appropriate only when the aggregate is non-sensitive and the institution controls the Zemtik process end-to-end.

In plain terms: Zemtik stops raw data from reaching the LLM, but the institution must still trust Zemtik's own code and key management — and on the FastLane path, there is no ZK proof to fall back on.

---

## How FastLane Works

FastLane is the sub-50ms path for tables with `"sensitivity": "low"`. It skips the ZK circuit entirely and instead produces a BabyJubJub EdDSA attestation over the aggregate.

**Step 1 — Database aggregate.** Zemtik runs a single SQL aggregate query (`SUM` or `COUNT`) against the database. The query is parameterized by the columns declared in `schema_config.json` (`value_column`, `timestamp_column`, `category_column`, `agg_fn`) and the time range extracted from the user's prompt. Individual rows are never fetched.

**Step 2 — Attestation.** `engine_fast.rs::attest_fast_lane()` hashes the query descriptor and result:

```
SHA-256(
  category_name ||
  start_time_le || end_time_le ||
  aggregate_le || row_count_le || timestamp_now_le ||
  resolved_table ||
  value_column || timestamp_column || category_column_or_empty ||
  agg_fn || metric_label ||
  effective_client_id_le
)
  → 32-byte payload hash

le_bytes_to_integer(payload_hash) mod BN254_FIELD_ORDER
  → signing scalar

BabyJubJub EdDSA sign(bank_sk, signing scalar)
  → (sig_r8_x, sig_r8_y, sig_s)

attestation_hash = SHA-256("{sig_r8_x}:{sig_r8_y}:{sig_s}")
```

The `attestation_hash` acts as a receipt: it cryptographically binds the aggregate to the institution's signing key and the exact query parameters. `signing_version: 2` in the receipt record identifies the full `TableConfig`-aware format (introduced in v0.7.0).

**Step 3 — OpenAI payload.** The aggregate and `attestation_hash` are included in the substituted user message sent to OpenAI. The raw rows, individual transaction amounts, and any PII columns are never present.

The HTTP response to the caller includes an `evidence` object with `engine: "FastLane"`, `attestation_hash`, `actual_row_count`, `data_exfiltrated: 0`, and `evidence_version: 2`.

> **No offline verification.** Unlike ZK SlowLane bundles, FastLane attestations cannot be independently verified with `bb verify`. An auditor can recompute the descriptor, verify the signature material behind `attestation_hash` with the institution's public key, and confirm the attestation format was followed — but cannot prove the aggregate was computed from real database rows.

---

## Project Structure

```
zemtik-core/
├── src/
│   ├── main.rs           # Pipeline orchestrator + CLI subcommand routing
│   ├── proxy.rs          # Axum proxy server (localhost:4000); FastLane + ZK dispatch; build_proxy_router()
│   ├── intent.rs         # IntentBackend trait dispatch (EmbeddingBackend or RegexBackend)
│   ├── intent_embed.rs   # EmbeddingBackend: fastembed BGE-small-en ONNX, cosine similarity
│   ├── time_parser.rs    # DeterministicTimeParser: Q/H/FY/month/relative/YTD → Unix range
│   ├── router.rs         # Routing decision (schema_config sensitivity → FastLane or ZK)
│   ├── engine_fast.rs    # FastLane: generic aggregate (SUM/COUNT) → BabyJubJub attestation (sub-50ms)
│   ├── evidence.rs       # EvidencePack builder for both engine paths
│   ├── db.rs             # DB backend (SQLite / Supabase) + BabyJubJub KMS + aggregate_table
│   ├── prover.rs         # nargo / bb subprocess pipeline
│   ├── openai.rs         # OpenAI Chat Completions client (CLI mode)
│   ├── audit.rs          # Audit record writer
│   ├── receipts.rs       # Receipts ledger (CRUD + v5 migration: actual_row_count; v3: outgoing_prompt_hash; v2: engine_used, intent_confidence)
│   ├── keys.rs           # BabyJubJub key generation + persistence
│   ├── config.rs         # Layered config + SchemaConfig / TableConfig loading; AggFn enum (SUM/COUNT/AVG)
│   ├── lib.rs            # Library crate root (for eval harness and integration tests)
│   └── types.rs          # Shared types
├── tests/
│   ├── integration_proxy.rs  # Integration tests: full proxy with mock OpenAI (7 tests)
│   └── test_*.rs             # Unit tests per module
├── circuit/
│   ├── sum/           # SUM mini-circuit (Nargo.toml + src/main.nr)
│   ├── count/         # COUNT mini-circuit (Nargo.toml + src/main.nr)
│   └── lib/           # Shared Noir library (poseidon, eddsa helpers)
├── vendor/eddsa/      # Vendored EdDSA library (noir-lang/eddsa, -59% gates)
├── supabase/
│   └── migrations/    # SQL schema for Supabase backend
├── eval/
│   ├── intent_eval.rs   # Intent eval harness (235 labeled prompts, CI gate)
│   └── labeled_prompts.json
├── docs/
│   ├── ARCHITECTURE.md       # Full component breakdown and data flow
│   ├── COMPLIANCE_RECEIPT.md # Evidence response field descriptions for auditors
│   ├── CONFIGURATION.md      # All config fields, env vars, schema_config.json format
│   ├── GETTING_STARTED.md    # End-to-end setup guide
│   ├── HOW_TO_ADD_TABLE.md   # Add a new table to the schema (step-by-step)
│   ├── INTENT_ENGINE.md      # How EmbeddingBackend + DeterministicTimeParser work
│   ├── SCALING.md            # Recursive proofs, production path, why remote proving breaks ZK
│   └── SUPPORTED_QUERIES.md  # v1 query contract: supported patterns, error reference
├── Dockerfile            # Multi-stage build; non-root user; FastLane only (no nargo/bb)
├── docker-compose.yml    # Compose file for local Docker runs
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

- **Hard 500-row circuit limit** — The ZK circuit is compiled with `TX_COUNT=50` and `BATCH_COUNT=10` (500 rows total). Any query whose time window matches more than 500 rows will error. Changing the limit requires recompiling the circuit. See [docs/SCALING.md](docs/SCALING.md) for the multi-batch production path.
- **No raw Postgres connector** — `DB_BACKEND` supports `sqlite` (demo) and `supabase` (PostgREST). Connecting an arbitrary Postgres database requires PostgREST deployed in front of it. A native `sqlx` connector (`DB_BACKEND=postgres`) is planned for v2.
- **File-based signing key** — `~/.zemtik/keys/bank_sk` is the BabyJubJub private key. A compromised file produces validly-signed but fraudulent proofs. Production deployments must use an HSM or KMS.
- **ZK proof generation blocked** — `bb prove` fails on the current circuit due to an incompatibility between `eddsa v0.1.3` and Barretenberg v3+/v4+ BigField operations. `nargo execute` validates all constraints successfully. The blocker is in the `eddsa` Noir library, not in Zemtik's circuit logic — unblocked when the library is updated.
- **Aggregation support** — FastLane supports `SUM` and `COUNT` via `"agg_fn"` in `schema_config.json`. The ZK SlowLane additionally supports `AVG` as a composite proof (two sequential ZK proofs for SUM and COUNT + BabyJubJub attestation for the division step). GROUP BY and multi-table JOINs are not supported.
- **CLI pipeline is hardcoded** — 500 transactions, client 123, `aws_spend`, Q1 2024. Proxy mode supports natural-language queries against tables in `schema_config.json`.
- **Local CPU proving** — ~17s per query. Sub-second latency requires GPU/FPGA hardware on-prem (remote proving exposes the private witness — see [docs/SCALING.md](docs/SCALING.md)).

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
- [Industry Use Cases](docs/INDUSTRY_USE_CASES.md) — End-to-end integration examples for healthcare, legal, insurance, e-commerce, government, pharma, and fintech
- [Intent Engine](docs/INTENT_ENGINE.md) — How embedding-based routing and the time parser work
- [Supported Queries](docs/SUPPORTED_QUERIES.md) — v1 query contract: time expressions, table matching, error reference
- [Configuration](docs/CONFIGURATION.md) — All config fields, env vars, schema_config.json format
- [Getting Started](docs/GETTING_STARTED.md) — End-to-end setup guide (Docker + build-from-source)
- [Compliance Receipt](docs/COMPLIANCE_RECEIPT.md) — Evidence response fields: what each field means, how to verify
- [How to Add a Table](docs/HOW_TO_ADD_TABLE.md) — Step-by-step guide to adding a new table
- [Scaling](docs/SCALING.md) — Recursive proofs vs aggregation; why remote proving breaks the privacy guarantee

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Zemtik Contributors
