# Zemtik Architecture

**Document type:** Explanation + Reference
**Audience:** Bank CISOs, enterprise security architects, and technical evaluators
**Goal:** Understand how Zemtik guarantees zero raw data exfiltration to external AI systems

---

## The Problem Zemtik Solves

Financial institutions accumulate petabytes of transaction data that could generate competitive intelligence through AI analysis. The obstacle is contractual, regulatory, and fiduciary: raw ledger data cannot leave the enterprise perimeter. Sending individual transactions to a third-party LLM violates data residency rules, client confidentiality agreements, and in many jurisdictions, financial privacy law.

Existing workarounds — on-premises LLMs, data anonymization, synthetic data — involve substantial infrastructure cost, accuracy loss, or both.

Zemtik takes a different approach: **compute the answer locally, prove the computation was honest, and send only the proven answer to the LLM.**

---

## Core Guarantee

> **Zero raw transaction rows are transmitted to OpenAI at any point in the pipeline.**

The payload sent to the LLM is a JSON object containing only three fields: the aggregate metric, the query parameters that produced it, and a provenance tag indicating the result was ZK-verified.

The mathematical mechanism that makes this trustworthy is described below.

---

## Architecture Overview

```
Bank Perimeter
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  ┌──────────────┐    sign     ┌───────────────────────┐    │
│  │  Transaction │ ──────────► │  Bank KMS (Mock)       │    │
│  │  DB (SQLite  │             │  BabyJubJub EdDSA      │    │
│  │  or Supabase)│             │  Poseidon hash tree    │    │
│  └──────────────┘             └───────────┬───────────┘    │
│         │                                 │                 │
│         │ raw rows (private)              │ signature       │
│         ▼                                 ▼                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Noir ZK Circuit                          │   │
│  │                                                       │   │
│  │  1. Verify EdDSA signature over transaction hash      │   │
│  │     assert(eddsa_verify(bank_pub_key, sig, hash))     │   │
│  │                                                       │   │
│  │  2. Aggregate: SUM(amount) WHERE category=AWS         │   │
│  │     AND timestamp IN [Q1_start, Q1_end]               │   │
│  │                                                       │   │
│  │  Private witness: 50 transaction rows, signature      │   │
│  │  Public output: verified_aggregate (u64)              │   │
│  └──────────────────────────────────────────────────────┘   │
│                             │                               │
│                             │ $158,100  (one number)        │
└─────────────────────────────┼───────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  OpenAI API         │
                   │  gpt-5.4-nano       │
                   │                     │
                   │  Payload received:  │
                   │  { category: "AWS", │
                   │    spend: 158100,   │
                   │    provenance:      │
                   │    "ZEMTIK_ZK" }    │
                   └─────────────────────┘
```

---

## Component Deep-Dive

### 1. The Bank Ledger (`src/db.rs`)

The database backend is selected by the `DB_BACKEND` environment variable:

- **`sqlite`** (default) — An in-memory SQLite database, re-created on each run. Useful for offline development and CI.
- **`supabase`** — A persistent Supabase (PostgreSQL) database, accessed via PostgREST for data operations and direct Postgres for DDL. Useful for demos where the audience needs to verify the data isn't forged.

In production, this component would be a read-only adapter to the bank's actual database system.

**Schema (identical across both backends):**
```sql
CREATE TABLE transactions (
    id        BIGINT PRIMARY KEY,
    client_id BIGINT NOT NULL,
    amount    BIGINT NOT NULL,    -- in USD
    category  BIGINT NOT NULL,    -- 1=Payroll, 2=AWS, 3=Coffee
    timestamp BIGINT NOT NULL     -- UNIX seconds
);
```

The POC seeds 500 transactions (10 batches × 50) for `client_id = 123` distributed across Q1 2024. Both backends use the same `generate_seed_transactions()` function to guarantee identical data and therefore identical ZK proofs.

### 2. The Bank KMS Mock (`src/db.rs` — `sign_transactions`)

Before any data leaves the database layer (even internally), the full transaction payload is cryptographically signed. This signature is what allows the circuit to assert data integrity.

**Signature scheme:** BabyJubJub EdDSA with Poseidon hash

BabyJubJub is a twisted Edwards elliptic curve defined over the BN254 scalar field. It was chosen because its arithmetic is native to Noir's constraint system, making in-circuit signature verification dramatically cheaper than secp256k1 ECDSA.

**What is signed:** Not the raw bytes, but a structured Poseidon hash commitment to the transaction array. The commitment is a 4-level Merkle-like tree:

```
L1: Poseidon_3([amount_i, category_i, timestamp_i])  -- one hash per transaction
    ↓ (50 hashes grouped into ten 5-element sets)
L2: Poseidon_5([L1[0..4]])  ...  Poseidon_5([L1[45..49]])   -- 10 hashes
    ↓ (10 hashes grouped into two 5-element sets)
L3: Poseidon_5([L2[0..4]])  ...  Poseidon_5([L2[5..9]])      -- 2 hashes
    ↓
L4: Poseidon_2([L3[0], L3[1]])                               -- 1 commitment (msg_hash)
```

The bank signs `msg_hash`. All Poseidon nodes use the circomlib-compatible BN254 permutation with arity ≤ 5, which is identical in both the Rust signing code (`poseidon-rs 0.0.8`) and the Noir circuit (`poseidon::poseidon::bn254::hash_N`). This cross-language hash compatibility was empirically verified during development.

### 3. The ZK Circuit (`circuit/src/main.nr`)

Written in Noir 1.0.0-beta.19. The circuit is the core mathematical guarantee of the system.

**Public inputs** (visible to anyone holding the proof):
| Name | Type | Description |
|------|------|-------------|
| `target_category` | `u64` | Category code being queried |
| `start_time` | `u64` | Query time range start (UNIX) |
| `end_time` | `u64` | Query time range end (UNIX) |
| `bank_pub_key_x` | `Field` | BabyJubJub public key x-coordinate |
| `bank_pub_key_y` | `Field` | BabyJubJub public key y-coordinate |

**Private inputs** (hidden from the verifier — this is the privacy guarantee):
| Name | Type | Description |
|------|------|-------------|
| `transactions` | `[Transaction; 50]` | The raw ledger rows |
| `sig_s` | `Field` | EdDSA signature scalar |
| `sig_r8_x` | `Field` | EdDSA signature R8 point x |
| `sig_r8_y` | `Field` | EdDSA signature R8 point y |

**Public output:**
The verified aggregate sum — a single `Field` element.

**Circuit logic (three steps):**

**Step 1 — Reconstruct the commitment.** The circuit re-hashes the private transaction array using the same 4-level Poseidon tree. This reconstructed `msg_hash` must match what the bank signed.

**Step 2 — Verify the EdDSA signature.** The circuit calls `eddsa_verify::<PoseidonHasher>()` from the `noir-lang/eddsa` library. This asserts that the signature was produced by the holder of the private key corresponding to `bank_pub_key`. If the assertion fails, no valid witness exists and no proof can be generated — a dishonest prover cannot forge a valid proof.

```noir
assert(eddsa_verify::<PoseidonHasher>(
    bank_pub_key_x, bank_pub_key_y,
    sig_s, sig_r8_x, sig_r8_y,
    msg_hash,
));
```

**Step 3 — Aggregate with branchless masking.** The circuit sums transaction amounts using conditional `if/else` expressions that the Noir compiler lowers to arithmetic selects. Both branches are always evaluated (ACIR flattens control flow), which means no timing information leaks about which transactions matched the predicate.

```noir
total += if matches_query { transactions[i].amount as Field } else { 0 };
```

### 4. The Noir Pipeline (`src/prover.rs`)

The Rust orchestrator drives the Noir toolchain via subprocess:

| Command | Purpose | Output |
|---------|---------|--------|
| `nargo compile` | Compiles `main.nr` to ACIR bytecode | `target/zemtik_circuit.json` (3.1 MB) |
| `nargo execute` | Solves the circuit with private witness, verifies all constraints | `target/zemtik_circuit.gz` + circuit return value printed to stdout |
| `bb prove -s ultra_honk` | Generates a UltraHonk ZK proof | `proofs/proof` |
| `bb write_vk` + `bb verify` | Generates verification key, verifies proof | exit code 0 = valid |

`nargo execute` is itself a complete constraint check: if the EdDSA signature is invalid, if the witness is inconsistent, or if any assertion fails, the command exits with a non-zero code and no witness is produced. The subsequent OpenAI call is only reached after this verification.

### 5. The OpenAI Client (`src/openai.rs`)

Sends the following JSON payload — and nothing else — to the OpenAI Chat Completions API:

```json
{
  "category": "AWS Infrastructure",
  "total_spend_usd": 158100,
  "period_start": "2024-01-01",
  "period_end": "2024-03-31",
  "data_provenance": "ZEMTIK_VALID_ZK_PROOF",
  "raw_data_transmitted": false
}
```

**What is NOT in this payload:**
- Individual transaction amounts
- Transaction timestamps
- Client identifiers
- Any row-level data whatsoever

The system prompt instructs the model to act as a bank advisor receiving cryptographically verified data, explicitly prohibiting it from requesting raw transaction data.

---

## Data Flow: Step-by-Step

```
1. cargo run
   └── dotenvy::dotenv() loads .env (OPENAI_API_KEY, DB_BACKEND, etc.)

2. db::init_db()
   ├── [sqlite]    Creates in-memory SQLite, seeds 500 transactions for client 123
   └── [supabase]  Ensures table exists (DDL via Postgres), auto-seeds if empty (via PostgREST)

3. db::query_transactions(&backend, 123)
   └── Returns Vec<Transaction> [500 rows, ORDER BY id ASC]

4. db::sign_transactions(&txns)
   └── Computes 4-level Poseidon commitment (msg_hash)
   └── Signs msg_hash with fixed BabyJubJub private key
   └── Returns SignatureData { pub_key_x, pub_key_y, sig_s, sig_r8_x, sig_r8_y }
       (all as BN254 decimal strings)

5. prover::generate_prover_toml(&txns, &sig, &params)
   └── Writes circuit/Prover.toml with all inputs serialized

6. prover::compile_circuit()       [skipped if already compiled]
   └── $ nargo compile
   └── Produces circuit/target/zemtik_circuit.json

7. prover::execute_circuit()
   └── $ nargo execute
   └── Noir runtime verifies:
       a. EdDSA signature valid (BabyJubJub + Poseidon)
       b. Aggregation correct for given query params
   └── Parses "Circuit output: 0x..." -> u64 aggregate
   └── Returns: 158100

8. prover::generate_proof()        [may skip if CRS insufficient]
   └── $ bb prove -s ultra_honk ...

9. openai::query_openai(158100, "AWS Infrastructure", ...)
   └── Constructs ZK payload (no raw rows)
   └── POST to https://api.openai.com/v1/chat/completions
   └── Returns AI advisory text

10. Print results
```

---

## Cryptographic Security Properties

### Soundness
A dishonest prover who attempts to submit fabricated transaction data or an inflated aggregate cannot produce a valid witness. The EdDSA assertion in Step 2 of the circuit ensures that the commitment to the transaction array must match a value signed by the bank's private key. Without the bank's private key, no valid signature can be produced for a modified dataset.

### Zero-Knowledge
The ZK proof reveals nothing about the private inputs beyond what is logically implied by the public inputs and output. An observer who holds the proof and public inputs learns only: "the holder of the bank private key signed a payload, and the AWS spend derived from that payload in Q1 2024 was $158,100."

### Completeness
Any honest prover with valid transaction data and the correct bank signature can always produce a valid witness and proof.

---

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| ZK circuit language | Noir | 1.0.0-beta.19 |
| Proof system backend | Barretenberg (UltraHonk) | v0.82.2 |
| EdDSA circuit library | noir-lang/eddsa | v0.1.3 |
| Poseidon circuit library | noir-lang/poseidon | v0.1.1 |
| Orchestrator language | Rust | 1.93.1 |
| Database | rusqlite (SQLite) or Supabase (PostgREST + direct Postgres for DDL) | 0.32 / — |
| BabyJubJub signing | babyjubjub-rs | 0.0.11 |
| Poseidon hashing (Rust) | poseidon-rs | 0.0.8 |
| HTTP client | reqwest | 0.12 |
| AI inference | OpenAI gpt-5.4-nano | Chat Completions API |

---

## Known Limitations of This POC

### 1. CRS Size for ZK Proof Generation
The circuit (EdDSA + 50-transaction Poseidon tree) exceeds the local Grumpkin CRS of 65,537 points cached by Barretenberg. In production, deploy with a pre-downloaded SRS or use a proof server (e.g., Aztec Network's proving infrastructure). The `nargo execute` step — which fully verifies all circuit constraints — completes successfully and is sufficient for local validation.

### 2. Deterministic Private Key
The bank's private key is hardcoded as `[0x01..0x20]` for demo reproducibility. In production, integrate with an HSM or a secrets manager.

### 3. Fixed Transaction Count
The circuit is compiled with `TX_COUNT = 50` as a compile-time constant. Changing this requires recompilation. Production deployments would expose multiple compiled circuits for different batch sizes, or use a recursive proof that handles variable-length inputs.

### 4. Single Query Type
The current circuit supports sum aggregation with category and time-range predicates. Extending to COUNT, AVG, or multi-dimensional filters requires new circuit variants.

---

## Running the POC

```bash
# Prerequisites: nargo 1.0.0-beta.19, bb v0.82.2, Rust 1.70+
# Copy the example env and set OPENAI_API_KEY (never commit .env)
cp .env.example .env
# Edit .env and add your key from https://platform.openai.com/api-keys

# Build and run (first run compiles the Noir circuit, ~10s)
cargo run

# Subsequent runs skip compilation (~2.5s total)
cargo run
```

**Expected output:**
```
[DB]   Initializing in-memory SQLite ledger... OK (50 transactions for client 123)
[KMS]  Signing 50-row payload with BabyJubJub EdDSA... OK
[NOIR] Writing Prover.toml... OK
[NOIR] Circuit already compiled, skipping nargo compile
[NOIR] Executing circuit (signature verification + aggregation)...
[NOIR] Circuit executed in 0.39s
[NOIR] Verified aggregate AWS Infrastructure spend = $158100
[NOIR] Attempting UltraHonk proof generation...
[NOIR] Circuit constraints verified by nargo execute (EdDSA + aggregation).
[AI]   Querying gpt-5.4-nano with ZK-verified payload...

══════════════════════════════════════════════════════
  ZEMTIK RESULT (total time: 2.37s)
══════════════════════════════════════════════════════
  Category : AWS Infrastructure
  Period   : Q1 2024
  Aggregate: $158100
  ZK Proof : VERIFIED (nargo execute - all constraints including EdDSA satisfied)
  Raw rows sent to OpenAI: 0

  AI Advisory (gpt-5.4-nano):
  Your AWS Infrastructure spend of $158,100 for Q1 2024 is now verified...
══════════════════════════════════════════════════════
```
