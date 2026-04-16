# Evidence Pack — Auditor Guide

**Document type:** Audit Evidence Reference  
**Audience:** External auditors, compliance officers, CISOs reviewing Zemtik Evidence Packs as control evidence  
**Goal:** Understand what a Zemtik Evidence Pack proves, how to read each field, how to independently verify the cryptographic claims, and what questions to ask the institution.

---

## What Is Zemtik?

Zemtik is a compliance middleware that sits between an enterprise's data infrastructure and an LLM provider (such as OpenAI or Azure OpenAI). Its purpose is to ensure that **no individual records from sensitive datasets are transmitted to external AI systems** — only aggregate results (totals, counts, averages) are forwarded.

Every query Zemtik intercepts produces an **Evidence Pack**: a machine-readable JSON record attached to the LLM response. The Evidence Pack answers the question:

> *"What computation ran, what data stayed inside the institution's infrastructure, and how can I verify that cryptographically?"*

Evidence Packs are version-stamped. This guide covers **Evidence Pack v3** (`evidence_version: 3`), introduced in v0.13.2.

---

## The Core Guarantee

Zemtik enforces one invariant on every query:

**The LLM receives only a single aggregate scalar (e.g., `SUM = $142,500,000`). Individual records never cross the Zemtik process boundary.**

This guarantee is enforced architecturally (the aggregate is the only value Zemtik includes in the LLM request) and, for high-sensitivity queries, cryptographically (via a zero-knowledge proof that certifies the aggregate is correct without revealing the underlying rows).

---

## Two Engine Paths

Zemtik routes queries to one of two engines based on the data sensitivity classification in `schema_config.json`:

### FastLane (low-sensitivity tables)

- Computes the aggregate in-process (no ZK proof).
- Signs the result with a BabyJubJub EdDSA private key that never leaves the host machine.
- Response time: < 50 ms.
- Evidence: `attestation_hash` (SHA-256 of the signature components). Verifiable by an institution-provided public key.

### ZK SlowLane (high-sensitivity tables)

- Computes the aggregate inside a zero-knowledge circuit (UltraHonk proof via Barretenberg).
- The proof mathematically certifies the aggregate without exposing any underlying row.
- The proof is verified locally before the result is sent to the LLM.
- Response time: ~17–20 seconds on CPU (first query per table may include circuit compile time).
- Evidence: `proof_hash` (SHA-256 of the UltraHonk proof). The proof bundle is independently verifiable by any third party.

---

## Reading an Evidence Pack

A typical Evidence Pack (FastLane, v3) looks like this:

```json
{
  "evidence_version": 3,
  "engine_used": "fast_lane",
  "engine": "FastLane",
  "data_exfiltrated": 0,
  "privacy_model": "architectural_isolation",
  "attestation_hash": "a3f2b1c9d4e5...",
  "proof_hash": null,
  "aggregate": 142500000,
  "row_count": 127,
  "actual_row_count": null,
  "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-04-15T14:30:00Z",
  "key_id": "7f3a91b2...",
  "schema_config_hash": "d4e5f6a7...",
  "zemtik_confidence": 0.95,
  "outgoing_prompt_hash": "c9b8a7f6...",
  "human_summary": "Aggregated 127 rows from 'aws_spend' into a single SUM attested by Zemtik (BabyJubJub EdDSA). No individual records left the institution's infrastructure.",
  "checks_performed": [
    "intent_classification",
    "schema_sensitivity_check",
    "aggregate_only_enforcement",
    "babyjubjub_attestation"
  ]
}
```

---

## Field-by-Field Explanation

### `human_summary`

**Start here.** This field is a plain-language statement of what Zemtik computed, what data stayed local, and (for ZK slow-lane queries) how to verify the result. It is generated automatically by Zemtik based on the engine path and query parameters.

This field is designed to be included directly in a compliance report as a narrative description of the control in operation.

**What it does NOT claim:** The `human_summary` describes what happened inside Zemtik's process boundary. It does not make claims about what occurred inside the LLM provider's infrastructure after the sanitized request was forwarded. See "Scope of the Guarantee" below.

---

### `checks_performed`

An ordered list of every cryptographic and policy check Zemtik ran before forwarding the aggregate to the LLM. The sequence reflects actual execution order.

| Check identifier | What it means |
|------------------|---------------|
| `intent_classification` | The user's natural-language prompt was analyzed to identify which database table to query and which aggregation function to apply. Zemtik did not forward the prompt to any AI system during this step. |
| `schema_sensitivity_check` | The identified table's sensitivity level was looked up from the institution's `schema_config.json` configuration file. This determines whether the query goes through FastLane or ZK SlowLane. |
| `aggregate_only_enforcement` | (FastLane only) Confirmed that the computation produces exactly one aggregate scalar. This is an architectural check — the query API does not expose a path for returning individual rows. |
| `babyjubjub_attestation` | The aggregate result was digitally signed with the institution's BabyJubJub EdDSA private key. The signature binds this specific result to this specific key. If the aggregate value is altered after signing, the signature will not verify. |
| `babyjubjub_signing` | (ZK SlowLane) Each batch of raw transactions was signed before entering the ZK circuit, creating cryptographic commitments to the input data. |
| `poseidon_commitment` | (ZK SlowLane) A Poseidon hash (a ZK-native hash function) was computed over each signed batch inside the circuit, linking the proof to the committed input data. |
| `ultrahonk_proof` | (ZK SlowLane) An UltraHonk zero-knowledge proof was generated. This proof certifies that the claimed aggregate is the correct result of applying the stated aggregation function to the committed input data — without revealing any individual row. |
| `bb_verify_local` | (ZK SlowLane) The proof was verified locally on the institution's host machine using the Barretenberg (`bb`) verifier before the result was forwarded to the LLM. The LLM only receives results from proofs that passed local verification. |

**FastLane queries** always produce 4 checks.  
**ZK SlowLane SUM/COUNT queries** always produce 6 checks.  
**ZK SlowLane AVG queries** produce 11 checks: SUM circuit (4: sign→commit→prove→verify) + COUNT circuit (4: sign→commit→prove→verify) + intent + schema + division attestation.

---

### `data_exfiltrated`

**Value: always `0`.**

This field certifies that zero individual records were included in the request sent to the LLM provider. It is hardcoded by Zemtik's architecture — it is not configurable and cannot be set to any other value.

---

### `engine_used`

`"fast_lane"` or `"zk_slow_lane"`. Determines which cryptographic guarantees apply:

- `fast_lane` — BabyJubJub attestation only. The aggregate is signed but not zero-knowledge proven.
- `zk_slow_lane` — Full ZK proof. The aggregate is cryptographically proven correct without revealing input data.

The routing decision is based on the `sensitivity` field in `schema_config.json`. Ask the institution for their `schema_config.json` to verify that the tables you care about are classified correctly.

---

### `attestation_hash` (FastLane)

SHA-256 of the BabyJubJub EdDSA signature components (`sig_r8_x:sig_r8_y:sig_s`). To verify:

1. Ask the institution for their public key (`~/.zemtik/keys/bank_sk.pub` or the `key_id` field in the receipt).
2. Re-compute `SHA-256(sig_r8_x:sig_r8_y:sig_s)` from the raw signature bytes and confirm it matches `attestation_hash`.
3. Verify the signature over `SHA-256(aggregate_as_decimal)` using the public key and standard BabyJubJub EdDSA verification.

---

### `proof_hash` (ZK SlowLane)

SHA-256 of the UltraHonk proof bytes. To verify independently:

```bash
zemtik verify path/to/bundle.zip
```

Or directly with Barretenberg:

```bash
bb verify --proof path/to/proof.bin --vk path/to/vk.bin
```

A `VALID` result confirms: the aggregate in the Evidence Pack is the mathematically correct result of the stated computation over the committed input data. The proof does not reveal any individual records.

The proof bundle is stored at the path referenced by `receipt_id` in the institution's receipts database (`~/.zemtik/receipts.db`).

---

### `receipt_id`

Unique UUIDv4 for this computation. Allows cross-reference with:
- The institution's receipts database (`zemtik list`)
- The proof bundle (for ZK SlowLane)
- Any downstream audit log the institution maintains

For a quick visual check while the proxy is running, open `http://<proxy-host>:4000/verify/<receipt_id>` in a browser — the page shows proof status, verified aggregate, and category. See [Getting Started, Step 7](GETTING_STARTED.md#step-7--view-your-audit-trail).

---

### `key_id`

SHA-256 of the institution's BabyJubJub public key. Use this to confirm which signing key was in use at the time of the query. The corresponding private key is stored at `~/.zemtik/keys/bank_sk` and is never transmitted anywhere — it never leaves the institution's host.

To confirm key continuity across multiple receipts, verify that `key_id` is consistent. A change in `key_id` indicates a key rotation event.

---

### `schema_config_hash`

SHA-256 of `schema_config.json` — the configuration file that defines which tables exist, their sensitivity levels, and which aggregation functions are allowed. This hash allows you to confirm that the sensitivity routing configuration in effect at query time has not changed. Ask the institution for their current `schema_config.json` and compute `SHA-256` to verify the hash matches.

---

### `outgoing_prompt_hash`

SHA-256 of the JSON payload Zemtik sent to the LLM provider. This is a Rust-layer commitment — it commits to the exact content of the outgoing request (which contains only the aggregate, not raw records). It does not constitute a ZK circuit input (that is a known limitation tracked as a deferred improvement).

---

### `zemtik_confidence`

Confidence score (0.0–1.0) for the intent classification step. For exact-match regex routing: always `1.0`. For semantic embedding routing: cosine similarity between the user's prompt and the matched table's description. Values below the configured threshold (default: `0.6`) are routed to ZK SlowLane regardless of table sensitivity.

---

## Scope of the Guarantee

Zemtik's Evidence Pack proves **proxy-level governance** — what happened between the institution's data store and the LLM provider's API endpoint. Specifically:

**What is proven:**
- The LLM received only an aggregate scalar (not individual records) in the request payload.
- The aggregate was computed locally on the institution's infrastructure.
- The computation is cryptographically bound to the institution's signing key (FastLane) or certified by a verifiable ZK proof (ZK SlowLane).
- Every policy check listed in `checks_performed` ran and passed before the result was forwarded.

**What is NOT proven:**
- What occurs inside the LLM provider's infrastructure after Zemtik forwards the sanitized request.
- GPU memory state at the LLM provider.
- End-to-end network confidentiality (that is the responsibility of TLS, which is the institution's standard infrastructure).
- That the `schema_config.json` sensitivity classifications are appropriate for the institution's regulatory obligations — that is a configuration decision the institution makes.

---

## Questions to Ask the Institution

If you are conducting a compliance review, these questions will help you assess the completeness of Zemtik's controls:

1. **Show me your `schema_config.json`.** Which tables are classified as `"critical"` (ZK SlowLane) vs `"low"` (FastLane)? Are the tables that hold regulated data in the `"critical"` tier?

2. **Where is the signing key stored?** The key at `~/.zemtik/keys/bank_sk` should be on a host with controlled access. Who has access to that host?

3. **Can you run `zemtik list` and show me the receipts?** Receipts are stored in `~/.zemtik/receipts.db`. Confirm that `data_exfiltrated` is `0` for all records and that `engine_used` matches what the configuration dictates for each table.

4. **For a ZK SlowLane receipt, can you run `zemtik verify <bundle.zip>`?** This confirms the proof bundle is intact and the proof verifies. If the bundle is missing or the proof fails, that is a finding.

5. **What is the key rotation policy?** A change in `key_id` across receipts indicates a key rotation. Ask for the rotation log.

6. **Is `ZEMTIK_TUNNEL_DEBUG_PREVIEWS` disabled?** In production, this environment variable should be `0` (the default). If enabled, Zemtik stores 500-character plaintext snippets of LLM responses in the tunnel audit database. Confirm it is off in the pilot environment.

---

## SOC 2 Mapping (Preliminary — Pending Auditor Validation)

The following is a preliminary mapping of Evidence Pack fields to SOC 2 Trust Services Criteria. **This mapping has not been validated by an independent SOC 2 auditor.** It is provided as a starting point for discussion.

| SOC 2 Criterion | Evidence Pack Field(s) | Preliminary Rationale |
|-----------------|----------------------|----------------------|
| CC6.1 (Logical access controls) | `key_id`, `engine_used` | Signing key access controls and routing policy enforce who can trigger a computation and what data is accessible. |
| CC6.6 (Restricts logical access to information assets) | `data_exfiltrated: 0`, `checks_performed`, `human_summary` | Architectural isolation prevents raw records from crossing the process boundary to the LLM provider. |
| CC6.8 (Prevents unauthorized changes to information) | `attestation_hash` / `proof_hash`, `schema_config_hash` | Aggregate results are cryptographically bound at computation time. Schema configuration changes are detectable via hash comparison. |
| CC7.2 (Monitors system components for anomalies) | `receipt_id`, `timestamp`, `zemtik_confidence` | Every query produces a timestamped, uniquely identified receipt. Confidence scores below threshold trigger ZK SlowLane routing regardless of table classification. |

**To validate this mapping:** Present a sample Evidence Pack to your SOC 2 auditor and ask: "Does `data_exfiltrated: 0` combined with the `checks_performed` list and the verifiable `attestation_hash`/`proof_hash` satisfy the information flow restriction requirement in CC6.6? What additional fields or external documentation would you need to include this as control evidence in a Type 2 report?"

---

## Changelog

| Evidence Pack Version | What Changed |
|-----------------------|-------------|
| v1 | Initial release: `engine_used`, `attestation_hash`, `proof_hash`, `data_exfiltrated`, `row_count`, `receipt_id` |
| v2 | Added `actual_row_count` (real rows vs padding in ZK proofs), AVG dual-proof support |
| v3 | Added `human_summary` (plain-language narrative) and `checks_performed` (ordered check list). AVG produces 11 checks (corrected from initial 9-check claim that omitted COUNT circuit signing/commitment steps). |

---

*This document is part of the Zemtik compliance documentation suite. For technical details on ZK circuit construction and proof verification, see `docs/ZK_CIRCUITS.md`. For the full field reference with implementation notes, see `docs/COMPLIANCE_RECEIPT.md`.*
