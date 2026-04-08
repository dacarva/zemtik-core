# Compliance Receipt

Every query intercepted by Zemtik returns an `evidence` object alongside the LLM response.
This document explains each field for compliance review, audit, and regulatory purposes.

## What is a Compliance Receipt?

A compliance receipt is a cryptographically-bound record that proves:
1. The LLM received only an aggregate result (e.g. total AUM = $142M), **not raw client records**.
2. The aggregate was computed locally on your infrastructure, under a signing key that never leaves your environment.
3. No individual portfolio records were transmitted to any third party.

The receipt can be presented to auditors as evidence that data handling obligations were met for each LLM query.

---

## Evidence Fields

### `data_exfiltrated`

**Value: always `0`**

Certifies that zero individual client records were transmitted to the LLM provider. The LLM receives only the verified aggregate scalar. This field is hardcoded by Zemtik's architecture — it is not configurable.

### `engine_used`

**Values: `"fast_lane"` or `"zk_slow_lane"`**

- `fast_lane` — aggregate computed in-process using BabyJubJub EdDSA attestation. Response time: <500ms.
- `zk_slow_lane` — aggregate computed inside a zero-knowledge circuit (UltraHonk proof via Barretenberg). Response time: 30–120s. The proof is mathematically verifiable by any third party holding the verification key.

### `attestation_hash`

**Present when `engine_used = "fast_lane"`, null for ZK slow lane.**

SHA-256 of the BabyJubJub EdDSA signature components (`sig_r8_x:sig_r8_y:sig_s`). This hash binds the aggregate result to the institution's signing key. If the aggregate value is altered, the `attestation_hash` will not match the signature — the receipt cannot be forged.

### `proof_hash`

**Present when `engine_used = "zk_slow_lane"`, null for FastLane.**

SHA-256 of the UltraHonk ZK proof bytes. The proof itself is stored in the proof bundle and can be independently verified with `zemtik verify <bundle.zip>` or `bb verify`. The `proof_hash` acts as a tamper-evident pointer to the bundle artifact.

### `privacy_model`

**Value: always `"architectural_isolation"`**

Describes the privacy mechanism: raw records are processed inside the Zemtik process boundary and the aggregate is the only value that crosses into the LLM request. This is an architectural guarantee, not a policy assertion.

### `receipt_id`

Unique UUIDv4 for this computation. Use this to look up the full audit record or verify the receipt via the `/verify/<receipt_id>` endpoint.

### `timestamp`

Unix epoch seconds (UTC) when the aggregate was computed. Use this to cross-reference with your own audit log or data access records.

### `aggregate`

The numeric aggregate result that was sent to the LLM (e.g. total AUM in USD, headcount, etc.). The LLM's response is based exclusively on this value.

### `row_count`

Number of rows included in the aggregate query (FastLane). For ZK slow lane, see `actual_row_count`.

### `actual_row_count`

(ZK slow lane only) The real number of matching transactions included in the proof, excluding padding rows. The ZK circuit pads to 500 rows for a fixed-size proof; this field tells you how many of those were real data.

### `key_id`

SHA-256 of the institution's BabyJubJub public key (`pub_key_x:pub_key_y`). Use this to verify which signing key produced this receipt. The key is stored at `~/.zemtik/keys/bank_sk` and never leaves the host.

### `schema_config_hash`

SHA-256 of the `schema_config.json` file in use at the time of the query. Allows auditors to confirm which table definitions and sensitivity classifications governed the routing decision.

### `zemtik_confidence`

Intent matching confidence score (0.0–1.0). For the regex backend, this is always 1.0 (exact substring match). For the embedding backend, this is the cosine similarity between the prompt and the matched table's description vector.

---

## Reading a Receipt

Example receipt from a FastLane SUM query:

```json
{
  "engine_used": "fast_lane",
  "data_exfiltrated": 0,
  "privacy_model": "architectural_isolation",
  "attestation_hash": "a3f2b1c9d4e5...",
  "proof_hash": null,
  "aggregate": 142500000,
  "row_count": 127,
  "actual_row_count": null,
  "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1743972600,
  "key_id": "7f3a91b2...",
  "schema_config_hash": "d4e5f6a7...",
  "zemtik_confidence": 1.0,
  "outgoing_prompt_hash": "c9b8a7f6..."
}
```

**What to tell a regulator:**

> "For this query, Zemtik computed the aggregate locally on our infrastructure. The `data_exfiltrated: 0` field certifies that no individual client records were transmitted to OpenAI. The `attestation_hash` is a cryptographic signature over the aggregate result, bound to our institution's signing key. This receipt cannot be fabricated — if the aggregate were altered after signing, the signature would not verify."

---

## Verifying a ZK Receipt

For `engine_used: "zk_slow_lane"`, the proof can be independently verified:

```bash
zemtik verify path/to/bundle.zip
```

This runs `bb verify` on the UltraHonk proof using the public verification key. A `VALID` result confirms that the aggregate was computed inside the zero-knowledge circuit — no individual records could have been exposed without invalidating the proof.
