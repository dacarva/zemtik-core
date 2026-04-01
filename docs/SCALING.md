# Zemtik Scaling Architecture

**Document type:** Explanation
**Audience:** Security architects and technical evaluators
**Goal:** Understand the distinction between recursive proofs and recursive aggregation, and why the production scaling path for Zemtik requires proving to stay inside the bank perimeter.

---

## The Proving Cost Problem

The current POC circuit — EdDSA signature verification + 50-transaction Poseidon commitment tree — generates approximately 200,000+ arithmetic gates. Barretenberg's default local CRS covers 65,537 points (2^16), which is insufficient for this circuit size.

There are two conceptually distinct solutions:

1. **Acquire more CRS** — download a larger SRS, or delegate proving to an external server
2. **Restructure the circuit** — split work across smaller circuits that fit within the local CRS

Only option 2 preserves Zemtik's privacy guarantee. Option 1 reintroduces the data exposure problem that Zemtik was built to solve.

---

## Recursive Proofs vs Recursive Aggregation

These terms are related but not interchangeable.

### Recursive Proofs

A circuit that **verifies another proof inside itself**. The output is a single proof that attests to both the inner verification and any additional logic in the outer circuit.

```
Proof_A  ──►  Outer circuit (verifies Proof_A + own logic)  ──►  Proof_B
```

The key property: Proof_B is the same size as Proof_A regardless of how many inner proofs were verified. This enables **proof compression** — a chain of N computations collapses into a single constant-size proof.

Noir exposes this via `std::verify_proof()`. The verification key of the inner circuit becomes a public input to the outer circuit.

### Recursive Aggregation

A technique for **accumulating multiple proofs without fully verifying each one immediately**. Each proof contributes to a shared mathematical object (the aggregation object). A single verification operation at the end checks all accumulated proofs simultaneously.

```
Proof_1 ─┐
Proof_2 ─┼──►  aggregation_object  ──►  single final verification
Proof_3 ─┘
```

The key property: verification cost is paid once at the end, not once per proof. This is more efficient than recursive proofs when batching many proofs of the **same circuit**.

Noir exposes this via `std::recursion::verify_proof()` with an explicit aggregation object that threads through the circuit.

### Summary

| Property | Recursive Proofs | Recursive Aggregation / IVC |
|---|---|---|
| Verification timing | At each recursion step | Once at the end |
| Per-step overhead | High -- full in-circuit verification | Low -- accumulation only |
| Output | Single compressed proof | Aggregation object + final proof |
| Best for | Compressing chains of computation | Batching many proofs of the same circuit |
| Noir API | `verify_proof_with_type()` | `#[fold]` + `bb prove -s client_ivc` |

> **Note (Noir 1.0.0-beta.19)**: `std::verify_proof()` and `std::recursion::verify_proof()` are removed.
> Recursive proofs use `verify_proof_with_type()`. Incremental folding uses the `#[fold]` attribute
> combined with `bb prove -s client_ivc --input_type compiletime_stack`.

---

## The Production Path for Zemtik

Zemtik's scaling problem is batching: as the number of transactions grows, the single circuit grows proportionally. The solution combines both techniques.

### Step 1 — Batch leaf circuits

Split transactions into fixed-size batches. Each batch uses the current circuit (`TX_COUNT = 50`) and produces a proof locally, within the bank perimeter.

```
Batch_1: tx[0..49]    → nargo execute + bb prove  →  Proof_1  (inside perimeter)
Batch_2: tx[50..99]   → nargo execute + bb prove  →  Proof_2  (inside perimeter)
Batch_3: tx[100..149] → nargo execute + bb prove  →  Proof_3  (inside perimeter)
```

Each leaf circuit fits within the local CRS (50 transactions is the current limit before the CRS is exceeded). The EdDSA signature verification happens in the first leaf; subsequent leaves verify a chain commitment.

### Step 2 — Fold locally with `#[fold]` + Client IVC

The `#[fold]` attribute (available from Noir 1.0.0-beta.19) compiles a function into a separate ACIR
program. `bb prove -s client_ivc --input_type compiletime_stack` folds all leaf proofs incrementally
into a single final proof. This is the **planned production approach** in `circuit/src/main.nr`.

> **Current status:** `bb prove -s client_ivc` is blocked by an incompatibility between `eddsa v0.1.3` and Barretenberg v3+/v4+ (see blocker section below). `nargo execute` verifies all circuit constraints successfully. The circuit structure already implements `#[fold]`-compatible batching — the blocker is only in the final proof generation step.

```
[BatchInput_0..9]
        |
  #[fold] process_batch()  x10   (each leaf: ~41k ACIR opcodes, EdDSA + Poseidon + aggregate)
        |
  main() aggregator         (trivial: ~1.5k opcodes, sums 10 partial aggregates)
        |
  bb prove -s client_ivc
        |
  Proof_final  (single proof, constant size, contains verified total)
```

The aggregator runs locally. No batch proof or private witness leaves the bank perimeter at any point.

### Why not use a remote proving server?

The ZK prover requires the **private witness** to generate a proof. For Zemtik, the private witness includes the raw transaction rows — exactly the data that must not leave the perimeter.

Delegating proof generation to any external party (a cloud server, or Aztec Network's proving infrastructure) would transmit the raw transaction data outside the bank perimeter, defeating the system's core guarantee. The problem is architectural: the prover always needs the private inputs.

The only architecturally sound options for production are:

| Approach | Private data stays in perimeter | Notes |
|---|---|---|
| Local proving (GPU/FPGA hardware) | Yes | Preferred production path |
| TEE (Intel SGX / AMD SEV) on-prem | Yes — with attestation | High complexity |
| MPC proving | Yes — witness never reconstructed | Experimental, not production-ready |
| Remote server (cloud / Aztec) | **No** | Breaks privacy guarantee |

---

## Scaling Table

| Transactions | Approach | Proof generation | Status |
|---|---|---|---|
| 50 | Single circuit, local | `bb prove` requires larger CRS | Superseded by batched architecture |
| 500 | 10x `#[fold]` batches, `nargo execute` | CRS limits `bb prove`; all constraints verified | **IMPLEMENTED** |
| 500 | 10x `#[fold]` batches, `bb prove -s client_ivc` | Blocked: eddsa v0.1.3 incompatible with bb v3+/v4+ BigField | Unblocked when eddsa lib updated |
| 5,000+ | 100+ batches + `#[fold]` + `client_ivc` | Minutes on dedicated hardware | **Production path** |

### Current blocker: eddsa v0.1.3 + bb v3+/v4+ incompatibility

`eddsa v0.1.3` uses BigField operations that trigger an assertion failure in Barretenberg v3.0.0-nightly
and v4.0.0-nightly:

```
Assertion failed: (uint256_t(fr_vec[1]) < (uint256_t(1) << (TOTAL_BITS - NUM_LIMB_BITS * 2)))
```

This affects `bb prove` with both `ultra_honk` and `client_ivc` schemes. The fix requires either:
- An updated `eddsa` Noir library compatible with new Barretenberg BigField limits
- A manual circuit reimplementation of EdDSA that avoids the problematic BigField ops

`nargo execute` is unaffected and fully verifies all circuit constraints including EdDSA.

---

## Trusted Setup Note

All approaches that use Barretenberg/UltraHonk rely on the BN254 structured reference string (SRS) generated in Aztec's trusted setup ceremony. If the toxic waste from that ceremony was not destroyed, an attacker possessing it could forge valid proofs for any circuit using that SRS.

This is a universal assumption of all pairing-based SNARKs and is not specific to Zemtik. For production deployments, verify the ceremony transcript and consider whether the trust assumptions are acceptable under your regulatory framework.
