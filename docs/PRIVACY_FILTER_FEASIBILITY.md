> **Note:** This document is a legacy design feasibility study from early development. The features it describes are now implemented — see [docs/ANONYMIZER.md](ANONYMIZER.md) for current documentation. This document is retained for historical reference only.

# openai/privacy-filter — Feasibility & Integration Analysis

## Overview

This document compares [openai/privacy-filter](https://huggingface.co/openai/privacy-filter) (released 2025 under Apache-2.0) with the current Zemtik anonymizer sidecar. It covers architecture, deployment feasibility on consumer-grade hardware, possible integration paths, and tradeoffs.

---

## 1. Current Sidecar Architecture

The Zemtik anonymizer runs as a standalone Python gRPC service (`sidecar/`) called from the Rust proxy via `tonic`.

### Recognition stack

| Layer | Model / Library | What it covers |
|---|---|---|
| GLiNER | `urchade/gliner_multi_pii-v1` (~400 MB) | PERSON, ORG only (LOCATION excluded: Spanish determiner false-positives "La", "del") |
| Presidio | `presidio-analyzer` + spaCy `en_core_web_lg` (~400 MB) | DATE_TIME, MONEY, PHONE_NUMBER, EMAIL_ADDRESS, custom LATAM ID patterns |
| Regex (`PatternRecognizer`) | `sidecar/recognizers.py` | CO_NIT, CO_CEDULA, CL_RUT, MX_CURP, MX_RFC, BR_CPF, BR_CNPJ, AR_DNI, ES_NIF, IBAN_CODE, plus Spanish addresses and bank names |

### Token format

Recognized spans become `[[Z:{type_hash}:{counter}]]` tokens (e.g., `[[Z:e47f:2]]` for PERSON). The 4-hex type codes are defined in `src/entity_hashes.rs` and `sidecar/entity_hashes.py` — both must stay in sync. The Rust proxy assigns counters from the per-session `VaultStore`; the sidecar emits placeholder counter `:0`.

### 17 entity types supported

`PERSON`, `ORG`, `LOCATION`, `CO_CEDULA`, `CO_NIT`, `CL_RUT`, `MX_CURP`, `MX_RFC`, `BR_CPF`, `BR_CNPJ`, `AR_DNI`, `ES_NIF`, `PHONE_NUMBER`, `EMAIL_ADDRESS`, `IBAN_CODE`, `DATE_TIME`, `MONEY`.

### Hardware footprint

- Docker image: ~900 MB
- Resident RAM: ~800 MB (CPU inference)
- CUDA: optional (`ARG INSTALL_CUDA=false`)
- Platforms: Apple Silicon, x86_64
- Cold start: 10–30 s (GLiNER + spaCy model load)

### Integration contract

```
AnonymizerService.Anonymize(AnonymizeRequest) -> AnonymizeResponse
```
Spans returned as byte offsets (UTF-8 safe; `offsets.char_to_byte_offset` used throughout). The sidecar fails closed (`UNAVAILABLE`) until models are ready.

---

## 2. openai/privacy-filter — Technical Details

### Architecture

- **Type**: Bidirectional token-classification transformer with constrained Viterbi BIOES span decoding.
- **Parameters**: 1.5B total, ~50M active (sparse MoE, 128 experts, top-4 routing per token).
- **Transformer stack**: 8 blocks, d_model=640, grouped-query attention (14 Q / 2 KV heads, band size 128, window 257 tokens). Supports up to **128k token context**.
- **Output**: 33 classes (8 PII categories × 4 BIOES tags + O background).
- **Inference**: single forward pass — no token-by-token generation.
- **Precision/recall tuning**: runtime transition-bias parameters allow adjusting operating points without retraining.

### Entity categories (8)

| Category | Zemtik equivalent |
|---|---|
| `private_person` | PERSON |
| `private_email` | EMAIL_ADDRESS |
| `private_phone` | PHONE_NUMBER |
| `private_address` | LOCATION |
| `private_date` | DATE_TIME |
| `account_number` | IBAN_CODE *(lossy — see below)* |
| `private_url` | *(no Zemtik type)* |
| `secret` | *(no Zemtik type)* |

**Not covered**: ORG, CO_NIT, CO_CEDULA, CL_RUT, MX_CURP, MX_RFC, BR_CPF, BR_CNPJ, AR_DNI, ES_NIF, MONEY.

### Language support

Primary language: **English**. Multilingual robustness is described as "selected" in the model card — not LATAM-tuned. Non-English, non-Latin text performance is explicitly flagged as a known limitation.

### License

Apache-2.0. Commercial deployment permitted without restrictions.

### Running it

```python
from transformers import pipeline

classifier = pipeline(
    task="token-classification",
    model="openai/privacy-filter",
)
classifier("My name is Alice Smith")
# → [{'entity': 'S-private_person', 'word': ' Alice Smith', ...}]
```

Browser (WebGPU, q4):
```javascript
import { pipeline } from "@huggingface/transformers";
const classifier = await pipeline("token-classification", "openai/privacy-filter", {
    device: "webgpu", dtype: "q4"
});
```

---

## 3. Deployment Feasibility on Consumer Hardware

| Dimension | privacy-filter | Current sidecar |
|---|---|---|
| Model on disk (F32) | ~4 GB | ~800 MB |
| Model on disk (BF16) | ~2 GB | ~800 MB |
| Model on disk (q4) | ~500–600 MB | n/a (no quantized path) |
| Resident RAM (BF16, CPU) | ~2.5–3.5 GB | ~800 MB |
| Resident RAM (q4 / WebGPU) | ~700 MB–1 GB | n/a |
| CPU latency per request | ~80–250 ms (estimated, no published numbers) | ~100–200 ms (GLiNER + Presidio) |
| WebGPU latency per request | <30 ms (per HF demo) | not available |
| Cold start | 5–15 s | 10–30 s |
| Browser deployable | Yes (transformers.js) | No |
| Apple Silicon CPU | Yes | Yes |
| x86_64 CPU | Yes | Yes |
| CUDA GPU | Yes | Yes (optional) |

**Verdict**: Feasible. A developer laptop with 16 GB RAM can run BF16. A pilot-customer VM (4 vCPU / 8 GB) is borderline on BF16 but comfortable with a q4 quantized variant — community q4 builds exist on the Hub. The WebGPU/browser path is a qualitatively new capability: client-side redaction before data leaves the network edge.

---

## 4. Integration Paths

The sidecar's integration contract is model-agnostic: emit byte-offset spans with entity-type codes. Any new recognizer only needs to implement that interface.

### Path 1: Replace GLiNER

Keep Presidio (LATAM regex is precision-critical). Drop GLiNER; use privacy-filter for semantic NER.

- Maps cleanly for: PERSON, EMAIL, PHONE, LOCATION, DATE.
- `account_number` → IBAN_CODE mapping is **lossy** (CO_NIT and BR_CPF are structurally different documents; Presidio regex already handles these more precisely).
- **ORG disappears** — GLiNER currently provides the only ORG detection, and privacy-filter has no ORG class.
- Net result: smaller image, simpler deps, but a capability regression on ORG.

### Path 2: Add as third recognizer (Recommended for evaluation)

Run privacy-filter alongside GLiNER + Presidio. The existing span reconciliation loop in `sidecar/server.py` merges overlapping spans from multiple recognizers already. Privacy-filter would be a new entry in that pipeline, reconciled by byte-offset overlap.

- Zero capability regression.
- Higher recall (especially for `private_url` and `secret`, which no current recognizer handles).
- Adds ~700 MB–2 GB RAM overhead depending on quant.
- Should be gated behind a feature flag: `ZEMTIK_ANONYMIZER_PRIVACY_FILTER_ENABLED`.

### Path 3: Browser-side pre-anonymization

Use transformers.js + WebGPU in the customer's frontend application for a first-pass redaction before the request reaches Zemtik. The gRPC sidecar remains the authoritative, auditable pass. This is belt-and-suspenders: even if the browser model misses an entity, the server-side sidecar catches it.

- Data never leaves the device for initial redaction — a strong privacy story for regulated industries.
- No server RAM impact.
- Requires customer-side JavaScript SDK integration.
- Not a sidecar change — a separate deliverable.

---

## 5. Tradeoffs Summary

### Advantages of privacy-filter

- **128k context window**: GLiNER chunks at ~512 tokens; privacy-filter processes long documents without chunking, reducing boundary-edge misses.
- **Simpler model graph**: one transformer vs. GLiNER + spaCy + Presidio + custom recognizers.
- **Browser deployable**: WebGPU + q4 enables on-device redaction — zero server-side data exposure.
- **Runtime tunable**: transition-bias knobs allow per-tenant precision/recall profiles without retraining (useful for strict vs. lenient anonymization modes).
- **Sustained upstream**: OpenAI maintains it; 21k downloads/month; 15 fine-tuned variants; 2 quantized builds.
- **Apache-2.0**: no license friction.

### Disadvantages / Risks

| Risk | Severity | Notes |
|---|---|---|
| No ORG class | High | Zemtik detects org names for compliance. Dropping GLiNER removes this entirely. |
| No LATAM ID classes | High | `account_number` ≠ CO_NIT / CL_RUT / MX_RFC. Presidio regex must stay regardless. |
| English-primary | High for production | Zemtik pilots are Spanish-language. "Selected multilingual" is not a guarantee. Needs F1 benchmarking on `eval/` corpus before any commitment. |
| Static label policy | Medium | Adding new entity types (e.g., Venezuelan VE_RIF) requires fine-tuning; GLiNER handles arbitrary zero-shot labels. |
| Larger memory footprint | Medium | BF16 doubles RAM vs current sidecar. q4 mitigates but requires testing span accuracy at reduced precision. |
| No published accuracy / latency numbers | Medium | Model card contains no F1 scores or latency benchmarks. All quantitative claims must be validated internally. |
| 8 categories ≠ 17 Zemtik types | Low (additive) | Mapping is lossy only in the replacement scenario. In additive path 2, additional entities are net gain. |

---

## 6. Recommended Next Steps

Before any integration work, validate the following empirically:

1. **Spanish/LATAM F1 benchmark**: run privacy-filter on the existing fixtures in `eval/` and compare per-entity precision/recall against the GLiNER+Presidio pipeline. Pay attention to ORG and LOCATION on Spanish text.
2. **Latency on pilot footprint**: measure p95 latency on a 4 vCPU / 8 GB VM (BF16 and q4 variants) at realistic request rates (~50 rpm).
3. **`account_number` disambiguation**: assess whether a Zemtik-side post-classifier can reliably map privacy-filter's `account_number` spans to CO_NIT / CL_RUT / etc. (regex re-match on extracted span text).
4. **Browser path spike**: prototype `transformers.js` + WebGPU in a sandbox to measure first-load time, per-request latency, and battery impact on a consumer laptop. This is independent of the sidecar and can proceed in parallel.

If benchmark results are satisfactory, integrate via **Path 2** (additive third recognizer) gated behind `ZEMTIK_ANONYMIZER_PRIVACY_FILTER_ENABLED`. No Rust changes needed — the proxy is model-agnostic.

---

## 7. Affected Files (if integration proceeds)

| File | Change |
|---|---|
| `sidecar/recognizers.py` | Add `PrivacyFilterRecognizer` class emitting byte-offset spans |
| `sidecar/server.py` | Register recognizer in pipeline; add feature-flag env var |
| `sidecar/requirements.txt` | Add `transformers>=4.40`, `torch` (already present for GLiNER) |
| `sidecar/entity_hashes.py` | Add codes for `URL` and `SECRET` if those categories are adopted |
| `src/entity_hashes.rs` | Mirror new codes |
| `sidecar/Dockerfile` | Add model pre-download step for `openai/privacy-filter` |
| `eval/privacy_filter/` | New benchmark harness |

**No changes to `src/anonymizer.rs` or `proto/anonymizer.proto`** — the gRPC contract is model-agnostic.
