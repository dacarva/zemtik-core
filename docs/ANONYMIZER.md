# Anonymizer v1

**Document type:** Guide + Reference
**Audience:** Developers integrating Zemtik's PII anonymization into LLM pipelines
**Goal:** Enable zero-PII LLM calls without changing client code

---

## Quick Start

### 1. Start the sidecar and proxy

```bash
export OPENAI_API_KEY=sk-...
export ZEMTIK_ANONYMIZER_ENABLED=true

# Start the full stack (sidecar + proxy)
docker compose --profile anonymizer up --build
```

Wait for the `anonymizer` service to report `healthy` (~30s — GLiNER model load).

### 2. Preview anonymization (no LLM call)

```bash
curl -X POST http://localhost:4000/v1/anonymize/preview \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{
      "role": "user",
      "content": "El contrato de la empresa ACME fue firmado por Carlos García, titular de la cédula 79.123.456"
    }]
  }'
```

Expected response (with default `ZEMTIK_ANONYMIZER_ENTITY_TYPES=PERSON,ORG,LOCATION`):

```json
{
  "anonymized_messages": [
    {"role": "user", "content": "El contrato de la empresa [[Z:0e67:1]] fue firmado por [[Z:e47f:2]], titular de la cédula 79.123.456"}
  ],
  "tokens":    ["[[Z:0e67:1]]", "[[Z:e47f:2]]"],
  "originals": ["ACME", "Carlos García"],
  "entities_found": 2,
  "entity_types": ["ORG", "PERSON"],
  "sidecar_used": true,
  "sidecar_ms": 42
}
```

`tokens`, `originals`, and `entity_types` are parallel arrays with identical length and ordering — consumers can zip them to reconstruct `(original, token, type)` triples.

> **Note:** With the default entity types, `79.123.456` (Colombian cédula) is not anonymized.
> To include LATAM structured IDs, add them to `ZEMTIK_ANONYMIZER_ENTITY_TYPES`:
> ```bash
> export ZEMTIK_ANONYMIZER_ENTITY_TYPES="PERSON,ORG,LOCATION,CO_CEDULA"
> ```
> This would produce `entities_found: 3` with `[[Z:5b46:1]]` for the cédula.

### 3. Full E2E (with LLM)

```bash
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "Analiza el riesgo del contrato entre Carlos García y ACME S.A.S."}]
  }'
```

The response will contain the original names (`Carlos García`, `ACME S.A.S.`) restored from the vault — the LLM only ever saw the tokens.

Check `zemtik_meta.anonymizer` in the response body:

```json
{
  "zemtik_meta": {
    "anonymizer": {
      "entities_found": 2,
      "entity_types": ["PERSON", "ORG"],
      "sidecar_used": true,
      "sidecar_ms": 38,
      "dropped_tokens": 0
    }
  }
}
```

> **Single-turn vault:** The vault that maps tokens back to original values is cleared after each request via `scopeguard::defer!`. Tokens assigned in one turn are NOT available in the next — each request starts with a fresh vault. Multi-turn vault persistence is planned for Phase 2-3.

> ⚠️ **Sidecar fallback indicator:** If `sidecar_used: false` appears in `zemtik_meta.anonymizer`, the sidecar was unreachable and only regex patterns were active. PERSON, ORG, and LOCATION detection requires the sidecar — structured IDs (emails, phone numbers, LATAM IDs) still work via the regex fallback, but named entity recognition is disabled.

### Sidecar address — local dev vs Docker Compose

| Deployment | `ZEMTIK_ANONYMIZER_SIDECAR_ADDR` |
|------------|----------------------------------|
| Local dev (sidecar started manually with `docker run`) | `http://127.0.0.1:50051` |
| Docker Compose (`--profile anonymizer`) | `http://sidecar:50051` (set automatically in `docker-compose.yml`) |

When running both services inside Docker Compose, the proxy resolves `sidecar` via Docker's internal DNS. For local dev where only the sidecar container is running, use `127.0.0.1`.

### 4. Regex-only mode (no sidecar)

For LATAM structured IDs without the sidecar:

```bash
export ZEMTIK_ANONYMIZER_ENABLED=true
export ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true
# Do NOT start the sidecar
cargo run -- proxy
```

PERSON/ORG/LOCATION detection requires the sidecar. Regex mode only covers structured IDs (CO_CEDULA, BR_CPF, etc.).

---

## Architecture

The anonymizer pipeline uses two detection backends:

- **Sidecar (gRPC, port 50051):** Python service running GLiNER (`urchade/gliner_multi_pii-v1`) for named entity recognition plus Presidio `PatternRecognizer` plugins for structured PII. Handles `PERSON`, `ORG`, `LOCATION`, and supplementary Presidio patterns.
- **Regex fast-path (Rust process):** Static patterns compiled at startup. Handles structured IDs (CO_CEDULA, BR_CPF, etc.), emails, phone numbers, and IBAN codes. Active even when the sidecar is down and `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true`.

---

## Entity Types

Zemtik v1 supports 22 entity types across two detection backends. 15 are enabled by default; `PHONE_NUMBER`, `EMAIL_ADDRESS`, `EC_RUC`, `PE_RUC`, `BO_NIT`, `UY_CI`, and `VE_CI` are supported but excluded from the default set (set `ZEMTIK_ANONYMIZER_ENTITY_TYPES` explicitly to include them).

### Sidecar-detected (GLiNER + Presidio)

These require the Python sidecar to be running.

| Entity Type | Description | Example |
|-------------|-------------|---------|
| `PERSON` | Personal names | `Carlos García`, `María Pérez` |
| `ORG` | Organizations and companies | `ACME S.A.S.`, `Banco de Bogotá` |
| `LOCATION` | Locations, addresses, places | `Bogotá D.C.`, `Calle 72 # 10-34` |

### Regex fast-path (no sidecar required)

These are detected by the Rust process itself via regex patterns. Available even when the sidecar is down and `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true`.

| Entity Type | Description | Pattern examples | Coverage notes (Rust fallback) |
|-------------|-------------|-----------------|-------------------------------|
| `CO_CEDULA` | Colombian national ID | `79.123.456`, `CC 12345678` | Dotted format (`79.123.456`) OR keyword prefix (`Cédula`, `CC`, `C.C.`) required. Plain 8–10 digit runs without keyword context are not matched to avoid false positives on invoice numbers. Presidio patterns in the sidecar cover plain formats in context. |
| `CO_NIT` | Colombian tax ID (NIT) | `900.123.456-7` | Full dotted-plus-check-digit format only. |
| `CL_RUT` | Chilean tax ID (RUT) | `12.345.678-9`, `12345678-K` | Dotted or bare with hyphen separator. |
| `MX_CURP` | Mexican unique population registry code | `BADD110313HCMLNS09` | Full 18-character alphanumeric structure. |
| `MX_RFC` | Mexican tax ID (RFC) | `XAXX010101000` | 12–13 character alphanumeric structure. |
| `BR_CPF` | Brazilian individual tax ID | `000.000.000-00` | Dotted format with hyphen only. |
| `BR_CNPJ` | Brazilian company tax ID | `00.000.000/0000-00` | Full structured format only. |
| `AR_DNI` | Argentine national ID | `12.345.678` | Dotted format only (`12.345.678`). Plain 8-digit runs are not matched — they overlap with phone numbers and Colombian cédulas. |
| `ES_NIF` | Spanish national ID / NIE | `12345678A`, `X1234567A` | Letters I, O, U excluded per DNI/NIE spec. |
| `PHONE_NUMBER` | Phone numbers (international or formatted) | `+57 300 123 4567`, `(601) 234-5678` | Requires international prefix (`+`) or separator characters; bare 10-digit runs are not matched. |
| `EMAIL_ADDRESS` | Email addresses | `user@example.com` | Standard RFC 5321 structure. |
| `IBAN_CODE` | IBAN bank account numbers | `ES9121000418450200051332` | 2-letter country code + 2 check digits + up to 30 alphanumerics. |
| `DATE_TIME` | Dates and times (regex-based; GLiNER may also detect) | `2024-01-15`, `15/01/2024` | ISO 8601 and slash-separated formats. |
| `MONEY` | Monetary amounts | `$12.500.000 COP`, `USD 500,000` | Currency symbol or code required. |
| `EC_RUC` | Ecuadorian RUC tax ID | `1234567890001` | 13-digit format. |
| `PE_RUC` | Peruvian RUC tax ID | `20123456789` | 11-digit format. |
| `BO_NIT` | Bolivian NIT tax ID | `1234567` | 7-digit format. |
| `UY_CI` | Uruguayan cédula de identidad | `1.234.567-8` | Dotted format with check digit. |
| `VE_CI` | Venezuelan cédula de identidad | `V-12345678` | Prefix V/E with 7–8 digits. |

> **Detection quality:** Tokenization accuracy depends on GLiNER entity boundary precision. Compound organizational names (e.g. `"Andina de Inversiones y Capital S.A.S."`), abbreviated identifiers, and code-switched text may be partially tokenized — the un-tokenized portion reaches the LLM in plaintext. Verify output via `POST /v1/anonymize/preview` before relying on the anonymizer in regulated environments.

### Configuring entity types

```bash
# Default: 15-type set
export ZEMTIK_ANONYMIZER_ENTITY_TYPES="PERSON,ORG,LOCATION,CO_NIT,CO_CEDULA,AR_DNI,CL_RUT,BR_CPF,BR_CNPJ,MX_CURP,MX_RFC,ES_NIF,IBAN_CODE,DATE_TIME,MONEY"

# Extended: add LatAm IDs (EC_RUC, PE_RUC, BO_NIT, UY_CI, VE_CI) + contact types
export ZEMTIK_ANONYMIZER_ENTITY_TYPES="PERSON,ORG,LOCATION,CO_NIT,CO_CEDULA,AR_DNI,CL_RUT,BR_CPF,BR_CNPJ,MX_CURP,MX_RFC,ES_NIF,IBAN_CODE,DATE_TIME,MONEY,EC_RUC,PE_RUC,BO_NIT,UY_CI,VE_CI"

# Include all 22 types:
export ZEMTIK_ANONYMIZER_ENTITY_TYPES="PERSON,ORG,LOCATION,CO_NIT,CO_CEDULA,AR_DNI,CL_RUT,BR_CPF,BR_CNPJ,MX_CURP,MX_RFC,ES_NIF,IBAN_CODE,DATE_TIME,MONEY,EC_RUC,PE_RUC,BO_NIT,UY_CI,VE_CI,PHONE_NUMBER,EMAIL_ADDRESS"
```

### Token format

Each detected entity is replaced with an opaque token:

```text
[[Z:{type_hash}:{counter}]]
```

- `[[Z:` / `]]` — double brackets survive LLM summarization verbatim
- `type_hash` — 4-hex canonical hash: `hex(SHA256(entity_type.as_bytes())[0..2])`
- `counter` — session-scoped integer; same entity always maps to the same counter

| Entity Type | Token hash | Example token |
|-------------|-----------|---------------|
| `PERSON` | `e47f` | `[[Z:e47f:1]]` |
| `ORG` | `0e67` | `[[Z:0e67:1]]` |
| `LOCATION` | `ec4e` | `[[Z:ec4e:1]]` |
| `CO_CEDULA` | `5b46` | `[[Z:5b46:1]]` |
| `CO_NIT` | `bba1` | `[[Z:bba1:1]]` |
| `CL_RUT` | `fe8c` | `[[Z:fe8c:1]]` |
| `MX_CURP` | `87fb` | `[[Z:87fb:1]]` |
| `MX_RFC` | `95d9` | `[[Z:95d9:1]]` |
| `BR_CPF` | `d8f7` | `[[Z:d8f7:1]]` |
| `BR_CNPJ` | `3834` | `[[Z:3834:1]]` |
| `AR_DNI` | `f76d` | `[[Z:f76d:1]]` |
| `ES_NIF` | `fc3d` | `[[Z:fc3d:1]]` |
| `PHONE_NUMBER` | `ca71` | `[[Z:ca71:1]]` |
| `EMAIL_ADDRESS` | `a8d8` | `[[Z:a8d8:1]]` |
| `IBAN_CODE` | `3f21` | `[[Z:3f21:1]]` |
| `DATE_TIME` | `322b` | `[[Z:322b:1]]` |
| `MONEY` | `ed2f` | `[[Z:ed2f:1]]` |
| `EC_RUC` | `20ab` | `[[Z:20ab:1]]` |
| `PE_RUC` | `124a` | `[[Z:124a:1]]` |
| `BO_NIT` | `5121` | `[[Z:5121:1]]` |
| `UY_CI` | `7f8a` | `[[Z:7f8a:1]]` |
| `VE_CI` | `e41a` | `[[Z:e41a:1]]` |

> **Hash consistency:** Hashes are derived from `SHA256(entity_type)[0..2]` (first 2 bytes as hex). They are hardcoded in `src/entity_hashes.rs` and `sidecar/zemtik_entity_hashes.py` — both files must be updated together if a new entity type is added.

Verify cross-layer hash parity (Rust ↔ Python):

```bash
# Rust
cargo run --bin zemtik -- anonymizer hashes

# Python
cd sidecar && python -c "from entity_hashes import print_canonical_hashes; print_canonical_hashes()"

# Diff must be zero bytes
```

---

## Privacy Guarantees v1

### What never leaves the Zemtik process in plaintext

- Original entity text (names, IDs, addresses)
- Session vault mapping tokens back to originals
- Outgoing prompt content (only sanitized tokens are forwarded to OpenAI)

### What is logged

- `zemtik_meta.anonymizer` in the response body and `X-Zemtik-Meta` header: entity counts, types, sidecar usage, dropped token count, and optionally a 200-character preview of the outgoing (sanitized) prompt if `ZEMTIK_ANONYMIZER_DEBUG_PREVIEW=true`
- Audit spans in the `audit/` directory: byte offsets of each detected entity per message (no original text, only offsets and type)

### Vault lifecycle

1. A fresh vault is created at the start of each request (remove-after-turn)
2. The vault is stored in process memory under `std::sync::Mutex` — never written to disk in v1
3. `scopeguard::defer!` ensures the vault is removed even if the LLM call panics
4. Background TTL eviction runs every 60 seconds; vaults older than `ZEMTIK_ANONYMIZER_VAULT_TTL_SECS` (default 300s) are purged

> **Single-turn limitation:** The vault persists for the duration of a single request only. Tokens from turn N are NOT reused in turn N+1 — each request starts with a fresh vault. This means multi-turn conversations where the LLM response in turn N contains tokens that need re-anonymization in turn N+1 are not covered in v1. Multi-turn vault persistence is planned for Phase 2-3.

### System prompt injection

The proxy automatically appends a system message to every request when the anonymizer is enabled:

```
This text contains privacy tokens in the format [[Z:xxxx:n]].
Preserve every token exactly — do not expand, paraphrase, split, or omit them.
Treat them as opaque identifiers.
```

This instructs the LLM to return tokens verbatim so deanonymization can succeed. If the LLM paraphrases or omits a token, `dropped_tokens` in `zemtik_meta.anonymizer` will be greater than 0. Consistently high `dropped_tokens` indicates the model is not following the instruction — consider switching to a stronger instruction-following model via `ZEMTIK_OPENAI_MODEL`.

### What "fail-closed" means

When `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=false` and the sidecar is unreachable:

- Zemtik returns HTTP 503 immediately
- The request is **not** forwarded to OpenAI
- No PII passes through in plaintext

### Limitations

See the [Compatibility matrix](#compatibility-matrix-known-limitations) below.

---

## `zemtik_meta.anonymizer` Block

Every response from the proxy includes a `zemtik_meta` object when anonymizer is enabled. The `anonymizer` sub-block has the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `entities_found` | integer | Total number of entity spans detected and tokenized across all messages (user and assistant) |
| `entity_types` | string[] | Deduplicated list of entity types detected (e.g. `["PERSON", "ORG"]`) |
| `sidecar_used` | boolean | `true` if the gRPC sidecar ran; `false` if regex-only fallback was used |
| `sidecar_ms` | integer | Wall-clock milliseconds for the gRPC anonymization call. `0` if sidecar was not used. |
| `dropped_tokens` | integer | Count of tokens in the vault that do NOT appear in the LLM response. Non-zero means the LLM paraphrased or omitted some anonymized entities instead of preserving the token verbatim. |
| `outgoing_preview` | string \| null | First 200 characters of the sanitized outgoing prompt (tokens only, no originals). Present only when `ZEMTIK_ANONYMIZER_DEBUG_PREVIEW=true` and `sidecar_used=true`. **Disable in production.** |

### Example

```json
{
  "id": "chatcmpl-...",
  "choices": [...],
  "zemtik_meta": {
    "engine_used": "general_lane",
    "receipt_id": "...",
    "anonymizer": {
      "entities_found": 3,
      "entity_types": ["PERSON", "ORG", "CO_CEDULA"],
      "sidecar_used": true,
      "sidecar_ms": 41,
      "dropped_tokens": 0,
      "outgoing_preview": "El contrato de la empresa [[Z:0e67:1]] fue firmado por [[Z:e47f:1]], titular de la cédula [[Z:5b46:1]]"
    }
  }
}
```

### Monitoring `dropped_tokens`

A `dropped_tokens` value greater than 0 means the LLM did not preserve one or more opaque tokens in its response. This can happen when:

- The LLM paraphrases or summarizes instead of preserving the token
- Long context truncation removes the token before the generation step
- The model is not instruction-following enough for token preservation

Mitigation: the system prompt injected by Zemtik instructs the model to treat tokens as opaque identifiers. If `dropped_tokens` is consistently high, consider using a stronger model via `ZEMTIK_OPENAI_MODEL`.

---

## Compatibility Matrix (Known Limitations)

| Feature | Status | Notes |
|---------|--------|-------|
| `stream: false` | ✅ Supported | Full anonymize → LLM → deanonymize pipeline |
| `stream: true` | ❌ Not supported | Returns HTTP 415. Buffer + re-stream deferred to Phase 3. |
| JSON mode (`response_format: json_object`) | ⚠️ Partial | Anonymization works; deanonymization runs on the raw JSON string — tokens preserved in string values are restored, but schema structure is not interpreted. |
| Tool use / function calling | ⚠️ Partial | Anonymization runs on message content before routing. Tool call arguments and tool results are not anonymized. |
| Structured outputs (`response_format: json_schema`) | ⚠️ Partial | Same as JSON mode — token restoration runs on raw output string. |
| Multi-turn conversations | ✅ Supported | All user-role messages are anonymized in a single gRPC batch per request. Each turn creates a fresh vault. |
| Tunnel mode | ✅ Skip (by design) | The anonymizer pipeline is skipped in tunnel mode — FORK 2 verification needs the original, unmodified text to diff against. The `/v1/anonymize/preview` endpoint remains available in tunnel mode for inspection purposes. |
| FastLane (low sensitivity tables) | ✅ Supported | Deanonymization runs on the FastLane response body before envelope. |
| ZK SlowLane (critical sensitivity tables) | ✅ Supported | Deanonymization runs on the ZK SlowLane response body before envelope. |
| General Passthrough lane | ✅ Supported | Deanonymization and `zemtik_meta.anonymizer` block present on general lane responses. |
| MCP tool-result anonymization | 🚧 Phase 2 | `handle_fetch` and `handle_read_file` hooks deferred. |
| Vault persistence (cross-restart) | 🚧 Phase 2 | Vault is in-memory only in v1. Planned: `receipts.db` + AES-256-GCM. |

---

## Operator Monitoring

### Sidecar status via `/health`

`GET /health` always includes an `anonymizer` block. Use it to confirm the sidecar is reachable before sending traffic.

When the anonymizer is disabled (default):

```json
{
  "anonymizer": {
    "enabled": false,
    "sidecar_status": "disabled"
  }
}
```

When the anonymizer is enabled and the sidecar is ready:

```json
{
  "anonymizer": {
    "enabled": true,
    "sidecar_addr": "http://sidecar:50051",
    "sidecar_status": "serving",
    "probe_latency_ms": 23
  }
}
```

`sidecar_status` values:

| Value | Meaning |
|---|---|
| `"serving"` | gRPC health check passed; sidecar is ready |
| `"not_serving"` | Sidecar is running but reports NOT_SERVING (model still loading) |
| `"unreachable"` | Could not connect or probe timed out (> 500 ms); regex fallback is active |
| `"disabled"` | `ZEMTIK_ANONYMIZER_ENABLED=false` — no probe was run |

The HTTP status code of `/health` is not affected by sidecar state — it remains `200` as long as the database is up. An `unreachable` sidecar degrades detection to regex-only mode but does not take the proxy offline.

---

## Troubleshooting

### Sidecar won't start

**Symptom:** `docker compose ps` shows `anonymizer` as `starting` or `unhealthy` for more than 60s.

```bash
# View sidecar logs
docker compose logs anonymizer --tail=50

# Check health directly
docker compose exec anonymizer grpc-health-probe -addr=localhost:50051
```

**Healthcheck timing:** The sidecar container has a `start_period: 60s` before Docker begins counting healthcheck failures. During this window the container shows `starting` — this is expected. The sidecar server starts immediately but transitions from `NOT_SERVING` to `SERVING` only after GLiNER finishes loading (~10–30s). `healthy` means the gRPC health check returned `SERVING` — it is not sufficient for the container to be "running".

If the sidecar is still `unhealthy` after 60s, the GLiNER model may be missing. GLiNER is baked into the image at build time (`docker compose --build`). If the image was built without internet access, the model will not be present.

### HTTP 503 — `SidecarUnreachable`

The proxy cannot connect to the sidecar. Check:

1. Is the sidecar running? `docker compose ps anonymizer`
2. Is `ZEMTIK_ANONYMIZER_SIDECAR_ADDR` correct? Default: `http://sidecar:50051` in Docker Compose, `http://127.0.0.1:50051` for local dev.
3. Is the sidecar port exposed? Check `docker-compose.yml` — port `50051` must not be firewalled between containers.

**Workaround:** Set `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true` to allow regex-only mode when the sidecar is unavailable. Note: PERSON/ORG/LOCATION will not be detected.

### HTTP 503 — `SidecarStarting`

The sidecar is running but GLiNER has not finished loading. This typically happens within the first 30s of startup.

```bash
# Wait for healthy status
docker compose ps anonymizer
# STATUS column should show "healthy" before sending requests
```

### HTTP 415 — `anonymizer_streaming_unsupported`

Streaming requests (`stream: true`) are not supported when the anonymizer is enabled. Set `stream: false` in your request body, or disable the anonymizer for streaming use cases.

### `dropped_tokens` > 0

The LLM did not return one or more tokens verbatim. Check:

1. Is the model following the system prompt? Try `gpt-5.4-nano` (default) or a stronger instruction-following model.
2. Is the response long enough for the LLM to include all tokens? Very short responses may truncate context.
3. Is `ZEMTIK_ANONYMIZER_DEBUG_PREVIEW=true` set? Enable it to see the sanitized outgoing prompt and verify tokens were included correctly.

### Hash parity mismatch (Rust ↔ Python)

```bash
cargo run --bin zemtik -- anonymizer hashes
cd sidecar && python -c "from entity_hashes import print_canonical_hashes; print_canonical_hashes()"
```

If hashes differ, check that `src/entity_hashes.rs` and `sidecar/entity_hashes.py` were generated from the same source (`SHA256(entity_type.encode('utf-8'))[:2].hex()`). Do not manually edit either file — regenerate from the canonical test.

### Byte offset errors (accented characters)

If entity spans are off for names like `José`, `García`, or `Peña`, the sidecar may be using char offsets instead of byte offsets. Run the offset test:

```bash
cd sidecar && python -m pytest tests/test_byte_offsets.py -v
```

The test verifies that `"José García"` produces correct UTF-8 byte offsets. All entity spans in the gRPC response must use byte offsets (not Unicode char offsets) because Rust string slicing operates on bytes.

### Sidecar timeout

If requests are failing with `SidecarTimeout`, increase the timeout:

```bash
export ZEMTIK_ANONYMIZER_SIDECAR_TIMEOUT_MS=3000  # default 1500ms
```

For long documents (>2000 tokens), the sidecar may need more time. Monitor `sidecar_ms` in `zemtik_meta.anonymizer` to determine the baseline.
