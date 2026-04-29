# Zemtik Concepts

**Document type:** Conceptual Reference
**Audience:** Anyone who wants to understand how zemtik works before reading the feature documentation
**Goal:** Define the key abstractions clearly and honestly, including v1 limitations

---

## Pseudonymization vs Anonymization

These terms are often used interchangeably in practice, but they have distinct legal meanings.

**Anonymization** (GDPR Recital 26) is an irreversible process. After true anonymization, re-identifying an individual from the data is not reasonably possible by any party, including the organization that performed the anonymization. Truly anonymized data falls outside GDPR's scope.

**Pseudonymization** replaces identifying information with a substitute (a "pseudonym" or token) while retaining a mapping that can reverse the substitution. The data can be re-identified using that mapping. Pseudonymized data is still personal data under GDPR and equivalent laws.

**Zemtik performs pseudonymization, not legal anonymization.** The in-memory vault holds the mapping between original values and tokens. Anyone with access to the vault — or to the zemtik process memory — can reverse the substitution. This is intentional: zemtik needs to restore original values in AI responses before returning them to the user. It means data processed by zemtik remains personal data under GDPR Recital 26 and equivalent provisions in LGPD, Ley 1581, LFPDPPP, and Ley 25.326.

For compliance implications, see [docs/COMPLIANCE_LATAM.md](./COMPLIANCE_LATAM.md).

---

## Token Format

Each detected entity is replaced with a structured token:

```
[[Z:{type_hash}:{counter}]]
```

| Component | Meaning |
|-----------|---------|
| `[[Z:` and `]]` | Fixed delimiters. Double brackets survive LLM summarization verbatim in most instruction-following models. |
| `type_hash` | 4-character hex code derived from `SHA-256(entity_type)[0..2]`. Encodes the entity category. See table below. |
| `counter` | Per-session monotonic integer starting at 1. The same entity within one session always gets the same counter, so the LLM sees consistent references. |

**Same entity, same session → same token.** If "Carlos García" appears three times in one request, all three occurrences become `[[Z:e47f:1]]`.

**New session → new token.** After the vault is evicted (TTL default 300s) or the process restarts, a new session assigns different counter values. There is no cross-session continuity.

### All 23 Entity Types and Their Hashes

| Entity Type | Type hash | Example token |
|------------|-----------|---------------|
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
| `PASSPORT` | `02bc` | `[[Z:02bc:1]]` |

Hashes are derived from `hex(SHA256(entity_type)[0..2])` and are hardcoded in `src/entity_hashes.rs`. The Python sidecar uses the same values in `sidecar/entity_hashes.py`. Both files must be updated together when a new entity type is added.

**Default entity set (21 types, as of v1):** All types above except `PHONE_NUMBER` and `EMAIL_ADDRESS`. To include them, set `ZEMTIK_ANONYMIZER_ENTITY_TYPES` explicitly.

---

## The Five Lanes

Every request to zemtik is routed to one of five lanes based on intent classification and configuration. Here is each lane and its current v1 status.

### 1. FastLane

**What it does:** Runs a database aggregate (SUM or COUNT) against the matched table, signs the result with a BabyJubJub EdDSA key, and packages the result into an Evidence Pack. No zero-knowledge proof is generated.

**When it runs:** When the matched table's `sensitivity` in `schema_config.json` is set to `"low"`.

**v1 status: Shipped.** Fully operational for both SQLite and Supabase backends.

### 2. ZK SlowLane

**What it does:** Generates transaction witnesses, runs the Noir mini-circuit (SUM or COUNT) with Poseidon commitments and EdDSA batch signing, and produces an UltraHonk proof via Barretenberg (`bb`). The proof is verified locally before the aggregate is forwarded to the AI model.

**When it runs:** When the matched table's `sensitivity` is set to `"critical"`.

**v1 status: Partial.** The witness generation and circuit execution pipeline is implemented. Proof generation via `bb prove` does not complete in the current upstream Barretenberg version — this is a blocker tracked in the issue backlog. Witnesses are generated but final proof output is not produced. Use FastLane for production deployments until this is resolved.

> **Compliance note:** FastLane receipts are BabyJubJub digital signatures, not zero-knowledge proofs. If your regulatory requirement or contractual commitment specifies zero-knowledge proofs for data aggregation, the ZK SlowLane must be fully functional — FastLane does not satisfy that requirement in v1.

### 3. Tunnel

**What it does:** Forwards every request to the AI provider untouched (FORK 1) while simultaneously running ZK verification in the background (FORK 2). Writes a comparison audit record to `tunnel_audit.db` with a `TunnelMatchStatus` indicating whether zemtik's computation agreed with the model's response. No customer request or response is modified.

**When it runs:** When `ZEMTIK_MODE=tunnel` is set.

**v1 status: Shipped.** Six match status variants: `Matched`, `Diverged`, `Unmatched`, `Error`, `Timeout`, `Backpressure`.

### 4. MCP

**What it does:** Acts as an attestation proxy between Claude Desktop (or another MCP client) and tool calls. Every tool call is signed with BabyJubJub EdDSA and written to `mcp_audit.db`. Supports `zemtik_read_file`, `zemtik_fetch`, `zemtik_analyze`, and custom tools loaded from `mcp_tools.json`.

**When it runs:** When launched as `zemtik mcp` (stdio) or `zemtik mcp-serve` (HTTP).

**v1 status: Shipped.** Limitation: MCP tool-result anonymization (scanning AI tool results for PII before returning to Claude) is not implemented in v1 and is planned for Phase 2.

### 5. General Passthrough

**What it does:** Forwards non-data queries — requests that do not match any table in `schema_config.json` — to the AI model with a receipt and `zemtik_meta` block. Returns HTTP 400 when disabled (default behavior).

**When it runs:** When `ZEMTIK_GENERAL_PASSTHROUGH=1` is set and intent classification does not identify a data table.

**v1 status: Shipped.** Rate-limitable via `ZEMTIK_GENERAL_MAX_RPM`.

---

## Vault Lifecycle

The vault is the in-memory data structure that maps tokens back to original entity values within a single request.

```
Request arrives
    │
    ▼
ZEMTIK_ANONYMIZER_ENABLED=true?
    │
    ├─ No → request forwarded without tokenization
    │
    └─ Yes → fresh vault created for this request
                │
                ▼
            Entity detection (sidecar or regex fallback)
                │
                ▼
            Entities tokenized → vault stores:
              (original_text, token, entity_type, session_id, created_at)
                │
                ▼
            Tokenized prompt forwarded to AI model
                │
                ▼
            AI model response returned
                │
                ▼
            De-tokenization: tokens in response replaced with originals
                │
                ▼
            Response returned to client
                │
                ▼
            scopeguard::defer! clears vault immediately after response
                │
                ▼
            Background TTL eviction: any vault older than
            ZEMTIK_ANONYMIZER_VAULT_TTL_SECS (default 300s) is purged
```

**Important v1 limitations:**

- The vault exists for one request only. Tokens from turn N are not available in turn N+1. Multi-turn vault persistence is planned for Phase 2.
- Zemtik de-tokenizes AI responses in the proxy path. In the MCP path, AI tool results are not currently scanned for tokens to restore. This is a known gap (Phase 2).
- The vault is never written to disk in v1. A process restart loses all vault state.

---

## Sidecar vs Regex Fallback Decision Tree

```
ZEMTIK_ANONYMIZER_ENABLED=true?
    │
    ├─ No  → passthrough (no tokenization; request forwarded as-is)
    │
    └─ Yes → try gRPC call to sidecar at ZEMTIK_ANONYMIZER_SIDECAR_ADDR
                 (default http://127.0.0.1:50051; timeout: ZEMTIK_ANONYMIZER_SIDECAR_TIMEOUT_MS)
                  │
                  ├─ Sidecar responds (status: SERVING)
                  │     → use entity spans from sidecar
                  │       (all 23 entity types; full GLiNER + Presidio detection)
                  │
                  └─ Sidecar unreachable or timed out
                        │
                        ├─ ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true
                        │     → regex fallback runs in-process (Rust)
                        │       covers: CO_CEDULA, CO_NIT, CL_RUT, MX_CURP, MX_RFC,
                        │               BR_CPF, BR_CNPJ, AR_DNI, ES_NIF, PHONE_NUMBER,
                        │               EMAIL_ADDRESS, IBAN_CODE, DATE_TIME, MONEY,
                        │               EC_RUC, PE_RUC, BO_NIT, UY_CI, VE_CI
                        │       does NOT cover: PERSON, ORG, LOCATION, PASSPORT
                        │       zemtik_meta.anonymizer.sidecar_used → false
                        │
                        └─ ZEMTIK_ANONYMIZER_FALLBACK_REGEX=false  (recommended for production)
                              → HTTP 503 returned immediately
                                request NOT forwarded to AI model
                                no PII passes through
```

**Production recommendation:** Set `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=false` so that a sidecar outage causes a visible failure rather than silent degradation to partial-coverage detection. The regex fallback is useful in development and for deployments where structured IDs are the only concern.

---

*For entity type details, regex pattern coverage, and detection accuracy notes, see [docs/ANONYMIZER.md](./ANONYMIZER.md). For compliance implications of pseudonymization, see [docs/COMPLIANCE_LATAM.md](./COMPLIANCE_LATAM.md). For Evidence Pack cryptographic details, see [docs/EVIDENCE_PACK_AUDITOR_GUIDE.md](./EVIDENCE_PACK_AUDITOR_GUIDE.md).*
