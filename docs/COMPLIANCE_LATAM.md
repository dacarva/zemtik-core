# Compliance Reference — LATAM and EU Data Protection Mapping

**Document type:** Audit Evidence Reference
**Audience:** DPOs, legal counsel, external auditors performing regulatory due diligence on a zemtik deployment
**Goal:** Map zemtik's technical controls to data protection obligations; identify gaps; provide a DPIA starter kit

---

## What This Document Covers

This document maps zemtik's privacy architecture against GDPR, LGPD (Brazil), Ley 1581/Decreto 1377/2013 (Colombia), LFPDPPP (Mexico), and Ley 25.326 (Argentina). It is intended to supplement, not replace, legal advice. All compliance gaps identified here are tracked in the project issue backlog.

For non-technical context, read [docs/FOR_LEGAL.md](./FOR_LEGAL.md) first.

---

## Deployment Role Matrix

In all deployment modes, the organization running zemtik is the **data controller**. The zemtik-core software, as deployed, acts as the **data processor** on the controller's behalf. OpenAI and Anthropic are **sub-processors**.

| Deployment mode | Data controller | Data processor | Sub-processor(s) |
|-----------------|----------------|---------------|-----------------|
| Proxy (`zemtik proxy`) | Organization running zemtik | zemtik-core process on the controller's infrastructure | OpenAI, Inc. and/or Anthropic, PBC (depending on `ZEMTIK_LLM_PROVIDER`) |
| Tunnel (`ZEMTIK_MODE=tunnel`) | Organization running zemtik | zemtik-core process on the controller's infrastructure | OpenAI, Inc. (FORK 1 passthrough; FORK 2 verification also contacts OpenAI) |
| MCP stdio (`zemtik mcp`) | Organization running zemtik | zemtik-core process on the controller's infrastructure | OpenAI, Inc. or Anthropic, PBC (via Claude Desktop) |
| MCP HTTP (`zemtik mcp-serve`) | Organization running zemtik | zemtik-core process on the controller's infrastructure | OpenAI, Inc. or Anthropic, PBC (via HTTP integrations) |

**Note on zemtik the company:** zemtik-core is open-source software that the controller self-hosts. In a standard self-hosted deployment, zemtik the company does not receive personal data from the controller's deployment. If the controller uses a cloud-hosted zemtik service, the contractual relationship with zemtik the company must be governed by a separate DPA.

---

## Token Re-Identification Risk

Zemtik performs pseudonymization. The vault that maps tokens back to original values is held in memory. This section quantifies the residual re-identification risk.

**Token structure:** `[[Z:{type_hash}:{counter}]]`

- `type_hash`: 4 hexadecimal characters = 16 bits = 65,536 distinct values per entity type. This value encodes the entity category (PERSON, ORG, CO_CEDULA, etc.) and is not secret — the mapping is published in `src/entity_hashes.rs` and this documentation.
- `counter`: per-session monotonic integer starting at 1. Resets on vault eviction (TTL default 300 seconds) and on process restart. Not secret.

**Within-session consistency:** The same entity within a single session always receives the same token. This is intentional — it allows the AI model to use the token consistently in its response.

**Cross-session isolation:** The same entity in a new session (after vault eviction or restart) receives a *different* token. The vault is in-memory only; it is not persisted to disk in this version.

**Audit preview risk:** The `preview_input` and `preview_output` columns in `mcp_audit.db` store the first 500 characters of tool input and output. These previews contain tokenized text (`[[Z:xxxx:n]]`) but not original PII — as long as the anonymizer ran successfully. If the anonymizer was disabled or the sidecar was unreachable with `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true`, previews may contain structured IDs that were tokenized by the regex fallback, but named entities (PERSON, ORG, LOCATION) will appear in plaintext.

**Residual risk:** Within a single session, frequency and positional analysis of tokens in audit previews could correlate entities across calls. For example, `[[Z:e47f:1]]` appearing consistently in the same role across multiple tool calls indicates a single person is referenced repeatedly. The original name is not stored in the audit DB, but the structural pattern may be informative to a motivated adversary with access to other contextual data.

---

## GDPR Control Mapping

| Article | Obligation | Zemtik capability | Remaining gap |
|---------|-----------|------------------|---------------|
| Art. 5(1)(c) Data minimization | Only data necessary for the purpose should be processed | Default entity set covers 21 types; PHONE_NUMBER and EMAIL_ADDRESS excluded from default | Operator should evaluate whether PHONE_NUMBER and EMAIL_ADDRESS are needed; exclusion from default is tracked in issue backlog |
| Art. 5(1)(e) Storage limitation | Data should not be kept longer than necessary | Vault TTL 300s (configurable). Audit DBs: **no automatic expiry** | Operator must implement manual pruning; automated retention is a known gap tracked in issue backlog |
| Art. 6 Lawful basis | Processing must have a documented lawful basis | Zemtik does not establish or verify lawful basis | Controller must establish lawful basis independently before deploying |
| Art. 9 Special categories | Extra protection for health, biometric, genetic data, etc. | No additional protection layer in v1 | Controller must implement additional controls for any special-category data flowing through zemtik |
| Art. 25 Privacy by design | Appropriate technical measures at design stage | Pseudonymization active when operator sets `ZEMTIK_ANONYMIZER_ENABLED=true` (off by default); fail-closed option (`ZEMTIK_ANONYMIZER_FALLBACK_REGEX=false`) prevents PII from passing through if sidecar is down | Anonymizer is disabled by default — operator must explicitly enable it; MCP tool-result anonymization not yet implemented (Phase 2) |
| Art. 28 Processor contract | Written contract between controller and processor | No DPA template bundled with zemtik | Controller must execute DPA with deployer and sub-processors (OpenAI, Anthropic) |
| Art. 30 ROPA | Records of processing activities | Receipt fields (`receipt_id`, `outgoing_prompt_hash`, `ts`, `intent_confidence`, `engine_used`) provide an audit artifact per query | No ROPA template included; controller must construct ROPA independently |
| Art. 32 Security | Appropriate technical and organizational measures | BabyJubJub EdDSA signed audit records; file permissions on signing key (mode 0600); fail-closed sidecar option | No hash chain linking records; no algorithm versioning for signatures; no automated rotation policy |
| Art. 33 Breach notification | Notify supervisory authority within 72 hours | No automated alerting; signed receipts provide post-incident evidence | Operator must implement external monitoring and incident notification workflow |
| Art. 35 DPIA | Data Protection Impact Assessment for high-risk processing | No DPIA template bundled | Controller must conduct DPIA; see DPIA Starter Questions section below |
| Art. 17 Right to erasure | Data subjects can request deletion of their data | Manual procedure only: identify `receipt_id` via `zemtik list-mcp` or direct SQLite query | Deleting a signed audit record breaks the signature chain integrity claim; no automated erasure workflow; tracked in issue backlog |

---

## LGPD (Brazil) Mapping

| Article | Obligation | Zemtik capability | Remaining gap |
|---------|-----------|------------------|---------------|
| Art. 6 Finality | Processing must serve a documented, legitimate purpose | Pseudonymization serves the stated purpose of protecting personal data in LLM requests | Controller must document finality before deploying |
| Art. 16 Storage | Data should not be retained beyond its purpose | Vault TTL 300s (configurable) | Audit DB no-expiry gap identical to GDPR Art. 5(1)(e) — operator must prune manually |
| Art. 18 Data subject rights (DSAR) | Rights of access, correction, anonymization, blocking, deletion, portability | No automated workflow | Manual SQL procedure only; same signed-record tension as GDPR Art. 17 |
| Art. 33 International data transfer | Transfer outside Brazil requires adequacy finding or safeguard mechanism | Tokenized prompts forwarded to OpenAI/Anthropic (United States) — tokens only, not originals | Controller needs an adequacy finding or standard clauses for each provider; zemtik does not provide transfer impact assessment (TIA) |
| Encarregado (DPO equivalent) | Operator must appoint an Encarregado | Not applicable to zemtik software itself | Controller deploying zemtik must appoint an Encarregado and register with ANPD as required |

---

## Habeas Data — Colombia (Ley 1581 / Decreto 1377/2013)

**Autorización previa del titular.** Colombian law requires prior authorization from the data subject before collecting and processing personal data. Zemtik does not collect or verify this authorization. The controller must obtain and document autorización before any personal data flows through zemtik.

**Finalidad (purpose).** The purpose of processing must be communicated to the data subject and documented. The controller must define and disclose the purpose for which LLM queries contain personal data.

**Registro ante la SIC.** If the controller's data bank is subject to registration with the Superintendencia de Industria y Comercio, the controller is responsible for that registration. Zemtik does not create or maintain data banks in the SIC sense.

**Transferencia internacional de datos.** Tokenized prompts sent to OpenAI or Anthropic (United States) constitute an international transfer. Colombian law requires that the receiving country provides adequate protection, or that the controller obtains SIC authorization, or uses binding corporate rules. The controller must implement one of these mechanisms before routing data to US-based providers via zemtik.

**Encargado del Tratamiento.** The organization deploying zemtik is the Responsable del Tratamiento. If a third party (e.g., a technology vendor) deploys zemtik on the controller's behalf, a tratamiento contract must be executed between Responsable and Encargado before deployment begins.

**Derechos ARSOP (Acceso, Rectificación, Supresión, Oposición, Portabilidad).** No automated workflow in this version. Manual procedure: locate records via `zemtik list-mcp` or direct SQLite query on `~/.zemtik/mcp_audit.db`.

---

## LFPDPPP — Mexico

**ARCO rights (Acceso, Rectificación, Cancelación, Oposición).** No automated ARCO fulfillment workflow in this version. The controller must establish a manual process for responding to data subject requests. Records are accessible via `zemtik list-mcp` or direct SQLite query.

**Aviso de privacidad.** The controller must provide a privacy notice (aviso de privacidad) to data subjects before processing their personal data through zemtik. Zemtik does not generate or host a privacy notice.

**INAI registration.** If the controller's processing activities require registration with the Instituto Nacional de Transparencia, Acceso a la Información y Protección de Datos Personales, the controller is responsible for that registration.

**International transfers.** Tokenized prompts forwarded to OpenAI or Anthropic (US) constitute an international transfer under LFPDPPP. The controller must ensure consent or a contractual mechanism is in place.

---

## Ley 25.326 — Argentina

**AAIP registration.** If the controller's database of personal data is subject to registration with the Agencia de Acceso a la Información Pública, the controller is responsible for that registration. Zemtik does not register databases on the controller's behalf.

**Habeas data rights.** Data subjects have the right to access, correct, and request deletion of personal data. No automated workflow in this version. Records are accessible via `zemtik list-mcp` or direct SQLite query on `~/.zemtik/mcp_audit.db`.

**International transfers.** Argentina has an adequacy decision from the EU. Transfers to US-based providers still require a contractual mechanism. The controller must implement the appropriate safeguard before routing data to OpenAI or Anthropic.

---

## Cross-Border Transfer Guidance

Applicable to all LATAM regimes. Zemtik pseudonymizes prompts before forwarding to the AI provider. However, pseudonymized data remains personal data (see GDPR Recital 26; the same principle applies under LGPD and LATAM privacy laws with similar definitions). Therefore, forwarding tokenized prompts to OpenAI or Anthropic (United States) constitutes a cross-border transfer of personal data.

**Available transfer mechanisms (controller must select and implement):**

- Standard Contractual Clauses (EU SCCs or LATAM-equivalent clauses recognized by the relevant DPA)
- Adequacy decisions where applicable
- Binding Corporate Rules (for intra-group transfers)
- Explicit consent of the data subject (fragile; avoid for systematic processing)
- Transfer Impact Assessment (TIA) to supplement SCCs

Zemtik does not provide a TIA template in this version. This is a known gap tracked in the issue backlog.

---

## Sub-Processor Table

| Name | Role | Jurisdiction | DPA / certification | Data received |
|------|------|-------------|---------------------|---------------|
| OpenAI, Inc. | LLM API — receives and processes prompts | United States | DPA available at openai.com/policies/data-processing-addendum | Tokenized prompt text only (no original PII when anonymizer is active) |
| Anthropic, PBC | LLM API — optional; receives and processes prompts | United States | DPA available at anthropic.com/legal/dpa | Tokenized prompt text only (no original PII when anonymizer is active) |
| Hugging Face, Inc. (US) / Hugging Face SAS (FR) | AI model CDN — one-time download of GLiNER and BGE models on first server start | United States / France | Privacy policy at huggingface.co/privacy | IP address of the server performing the download only; no personal data |
| Microsoft Corporation | Presidio NLP library — runs locally inside the sidecar container | United States (library origin) | N/A — local execution; no data transfer to Microsoft | None |
| urchade/GLiNER | Open-weight NLP model — runs locally inside the sidecar container | N/A | N/A — local execution; no data transfer | None |
| Supabase, Inc. | Database backend — only if `DB_BACKEND=supabase` is configured | United States | Privacy policy at supabase.com/privacy | Database transaction records (if Supabase backend is enabled) |

---

## DPIA Starter Questions

The following questions are a starting point for the controller's Data Protection Impact Assessment. They are not a complete DPIA — engage a qualified DPO or legal advisor to complete the full assessment.

1. What personal data categories will flow through zemtik? List the entity types enabled via `ZEMTIK_ANONYMIZER_ENTITY_TYPES` and assess whether any are special-category data under GDPR Art. 9 or equivalent provisions.

2. What is the lawful basis for processing the personal data that appears in LLM prompts under your applicable law? Document this before deployment.

3. Is the sidecar deployed in the same jurisdiction as the data subjects? If not, does the cross-border transfer of entity spans (used for local tokenization) require a legal mechanism?

4. What is the maximum retention period your organization requires for `mcp_audit.db`, `receipts.db`, and `tunnel_audit.db`? Who is responsible for implementing manual pruning on this schedule?

5. Have you executed DPAs with OpenAI and/or Anthropic that name your organization as the data controller?

6. Who is the appointed DPO / Encarregado / Responsable de Privacidad / AAIP contact for this deployment?

7. How will your organization handle data subject access requests involving audit records that are signed with BabyJubJub EdDSA? What is the procedure if erasure of a signed record is required?

---

## Known Compliance Gaps

The following gaps are identified and tracked in the project issue backlog. This list is accurate as of the document revision date. Verify the issue backlog for current status before audit.

1. **Audit DB automatic retention / expiry not implemented.** `mcp_audit.db`, `receipts.db`, and `tunnel_audit.db` grow indefinitely. Operator must prune manually.

2. **Right-to-erasure workflow not implemented.** Deleting a signed audit record breaks the integrity claim of the signature over that record. No automated erasure workflow exists; no solution that preserves signature integrity while satisfying erasure obligations has been implemented.

3. **PHONE_NUMBER and EMAIL_ADDRESS excluded from default entity set.** Operators who need these types must add them explicitly via `ZEMTIK_ANONYMIZER_ENTITY_TYPES`. The default set includes 21 types; PHONE_NUMBER and EMAIL_ADDRESS are supported but excluded by default.

4. **No DPIA or ROPA template bundled.** Controllers must construct these documents independently.

5. **No Transfer Impact Assessment (TIA) template for international transfers.** Controllers must conduct their own TIA before forwarding data to US-based AI providers.

6. **No Art. 33 / LGPD Art. 48 breach notification automation.** Operator must implement external monitoring and incident response procedures.

7. **No DPA template included.** Controllers must execute DPAs with sub-processors (OpenAI, Anthropic) and with any third-party deployer independently.

8. **MCP tool-result anonymization not implemented (Phase 2).** Tool results returned to Claude are not currently scanned for PII. This is planned for a future release.

9. **Multi-turn vault persistence not implemented (Phase 2).** Vault resets on each request and on process restart. Cross-session token continuity is not supported.

---

*This document is part of the Zemtik compliance documentation suite. For plain-language guidance for non-technical readers, see [docs/FOR_LEGAL.md](./FOR_LEGAL.md). For operator setup and retention procedures, see [docs/RUNBOOK.md](./RUNBOOK.md). For cryptographic audit record verification, see [docs/EVIDENCE_PACK_AUDITOR_GUIDE.md](./EVIDENCE_PACK_AUDITOR_GUIDE.md).*
