# Zemtik — Plain-Language Guide for Legal, Privacy, and Compliance Teams

**Document type:** Plain-Language Privacy Guide
**Audience:** Privacy lawyers, Data Protection Officers, compliance officers — no terminal required
**Goal:** Answer the questions your team will ask before approving a zemtik deployment

---

## What Zemtik Does in Plain English

Zemtik sits between your team's AI client (such as Claude Desktop or a custom application) and the AI model provider (such as OpenAI or Anthropic). **When the PII anonymizer is enabled** (`ZEMTIK_ANONYMIZER_ENABLED=true` — off by default), before any message leaves your machine and reaches the AI provider, zemtik scans it for personal data, replaces identifying information with anonymous-looking codes ("tokens"), and forwards only the coded version. The codes stay on your machine. The AI provider never sees the original names, ID numbers, or financial identifiers. When the anonymizer is disabled, messages pass through to the AI provider unmodified.

---

## What Zemtik Does for Personal Data

**Token replacement.** Every message is scanned for personal data before it leaves your infrastructure. Detected items — names, national ID numbers, IBAN codes, dates, monetary amounts, and others — are replaced with placeholder codes in the format `[[Z:xxxx:n]]`. The AI model reasons over the codes, not the originals.

**In-memory vault.** The mapping from code back to original value is kept in memory ("RAM") on the machine running zemtik. It is never written to disk in this version. The vault entry for a session is cleared immediately after the AI response is returned to the user (per-request clear). Any vault entries not yet cleared are also evicted after a configurable period (default: 5 minutes, controlled by the `ZEMTIK_ANONYMIZER_VAULT_TTL_SECS` setting). The vault exists solely so zemtik can restore original values in the AI's response before returning it to your user.

**Sidecar processing on your own server.** The detection of personal data names, organizations, and locations is performed by a software component called the "sidecar" — a separate process that runs on your own server alongside zemtik. No personal data is sent to zemtik the company. Detection happens entirely within your infrastructure.

---

## What Zemtik Does NOT Do

Read this section carefully before advising on regulatory compliance.

**Not legal anonymization under GDPR Recital 26.** Recital 26 of the GDPR defines anonymization as an irreversible process after which individuals cannot be re-identified. Zemtik performs *pseudonymization* — a reversible substitution. The vault holds the mapping that allows zemtik to restore original values. This means zemtik-processed data remains personal data under GDPR; it is not exempt from data protection obligations.

**Not a Data Processing Agreement substitute.** Zemtik does not create, sign, or replace a Data Processing Agreement ("DPA") between your organization and any AI model provider. You must execute your own DPAs with OpenAI, Anthropic, or any other provider you configure.

**Cannot prevent a user from typing raw personal data in follow-up messages.** Zemtik intercepts and tokenizes data in the messages it sees. A user who types a person's name directly into a new message after the vault has been cleared will cause that name to appear un-tokenized in the request to the AI provider. Operator training and access controls are still necessary.

**MCP tool-result anonymization is not available in this version.** When zemtik is used as an MCP ("Model Context Protocol") attestation server — the integration that connects zemtik to Claude Desktop — the results returned by AI tools are not currently scanned and tokenized on the way back. This is planned for a future release ("Phase 2"). Until then, AI tool results that include personal data are not protected by tokenization.

**Multi-turn vault persistence across restarts is not available in this version.** The vault is held only in memory. When the zemtik process stops (server restart, container redeploy, crash), all vault mappings are lost. Each new session starts with a fresh vault. There is no cross-session continuity of token assignments.

---

## Where Your Data Goes

| Component | Where it runs | What it sends outside your machine |
|-----------|--------------|-------------------------------------|
| PII sidecar (GLiNER / Presidio NLP) | Your server | Nothing — detection runs locally |
| In-memory vault | Your server RAM (cleared every 5 min by default) | Nothing |
| `mcp_audit.db` / `receipts.db` / `tunnel_audit.db` | Your disk at `~/.zemtik/` | Nothing |
| LLM request (tokenized — codes only, no originals) | Your server → OpenAI or Anthropic API, United States | The tokenized message text only |
| AI model download (first start only) | Your server → HuggingFace CDN, United States | Nothing after download; model runs locally |

---

## Sub-Processors When You Use Zemtik

These are the external services zemtik may involve when processing a request. All AI model inference happens at the provider listed below — zemtik forwards tokenized text only.

| Name | Role | Jurisdiction | DPA available? |
|------|------|-------------|----------------|
| OpenAI, Inc. | LLM API (default provider) | United States | Yes — [openai.com/policies/data-processing-addendum](https://openai.com/policies/data-processing-addendum) |
| Anthropic, PBC | LLM API (optional) | United States | Yes — [anthropic.com/legal/dpa](https://www.anthropic.com/legal/dpa) |
| Hugging Face, Inc. (US) / Hugging Face SAS (FR) | AI model CDN — two model downloads on first server start: (1) GLiNER named-entity detection model (~220MB, sidecar), (2) BGE-small-en intent embedding model (~130MB, downloaded to `~/.zemtik/models/` when the proxy starts). Both run locally after download; no data is sent to Hugging Face during operation. | United States / France | Yes — [huggingface.co/privacy](https://huggingface.co/privacy) |
| Microsoft Corporation | Presidio NLP library — runs locally inside the sidecar; no data is sent to Microsoft | United States (library origin) | N/A — runs locally, no data transfer |
| urchade/GLiNER | NLP model for named-entity detection — runs locally inside the sidecar; no data is sent externally | N/A (open-weight model) | N/A — runs locally, no data transfer |
| Supabase, Inc. (optional) | Database backend — only if your deployment uses `DB_BACKEND=supabase` | United States | Yes — [supabase.com/privacy](https://supabase.com/privacy) |

**Important:** Supabase is not used in the default SQLite configuration. If your deployer has not explicitly enabled Supabase, it is not a sub-processor.

---

## Data Retention Today

Be aware of the following retention behaviors before approving a deployment.

**In-memory vault:** Cleared automatically after the configured TTL (default 5 minutes). Configurable via `ZEMTIK_ANONYMIZER_VAULT_TTL_SECS`.

**Audit databases (`mcp_audit.db`, `receipts.db`, `tunnel_audit.db`):** These files grow indefinitely. There is **no automatic expiry or rotation** in this version. Your deployer must manually delete old records or implement a scheduled cleanup. This is a known gap tracked in the project issue backlog.

**Audit JSONL logs (`audit/` directory):** Append-only log files with no rotation configured by default. Grows indefinitely.

**Recommendation:** Before going live, agree on a retention schedule with your deployer and document it in your Records of Processing Activities.

---

## Data Subject Rights (Access and Erasure Requests)

**Access requests.** No automated workflow for data subject access requests ("DSARs") exists in this version. Records can be located manually by querying the SQLite databases using the `zemtik list-mcp` command or direct SQL queries. Consult your legal team on the scope of data held before responding to a DSAR.

**Erasure requests.** Each audit record is individually signed with a cryptographic key ("BabyJubJub EdDSA"). If a record is deleted, the signature chain that proves the integrity of surrounding records is broken. This creates a tension between erasure obligations and audit integrity. **Consult your legal team before deleting signed audit records.** There is no automated erasure workflow in this version; this limitation is tracked in the issue backlog.

---

## LATAM and EU Regulation Map

| Regulation | What zemtik helps with | What you still need to do yourself |
|------------|------------------------|--------------------------------------|
| **GDPR (EU/EEA)** | Pseudonymization of personal data in LLM prompts; signed audit trail for processing activities | DPA with OpenAI/Anthropic; Data Protection Impact Assessment ("DPIA"); Records of Processing Activities ("ROPA"); Art. 33 breach notification procedure; controller-to-processor contract if multiple teams share a deployment |
| **LGPD (Brazil)** | Same pseudonymization and signed audit trail | Appointment of an Encarregado (Data Protection Officer); ANPD incident notification procedure; Art. 33 international transfer mechanism for transfers to US-based AI providers |
| **Ley 1581 / Decreto 1377/2013 (Colombia)** | Pseudonymization before cross-border transfer to US-based AI providers | Autorización previa del titular (prior authorization from data subjects); registro ante la SIC (if applicable); disclosure of transferencia internacional; designation of an Encargado del Tratamiento if a third party deploys on your behalf |
| **LFPDPPP (Mexico)** | Pseudonymization before transfer to US-based AI providers | ARCO rights workflow (Acceso, Rectificación, Cancelación, Oposición); Aviso de privacidad; INAI registration if applicable |
| **Ley 25.326 (Argentina)** | Pseudonymization before transfer to US-based AI providers | AAIP database registration if applicable; habeas data rights workflow |

---

## Questions to Ask Before You Sign with Your Vendor or Deployer

Ask these questions of the person or company setting up zemtik on your behalf. Request written answers.

1. Has a DPA been signed with OpenAI and/or Anthropic that names my organization as the data controller?
2. What is the data residency of the zemtik deployment? Is the server located within the jurisdiction my regulations require?
3. What is the backup and retention policy for `mcp_audit.db` and `receipts.db`? How often are they backed up, and when are old records deleted?
4. How will you notify me of a security incident within 72 hours (as required by GDPR Art. 33)? What is the agreed notification channel?
5. Has a sub-processor change notification process been agreed? If zemtik adds a new external service, how will you inform me before the change takes effect?

---

*For deep compliance mapping see [docs/COMPLIANCE_LATAM.md](./COMPLIANCE_LATAM.md). For operator setup and retention configuration see [docs/RUNBOOK.md](./RUNBOOK.md).*
