# Industry Use Cases

**Document type:** How-to + Reference
**Audience:** Developers and CTOs evaluating Zemtik for their industry
**Goal:** End-to-end examples showing how to connect a real database from 7 different industries to Zemtik

---

Every example in this document follows the same integration pattern:

1. Point Zemtik at your existing table (via `physical_table` in `schema_config.json` — Supabase/PostgREST backend only; the SQLite demo ledger always uses the built-in `transactions` table regardless of this setting)
2. Map your column names (`value_column`, `timestamp_column`, `category_column`)
3. Choose sensitivity (`"low"` for FastLane attestation, `"critical"` for ZK proof)
4. Send natural-language queries — Zemtik returns only the cryptographically attested aggregate

No raw rows ever leave your perimeter.

---

## Healthcare — HIPAA Compliance

**Regulation:** HIPAA 45 CFR §164.502. Protected Health Information (PHI) cannot be transmitted to third-party processors without a Business Associate Agreement. Most LLM providers do not sign BAAs. Zemtik eliminates the need for one by ensuring PHI — patient identifiers, individual claim amounts, treatment details — never leaves the host process.

**Use case:** A hospital CFO asks "What were our total cardiology claims last quarter?" without sending patient records to OpenAI.

**Table schema:**

```sql
CREATE TABLE medical_claims (
    claim_id          BIGINT PRIMARY KEY,
    patient_id        BIGINT NOT NULL,         -- PHI: never leaves the perimeter
    amount_cents      BIGINT NOT NULL,          -- individual amounts stay private
    department        TEXT NOT NULL,            -- "cardiology", "oncology", "ER"
    claim_date_epoch  BIGINT NOT NULL           -- UNIX seconds
);
```

**`schema_config.json`:**

```json
{
  "cardiology_claims": {
    "sensitivity": "critical",
    "physical_table": "medical_claims",
    "value_column": "amount_cents",
    "timestamp_column": "claim_date_epoch",
    "category_column": "department",
    "agg_fn": "SUM",
    "metric_label": "total_claims_usd",
    "skip_client_id_filter": true,
    "description": "Medical insurance claims by department: cardiology, oncology, ER, surgical.",
    "example_prompts": [
      "What were our total cardiology claims last quarter?",
      "Show me ER claim costs for Q1 2025",
      "How much did oncology claims cost this year?",
      "Total medical claims by department for H1 2024",
      "What is our surgical claim spend this quarter?"
    ]
  },
  "patient_admissions": {
    "sensitivity": "low",
    "physical_table": "medical_claims",
    "value_column": "claim_id",
    "timestamp_column": "claim_date_epoch",
    "category_column": "department",
    "agg_fn": "COUNT",
    "metric_label": "admission_count",
    "skip_client_id_filter": true,
    "description": "Count of patient admissions and claims filed by department.",
    "example_prompts": [
      "How many patients were admitted to cardiology last quarter?",
      "Show me ER admission count for 2024",
      "How many claims were filed this month?",
      "Total oncology admissions this year"
    ]
  }
}
```

**What the LLM receives:**
```json
{
  "department": "cardiology",
  "total_claims_usd": 4200000,
  "period": "Q1 2025",
  "data_exfiltrated": 0,
  "engine": "ZkSlowLane",
  "proof_hash": "7c3a..."
}
```

**What stays private:** `patient_id`, individual claim amounts, treatment codes, diagnosis information.

**Notes:**
- Use `"sensitivity": "critical"` — individual claim amounts reveal treatment cost patterns that can identify patients in small departments.
- `skip_client_id_filter: true` — a hospital typically does not use multi-tenant `client_id` partitioning. Zemtik aggregates the entire table.
- Two entries from the same table: `cardiology_claims` (SUM of dollars) and `patient_admissions` (COUNT of entries). The same physical table, two different Zemtik questions.

---

## Legal / Law Firms — Attorney-Client Privilege

**Regulation:** Attorney-client privilege and work product doctrine. Billing records identify which attorneys worked on which matters, revealing client relationships and case strategy. Sending these records to a third-party LLM may constitute a waiver of privilege.

**Use case:** A managing partner asks "What was our total litigation revenue last quarter?" without exposing which attorneys billed to which clients.

**Table schema:**

```sql
CREATE TABLE billable_hours (
    entry_id          BIGINT PRIMARY KEY,
    attorney_id       BIGINT NOT NULL,          -- privileged: who worked on what
    matter_id         BIGINT NOT NULL,           -- privileged: identifies client
    hours_billed      BIGINT NOT NULL,           -- in hundredths (150 = 1.50 hours)
    rate_cents        BIGINT NOT NULL,           -- hourly rate in cents
    practice_area     TEXT NOT NULL,             -- "litigation", "corporate", "IP", "tax"
    entry_date_epoch  BIGINT NOT NULL
);
```

**`schema_config.json`:**

```json
{
  "practice_revenue": {
    "sensitivity": "critical",
    "physical_table": "billable_hours",
    "value_column": "rate_cents",
    "timestamp_column": "entry_date_epoch",
    "category_column": "practice_area",
    "agg_fn": "SUM",
    "metric_label": "total_billed_usd",
    "skip_client_id_filter": true,
    "description": "Billable revenue by practice area: litigation, corporate, IP, tax, employment.",
    "example_prompts": [
      "What was our total litigation revenue last quarter?",
      "Show me corporate practice billing for 2024",
      "How much did we bill in IP matters this year?",
      "Total tax practice revenue Q1 2025",
      "What is our practice revenue breakdown for H1 2024?"
    ]
  },
  "billable_hours_total": {
    "sensitivity": "low",
    "physical_table": "billable_hours",
    "value_column": "hours_billed",
    "timestamp_column": "entry_date_epoch",
    "category_column": "practice_area",
    "agg_fn": "SUM",
    "metric_label": "total_hours",
    "skip_client_id_filter": true,
    "description": "Total hours billed by practice area.",
    "example_prompts": [
      "How many billable hours did litigation log last quarter?",
      "Show me total hours for corporate practice this year",
      "What are our total billed hours for IP in 2024?"
    ]
  }
}
```

**What the LLM receives:**
```json
{
  "practice_area": "litigation",
  "total_billed_usd": 3850000,
  "period": "Q4 2024",
  "data_exfiltrated": 0
}
```

**What stays private:** `attorney_id`, `matter_id` (client identity), individual hourly rates, time entry descriptions.

**Notes:**
- `"sensitivity": "critical"` for revenue — aggregate billing per practice area could reveal sensitive business intelligence about client concentration.
- `"sensitivity": "low"` for hours — count of hours is less sensitive than dollar amounts tied to client relationships.
- Two entries, same table: revenue (SUM of `rate_cents`) and hours (SUM of `hours_billed`).

---

## Insurance — Claims Analytics

**Regulation:** GDPR Article 9 (special category data) and CCPA. Insurance claims contain health, financial, and property data classified as sensitive personal information. Transmitting policy holder records to external AI processors requires explicit consent under GDPR and specific disclosures under CCPA.

**Use case:** A VP of Actuarial asks "What were our total auto claim payouts in Q3?" without sending policyholder records to OpenAI.

**Table schema:**

```sql
CREATE TABLE insurance_claims (
    claim_id          BIGINT PRIMARY KEY,
    policy_holder_id  BIGINT NOT NULL,          -- PII: never leaves perimeter
    payout_cents      BIGINT NOT NULL,
    claim_type        TEXT NOT NULL,             -- "auto", "home", "life", "health"
    region            TEXT,
    filed_date_epoch  BIGINT NOT NULL
);
```

**`schema_config.json`:**

```json
{
  "claim_payouts": {
    "sensitivity": "critical",
    "physical_table": "insurance_claims",
    "value_column": "payout_cents",
    "timestamp_column": "filed_date_epoch",
    "category_column": "claim_type",
    "agg_fn": "SUM",
    "metric_label": "total_payouts_usd",
    "skip_client_id_filter": true,
    "description": "Insurance claim payouts by type: auto, home, life, health.",
    "example_prompts": [
      "What were total auto claim payouts last quarter?",
      "Show me home insurance claim costs for 2024",
      "How much did we pay out in life insurance claims this year?",
      "Total health claim payouts Q1 2025",
      "What are our auto claim costs for H1 2024?"
    ]
  },
  "claims_volume": {
    "sensitivity": "low",
    "physical_table": "insurance_claims",
    "value_column": "claim_id",
    "timestamp_column": "filed_date_epoch",
    "category_column": "claim_type",
    "agg_fn": "COUNT",
    "metric_label": "claims_filed",
    "skip_client_id_filter": true,
    "description": "Number of insurance claims filed by type: auto, home, life, health.",
    "example_prompts": [
      "How many auto claims were filed this quarter?",
      "Show me home insurance claim volume for 2024",
      "How many health claims were submitted last month?",
      "Total claims filed by type this year"
    ]
  }
}
```

**What the LLM receives:**
```json
{
  "claim_type": "auto",
  "total_payouts_usd": 12800000,
  "period": "Q3 2024",
  "data_exfiltrated": 0
}
```

**What stays private:** `policy_holder_id`, individual payout amounts, claimant addresses, accident details.

---

## E-commerce / Retail — Revenue Analytics

**Regulation:** CCPA and PCI DSS. Order records contain customer identity, payment method, and purchase history. PCI DSS prohibits storing unencrypted cardholder data; CCPA treats purchase history as personal information requiring disclosure and opt-out rights.

**Use case:** A Head of Revenue asks "What did electronics generate in Q4?" without sending customer order records to OpenAI.

**Table schema:**

```sql
CREATE TABLE orders (
    order_id           BIGINT PRIMARY KEY,
    customer_id        BIGINT NOT NULL,          -- PII / purchase history
    total_cents        BIGINT NOT NULL,
    product_category   TEXT NOT NULL,            -- "electronics", "apparel", "grocery"
    order_date_epoch   BIGINT NOT NULL
);
```

**`schema_config.json`:**

```json
{
  "category_revenue": {
    "sensitivity": "low",
    "physical_table": "orders",
    "value_column": "total_cents",
    "timestamp_column": "order_date_epoch",
    "category_column": "product_category",
    "agg_fn": "SUM",
    "metric_label": "total_revenue_usd",
    "skip_client_id_filter": true,
    "description": "Retail sales revenue by product category: electronics, apparel, grocery, home goods.",
    "example_prompts": [
      "What was total electronics revenue last quarter?",
      "Show me apparel sales for Q4 2024",
      "How much did grocery generate this year?",
      "Total revenue for electronics in H1 2025",
      "What are our home goods sales for this quarter?"
    ]
  },
  "order_volume": {
    "sensitivity": "low",
    "physical_table": "orders",
    "value_column": "order_id",
    "timestamp_column": "order_date_epoch",
    "category_column": "product_category",
    "agg_fn": "COUNT",
    "metric_label": "order_count",
    "skip_client_id_filter": true,
    "description": "Number of orders placed by product category.",
    "example_prompts": [
      "How many electronics orders last quarter?",
      "Show me apparel order volume this month",
      "Total orders by category for Q1 2025"
    ]
  }
}
```

**What the LLM receives:**
```json
{
  "product_category": "electronics",
  "total_revenue_usd": 8450000,
  "period": "Q4 2024",
  "data_exfiltrated": 0,
  "engine": "FastLane"
}
```

**What stays private:** `customer_id`, individual order amounts, purchase history, shipping addresses.

**Notes:**
- Revenue and order count can safely use `"sensitivity": "low"` — aggregate sales by category is not sensitive, only individual customer records are.
- FastLane latency: < 50ms. Suitable for dashboard queries run hundreds of times per day.

---

## Government / Defense — Procurement Analytics

**Regulation:** FAR (Federal Acquisition Regulation) and classified information statutes. Procurement records identify contractor relationships, contract values, and program funding allocations. Transmitting this to commercial LLM APIs may violate FedRAMP controls and classification requirements.

**Use case:** A contracting officer asks "What was our total IT procurement spend this fiscal year?" without exposing individual contractor awards.

**Table schema:**

```sql
CREATE TABLE procurement_contracts (
    contract_id        BIGINT PRIMARY KEY,
    contractor_id      BIGINT NOT NULL,          -- may be classified relationship
    award_amount       BIGINT NOT NULL,
    contract_type      TEXT NOT NULL,             -- "IT", "logistics", "construction", "R&D"
    award_date_epoch   BIGINT NOT NULL
);
```

**`schema_config.json`:**

```json
{
  "procurement_spend": {
    "sensitivity": "critical",
    "physical_table": "procurement_contracts",
    "value_column": "award_amount",
    "timestamp_column": "award_date_epoch",
    "category_column": "contract_type",
    "agg_fn": "SUM",
    "metric_label": "total_awarded_usd",
    "skip_client_id_filter": true,
    "description": "Government procurement contract awards by type: IT, logistics, construction, R&D.",
    "example_prompts": [
      "Total IT procurement spend this fiscal year",
      "Show me logistics contract awards for FY 2025",
      "How much was awarded in construction contracts Q1?",
      "What is our R&D procurement budget spend this quarter?",
      "Total contract awards by type for FY 2024"
    ]
  },
  "contract_count": {
    "sensitivity": "low",
    "physical_table": "procurement_contracts",
    "value_column": "contract_id",
    "timestamp_column": "award_date_epoch",
    "category_column": "contract_type",
    "agg_fn": "COUNT",
    "metric_label": "contracts_awarded",
    "skip_client_id_filter": true,
    "description": "Number of procurement contracts awarded by type.",
    "example_prompts": [
      "How many IT contracts were awarded this quarter?",
      "Show me logistics contract count for FY 2025",
      "Total contracts awarded by type this fiscal year"
    ]
  }
}
```

**What the LLM receives:**
```json
{
  "contract_type": "IT",
  "total_awarded_usd": 94000000,
  "period": "FY2025",
  "data_exfiltrated": 0,
  "engine": "ZkSlowLane",
  "proof_hash": "a91f..."
}
```

**What stays private:** `contractor_id`, individual award amounts per contractor, funding source allocations.

**Notes:**
- `"sensitivity": "critical"` — aggregate spend by contract type in defense contexts can reveal program structure.
- The ZK proof is the compliance artifact: an auditor can verify the aggregate without ever seeing contractor records.
- For non-classified agencies, `"sensitivity": "low"` on contract count is safe — total number of IT contracts is often public information anyway.

---

## Pharma / Biotech — R&D Spend Analytics

**Regulation:** SEC Regulation S-K (material non-public information) and competitive intelligence statutes. R&D expenditure by pipeline phase reveals which drug candidates are advancing — this is MNPI that cannot be shared with external parties before disclosure.

**Use case:** A CFO asks "How much did we invest in Phase 3 trials this year?" without exposing which compounds are in which phase.

**Table schema:**

```sql
CREATE TABLE rd_expenditures (
    expenditure_id     BIGINT PRIMARY KEY,
    trial_id           BIGINT NOT NULL,           -- MNPI: identifies compound pipeline
    amount_cents       BIGINT NOT NULL,
    phase              TEXT NOT NULL,              -- "preclinical", "phase1", "phase2", "phase3"
    recorded_epoch     BIGINT NOT NULL
);
```

**`schema_config.json`:**

```json
{
  "rd_spend": {
    "sensitivity": "critical",
    "physical_table": "rd_expenditures",
    "value_column": "amount_cents",
    "timestamp_column": "recorded_epoch",
    "category_column": "phase",
    "agg_fn": "SUM",
    "metric_label": "total_rd_usd",
    "skip_client_id_filter": true,
    "description": "R&D expenditures by clinical trial phase: preclinical, phase 1, phase 2, phase 3.",
    "example_prompts": [
      "Total R&D spend on Phase 3 trials last year",
      "Show me preclinical research costs for 2024",
      "How much did we invest in Phase 1 this quarter?",
      "What is our Phase 2 trial spend for H1 2025?",
      "Total R&D investment by phase this fiscal year"
    ]
  },
  "trial_count": {
    "sensitivity": "low",
    "physical_table": "rd_expenditures",
    "value_column": "trial_id",
    "timestamp_column": "recorded_epoch",
    "category_column": "phase",
    "agg_fn": "COUNT",
    "metric_label": "active_trials",
    "skip_client_id_filter": true,
    "description": "Count of active clinical trials with expenditure records by phase.",
    "example_prompts": [
      "How many Phase 3 trials are we running this year?",
      "Show me active trial count by phase for 2024",
      "How many preclinical programs had spend this quarter?"
    ]
  }
}
```

**What the LLM receives:**
```json
{
  "phase": "phase3",
  "total_rd_usd": 187000000,
  "period": "FY2024",
  "data_exfiltrated": 0,
  "engine": "ZkSlowLane",
  "proof_hash": "3d88..."
}
```

**What stays private:** `trial_id` (compound identity), individual expenditure amounts per program, which specific candidates are in which phase.

**Notes:**
- ZK proof serves as the audit trail for financial reporting: the aggregate is proven without revealing the pipeline composition.
- `trial_count` (COUNT) uses `"sensitivity": "low"` — total number of active trials by phase is disclosed in SEC filings anyway; it's the per-trial identity and spend that is MNPI.

---

## Fintech / Crypto — Transaction Volume Analytics

**Regulation:** MiCA (EU Markets in Crypto-Assets) Travel Rule and FATF Recommendation 16. DeFi platforms must prevent wallet address data from being processed by external parties without appropriate controls. The Travel Rule requires originator/beneficiary data to stay within compliant systems.

**Use case:** A DeFi protocol's Head of Risk asks "What was our total swap volume last month?" without sending wallet addresses to OpenAI.

**Table schema:**

```sql
CREATE TABLE blockchain_txns (
    tx_hash            TEXT PRIMARY KEY,
    wallet_address     TEXT NOT NULL,             -- PII under Travel Rule / MiCA
    amount_wei         BIGINT NOT NULL,            -- in wei (1 ETH = 1e18 wei)
    tx_type            TEXT NOT NULL,             -- "swap", "transfer", "stake", "bridge"
    block_timestamp    BIGINT NOT NULL             -- UNIX seconds (native to EVM)
);
```

**`schema_config.json`:**

```json
{
  "protocol_volume": {
    "sensitivity": "critical",
    "physical_table": "blockchain_txns",
    "value_column": "amount_wei",
    "timestamp_column": "block_timestamp",
    "category_column": "tx_type",
    "agg_fn": "SUM",
    "metric_label": "total_volume_wei",
    "skip_client_id_filter": true,
    "description": "DeFi transaction volume in wei by type: swaps, transfers, staking, bridging.",
    "example_prompts": [
      "What was total swap volume last month?",
      "Show me staking deposit volume for Q1 2025",
      "How much was bridged this quarter?",
      "Total transfer volume for 2024",
      "What is our protocol volume by transaction type this year?"
    ]
  },
  "transaction_count": {
    "sensitivity": "low",
    "physical_table": "blockchain_txns",
    "value_column": "tx_hash",
    "timestamp_column": "block_timestamp",
    "category_column": "tx_type",
    "agg_fn": "COUNT",
    "metric_label": "transaction_count",
    "skip_client_id_filter": true,
    "description": "Number of on-chain transactions by type: swaps, transfers, staking, bridging.",
    "example_prompts": [
      "How many swaps were executed last month?",
      "Show me transaction count by type for Q1 2025",
      "Total number of bridge transactions this year"
    ]
  }
}
```

**What the LLM receives:**
```json
{
  "tx_type": "swap",
  "total_volume_wei": 948200000000000000000,
  "period": "last month",
  "data_exfiltrated": 0,
  "engine": "ZkSlowLane",
  "proof_hash": "e14c..."
}
```

**What stays private:** `wallet_address`, individual transaction amounts and their source/destination relationships.

**Notes:**
- `block_timestamp` is already UNIX seconds — no conversion needed for EVM chains.
- `amount_wei` is a `BIGINT`. For very large chains with high volume, verify your DB stores wei as `NUMERIC` or `TEXT` and that the value fits in `i64` before connecting. For display purposes, divide the aggregate by `1e18` to get ETH.
- `tx_hash` is TEXT, not BIGINT — using it as `value_column` with `agg_fn: "COUNT"` works because COUNT only needs a non-null column to count, not to sum.

---

## Common Integration Pattern

All seven examples follow the same five-step process:

### Step 1 — Map your table to Zemtik's query model

| Your table | Zemtik parameter | Notes |
|-----------|-----------------|-------|
| The table name | `physical_table` | Any table visible to PostgREST (Supabase backend only; ignored on SQLite) |
| The column to aggregate | `value_column` | Must be numeric for SUM; any non-null column for COUNT |
| The column for time filtering | `timestamp_column` | Must be UNIX epoch seconds (BIGINT) |
| The column for category filtering | `category_column` | Set to `null` to aggregate the whole table |
| SUM or COUNT | `agg_fn` | `"SUM"` or `"COUNT"` |

### Step 2 — Handle timestamps

Zemtik expects `timestamp_column` to contain UNIX epoch seconds as a `BIGINT`. Most databases store timestamps differently:

| Source format | Migration |
|--------------|-----------|
| `TIMESTAMP WITH TIME ZONE` (Postgres) | `ALTER TABLE t ADD COLUMN ts_epoch BIGINT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM ts)::BIGINT) STORED;` |
| ISO 8601 string | Parse on insert; or add a generated column |
| Milliseconds (JavaScript, Kafka) | Divide by 1000 on insert; or add generated column `ts_ms / 1000` |
| EVM `block_timestamp` | Already UNIX seconds — no conversion needed |

### Step 3 — Decide on `client_id`

| Your setup | Configuration |
|-----------|--------------|
| Multi-tenant SaaS (one DB, many customers) | Keep `skip_client_id_filter: false`; add `client_id BIGINT NOT NULL` column; set `ZEMTIK_CLIENT_ID` per tenant |
| Single-tenant or global table | Set `skip_client_id_filter: true`; no `client_id` column needed |

### Step 4 — Choose sensitivity

| Data type | Recommended sensitivity |
|-----------|------------------------|
| PII (patient_id, wallet_address, policy_holder_id) in any column | `"critical"` — ZK proof |
| Aggregates that are themselves sensitive (MNPI, classified spend) | `"critical"` — ZK proof |
| Non-sensitive operational data (order count, contract count) | `"low"` — FastLane attestation, < 50ms |
| Public-facing metrics | `"low"` — FastLane attestation |

When in doubt, use `"critical"`. The ZK proof is slower (~17s) but provides a mathematical guarantee. FastLane provides a BabyJubJub EdDSA attestation — cryptographically binding, but not a succinct proof. **Exception:** `agg_fn: "COUNT"` cannot be paired with `sensitivity: "critical"` — the ZK circuit only handles SUM over BN254 field elements. For COUNT-based tables, use `sensitivity: "low"` (FastLane attestation).

### Step 5 — Write example prompts

The embedding backend (default) matches prompts by semantic similarity to `example_prompts`. Quality beats quantity: write prompts that reflect how your actual users phrase questions, including domain-specific vocabulary.

```json
"example_prompts": [
  "What was our total [category] [metric] last quarter?",
  "Show me [metric] for [time period]",
  "How much [metric] in [FY/Q/H] [year]?",
  "Total [metric] by [category] for [period]",
  "[Domain synonym] [metric] [time expression]"
]
```

Five prompts is the minimum. Ten or more produces significantly better intent matching across varied phrasing.

---

## Database Connectivity

All examples above require either:

- **Supabase** (managed PostgREST): set `DB_BACKEND=supabase`, `SUPABASE_URL`, and `SUPABASE_SERVICE_KEY`.
- **Self-hosted PostgREST** in front of your existing PostgreSQL: set `DB_BACKEND=supabase` and point `SUPABASE_URL` at your PostgREST instance. The `SUPABASE_*` variable names refer to PostgREST protocol, not Supabase the product.

```bash
# Example: self-hosted PostgREST in front of your existing Postgres
docker run \
  -e PGRST_DB_URI="postgres://user:pass@your-db-host:5432/yourdb" \
  -e PGRST_DB_SCHEMA="public" \
  -e PGRST_DB_ANON_ROLE="web_anon" \
  -p 3000:3000 postgrest/postgrest:v12.2.0

# Then in .env:
DB_BACKEND=supabase
SUPABASE_URL=http://localhost:3000
SUPABASE_SERVICE_KEY=your-postgrest-jwt
```

A native `sqlx`-based Postgres connector (`DB_BACKEND=postgres`) with column-mapping config is planned for v2.

See [Configuration Reference](CONFIGURATION.md) for the full environment variable list.
