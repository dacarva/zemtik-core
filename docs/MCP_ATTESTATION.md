# MCP Attestation — Integration Guide

## Quick Install (Claude Desktop — no terminal required)

Download the `.mcpb` for your platform from the [latest release](https://github.com/dacarva/zemtik-core/releases/latest) and double-click it. Claude Desktop installs Zemtik automatically.

| Platform | File |
|----------|------|
| macOS (Apple Silicon / Intel) | `zemtik-macos.mcpb` |
| Linux | `zemtik-linux.mcpb` |
| Windows | `zemtik-windows.mcpb` — see note below |

Then ask Claude:
> "Please read /Users/yourname/Desktop/contract.pdf and summarize the key parties and obligations."

To get the full path on macOS: right-click the file in Finder → hold Option → choose **Copy Pathname**.

Supported: PDF (text-layer), DOCX, plain text. Max 25 MB for PDF/DOCX, 10 MB for text.

### PII Anonymization requires the Zemtik sidecar

The `.mcpb` package enables PII anonymization by default (`ZEMTIK_ANONYMIZER_ENABLED=true`). Full entity detection (PERSON, ORG, LOCATION, IDs) requires the GLiNER/Presidio sidecar. Without it, file reads will return a sidecar error.

**macOS / Linux:** Start Docker Desktop, then:
```bash
docker compose --profile anonymizer up -d
```

**Windows:** PII anonymization requires one of:
1. **Docker Desktop with WSL2** — run the command above inside a WSL2 terminal.
2. **Cloud sidecar** — add `ZEMTIK_ANONYMIZER_SIDECAR_ADDR` pointing to your hosted endpoint in `claude_desktop_config.json` under the `zemtik` server's `env` block.

To disable anonymization (reads succeed without Docker, but no PII protection):
```json
"env": { "ZEMTIK_ANONYMIZER_ENABLED": "false" }
```

**Attestation note:** `output_hash` in each audit record covers the anonymized text delivered to Claude. `raw_file_hash` in the tool response covers the source binary file. Both can be verified independently.

---

Zemtik ships an MCP server that makes Claude Desktop safe for regulated industries. Every tool call is attested with a BabyJubJub EdDSA signature and logged to a tamper-evident audit database. In v0.18.0, `zemtik_read_file` supports PDF and DOCX extraction with hash separation (content hash vs. raw file hash). The `zemtik_analyze` tool adds PII tokenization: Claude calls it before reasoning on sensitive documents, so raw names, tax IDs, and financial identifiers never appear in Claude's context.

**Verify setup before connecting Claude Desktop:**

```bash
zemtik mcp --dry-run
```

This validates configuration, creates a test audit record in `mcp_audit.db`, and exits 0 (success) or 1 (failure). Use to confirm the signing key, audit DB, and anonymizer connectivity are all working before you point Claude Desktop at the server.

**Claude Desktop config file locations:**

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

## How attestation works

For each tool call, Zemtik:

1. Executes the tool (FORK 1) and returns the result to Claude with zero added latency.
2. Simultaneously (FORK 2, async, 1-second timeout): signs the call with a BabyJubJub EdDSA key and writes a signed audit record to `~/.zemtik/mcp_audit.db`.

The result is a tamper-evident log of every file read, HTTP fetch, and PII anonymization Claude performed, who authorized it, and when. Note: records are individually signed but not hash-chained — a deleted record leaves a gap without cryptographic evidence. See Known Audit/Compliance Limitations below.

---

## `zemtik_analyze` — PII Tokenization Tool (v0.16.0+)

`zemtik_analyze` exposes the same anonymizer pipeline used by the proxy directly to Claude Desktop. When enabled, Claude is instructed (via the MCP `instructions` string) to call `zemtik_analyze` before reasoning on any user-pasted sensitive document.

### Requirements

- `ZEMTIK_ANONYMIZER_ENABLED=true`
- Anonymizer sidecar running (GLiNER/Presidio gRPC on port 50051) — or `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true` for structured PII only

The tool is **hidden** from Claude when `ZEMTIK_ANONYMIZER_ENABLED=false`.

### What it does

1. Accepts raw text (max 100 KB)
2. Runs the text through the GLiNER/Presidio sidecar (regex fallback if sidecar unavailable)
3. Returns `{"anonymized_text": "...", "entities_found": N, "entity_types": [...]}`
4. Attests the transformation — `sha256(raw_input)` + `sha256(anonymized_output)` — with BabyJubJub EdDSA
5. Persists an audit record in `mcp_audit.db` with `tool_name: "zemtik_analyze"`

### Constraints

- Vault tokens (`[[Z:xxxx:n]]`) are stable within one `zemtik_analyze` call only. The vault is discarded after each invocation and never returned to Claude. Claude works with tokens as opaque strings.
- Regex fallback covers structured PII only (emails, IBANs, LATAM IDs). PERSON, ORG, and LOCATION detection requires the sidecar.
- Soft enforcement: Claude follows the `instructions` directive but a user can type a message directly to bypass `zemtik_analyze`. For hard enforcement, route all traffic through the Zemtik proxy on `localhost:4000` with `ZEMTIK_ANONYMIZER_ENABLED=true`.

### Quick start

```bash
# Start MCP server with anonymizer
export ZEMTIK_MCP_API_KEY=$(openssl rand -hex 32)
ZEMTIK_ANONYMIZER_ENABLED=true docker compose --profile anonymizer --profile mcp up -d

# Verify
curl http://localhost:4001/mcp/health
```

### Test prompt for Claude Desktop

```text
Summarize this contract: "Juan Carlos López (CC 1020304050) from Bogotá
agrees to pay $5,200,000 COP starting March 1, 2024."
```

Expected behavior: Claude calls `zemtik_analyze` first, then summarizes using only `[[Z:...:n]]` tokens.

---

## Audit Record Schema

Each record in `mcp_audit.db` (and in `GET /mcp/audit` JSON output) contains:

| Field | Type | Description |
|-------|------|-------------|
| `receipt_id` | string (UUID v4) | Unique ID for this call |
| `ts` | string (ISO 8601 UTC) | When the call was executed |
| `tool_name` | string | Tool called: `zemtik_read_file`, `zemtik_fetch`, `zemtik_analyze`, or `zemtik_fetch_bypass` |
| `input_hash` | string (`sha256:<hex>`) | SHA-256 of the JSON-serialized tool arguments |
| `output_hash` | string (`sha256:<hex>`) | SHA-256 of the JSON-serialized tool result |
| `preview_input` | string (≤500 chars) | First 500 characters of the tool input (URL or file path) |
| `preview_output` | string (≤500 chars) | First 500 characters of the tool output |
| `attestation_sig` | string (`<r.x>:<s>`) | BabyJubJub EdDSA signature — see Verification below |
| `public_key_hex` | string (`<x>:<y>`) | BabyJubJub public key at time of signing |
| `duration_ms` | integer | FORK 1 execution time in milliseconds |
| `mode` | string | `tunnel` (observe-only) or `governed` (attestation sidecar in response) |

### Audit Database Schema

```sql
CREATE TABLE IF NOT EXISTS mcp_audit (
    receipt_id      TEXT PRIMARY KEY,        -- UUIDv4
    ts              TEXT NOT NULL,           -- ISO 8601 UTC
    tool_name       TEXT NOT NULL,           -- e.g. "zemtik_fetch"
    input_hash      TEXT NOT NULL,           -- SHA-256 of JSON-serialized tool arguments
    output_hash     TEXT NOT NULL,           -- SHA-256 of JSON-serialized tool result
    preview_input   TEXT,                    -- first 500 chars of input (null if disabled)
    preview_output  TEXT,                    -- first 500 chars of output (null if disabled)
    attestation_sig TEXT NOT NULL,           -- BabyJubJub EdDSA: "pubkey_hex:sig_hex"
    public_key_hex  TEXT NOT NULL,           -- BabyJubJub public key
    duration_ms     INTEGER NOT NULL,        -- FORK 1 execution time
    mode            TEXT NOT NULL,           -- "tunnel" or "governed"
    file_format     TEXT                     -- "pdf"/"docx"/"text" for zemtik_read_file; NULL otherwise
);
```

### Special records: bypass events

When `zemtik_fetch` is called with a domain not in `ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS`:
- In **HTTP server mode**: the request is blocked. A record is written with `tool_name = "zemtik_fetch_bypass"`, `mode = "bypass_blocked"`, and empty `attestation_sig` (no signature — the tool was not executed, so there is no output to sign).
- In **stdio mode**: the request executes (local trust model), with `mode = "bypass_stdio"` and empty `attestation_sig`.

These bypass records are audit artifacts only — they document that an out-of-policy request was attempted.

---

## Viewing Audit Records

**stdio mode (no HTTP listener):**
```bash
zemtik list-mcp               # Last 20 records, table format
zemtik list-mcp --limit 100   # Last 100 records
```

### Inspecting a Single Receipt

To retrieve full detail for one receipt by UUID (e.g., during incident investigation):

```bash
zemtik list-mcp --id ab8095b8-a7f4-4ce7-bc36-9c8470aba1bf
```

Output:
```
┌─────────────────────────────────────────────────────────────────┐
│  MCP Audit Receipt                                              │
├─────────────────────────────────────────────────────────────────┤
│  ID          ab8095b8-a7f4-4ce7-bc36-9c8470aba1bf              │
│  Tool        zemtik_fetch                                       │
│  Timestamp   2026-04-29T14:23:01.456Z                          │
│  Duration    312ms                                              │
│  Mode        tunnel                                             │
│  Format      —                                                  │
├─────────────────────────────────────────────────────────────────┤
│  Hashes                                                         │
│  input   sha256:a1b2c3d4...                                    │
│  output  sha256:e5f6a7b8...                                    │
├─────────────────────────────────────────────────────────────────┤
│  Attestation   present                                          │
│  pubkey  <64-char BabyJubJub public key hex>                   │
│  sig     <BabyJubJub EdDSA signature>                          │
├─────────────────────────────────────────────────────────────────┤
│  Preview input                                                  │
│  (none — preview disabled)                                      │
├─────────────────────────────────────────────────────────────────┤
│  Preview output                                                 │
│  (none — preview disabled)                                      │
└─────────────────────────────────────────────────────────────────┘
```

Preview fields are populated only when the tool was called with preview logging enabled. Previews contain the first 500 chars of tool input/output — never enable in production if inputs may contain PII.

**HTTP server mode (`zemtik mcp-serve`):**
```bash
# JSON (all records)
curl -H "Authorization: Bearer $ZEMTIK_MCP_API_KEY" http://127.0.0.1:4001/mcp/audit

# HTML dashboard (for browser / compliance review)
curl -H "Accept: text/html" -H "Authorization: Bearer $ZEMTIK_MCP_API_KEY" \
  http://127.0.0.1:4001/mcp/audit
```

---

## Verifying a Signature

Each record includes the BabyJubJub public key that produced the signature, enabling offline verification without access to the Zemtik server.

### What is signed

The signature covers a SHA-256 digest of the concatenation:

```text
message = tool_name + input_hash + output_hash + ts
```

Where `+` is string concatenation. `input_hash` and `output_hash` are always 71-character strings (`sha256:` + 64 hex digits), so the field boundaries are unambiguous.

The message is then reduced modulo the BN254 scalar field order before signing:

```text
msg_bigint = SHA-256(message) mod BN254_r
```

### Verification using babyjubjub-rs (Rust)

```rust
use babyjubjub_rs::PrivateKey;
use num_bigint::BigInt;
use sha2::{Digest, Sha256};

fn verify(record: &McpAuditRecord, public_key_x: &BigInt, public_key_y: &BigInt) -> bool {
    let message = format!(
        "{}{}{}{}",
        record.tool_name, record.input_hash, record.output_hash, record.ts
    );
    let hash = Sha256::digest(message.as_bytes());
    let bn254_r = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    ).unwrap();
    let msg_bigint = BigInt::from_bytes_le(num_bigint::Sign::Plus, &hash) % &bn254_r;

    // Parse sig: "r_b8.x:s"
    let parts: Vec<&str> = record.attestation_sig.splitn(2, ':').collect();
    // ... use babyjubjub_rs::verify(pk, sig, msg_bigint)
    // TODO: Working BabyJubJub signature verification recipe — see issue in TODOS.md
    unimplemented!("verification not yet wired — see TODOS.md")
}
```

### Verification using Python (independent check)

```python
# pip install pysha3 babyjubjub
import hashlib, json

def verify_record(record: dict, pub_key_x: int, pub_key_y: int) -> bool:
    message = (
        record["tool_name"]
        + record["input_hash"]
        + record["output_hash"]
        + record["ts"]
    )
    digest = hashlib.sha256(message.encode()).digest()
    BN254_r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    msg_int = int.from_bytes(digest, "little") % BN254_r
    # Parse attestation_sig: "<r_b8.x>:<s>"
    r_x_str, s_str = record["attestation_sig"].split(":", 1)
    # Use a babyjubjub Python library to verify (r_b8.x, s) against (pub_key_x, pub_key_y)
    # TODO: Working BabyJubJub signature verification recipe — see issue in TODOS.md
    raise NotImplementedError("verification not yet wired — see TODOS.md")
```

---

## Tunnel vs Governed Mode

| | Tunnel | Governed |
|--|--------|---------|
| FORK 1 response to Claude | Tool result only | Tool result + attestation sidecar |
| FORK 2 audit record | Always written (async) | Always written (async) |
| Claude Desktop user sees | No change to tool output | `_zemtik_attestation` field in every response |
| `zemtik_analyze` available | Yes (when anonymizer enabled) | Yes (when anonymizer enabled) |
| Default | Yes (`ZEMTIK_MCP_MODE=tunnel`) | No |
| When to use | Pilot (zero Claude impact) | Production compliance requirement |

Set mode via `ZEMTIK_MCP_MODE=governed` in `config.yaml` or environment.

---

## Retention and Storage

Audit records are stored in `~/.zemtik/mcp_audit.db` (SQLite). There is no automatic expiry or rotation.

**stdio mode durability:** Best-effort. FORK 2 writes are async with a 1-second timeout. If the process exits before FORK 2 completes, the in-flight record may not be written. For compliance requirements needing guaranteed durability, use HTTP server mode (`zemtik mcp-serve`) with a persistent host process.

**HTTP server mode durability:** The host process is long-lived. FORK 2 failures are logged to stderr (`[MCP] FORK 2 error: ...`) but do not affect FORK 1 responses.

---

## Key Management

The BabyJubJub signing key is stored at `~/.zemtik/keys/bank_sk` (POSIX mode 0600). It is auto-generated on first `zemtik mcp` or `zemtik mcp-serve` startup.

Each audit record includes the `public_key_hex` used to produce its signature. This means:
- **Records signed before a key rotation remain verifiable** using the public key stored in each record.
- **Key rotation** is manual: delete `~/.zemtik/keys/bank_sk` and restart. A new key is generated automatically. Add a note in your audit log about the rotation date.

The signing key is **hardcoded-denied** in `zemtik_read_file` — Claude cannot read it regardless of `ZEMTIK_MCP_ALLOWED_PATHS` configuration.

---

## Security Boundaries

| Threat | Mitigation |
|--------|-----------|
| Claude reads signing key via `zemtik_read_file` | Hardcoded deny for all paths under `~/.zemtik/`. Cannot be overridden by config. |
| Symlink pointing into `~/.zemtik/` | `canonicalize()` resolves symlinks before the deny check. |
| SSRF via `zemtik_fetch` | Two-stage guard: (1) `ssrf_block_reason` (sync) — rejects non-HTTPS, literal private IPs, `file://`, malformed URLs; (2) `ssrf_dns_guard` (async) — resolves hostname via `tokio::net::lookup_host`, rejects if any returned IP is private/loopback (RFC 1918, loopback, 0.0.0.0/8, 169.254/16 IMDS, 100.64/10 CGNAT, broadcast, IPv4-mapped IPv6). Vetted IPs pinned via `resolve_to_addrs` to prevent TOCTOU rebinding. Domain allowlist (`ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS`) applied as an additional layer in `mcp-serve` mode. |
| Path traversal via `zemtik_read_file` | HTTP server mode: requires explicit `ZEMTIK_MCP_ALLOWED_PATHS`. Empty list = deny all. |
| Bearer token timing attack | `constant_time_eq` comparison on `/mcp/audit` and `/mcp/summary`. |
| Unauthenticated tool calls from LAN | Default bind is `127.0.0.1:4001`. Startup warning if non-loopback. |
| Audit record tampering | Each record is independently signed with BabyJubJub EdDSA. Verify with the `public_key_hex` field. |

### SSRF block error contract

When `zemtik_fetch` is blocked by the SSRF guard, it returns an MCP error (not a tool result):

```json
{ "code": -32002, "message": "ssrf_blocked: <reason>" }
```

Common `<reason>` values:

- `non-HTTPS scheme blocked` — only `https://` is allowed
- `private/loopback IP blocked: 192.168.1.1` — literal private IP in URL
- `private/loopback IP blocked: 127.0.0.1` — DNS resolved to loopback
- `DNS resolution failed for evil.example.com: ...` — hostname did not resolve
- `invalid URL: ...` — malformed input

**No audit record is written for SSRF blocks.** The `outcome` field in the audit DB is only populated for calls that reach the HTTP client. Blocks by the domain allowlist (`ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS`) do write an audit record with `outcome: zemtik_fetch_bypass`; SSRF blocks do not.

**Known bypass:** If the `HTTP_PROXY` or `HTTPS_PROXY` environment variables are set on the host, the reqwest HTTP client will tunnel `zemtik_fetch` requests through that proxy, bypassing the DNS-based SSRF guard. Do not set proxy environment variables on the host running zemtik in production. This is tracked as a code-level fix in the issue backlog (see TODOS.md).

---

## Known Audit/Compliance Limitations (v1)

The following gaps are documented and tracked in the issue backlog (see TODOS.md):

- **No hash chain**: mcp_audit.db rows are individually signed (BabyJubJub EdDSA) but there is no `prev_record_hash` linking records into a chain. A deleted record leaves a gap with no cryptographic evidence of the deletion.
- **No replay protection**: Evidence Pack receipts do not include a server-generated nonce. An old valid receipt could be re-presented as evidence of a new query.
- **No algorithm versioning**: Receipt records do not include an `alg` or `sig_version` field. Future algorithm changes will require a migration strategy.
- **No NTP requirement**: Timestamps are written from the local system clock. Clock skew or manipulation is not detected.
- **Audit DB file permissions**: Not enforced at create time in v1. Recommended: `chmod 0600 ~/.zemtik/mcp_audit.db`.
- **Single-operator separation of duties**: The same operator who runs the proxy can read and (silently) delete audit records. SOC 2 CC6.3 multi-party access control is not enforced.
- **No automatic audit DB expiry or rotation**: See RUNBOOK.md for manual retention procedure.
- **`ZEMTIK_MCP_TRANSPORT=sse` removed**: SSE transport was sunset on 2026-04-01. Setting this variable now causes a hard startup error (`SSE transport removed — use ZEMTIK_MCP_TRANSPORT=http or mcp-serve`). Remove the variable or set it to `http`.

---

## Custom Tools (`mcp_tools.json`)

Register additional MCP tools beyond the built-in `zemtik_fetch` and `zemtik_read_file` by pointing `ZEMTIK_MCP_TOOLS_PATH` at a JSON file.

**Schema:** [`docs/mcp_tools.schema.json`](docs/mcp_tools.schema.json)

**Example `mcp_tools.json`:**

```json
[
  {
    "name": "search_contracts",
    "description": "Search indexed contracts by keyword or clause type. Returns matching document IDs and excerpts.",
    "input_schema": {
      "type": "object",
      "properties": {
        "query": {
          "type": "string",
          "description": "Search query — keywords, clause names, or party names"
        },
        "limit": {
          "type": "integer",
          "description": "Maximum results to return (default 10, max 50)",
          "default": 10
        }
      },
      "required": ["query"]
    }
  }
]
```

Tool names must be lowercase ASCII alphanumeric + underscores. `input_schema` must be a JSON object with `"type": "object"`. Custom tools are attested and logged identically to built-in tools — each call produces an `McpAuditRecord` in `mcp_audit.db`.
