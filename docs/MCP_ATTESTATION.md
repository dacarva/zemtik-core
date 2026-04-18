# MCP Attestation — Audit Records

Zemtik MCP attests every tool call Claude makes on your data. For each call, Zemtik:

1. Executes the tool (FORK 1) and returns the result to Claude with zero added latency.
2. Simultaneously (FORK 2, async, 1-second timeout): signs the call with a BabyJubJub EdDSA key and writes a signed audit record to `~/.zemtik/mcp_audit.db`.

The result is a tamper-evident chain of every file read and HTTP fetch the AI performed, who authorized it, and when.

---

## Audit Record Schema

Each record in `mcp_audit.db` (and in `GET /mcp/audit` JSON output) contains:

| Field | Type | Description |
|-------|------|-------------|
| `receipt_id` | string (UUID v4) | Unique ID for this call |
| `ts` | string (ISO 8601 UTC) | When the call was executed |
| `tool_name` | string | Tool called: `zemtik_read_file`, `zemtik_fetch`, or `zemtik_fetch_bypass` |
| `input_hash` | string (`sha256:<hex>`) | SHA-256 of the JSON-serialized tool arguments |
| `output_hash` | string (`sha256:<hex>`) | SHA-256 of the JSON-serialized tool result |
| `preview_input` | string (≤500 chars) | First 500 characters of the tool input (URL or file path) |
| `preview_output` | string (≤500 chars) | First 500 characters of the tool output |
| `attestation_sig` | string (`<r.x>:<s>`) | BabyJubJub EdDSA signature — see Verification below |
| `public_key_hex` | string (`<x>:<y>`) | BabyJubJub public key at time of signing |
| `duration_ms` | integer | FORK 1 execution time in milliseconds |
| `mode` | string | `tunnel` (observe-only) or `governed` (attestation sidecar in response) |

### Special records: bypass events

When `zemtik_fetch` is called with a domain not in `ZEMTIK_MCP_ALLOWED_FETCH_DOMAINS`:
- In **SSE mode**: the request is blocked. A record is written with `tool_name = "zemtik_fetch_bypass"`, `mode = "bypass_blocked"`, and empty `attestation_sig` (no signature — the tool was not executed, so there is no output to sign).
- In **STDIO mode**: the request executes (local trust model), with `mode = "bypass_stdio"` and empty `attestation_sig`.

These bypass records are audit artifacts only — they document that an out-of-policy request was attempted.

---

## Viewing Audit Records

**STDIO mode (no HTTP listener):**
```bash
zemtik list-mcp               # Last 20 records, table format
zemtik list-mcp --limit 100   # Last 100 records
```

**SSE mode (`zemtik mcp-serve`):**
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
    true // placeholder
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
    # ...
    return True  # placeholder
```

---

## Tunnel vs Governed Mode

| | Tunnel | Governed |
|--|--------|---------|
| FORK 1 response to Claude | Tool result only | Tool result + attestation sidecar |
| FORK 2 audit record | Always written (async) | Always written (async) |
| Claude Desktop user sees | No change to tool output | `_zemtik_attestation` field in every response |
| Default | Yes (`ZEMTIK_MCP_MODE=tunnel`) | No |
| When to use | Pilot (zero Claude impact) | Production compliance requirement |

Set mode via `ZEMTIK_MCP_MODE=governed` in `config.yaml` or environment.

---

## Retention and Storage

Audit records are stored in `~/.zemtik/mcp_audit.db` (SQLite). There is no automatic expiry or rotation.

**STDIO mode durability:** Best-effort. FORK 2 writes are async with a 1-second timeout. If the process exits before FORK 2 completes, the in-flight record may not be written. For compliance requirements needing guaranteed durability, use SSE mode (`zemtik mcp-serve`) with a persistent host process.

**SSE mode durability:** The host process is long-lived. FORK 2 failures are logged to stderr (`[MCP] FORK 2 error: ...`) but do not affect FORK 1 responses.

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
| Path traversal via `zemtik_read_file` | SSE mode: requires explicit `ZEMTIK_MCP_ALLOWED_PATHS`. Empty list = deny all. |
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
