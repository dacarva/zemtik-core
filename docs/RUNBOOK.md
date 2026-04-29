# Operator Runbook

**Document type:** Operator Playbook
**Audience:** The person who installs, configures, and administers a zemtik deployment
**Goal:** Concrete commands and procedures — no marketing language

---

## Prerequisites

| Requirement | Version / Notes |
|-------------|----------------|
| Docker + Docker Compose v2 | Use `docker compose` (space), not `docker-compose` (hyphen) |
| Rust toolchain | Required only for non-Docker builds (`cargo build --release`) |
| `nargo` | 1.0.0-beta.19 — required for ZK SlowLane only |
| `bb` (Barretenberg) | v4.0.0-nightly — required for ZK SlowLane only; skip if running FastLane-only |
| `HF_TOKEN` environment variable | HuggingFace token — required for first anonymizer sidecar start (GLiNER model download) |

**Ports used by default:**

| Port | Service |
|------|---------|
| 4000 | zemtik proxy (HTTP) |
| 4001 | MCP attestation HTTP server |
| 50051 | Anonymizer sidecar (gRPC) — internal only; not exposed outside Docker network |

---

## Docker Compose Profiles

The `docker-compose.yml` defines three profiles. The default `zemtik` service starts regardless of which profile is specified.

### Default (no profile)

```bash
docker compose up --build
```

Starts: `zemtik` service only — the OpenAI-compatible proxy on port 4000. No sidecar, no MCP HTTP server.

### `--profile anonymizer`

```bash
ZEMTIK_ANONYMIZER_ENABLED=true docker compose --profile anonymizer up
```

Starts: `zemtik` + `sidecar`. The `sidecar` service runs GLiNER (`urchade/gliner_multi_pii-v1`) and Presidio for named-entity detection. gRPC on port 50051 (internal Docker network only — not exposed to host). Peak RAM: ~800MB. First start downloads the GLiNER model (~400MB) from HuggingFace CDN — requires `HF_TOKEN` for authenticated downloads (faster and cache-stable).

**GPU variant:** To enable CUDA inference (~50–100ms vs ~1–2s on CPU), set `INSTALL_CUDA=true` and rebuild:

```bash
INSTALL_CUDA=true DOCKER_BUILDKIT=1 \
  docker compose --profile anonymizer build --secret id=hf_token,env=HF_TOKEN
ZEMTIK_ANONYMIZER_ENABLED=true docker compose --profile anonymizer up
```

Requires: `nvidia-container-toolkit` on the host, CUDA 12.4, driver >= 550. Uncomment the `deploy` block in `docker-compose.yml` for the `sidecar` service.

### `--profile mcp`

```bash
export ZEMTIK_MCP_API_KEY=$(openssl rand -hex 32)
docker compose --profile mcp up
```

Starts: `mcp` service — the MCP attestation HTTP server (`zemtik mcp-serve`) on port 4001. Can run alongside the anonymizer:

```bash
ZEMTIK_ANONYMIZER_ENABLED=true docker compose --profile anonymizer --profile mcp up
```

`ZEMTIK_MCP_API_KEY` is required — the service will not start without it.

---

## Production Checklist

Review each item before routing production traffic through zemtik.

- [ ] Set `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=false` — fail-closed; regex fallback is for development and testing only. When false, zemtik returns HTTP 503 if the sidecar is unreachable instead of passing data through with regex-only detection (which misses PERSON, ORG, and LOCATION).
- [ ] Set `ZEMTIK_ANONYMIZER_DEBUG_PREVIEW=false` — the debug preview stores 200 characters of the outgoing (tokenized) prompt in the response and in audit records. Disable in production.
- [ ] Set `ZEMTIK_TUNNEL_DEBUG_PREVIEWS=0` — tunnel mode response previews store 500 characters of plaintext LLM output in `tunnel_audit.db`. Disable in production.
- [ ] Set `ZEMTIK_ANONYMIZER_VAULT_TTL_SECS` to your required retention window — default is 300 seconds.
- [ ] Restrict CORS: set `ZEMTIK_CORS_ORIGINS` to specific origins (e.g., `https://app.example.com`). Do not use `*` in production.
- [ ] Set file permissions on sensitive files:
  ```bash
  chmod 0600 ~/.zemtik/mcp_audit.db \
             ~/.zemtik/receipts.db \
             ~/.zemtik/tunnel_audit.db \
             ~/.zemtik/keys/bank_sk
  ```
- [ ] Confirm audit DBs are backed up — there is no automatic backup. See [Audit DB Hygiene](#audit-db-hygiene).
- [ ] Set `ZEMTIK_ANONYMIZER_ENABLED=true` explicitly in your `.env` file.
- [ ] Set `ZEMTIK_MCP_API_KEY` — this is a hard startup error in `mcp-serve` mode; the process will not start without it.
- [ ] Set `ZEMTIK_DASHBOARD_API_KEY` — protects the tunnel dashboard endpoints `/tunnel/audit` and `/tunnel/summary`.
- [ ] Confirm `HF_TOKEN` is set for the first sidecar start so the GLiNER model download succeeds.
- [ ] Verify `ZEMTIK_BIND_ADDR` is not `0.0.0.0:4000` unless zemtik is behind a reverse proxy with authentication. Default is `127.0.0.1:4000`.

---

## Bringing Up the Anonymizer

Step-by-step for a first-time deployment.

**Step 1.** Set required environment variables:

```bash
export ZEMTIK_ANONYMIZER_ENABLED=true
export HF_TOKEN=hf_xxxx          # Your HuggingFace token
export OPENAI_API_KEY=sk-...      # Or ZEMTIK_ANTHROPIC_API_KEY
```

**Step 2.** First start — build the sidecar image and download the GLiNER model (~400MB). This takes 30–120 seconds depending on your connection:

```bash
docker compose --profile anonymizer up --build
```

Wait until you see `anonymizer sidecar: SERVING` in the sidecar logs.

**Step 3.** Health check — confirm the sidecar is reachable:

```bash
curl http://localhost:4000/health
```

Expected: `"anonymizer": {"enabled": true, "sidecar_status": "serving", "probe_latency_ms": <N>}`

If `sidecar_status` is `"unreachable"`, the sidecar is still starting. Wait 30 seconds and retry.

**Step 4.** Smoke test — send a prompt with PII and verify tokenization ran:

```bash
curl -s -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4-nano",
    "messages": [{"role": "user", "content": "Summarize the contract signed by Carlos García of ACME S.A.S."}]
  }' | jq '.zemtik_meta.anonymizer'
```

Expected: `entities_found` >= 2, `sidecar_used: true`.

**Step 5.** Subsequent starts — model is cached in the sidecar Docker volume (`zemtik_models`); no `--build` needed:

```bash
docker compose --profile anonymizer up
```

---

## Bringing Up MCP

### stdio mode (Claude Desktop integration)

stdio mode is the default for Claude Desktop users. No Docker profile is needed — the binary runs directly.

```bash
zemtik mcp
```

For Claude Desktop configuration file paths, see [Claude Desktop Config Paths](#claude-desktop-config-paths). For full Claude Desktop setup instructions, see [docs/MCP_ATTESTATION.md](./MCP_ATTESTATION.md).

**Dry-run test** — validates key generation, creates a test audit record, and exits:

```bash
zemtik mcp --dry-run
# Exit 0: success; exit 1: failure
```

### HTTP server mode (IDE / CI integrations)

```bash
export ZEMTIK_MCP_API_KEY=$(openssl rand -hex 32)
zemtik mcp-serve
# Binds on 127.0.0.1:4001 by default
```

Or via Docker Compose:

```bash
export ZEMTIK_MCP_API_KEY=$(openssl rand -hex 32)
docker compose --profile mcp up
```

**Governed vs tunnel mode:**

| Mode | Behavior |
|------|---------|
| `ZEMTIK_MCP_MODE=tunnel` (default) | Tool result returned immediately to Claude; attestation written in background. Zero Claude latency impact. |
| `ZEMTIK_MCP_MODE=governed` | Attestation sidecar included in every tool response. Claude sees a `_zemtik_attestation` field. Use when a compliance requirement mandates visible attestation. |

---

## Key Rotation

**Downtime required.** There is no hot-swap key rotation in this version.

1. Stop the zemtik process.
2. Delete the private key file:
   ```bash
   rm ~/.zemtik/keys/bank_sk
   ```
3. Update bearer tokens in your `.env`:
   ```bash
   ZEMTIK_MCP_API_KEY=$(openssl rand -hex 32)
   ZEMTIK_DASHBOARD_API_KEY=$(openssl rand -hex 32)
   ZEMTIK_TUNNEL_API_KEY=$(openssl rand -hex 32)
   ```
4. Restart zemtik. A new BabyJubJub key is generated automatically on startup.
5. Document the rotation date in your audit log. All previously-issued signed records remain verifiable using the old public key stored in each record's `public_key_hex` field. **You do not need to preserve the private key for future audit verification** — each record embeds its public key, which is sufficient for signature verification. Archiving the private key is a security anti-pattern; destroy it by deleting it. New records use the new key. There is no dual-key overlap window in this version.

---

## Audit DB Hygiene

**Permissions** (not enforced at create time in this version — set manually):

```bash
chmod 0600 ~/.zemtik/mcp_audit.db \
           ~/.zemtik/receipts.db \
           ~/.zemtik/tunnel_audit.db
```

**Daily backup** — schedule via cron or your platform's equivalent:

```bash
cp ~/.zemtik/mcp_audit.db    /backup/mcp_audit_$(date +%Y%m%d).db
cp ~/.zemtik/receipts.db     /backup/receipts_$(date +%Y%m%d).db
cp ~/.zemtik/tunnel_audit.db /backup/tunnel_audit_$(date +%Y%m%d).db
```

**Retention pruning** — no automatic expiry exists. Prune manually. Consult your legal team before deleting signed audit records (see [docs/COMPLIANCE_LATAM.md](./COMPLIANCE_LATAM.md) — known gap #2).

```bash
# Example: delete MCP audit records older than 2025-01-01
sqlite3 ~/.zemtik/mcp_audit.db \
  "DELETE FROM mcp_audit WHERE ts < '2025-01-01'"
```

**Inspect a single receipt:**

```bash
zemtik list-mcp --id <uuid>
```

**Direct SQLite query:**

```bash
sqlite3 ~/.zemtik/mcp_audit.db \
  "SELECT receipt_id, ts, tool_name, duration_ms FROM mcp_audit ORDER BY ts DESC LIMIT 20"
```

---

## Incident Playbooks

### Signing Key Compromise

1. Stop zemtik immediately.
2. Preserve a copy of `mcp_audit.db` before rotating — records signed with the old key are still verifiable using the `public_key_hex` field stored in each record.
3. Rotate the key — see [Key Rotation](#key-rotation) above.
4. Notify affected parties per your breach notification obligation (GDPR Art. 33 / LGPD Art. 48 within 72 hours of becoming aware).
5. Document the rotation date and reason in your incident log.

### Sidecar PII Leak (Sidecar Returns Original Text Instead of Token)

1. Check sidecar logs:
   ```bash
   docker logs zemtik-sidecar 2>&1 | tail -100
   ```
2. Check anonymizer health:
   ```bash
   curl http://localhost:4000/health
   # Look for: "sidecar_status": "serving"
   ```
3. If sidecar is unhealthy and `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true`, the regex fallback may have run. Regex covers structured patterns (LATAM IDs, IBAN, dates, money) but **does not cover PERSON, ORG, or LOCATION**. Named entities may have passed through in plaintext.
4. Set `ZEMTIK_ANONYMIZER_ENABLED=false` to halt all processing until the sidecar is healthy and you have assessed the exposure.
5. Review `preview_input` and `preview_output` columns in `mcp_audit.db` for the affected time window to determine what was logged.

### Audit DB Corruption

1. Stop zemtik.
2. Run SQLite integrity check:
   ```bash
   sqlite3 ~/.zemtik/mcp_audit.db "PRAGMA integrity_check"
   ```
   Expected output: `ok`. Any other output indicates corruption.
3. If corrupted: restore from your most recent backup.
4. If no backup exists: document as a data-loss event. Signatures in corrupted records cannot be re-verified. Notify relevant stakeholders.

### Regex Fallback Active (Sidecar Down, `fallback_regex=true`)

- **What is covered:** Structured patterns — LATAM IDs, IBAN codes, dates, monetary amounts.
- **What is NOT covered:** PERSON, ORG, LOCATION — these require the GLiNER sidecar.
- **How to detect:** Query `/health` and check `"sidecar_status": "unreachable"`. Or check `zemtik_meta.anonymizer.sidecar_used: false` in proxy responses.
- **Action:** Restore the sidecar service. For production, set `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=false` to reject requests when the sidecar is down rather than allowing partial-coverage processing.

---

## Troubleshooting

### Sidecar OOM (exit code 137 / container killed)

**Symptom:** `docker logs zemtik-sidecar` shows "Killed" or exit code 137.

**Cause:** GLiNER model peak RAM is ~800MB. If the container's memory limit is below this, the OS OOM killer terminates the process.

**Fix:**
1. Increase `mem_limit` for the `sidecar` service in `docker-compose.yml` to at least `1.5g`.
2. Alternatively, build the GPU variant (CUDA inference has a lower peak RAM footprint on some configurations).

```yaml
# In docker-compose.yml, under the sidecar service:
mem_limit: 1536m
```

### BGE-small-en Model Download Fails (Intent Engine)

**Symptom:** Proxy startup hangs or logs "downloading model" for more than 120 seconds.

**Cause:** First start downloads ~130MB from HuggingFace CDN to `~/.zemtik/models/`.

**Corporate proxy fix:**
```bash
export HTTP_PROXY=http://proxy.corp.example.com:3128
export HTTPS_PROXY=http://proxy.corp.example.com:3128
docker compose up
```

**Air-gapped fix:** Pre-stage the model files in `~/.zemtik/models/` from a machine with internet access, then set:
```bash
export ZEMTIK_INTENT_BACKEND=regex
```
Regex backend skips the embedding model entirely. Intent matching is less accurate but functional.

### GLiNER Model Download Fails (Sidecar)

**Symptom:** Sidecar health shows `"starting"` or `"not_serving"` indefinitely.

**Cause:** HuggingFace requires an `HF_TOKEN` for some model downloads.

**Fix:**
```bash
export HF_TOKEN=hf_xxxx
docker compose --profile anonymizer up --build
```

**Diagnosis:**
```bash
docker logs zemtik-sidecar 2>&1 | grep -i "error\|token\|auth\|401\|403"
```

### Port Collisions

| Port conflict | Fix |
|--------------|-----|
| Port 4000 in use | Set `ZEMTIK_BIND_ADDR=127.0.0.1:4100` (or any free port) |
| Port 4001 in use | Set `ZEMTIK_MCP_BIND_ADDR=127.0.0.1:4101` |
| Port 50051 in use | Set `ZEMTIK_ANONYMIZER_SIDECAR_ADDR=http://127.0.0.1:50052` and update the sidecar startup to bind the same port |

### Claude Desktop Config Paths

| Platform | Config file location |
|----------|---------------------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

### `.mcpb` Install Troubleshooting

- If Claude Desktop does not register the zemtik server after opening the `.mcpb` file: restart Claude Desktop and check again.
- To uninstall: remove the `zemtik` entry from `claude_desktop_config.json` and restart Claude Desktop.
- Logs: Claude Desktop writes MCP server stderr to its own application log. Check the app's Developer Tools or equivalent console for `[zemtik]` prefixed output.

---

*For PII anonymizer architecture and entity type reference, see [docs/ANONYMIZER.md](./ANONYMIZER.md). For MCP attestation details and audit record schema, see [docs/MCP_ATTESTATION.md](./MCP_ATTESTATION.md). For compliance and regulatory mapping, see [docs/COMPLIANCE_LATAM.md](./COMPLIANCE_LATAM.md).*
