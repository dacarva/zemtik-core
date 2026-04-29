# Zemtik Anonymizer Sidecar

GLiNER + Presidio gRPC server that detects PII in free-text and returns entity spans with **byte** offsets. Zemtik's Rust proxy calls this before forwarding prompts to OpenAI.

## Requirements

- Python 3.11+
- RAM: 2 GB minimum (GLiNER model is ~400 MB; inference peaks at ~800 MB)
- Apple Silicon (M-series): uses CPU backend — no CUDA needed, no extra config
- x86_64: CPU backend, same requirements

## Quick start (local dev)

```bash
cd sidecar
pip install -r requirements.txt
python server.py          # listens on 0.0.0.0:50051
```

## Verify the sidecar is healthy

```bash
# With grpc-health-probe installed:
grpc-health-probe -addr localhost:50051
# Expected: status: SERVING
# (may show NOT_SERVING for ~10-30s while GLiNER loads)

# Without grpc-health-probe:
python -c "
import grpc, grpc_health.v1.health_pb2 as h, grpc_health.v1.health_pb2_grpc as hg
ch = grpc.insecure_channel('localhost:50051')
print(hg.HealthStub(ch).Check(h.HealthCheckRequest()).status)
"
# 1 = SERVING
```

## Entity types

Zemtik supports 23 entity types. The canonical hash codes are SHA-256-derived 4-hex codes (first 2 bytes of SHA-256 hash of the entity type name, encoded as 4 hex chars) — values defined in `src/entity_hashes.rs` and mirrored in `sidecar/zemtik_entity_hashes.py`. Both files must stay in sync with each other.

To inspect entity type hash codes, see `src/entity_hashes.rs`.

**Two entity hash files exist:**
- `zemtik_entity_hashes.py` — canonical file used by `server.py`
- `entity_hashes.py` — compatibility shim that imports from `zemtik_entity_hashes.py`

Both must stay in sync with `src/entity_hashes.rs`. Never edit hash values manually — regenerate from the canonical derivation (`SHA256(entity_type.encode('utf-8'))[:2].hex()`).

## Byte offset invariant

GLiNER returns **character** offsets. The server converts them to **UTF-8 byte** offsets before serializing each `AuditSpan` in the gRPC response:

```python
byte_start = len(text[:char_start].encode("utf-8"))
byte_end   = len(text[:char_end].encode("utf-8"))
```

This is critical for correctness with accented Spanish/Portuguese names (e.g., "José García"). Tests in `tests/test_byte_offsets.py` cover this invariant.

## Docker

Build from the **repo root** (required — the Dockerfile copies both `sidecar/` and `proto/`):

```bash
# Unauthenticated build (slower HF CDN, same cache behavior):
docker build -f sidecar/Dockerfile -t zemtik-sidecar .

# Authenticated build (faster download, cache-stable across HF_TOKEN rotation):
# The --secret flag passes HF_TOKEN into the build layer without storing it in the image.
export HF_TOKEN=hf_your_token
DOCKER_BUILDKIT=1 docker build \
  --secret id=hf_token,env=HF_TOKEN \
  -f sidecar/Dockerfile -t zemtik-sidecar .

docker run --rm -p 50051:50051 zemtik-sidecar
```

The image bakes GLiNER (`urchade/gliner_multi_pii-v1`) **and** spaCy `en_core_web_lg` at build time (~900 MB image, ~400 MB GLiNER + ~400 MB spaCy). First build takes 5–15 minutes on a cold cache. Subsequent builds are fast because model layers are cached.

## Troubleshooting

**`ImportError: attempted relative import with no known parent package`**

Sidecar crashes on every gRPC call with `Exception calling application`. Cause: `zemtik_entity_hashes.py` is run as a top-level script, not as part of a package. Fix is already applied — `zemtik_entity_hashes.py` uses a `try/except ImportError` fallback. If you see this, ensure you're running `python server.py` from `/app`, not via `python -m sidecar.server`.

**First request returns `sidecar_used: false` (tonic lazy connect)**

The Rust proxy builds a gRPC channel with `connect_lazy()` — TCP is deferred until the first call. With `ZEMTIK_ANONYMIZER_FALLBACK_REGEX=true`, if the first call races with the connection setup it may silently fall back to regex. The startup health ping (`[ANON] Sidecar OK at …`) warms the connection. If you skip `docker compose up` and start the proxy before the sidecar is `SERVING`, wait for `grpc-health-probe -addr=localhost:50051` to return `SERVING` before sending requests.

**Verify sidecar is receiving requests:**

```bash
# Manual gRPC call (requires grpcurl):
grpcurl -plaintext -d '{"text": "Hello Jose Garcia", "entity_types": ["PERSON"]}' \
  localhost:50051 zemtik.anonymizer.v1.AnonymizerService/Anonymize
```

**`HF_TOKEN` not set warning at runtime**

`Warning: unauthenticated requests to HF Hub` — this is cosmetic. Model files are baked into the image so no download occurs. Pass `HUGGING_FACE_HUB_TOKEN` at `docker run` time to silence it if HF Hub rate limits become an issue.
