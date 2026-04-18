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

See `entity_hashes.py` for the 16 supported types and their canonical SHA-256[:4hex] hashes. The hashes must match `src/entity_hashes.rs` in the Rust proxy — never edit them manually.

## Byte offset invariant

GLiNER returns **character** offsets. The server converts them to **UTF-8 byte** offsets before serializing each `AuditSpan` in the gRPC response:

```python
byte_start = len(text[:char_start].encode("utf-8"))
byte_end   = len(text[:char_end].encode("utf-8"))
```

This is critical for correctness with accented Spanish/Portuguese names (e.g., "José García"). Tests in `tests/test_byte_offsets.py` cover this invariant.

## Docker

```bash
docker build -t zemtik-anonymizer .
docker run -p 50051:50051 zemtik-anonymizer
```

The Docker image bakes the GLiNER model at build time (~500 MB image). First build takes 5-10 minutes on a cold cache.
