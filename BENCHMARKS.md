# Zemtik Anonymizer — Benchmarks

## Week 0 baseline (Phase 0 gate)

**TODO: Run this benchmark on target hardware before the Company 2 demo.**  
Current results are from development hardware (Apple Silicon MacBook Pro, CPU-only).
If p99 on target hardware exceeds 150ms, escalate before the demo date.

### Hardware

| Field | Value |
|---|---|
| Hardware | Apple Silicon MacBook Pro (M-series) |
| Backend | CPU-only (no CUDA) |
| Model | `urchade/gliner_multi_pii-v1` |
| Runtime | Python 3.11, GLiNER 1.2.x |

### Methodology

Input: 1000-token legal contract excerpt in Spanish (LATAM names + org names).  
Metric: p50 / p99 / p99.9 over 50 warmup + 200 timed runs.  
Command:

```bash
cd sidecar && python -m pytest tests/bench_gliner.py -v --benchmark-json bench_results.json
```

### Results

> **TODO: Fill in after running on MacBook Pro.**

| Metric | Latency |
|---|---|
| p50 | — ms |
| p99 | — ms |
| p99.9 | — ms |

### Gate criteria

| Condition | Action |
|---|---|
| p99 ≤ 120ms | Proceed with full implementation |
| 120ms < p99 ≤ 150ms | Switch to GLiNER ONNX quantized, re-benchmark |
| p99 > 150ms post-quantization | Fail-closed with `429 anonymizer_overloaded`; NEVER fail-open |
