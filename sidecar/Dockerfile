FROM python:3.12-slim

WORKDIR /app

# Install grpc-health-probe for Docker healthcheck.
# TARGETARCH is set by BuildKit (amd64, arm64, etc.) — supports multi-arch builds.
ARG TARGETARCH=amd64
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    GRPC_HEALTH_PROBE_VERSION=v0.4.25 && \
    curl -fsSL "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-${TARGETARCH}" \
    -o /usr/local/bin/grpc-health-probe && \
    chmod +x /usr/local/bin/grpc-health-probe && \
    apt-get remove -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Build context must be the repo root:
#   docker build -f sidecar/Dockerfile -t zemtik-sidecar .
#
# GPU build (requires nvidia-container-toolkit on the host):
#   INSTALL_CUDA=true DOCKER_BUILDKIT=1 docker compose --profile anonymizer build
# CPU build (default):
#   docker compose --profile anonymizer build
ARG INSTALL_CUDA=false

COPY sidecar/requirements.txt .
# Install CUDA torch before gliner so gliner picks up CUDA wheels instead of CPU.
# CUDA 12.4 wheels require driver >= 550. Adjust the index URL for other CUDA versions
# (cu118, cu121, cu126 — see https://pytorch.org/get-started/locally/).
RUN if [ "$INSTALL_CUDA" = "true" ]; then \
      pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cu124; \
    fi && \
    pip install --no-cache-dir -r requirements.txt

# Bake the GLiNER model into the image at build time.
# This avoids a 10-30s download on every container start and makes the
# Docker healthcheck transition from NOT_SERVING to SERVING predictable.
# Pass --secret id=hf_token,env=HF_TOKEN to use authenticated HF CDN (faster,
# cache-stable: secret is not stored in image layers or bust model cache on rotation).
# Usage: DOCKER_BUILDKIT=1 docker build --secret id=hf_token,env=HF_TOKEN -f sidecar/Dockerfile -t zemtik-sidecar .
RUN --mount=type=secret,id=hf_token \
    HUGGING_FACE_HUB_TOKEN=$(cat /run/secrets/hf_token 2>/dev/null || echo "") \
    python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi_pii-v1')"
# Bake in spaCy model so presidio-analyzer doesn't download it at runtime.
RUN python -m spacy download en_core_web_lg

COPY sidecar/ .
COPY proto/ /app/proto/

# Generate gRPC stubs from proto files
RUN python -m grpc_tools.protoc \
    -I/app/proto \
    --python_out=/app \
    --grpc_python_out=/app \
    /app/proto/anonymizer.proto \
    /app/proto/health.proto

EXPOSE 50051

HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=6 \
    CMD grpc-health-probe -addr=localhost:50051

CMD ["python", "server.py"]
