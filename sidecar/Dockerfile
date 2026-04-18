FROM python:3.12-slim

WORKDIR /app

# Install grpc-health-probe for Docker healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    GRPC_HEALTH_PROBE_VERSION=v0.4.25 && \
    curl -fsSL "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64" \
    -o /usr/local/bin/grpc-health-probe && \
    chmod +x /usr/local/bin/grpc-health-probe && \
    apt-get remove -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bake the GLiNER model into the image at build time.
# This avoids a 10-30s download on every container start and makes the
# Docker healthcheck transition from NOT_SERVING to SERVING predictable.
RUN python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi_pii-v1')"

COPY . .

# Generate gRPC stubs from proto files
COPY ../proto /app/proto
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
