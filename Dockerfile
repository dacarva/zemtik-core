# ============================================================
# Stage 1: Builder
# ============================================================
# regex-only build: no fastembed/ONNX dependency, no nargo/bb required at build time.
# Result: ~150MB runtime image (FastLane only) or ~450MB (INSTALL_ZK_TOOLS=true).
FROM rust:1.88-bookworm AS builder

WORKDIR /build

# Cache dependency compilation layer separately from source changes.
COPY Cargo.toml Cargo.lock ./
# Create stub lib/main so `cargo build --release` can resolve the manifest.
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && echo '' > src/lib.rs
RUN cargo build --release --no-default-features --features regex-only 2>&1 | tail -5 || true

# Copy real sources and rebuild (only zemtik crate recompiles — deps are cached).
COPY src/ src/
# Touch all .rs files so Cargo detects the source change (Docker COPY may preserve
# original mtime, making files appear older than the cached stub compilation).
RUN find src -name '*.rs' -exec touch {} +

RUN cargo build --release --no-default-features --features regex-only \
    && strip target/release/zemtik

# ============================================================
# Stage 2: Runtime
# ============================================================
FROM debian:bookworm-slim

# Set to "true" to install nargo + bb for ZK SlowLane support (~300MB image increase).
# When enabled, also remove ZEMTIK_SKIP_CIRCUIT_VALIDATION from your compose file
# and add a volume for the SRS cache (bb downloads ~1GB SRS on first ZK proof).
ARG INSTALL_ZK_TOOLS=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    # Non-root user for security hardening
    && groupadd -g 1001 zemtik \
    && useradd -u 1001 -g zemtik -m -d /home/zemtik zemtik

# Install ZK tools (nargo + bb) when INSTALL_ZK_TOOLS=true.
# nargo compiles the Noir circuit per ZK request; bb generates UltraHonk proofs.
# On first ZK proof, bb downloads the SRS (~1GB) to /home/zemtik/.bb/.
# Mount a named volume at /home/zemtik/.bb to persist the SRS across restarts.
RUN if [ "$INSTALL_ZK_TOOLS" = "true" ]; then \
    apt-get update && apt-get install -y --no-install-recommends git jq && rm -rf /var/lib/apt/lists/* \
    # Install nargo 1.0.0-beta.19 via noirup
    && curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash \
    && /root/.nargo/bin/noirup --version 1.0.0-beta.19 \
    # Install bb (barretenberg) via bbup for the installed nargo version
    && curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/bbup \
         -o /usr/local/bin/bbup && chmod +x /usr/local/bin/bbup \
    && bbup --noir-version 1.0.0-beta.19 \
    # Move nargo binary to system PATH (keep git — nargo needs it for git dependencies)
    && mv /root/.nargo/bin/nargo /usr/local/bin/nargo \
    && mv /root/.bb/bb /usr/local/bin/bb \
    && rm -rf /root/.nargo /root/.bb; \
fi

# Copy the binary
COPY --from=builder /build/target/release/zemtik /usr/local/bin/zemtik

# Bundle the demo schema config. Operators can override by mounting their own
# schema_config.json at /home/zemtik/.zemtik/schema_config.json.
COPY config/schema_config.demo.json /home/zemtik/.zemtik/schema_config.json

# Bundle ZK circuit sources (Noir source files compiled by nargo at request time).
# Only used when INSTALL_ZK_TOOLS=true; harmless to include in the base image.
COPY circuit/ /home/zemtik/.zemtik/circuit/
# Bundle the EdDSA vendored library that circuit/lib/ references (../../vendor/eddsa).
COPY vendor/ /home/zemtik/.zemtik/vendor/

# Create required runtime directories with correct ownership.
RUN mkdir -p /home/zemtik/.zemtik/keys \
             /home/zemtik/.zemtik/runs \
             /home/zemtik/.zemtik/receipts \
             /home/zemtik/.zemtik/circuit \
    && chown -R zemtik:zemtik /home/zemtik/.zemtik

USER zemtik
WORKDIR /home/zemtik

# Pre-compile ZK circuits as the runtime user so target/ artifacts are owned correctly.
# nargo downloads the poseidon git dependency on first compile (requires git above).
# Skipped automatically when nargo is not installed (FastLane-only image).
RUN if command -v nargo >/dev/null 2>&1; then \
    cd /home/zemtik/.zemtik/circuit/sum && nargo compile \
    && cd /home/zemtik/.zemtik/circuit/count && nargo compile; \
fi

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:4000/health || exit 1

ENTRYPOINT ["zemtik"]
CMD ["proxy"]
