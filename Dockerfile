# ============================================================
# Stage 1: Builder
# ============================================================
# BUILD_FEATURES controls which Cargo features are compiled in:
#   regex-only  (default) — no fastembed/ONNX; ~150MB image, fast start, regex intent matching
#   embed       — includes fastembed BGE-small-en ONNX; ~450MB image, semantic intent matching
#                 (model downloaded to ~/.zemtik/models/ on first proxy start, ~130MB)
# Result with ZK tools: add ~300MB on top of either base size.
#
# BUILDER_IMAGE / RUNTIME_IMAGE base image selection:
#   regex-only  → rust:1.88-bookworm builder + debian:bookworm-slim runtime (default)
#   embed       → ubuntu:24.04 builder + ubuntu:24.04 runtime
#                 Required: ort-sys (ONNX Runtime) links against glibc 2.38+ symbols
#                 (__isoc23_strtoll, __cxa_call_terminate) not present in glibc 2.36
#                 (Debian Bookworm). Ubuntu 24.04 ships glibc 2.39.
ARG BUILDER_IMAGE=rust:1.88-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim
ARG BUILD_FEATURES=regex-only

FROM ${BUILDER_IMAGE} AS builder

ARG BUILD_FEATURES

# When using ubuntu:24.04 as BUILDER_IMAGE (needed for embed/ONNX builds),
# Rust is not pre-installed. Bootstrap it via rustup with the same toolchain
# version used by the standard rust:1.88-bookworm image.
RUN if ! command -v cargo > /dev/null 2>&1; then \
    apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        curl gcc g++ pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
         | sh -s -- -y --profile minimal --default-toolchain 1.88 \
    && echo '. $HOME/.cargo/env' >> /root/.bashrc; \
  fi

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Cache dependency compilation layer separately from source changes.
COPY Cargo.toml Cargo.lock ./
# Create stub lib/main so `cargo build --release` can resolve the manifest.
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && echo '' > src/lib.rs
RUN cargo build --release --no-default-features --features ${BUILD_FEATURES} 2>&1 | tail -5 || true

# Copy real sources and rebuild (only zemtik crate recompiles — deps are cached).
COPY src/ src/
# Touch all .rs files so Cargo detects the source change (Docker COPY may preserve
# original mtime, making files appear older than the cached stub compilation).
RUN find src -name '*.rs' -exec touch {} +

RUN cargo build --release --no-default-features --features ${BUILD_FEATURES} \
    && strip target/release/zemtik

# ============================================================
# Stage 2: Runtime
# ============================================================
ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}

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
# Pinned ZK tool versions — update these together when bumping nargo/bb.
# bb version must match nargo version; check bb-versions.json in the Aztec repo:
#   https://github.com/AztecProtocol/aztec-packages/blob/next/barretenberg/bbup/bb-versions.json
ARG NARGO_VERSION=1.0.0-beta.19
ARG BB_VERSION=4.0.0-nightly.20260120

# Guard: bb nightly binaries require glibc >= 2.38 (GLIBC_2.38, GLIBC_2.39) and
# libstdc++ >= GLIBCXX_3.4.31. Debian Bookworm ships glibc 2.36 — too old. Fail
# fast at build time rather than silently producing a container where bb crashes
# at runtime and /health reports "bb": false.
# Ubuntu 24.04 (glibc 2.39) satisfies the requirement; pass RUNTIME_IMAGE=ubuntu:24.04.
RUN if [ "$INSTALL_ZK_TOOLS" = "true" ]; then \
    GLIBC_VER=$(ldd --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+$' || echo "0.0"); \
    GLIBC_MAJOR=$(echo "$GLIBC_VER" | cut -d. -f1); \
    GLIBC_MINOR=$(echo "$GLIBC_VER" | cut -d. -f2); \
    if [ "$GLIBC_MAJOR" -lt 2 ] || { [ "$GLIBC_MAJOR" -eq 2 ] && [ "$GLIBC_MINOR" -lt 38 ]; }; then \
        echo ""; \
        echo "ERROR: INSTALL_ZK_TOOLS=true requires glibc >= 2.38, but this image has glibc $GLIBC_VER."; \
        echo "       Barretenberg (bb) nightly binaries link against GLIBC_2.38 / GLIBC_2.39 symbols"; \
        echo "       not present in Debian Bookworm (glibc 2.36). Use RUNTIME_IMAGE=ubuntu:24.04."; \
        echo ""; \
        echo "       Correct invocation:"; \
        echo "         docker build --build-arg INSTALL_ZK_TOOLS=true \\\\"; \
        echo "                      --build-arg RUNTIME_IMAGE=ubuntu:24.04 \\\\"; \
        echo "                      --build-arg BUILDER_IMAGE=ubuntu:24.04 ."; \
        echo ""; \
        exit 1; \
    fi; \
fi

# NOTE: curl|bash@main is intentionally avoided here (supply-chain safety).
# Instead we download pinned release tarballs directly from GitHub.
# noirup/bbup installers pull from @master and must not be used in CI/CD.
# When building internally on a trusted host you can set INSTALL_ZK_TOOLS_INTERNAL=true
# to use the official installers — but never in a published Docker image.
#
# Multi-platform: Docker sets TARGETARCH to "amd64" or "arm64" during buildx.
# Declare it as an ARG so the RUN step can read it.
ARG TARGETARCH
RUN if [ "$INSTALL_ZK_TOOLS" = "true" ]; then \
    apt-get update && apt-get install -y --no-install-recommends git jq && rm -rf /var/lib/apt/lists/* \
    # Map Docker TARGETARCH to nargo and barretenberg arch strings
    && case "${TARGETARCH:-amd64}" in \
         amd64) NARGO_ARCH="x86_64-unknown-linux-gnu" ; BB_ARCH="amd64-linux" ;; \
         arm64) NARGO_ARCH="aarch64-unknown-linux-gnu" ; BB_ARCH="arm64-linux" ;; \
         *) echo "Unsupported TARGETARCH: ${TARGETARCH}" && exit 1 ;; \
       esac \
    # Install nargo from pinned GitHub release
    && NARGO_URL="https://github.com/noir-lang/noir/releases/download/v${NARGO_VERSION}/nargo-${NARGO_ARCH}.tar.gz" \
    && curl -fsSL "$NARGO_URL" -o /tmp/nargo.tar.gz \
    && mkdir -p /root/.nargo/bin \
    && tar -xzf /tmp/nargo.tar.gz -C /root/.nargo/bin \
    && chmod +x /root/.nargo/bin/nargo \
    # Install bb from pinned Aztec release
    # Tag format changed from "aztec-packages-vX.Y.Z" to "vX.Y.Z" for nightly builds.
    # Artifact renamed from barretenberg-x86_64-linux-gnu.tar.gz to barretenberg-{arch}-linux.tar.gz.
    && BB_URL="https://github.com/AztecProtocol/aztec-packages/releases/download/v${BB_VERSION}/barretenberg-${BB_ARCH}.tar.gz" \
    && curl -fsSL "$BB_URL" -o /tmp/bb.tar.gz \
    && mkdir -p /root/.bb \
    && tar -xzf /tmp/bb.tar.gz -C /root/.bb \
    && chmod +x /root/.bb/bb \
    # Move binaries to system PATH
    && mv /root/.nargo/bin/nargo /usr/local/bin/nargo \
    && mv /root/.bb/bb /usr/local/bin/bb \
    && rm -rf /root/.nargo /root/.bb /tmp/nargo.tar.gz /tmp/bb.tar.gz; \
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
