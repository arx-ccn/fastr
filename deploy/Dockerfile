# syntax=docker/dockerfile:1
# =============================================================================
# Dockerfile - fastr production image (minimal)
#
# Builds the Odin relay with a statically linked vendored libsecp256k1 and
# includes Git and curl for GRASP synchronization and private-peer discovery.
#
# Build (--network=host may be needed to fetch the Odin toolchain + secp256k1):
#   podman build --network=host -f deploy/Dockerfile -t fastr .
#
# Run:
#   podman run -d \
#     -p 127.0.0.1:8080:8080 \
#     -v fastr-data:/data \
#     --name fastr \
#     fastr
#
# TLS termination is handled by your reverse proxy (nginx, Caddy, etc.).
# Bind to 127.0.0.1 and proxy from there.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — build
# -----------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git cmake make clang llvm curl xz-utils libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Odin toolchain (pinned monthly release).
ARG ODIN_RELEASE=dev-2026-05
RUN curl -fsSL -o /tmp/odin.tar.gz \
    "https://github.com/odin-lang/Odin/releases/download/${ODIN_RELEASE}/odin-linux-amd64-${ODIN_RELEASE}.tar.gz" \
    && mkdir -p /opt/odin && tar -xzf /tmp/odin.tar.gz -C /opt/odin --strip-components=1 \
    && ln -s /opt/odin/odin /usr/local/bin/odin

WORKDIR /build

# Vendored libsecp256k1 (static, schnorrsig module).
RUN git clone --depth 1 --branch v0.7.0 https://github.com/bitcoin-core/secp256k1 vendor/secp256k1 \
    && cmake -S vendor/secp256k1 -B vendor/secp256k1/build \
        -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
        -DBUILD_SHARED_LIBS=OFF -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF \
        -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_CTIME_TESTS=OFF \
        -DCMAKE_BUILD_TYPE=Release \
    && cmake --build vendor/secp256k1/build -j

COPY src/ src/
COPY cmd/fastr/ cmd/fastr/

# Keep the TLS client enabled for wss:// repository relays.
RUN odin build cmd/fastr -out:fastr-bin -o:speed \
    && strip fastr-bin \
    && mkdir -p /data && chown 65532:65532 /data

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# Non-root UID is 65532 — /data is pre-created with that ownership
# so named volumes and bind mounts work without a separate init step.
# -----------------------------------------------------------------------------
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git curl libssl3t64 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/fastr-bin /fastr
COPY --chown=65532:65532 --from=builder /data /data

ENV FASTR_ADDR=0.0.0.0 \
  FASTR_PORT=8080 \
  FASTR_DATA_DIR=/data \
  FASTR_GRASP_DIR=/data/repos

USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/fastr"]
