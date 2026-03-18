# syntax=docker/dockerfile:1
# =============================================================================
# Dockerfile - fastr production image (minimal)
#
# Builds a statically-linked musl binary and drops it into a scratch image.
# Final image contains only the binary
#
# Build (--network=host lets Cargo reach crates.io at build time):
#   docker build --network=host -f deploy/Dockerfile -t fastr .
#
# Run:
#   docker run -d \
#     -p 127.0.0.1:8080:8080 \
#     -v fastr-data:/data \
#     --name fastr \
#     fastr
#
# TLS termination is handled by your reverse proxy (nginx, Caddy, etc.).
# Bind to 127.0.0.1 and proxy from there.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — build (musl = fully static binary)
# -----------------------------------------------------------------------------
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY benches/ benches/
COPY bench/   bench/

# Cache deps before copying real source
RUN mkdir -p src && \
  printf 'pub fn _stub() {}\n' > src/lib.rs && \
  printf 'fn main() {}\n'      > src/main.rs && \
  cargo build --release --bin fastr 2>/dev/null || true

COPY src/ src/
RUN touch src/lib.rs src/main.rs && \
  cargo build --release --bin fastr && \
  strip target/release/fastr && \
  mkdir -p /data && chown 65532:65532 /data

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# distroless/static:nonroot = ~1.7 MB, no shell, no libc, non-root user built in.
# distroless nonroot UID is 65532 — /data is pre-created with that ownership
# so named volumes and bind mounts work without a separate init step.
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /build/target/release/fastr /fastr
COPY --chown=65532:65532 --from=builder /data /data

ENV FASTR_ADDR=0.0.0.0 \
  FASTR_PORT=8080 \
  FASTR_DATA_DIR=/data

EXPOSE 8080

ENTRYPOINT ["/fastr"]
