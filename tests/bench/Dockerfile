# syntax=docker/dockerfile:1
# Six real relays: fastr, strfry, rnostr, nostr-rs-relay, Chorus, and n0str.
# Build from the repo root: podman build -f tests/bench/Dockerfile -t fastr-bench .
# Run with a writable /results mount; see docs/BENCHMARKS.md for controls.


# -----------------------------------------------------------------------------
# Stage 1 - build the fastr relay and the fastr-bench driver (both Odin).
# Uses the runner's Debian release with the pinned Odin compiler.
# -----------------------------------------------------------------------------
FROM docker.io/library/debian:trixie AS odin-builder

ARG ODIN_RELEASE=dev-2026-09

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  curl ca-certificates git \
  cmake clang llvm build-essential libssl-dev \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/odin.tar.gz \
    "https://github.com/odin-lang/Odin/releases/download/${ODIN_RELEASE}/odin-linux-amd64-${ODIN_RELEASE}.tar.gz" && \
  mkdir -p /opt/odin && \
  tar -xzf /tmp/odin.tar.gz -C /opt/odin --strip-components=1 && \
  ln -s /opt/odin/odin /usr/local/bin/odin && \
  rm /tmp/odin.tar.gz

WORKDIR /build

RUN git clone --depth 1 --branch v0.7.0 \
    https://github.com/bitcoin-core/secp256k1 vendor/secp256k1 && \
  cmake -S vendor/secp256k1 -B vendor/secp256k1/build \
    -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
    -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DSECP256K1_BUILD_TESTS=OFF \
    -DSECP256K1_BUILD_BENCHMARK=OFF \
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
    -DSECP256K1_BUILD_CTIME_TESTS=OFF \
    -DCMAKE_BUILD_TYPE=Release && \
  cmake --build vendor/secp256k1/build -j

COPY src/ src/
COPY cmd/fastr/ cmd/fastr/
COPY tests/bench/relay/ tests/bench/relay/
COPY tests/wsclient/ tests/wsclient/

RUN odin build cmd/fastr -out:fastr -o:speed && strip fastr && \
    odin build tests/bench/relay -out:fastr-bench -o:speed && strip fastr-bench && \
    odin version > /odin-version


# -----------------------------------------------------------------------------
# Stage 2 - build strfry from source.
# -----------------------------------------------------------------------------
FROM docker.io/library/debian:trixie AS strfry-builder

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
  git ca-certificates \
  g++ make cmake pkg-config \
  libssl-dev zlib1g-dev \
  liblmdb-dev \
  libflatbuffers-dev flatbuffers-compiler \
  libsecp256k1-dev \
  libzstd-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG STRFRY_REF=4cd3cf64850caf47dda46c2a2abbbf3525a64d10
RUN git init . && git remote add origin https://github.com/hoytech/strfry.git && \
  git fetch --depth 1 origin "${STRFRY_REF}" && git checkout --detach FETCH_HEAD && \
  git submodule update --init --recursive && \
  printf 'strfry %s\n' "$(git rev-parse HEAD)" > /strfry-version

RUN make setup-golpe && make -j2

RUN strip strfry


# -----------------------------------------------------------------------------
# Stage 3 - build rnostr from source.
# Built on bookworm so the binary's glibc requirement stays below the
# trixie-based runner stage.
# -----------------------------------------------------------------------------
FROM docker.io/library/rust:1-slim-bookworm AS rnostr-builder
ENV CARGO_BUILD_JOBS=8

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
  git ca-certificates build-essential \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG RNOSTR_REF=0983e527b23d3fe18f3d92b407ce31793900e767
RUN git init . && git remote add origin https://github.com/rnostr/rnostr.git && \
  git fetch --depth 1 origin "${RNOSTR_REF}" && git checkout --detach FETCH_HEAD

RUN cargo build --release --bin rnostr && strip target/release/rnostr && \
  printf 'rnostr %s\n' "$(git rev-parse HEAD)" > /rnostr-version && \
  rustc --version >> /rnostr-version


# -----------------------------------------------------------------------------
# Stage 4 - build nostr-rs-relay (SQLite).
# -----------------------------------------------------------------------------
FROM docker.io/library/rust:1-slim-bookworm AS rs-relay-builder
ENV CARGO_BUILD_JOBS=8

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
  git ca-certificates build-essential cmake protobuf-compiler pkg-config libssl-dev \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ARG RS_RELAY_REF=b5c1f642e4f4c3b9c54f5d18d66f4c53642076b4
RUN git init . && git remote add origin https://github.com/scsibug/nostr-rs-relay.git && \
  git fetch --depth 1 origin "${RS_RELAY_REF}" && git checkout --detach FETCH_HEAD
RUN cargo build --release --locked --bin nostr-rs-relay && \
  strip target/release/nostr-rs-relay && \
  printf 'nostr-rs-relay %s\n' "$(git rev-parse HEAD)" > /rs-relay-version && \
  rustc --version >> /rs-relay-version


# -----------------------------------------------------------------------------
# Stage 5 - build Chorus (Pocket/LMDB).
# -----------------------------------------------------------------------------
FROM docker.io/library/rust:1-slim-bookworm AS chorus-builder
ENV CARGO_BUILD_JOBS=8

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
  git ca-certificates build-essential cmake clang \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ARG CHORUS_REF=411f16ad18397cd3474016015f7f074a0c285430
RUN git init . && git remote add origin https://github.com/mikedilger/chorus.git && \
  git fetch --depth 1 origin "${CHORUS_REF}" && git checkout --detach FETCH_HEAD
RUN cargo build --release --locked --bin chorus && strip target/release/chorus && \
  printf 'chorus %s\n' "$(git rev-parse HEAD)" > /chorus-version && \
  rustc --version >> /chorus-version

# n0str is an upstream Bun/TypeScript server, not a benchmark implementation.
# Its native bun:sqlite backend needs no V8 addon or dependency lifecycle scripts.
FROM docker.io/oven/bun:1.4.2 AS n0str-builder

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
  git ca-certificates \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ARG N0STR_REF=2b7c77c05d8eaf5df4adb18fa3e4c66245cb2780
RUN git init . && git remote add origin https://github.com/tani/n0str.git && \
  git fetch --depth 1 origin "${N0STR_REF}" && git checkout --detach FETCH_HEAD && \
  bun --no-env-file install --frozen-lockfile --production --ignore-scripts && \
  printf 'n0str https://github.com/tani/n0str %s\n' "$(git rev-parse HEAD)" > /n0str-version && \
  printf 'Bun ' >> /n0str-version && bun --revision >> /n0str-version && \
  sha256sum bun.lock package.json /usr/local/bin/bun >> /n0str-version


# -----------------------------------------------------------------------------
# Stage 7 - benchmark runner.
# -----------------------------------------------------------------------------
FROM docker.io/library/debian:trixie-slim AS runner

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
  ca-certificates \
  liblmdb0 libzstd1 libssl3 libsecp256k1-2 \
  procps util-linux \
  && rm -rf /var/lib/apt/lists/*

COPY --from=odin-builder   /build/fastr        /usr/local/bin/fastr
COPY --from=odin-builder   /build/fastr-bench  /usr/local/bin/fastr-bench
COPY --from=strfry-builder /build/strfry       /usr/local/bin/strfry
COPY --from=rnostr-builder /build/target/release/rnostr /usr/local/bin/rnostr
COPY --from=rs-relay-builder /build/target/release/nostr-rs-relay /usr/local/bin/nostr-rs-relay
COPY --from=chorus-builder /build/target/release/chorus /usr/local/bin/chorus
COPY --from=n0str-builder /usr/local/bin/bun /usr/local/bin/bun
COPY --from=n0str-builder /build/index.ts /build/package.json /build/bun.lock /build/tsconfig.json /build/LICENSE /opt/n0str/
COPY --from=n0str-builder /build/src/ /opt/n0str/src/
COPY --from=n0str-builder /build/node_modules/ /opt/n0str/node_modules/
COPY --from=strfry-builder /strfry-version /usr/local/share/fastr-bench/strfry-version
COPY --from=rnostr-builder /rnostr-version /usr/local/share/fastr-bench/rnostr-version
COPY --from=rnostr-builder /build/Cargo.lock /usr/local/share/fastr-bench/rnostr-Cargo.lock
COPY --from=odin-builder /odin-version /usr/local/share/fastr-bench/odin-version
COPY --from=rs-relay-builder /rs-relay-version /usr/local/share/fastr-bench/rs-relay-version
COPY --from=chorus-builder /chorus-version /usr/local/share/fastr-bench/chorus-version
COPY --from=n0str-builder /n0str-version /usr/local/share/fastr-bench/n0str-version
COPY --from=n0str-builder /build/bun.lock /usr/local/share/fastr-bench/n0str-bun.lock
COPY tests/bench/n0str.sh /usr/local/bin/n0str
COPY tests/bench/run_bench.sh /usr/local/bin/run_bench.sh

ARG FASTR_REV=worktree
RUN chmod +x /usr/local/bin/run_bench.sh /usr/local/bin/n0str && \
  printf 'fastr %s (source copied from build context)\n' "${FASTR_REV}" \
    > /usr/local/share/fastr-bench/versions.txt && \
  cat /usr/local/share/fastr-bench/*-version >> /usr/local/share/fastr-bench/versions.txt && \
  sha256sum /usr/local/bin/fastr /usr/local/bin/fastr-bench \
    >> /usr/local/share/fastr-bench/versions.txt

ENV RESULTS_FILE=/results/BENCHMARKS.md \
    EVENTS=10000 \
    QUERIES=500 \
    CONCURRENCY=8 \
    REPEATS=3 \
    RELAYS="fastr strfry n0str" \
    BUN_RUNTIME_TRANSPILER_CACHE_PATH=0

RUN mkdir -p /results

ENTRYPOINT ["/usr/local/bin/run_bench.sh"]
