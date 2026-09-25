# Build the relay binary (release)
build:
    odin build cmd/fastr -out:fastr -o:speed

# Build with debug info
build-debug:
    odin build cmd/fastr -out:fastr-debug -debug

# Run all package test suites
test:
    bash tests/run.sh

# Type-check every package
check:
    odin check src/secp256k1 -vet -strict-style -no-entry-point
    odin check src/pack -vet -strict-style -no-entry-point
    odin check src/policy -vet -strict-style -no-entry-point
    odin check src/negentropy -vet -strict-style -no-entry-point
    odin check src/nostr -vet -strict-style -no-entry-point
    odin check src/git -vet -strict-style -no-entry-point
    odin check src/githttp -vet -strict-style -no-entry-point
    odin check src/grasp -vet -strict-style -no-entry-point
    odin check src/store -vet -strict-style -no-entry-point
    odin check src/tls -vet -strict-style -no-entry-point
    odin check src/peersync -vet -strict-style -no-entry-point
    odin check src/ws -vet -strict-style -no-entry-point
    odin check cmd/fastr
    odin check tests/smoke
    odin check tests/grasp
    odin check tests/wsclient -vet -strict-style -no-entry-point
    odin check cmd/wsq
    odin check cmd/genevent
    odin check tests/bench/query
    odin check tests/bench/relay

# Clone + build vendored libsecp256k1 (one-time)
vendor:
    test -d vendor/secp256k1 || git clone --depth 1 --branch v0.7.0 \
        https://github.com/bitcoin-core/secp256k1 vendor/secp256k1
    cmake -S vendor/secp256k1 -B vendor/secp256k1/build \
        -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
        -DBUILD_SHARED_LIBS=OFF -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF \
        -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_CTIME_TESTS=OFF \
        -DCMAKE_BUILD_TYPE=Release
    cmake --build vendor/secp256k1/build -j

# Self-contained end-to-end smoke test: spawns a throwaway fastr on
# $FASTR_SMOKE_PORT (default 18080) with a temp data dir, runs the client
# against it, and cleans up.
smoke: build
    #!/usr/bin/env bash
    set -euo pipefail
    odin build tests/smoke -out:fastr-smoke -o:speed
    port="${FASTR_SMOKE_PORT:-18080}"
    data=$(mktemp -d)
    FASTR_PORT="$port" FASTR_DATA_DIR="$data" ./fastr &
    pid=$!
    trap 'kill "$pid" 2>/dev/null || true; rm -rf "$data"' EXIT
    sleep 1
    FASTR_PORT="$port" ./fastr-smoke

# Run the self-contained GRASP-01 end-to-end test (spawns its own fastr;
# needs the git CLI as a dev dependency)
smoke-grasp: build
    odin build tests/grasp -out:fastr-graspsmoke -o:speed
    ./fastr-graspsmoke ./fastr
