# Build the relay binary (release)
build:
    odin build cmd -out:fastr -o:speed

# Build with debug info
build-debug:
    odin build cmd -out:fastr-debug -debug

# Run all package test suites
test:
    odin test secp256k1
    odin test pack
    odin test negentropy
    odin test nostr
    odin test store
    odin test ws
    odin test cmd

# Type-check every package
check:
    odin check secp256k1 -vet -strict-style -no-entry-point
    odin check pack -vet -strict-style -no-entry-point
    odin check negentropy -vet -strict-style -no-entry-point
    odin check nostr -vet -strict-style -no-entry-point
    odin check store -vet -strict-style -no-entry-point
    odin check ws -vet -strict-style -no-entry-point
    odin check cmd
    odin check smoke
    odin check wsq
    odin check genevent
    odin check qbench
    odin check bench

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

# Run the end-to-end smoke test against a relay on $FASTR_PORT (default 8080)
smoke:
    odin build smoke -out:fastr-smoke -o:speed
    ./fastr-smoke
