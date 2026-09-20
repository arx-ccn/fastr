#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
suite="${1:-all}"
if (( $# > 0 )); then
    shift
fi
if [[ "$suite" != all && ( ! "$suite" =~ ^[a-z0-9]+$ || ! -d "$root/tests/unit/$suite" ) ]]; then
    printf 'Unknown test suite: %s\n' "$suite" >&2
    exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/fastr-tests.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

# Compile tests with their package to retain access to private declarations.
# Mirror the layout so imports, embedded assets, and foreign libraries resolve.
cp -R "$root/src" "$root/cmd" "$root/tests" "$work/"
ln -s "$root/vendor" "$work/vendor"

for test_dir in "$root"/tests/unit/*; do
    name="${test_dir##*/}"
    if [[ "$suite" != all && "$suite" != "$name" ]]; then
        continue
    fi

    package="src/$name"
    flags=()
    if [[ "$name" == fastr ]]; then
        package="cmd/fastr"
        # Config tests mutate process environment variables.
        flags=(-define:ODIN_TEST_THREADS=1)
    elif [[ "$name" == wsclient ]]; then
        package="tests/wsclient"
    fi

    cp -R "$test_dir/." "$work/$package/"
    odin test "$work/$package" "$@" "${flags[@]}"
done
