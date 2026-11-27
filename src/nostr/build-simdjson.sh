#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script="$script_dir/${BASH_SOURCE[0]##*/}"
cd -- "$script_dir/../.."
version=v5.3.0
digest=f2ab8324b27884a6f5a833c15266d515cfb11a26421306dc8c76f54882b6af54
root=vendor/simdjson
archive="$root/$version.zip"
library="$root/libfastr_simdjson.a"
source=src/nostr/subscription_decode.cpp
compiler=${CXX:-clang++}
if [[ -f "$library" && "$library" -nt "$source" && "$library" -nt "$script" && "$library" -nt "$archive" ]]; then
    exit 0
fi
mkdir -p "$root"
work=$(mktemp -d "$root/build.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

if [[ ! -f "$archive" ]]; then
    curl -fsSL "https://github.com/simdjson/simdjson/releases/download/$version/singleheader.zip" -o "$work/source.zip"
    mv "$work/source.zip" "$archive"
fi
actual=$(openssl dgst -sha256 -r "$archive")
if [[ "${actual%% *}" != "$digest" ]]; then
    printf 'simdjson: unexpected SHA-256 for %s\n' "$archive" >&2
    exit 1
fi
unzip -q -j "$archive" simdjson.h simdjson.cpp -d "$work"

standard=-std=c++26
if ! "$compiler" "$standard" -x c++ -fsyntax-only /dev/null >/dev/null 2>&1; then
    standard=-std=c++2c
fi
flags=("$standard" -O3 -DNDEBUG -fPIC)
"$compiler" "${flags[@]}" -c "$work/simdjson.cpp" -o "$work/simdjson.o"
"$compiler" "${flags[@]}" -I "$work" -c "$source" -o "$work/subscription_decode.o"
ar rcs "$work/libfastr_simdjson.a" "$work/subscription_decode.o" "$work/simdjson.o"
mv "$work/libfastr_simdjson.a" "$library"
