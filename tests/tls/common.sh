# Sourced by the Linux TLS integration runners.
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/fastr-tls.XXXXXX")
relay_pid= driver_pid= ca_name=
relay_port=18443

stop_relay() {
    if [[ -n "$relay_pid" ]]; then
        kill "$relay_pid" 2>/dev/null || :
        wait "$relay_pid" 2>/dev/null || :
        relay_pid=
    fi
}

cleanup() {
    local status=$?
    if [[ -n "$driver_pid" ]]; then
        kill "$driver_pid" 2>/dev/null || :
        wait "$driver_pid" 2>/dev/null || :
    fi
    stop_relay
    if [[ -n "$ca_name" ]]; then
        podman stop --time 2 "$ca_name" >/dev/null 2>&1 || :
    fi
    if ((status == 0)); then
        rm -rf -- "$work"
    else
        printf 'TLS test artifacts: %s\n' "$work" >&2
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() { printf '%s\n' "$*" >&2; exit 1; }

await() {
    local seconds=$1 deadline
    shift
    deadline=$((SECONDS + seconds))
    while ! "$@"; do
        if ((SECONDS >= deadline)); then return 1; fi
        sleep .05
    done
}

port_free() {
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
        fail "Port $1 is already in use"
    fi
}

build_tls() {
    odin build cmd/fastr -o:speed -out:"$work/fastr"
    odin build tests/smoke -o:speed -out:"$work/fastr-smoke"
}

start_relay() {
    local data=$1
    shift
    env FASTR_ADDR=127.0.0.1 FASTR_PORT="$relay_port" FASTR_DATA_DIR="$work/$data" \
        FASTR_GRASP_ENABLED=0 "$@" "$work/fastr" >"$work/relay.log" 2>&1 &
    relay_pid=$!
}

reject_startup() {
    local message=$1 status=0
    shift
    timeout 8 env FASTR_ADDR=127.0.0.1 FASTR_PORT="$relay_port" FASTR_DATA_DIR="$work/rejected" \
        FASTR_GRASP_ENABLED=0 "$@" "$work/fastr" >"$work/rejected.log" 2>&1 || status=$?
    [[ $status == 1 ]] || fail "Expected startup exit 1, got $status: $message"
    grep -Fq "$message" "$work/rejected.log" || fail "Missing startup error: $message"
    ! grep -Fq 'fastr listening' "$work/rejected.log" || fail "Bound before failing startup"
}

curl_tls=(curl --disable --noproxy '*' --fail --silent --show-error --http1.1)
export NO_PROXY=localhost,127.0.0.1,acme-relay.test
unset FASTR_TLS_CERT_FILE FASTR_TLS_KEY_FILE FASTR_ACME_DOMAIN FASTR_ACME_ACCEPT_TOS FASTR_ACME_DIRECTORY
unset FASTR_URL FASTR_WHITELIST FASTR_SYNC_PEERS FASTR_SMOKE_DIAL
