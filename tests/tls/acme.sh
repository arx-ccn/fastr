#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

port_free "$relay_port"
port_free 14000
port_free 15000
command -v podman >/dev/null || fail 'Pebble verification requires Podman'
build_tls >"$work/build.log" 2>&1 || fail 'Odin test build failed (build.log)'

domain=acme-relay.test
directory=https://localhost:14000/dir
managed=(FASTR_ACME_DOMAIN="$domain" FASTR_ACME_DIRECTORY="$directory")
consent=FASTR_ACME_ACCEPT_TOS=1

reject_startup 'fastr: FASTR_ACME_ACCEPT_TOS=1 is required' "${managed[@]}"
mv "$work/rejected.log" "$work/consent.log"
reject_startup 'fastr: ACME and manual TLS certificates are mutually exclusive' \
    "${managed[@]}" "$consent" FASTR_TLS_CERT_FILE=manual.pem FASTR_TLS_KEY_FILE=manual.key
mv "$work/rejected.log" "$work/conflict.log"
reject_startup 'fastr: ACME helper is missing or not executable: fastr-acme' "${managed[@]}" "$consent"
mv "$work/rejected.log" "$work/missing-helper.log"

nip11() {
    "${curl_tls[@]}" --max-time 2 -H 'Accept: application/nostr+json' "$@" \
        -D "$work/headers" >"$work/nip11.json" 2>"$work/curl.log" &&
        grep -iq '^Content-Type: application/nostr+json' "$work/headers" &&
        jq -e '.supported_nips | index(11) != null' "$work/nip11.json" >/dev/null
}

start_relay plain
await 5 nip11 "http://127.0.0.1:$relay_port/" || fail 'Plaintext startup without worker failed'
stop_relay
mv "$work/relay.log" "$work/plain.log"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost -addext extendedKeyUsage=serverAuth \
    -keyout "$work/manual.key" -out "$work/manual.pem" 2>"$work/openssl.log"
start_relay manual FASTR_TLS_CERT_FILE="$work/manual.pem" FASTR_TLS_KEY_FILE="$work/manual.key"
await 5 nip11 --cacert "$work/manual.pem" "https://localhost:$relay_port/" ||
    fail 'Manual TLS startup without worker failed'
stop_relay
mv "$work/relay.log" "$work/manual.log"

go_supported() {
    local version
    version=$(GOTOOLCHAIN=local "$1" env GOVERSION) || return 1
    [[ $version =~ ^go([0-9]+)\.([0-9]+)(\.|$) ]] &&
        ((BASH_REMATCH[1] > 1 || (BASH_REMATCH[1] == 1 && BASH_REMATCH[2] >= 26)))
}

build_worker() {
    local compiler=go mise_go
    if ! go_supported "$compiler"; then
        compiler=
        if command -v mise >/dev/null && mise_go=$(mise where go@1.27.3) && go_supported "$mise_go/bin/go"; then
            compiler="$mise_go/bin/go"
        fi
    fi
    if [[ -n "$compiler" ]]; then
        (cd cmd/fastr-acme && GOTOOLCHAIN=local CGO_ENABLED=0 "$compiler" build -mod=readonly -trimpath -o "$work/fastr-acme" .)
    else
        podman run --rm --userns=keep-id --security-opt label=disable \
            -e GOTOOLCHAIN=local -e CGO_ENABLED=0 -e GOCACHE=/tmp/go-build -e GOMODCACHE=/tmp/go-mod \
            -v "$root/cmd/fastr-acme:/module:ro" -v "$work:/out:rw" -w /module \
            docker.io/library/golang:1.27.4-bookworm go build -mod=readonly -trimpath -o /out/fastr-acme .
    fi
}
build_worker >"$work/worker-build.log" 2>&1 || fail 'ACME worker build failed (worker-build.log)'

test_files=https://raw.githubusercontent.com/letsencrypt/pebble/v2.8.0/test
"${curl_tls[@]}" --max-time 20 "$test_files/config/pebble-config.json" \
    -o "$work/pebble-upstream.json" 2>"$work/pebble-download.log"
"${curl_tls[@]}" --max-time 20 "$test_files/certs/pebble.minica.pem" \
    -o "$work/pebble.minica.pem" 2>>"$work/pebble-download.log"
jq --argjson tlsPort "$relay_port" '
    .pebble.listenAddress = "127.0.0.1:14000" |
    .pebble.managementListenAddress = "127.0.0.1:15000" |
    .pebble.tlsPort = $tlsPort |
    .pebble.profiles = {default: (.pebble.profiles.default | .validityPeriod = 180)}
' "$work/pebble-upstream.json" >"$work/pebble-config.json"

ca_name="fastr-pebble-${work##*.}"
trap 'cleanup; podman rm "$ca_name" >/dev/null 2>&1 || :' EXIT
podman run -d --name "$ca_name" --network host --add-host "$domain:127.0.0.1" \
    --log-driver=k8s-file --log-opt "path=$work/pebble.log" \
    -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_AUTHZREUSE=0 -e PEBBLE_WFE_NONCEREJECT=0 \
    -v "$work/pebble-config.json:/test/acme-config.json:ro,Z" \
    ghcr.io/letsencrypt/pebble:2.8.0 -strict=false -config /test/acme-config.json \
    >"$work/pebble-start.log" 2>&1 || fail 'Could not start pinned Pebble (pebble-start.log)'
fetch_root() {
    "${curl_tls[@]}" --max-time 2 --cacert "$work/pebble.minica.pem" \
        https://localhost:15000/roots/0 -o "$work/issuance-root.pem" 2>"$work/pebble-root.log"
}
await 10 fetch_root || fail 'Pebble management root not available (pebble-root.log)'
cat "$work/pebble.minica.pem" "$work/issuance-root.pem" >"$work/acme-roots.pem"
export SSL_CERT_FILE="$work/acme-roots.pem"
export FASTR_SMOKE_URL="wss://$domain:$relay_port" FASTR_SMOKE_DIAL="127.0.0.1:$relay_port"

acme_nip11() {
    nip11 --resolve "$domain:$relay_port:127.0.0.1" --cacert "$SSL_CERT_FILE" "https://$domain:$relay_port/"
}
leaf_serial() {
    timeout 4 openssl s_client -connect "$FASTR_SMOKE_DIAL" -servername "$domain" \
        -verify_hostname "$domain" -verify_return_error -CAfile "$SSL_CERT_FILE" \
        </dev/null 2>"$work/verify.log" | openssl x509 -noout -serial 2>>"$work/verify.log"
}

start_relay acme-data "${managed[@]}" "$consent"
await 30 acme_nip11 || fail 'No trusted NIP-11 response from fresh ACME state'
await 2 grep -Fq 'fastr: ACME certificate installed' "$work/relay.log" || fail 'Initial install was not logged'
if grep -Fq 'VA always returns valid' "$work/pebble.log"; then fail 'Pebble skipped real validation'; fi
grep -Eq 'authz .* set VALID by completed challenge' "$work/pebble.log" || fail 'Pebble did not validate the first challenge'

state_hash=$(printf '%s\0%s' "$directory" "$domain" | sha256sum)
acme_root="$work/acme-data/acme"
state="$acme_root/${state_hash%% *}"
owner=$(id -u)
private_file() {
    [[ -f $1 && ! -L $1 && $(stat -c '%a:%u:%h' -- "$1") == "600:$owner:1" ]]
}
for dir in "$acme_root" "$state"; do
    [[ -d $dir && ! -L $dir && $(stat -c '%a:%u' -- "$dir") == "700:$owner" ]] || fail "Unsafe state directory: $dir"
done

no_attempt() {
    ! compgen -G "$state/attempt-*" >/dev/null
}
check_installed_state() {
    await 5 no_attempt || fail 'ACME attempt files were not cleaned up'
    [[ ! -e $state/challenge.pem && ! -L $state/challenge.pem ]] || fail 'Challenge bundle remained outside an attempt directory'
    private_file "$state/account.pem" || fail 'Unsafe or missing account.pem'
    private_file "$state/live.pem" || fail 'Unsafe or missing live.pem'
}
account_fingerprint() {
    openssl pkey -in "$state/account.pem" -pubout -outform DER 2>"$work/fingerprint.log" | sha256sum
}
check_installed_state
first_serial=$(leaf_serial) || fail 'Could not read initial leaf serial'
first_account=$(account_fingerprint) || fail 'Could not fingerprint account key'
[[ $(openssl x509 -in "$state/live.pem" -noout -serial) == "$first_serial" ]] || fail 'Initial served leaf differs from live.pem'
grep -Fq 'There are now 1 orders in the db' "$work/pebble.log" || fail 'Expected one ACME order'
stop_relay
mv "$work/relay.log" "$work/issued.log"

start_relay acme-data "${managed[@]}" "$consent"
await 5 acme_nip11 || fail 'Cached leaf not usable after restart'
[[ $(leaf_serial) == "$first_serial" ]] || fail 'Restart did not reuse cached leaf'
[[ $(account_fingerprint) == "$first_account" ]] || fail 'Restart changed the account key'
if await 3 grep -Fq 'There are now 2 orders in the db' "$work/pebble.log"; then
    fail 'Restart opened a new order before the renewal window'
fi

timeout --kill-after=5s 240 "$work/fastr-smoke" tls-reload "$work" 220 >"$work/held-wss.log" 2>&1 &
driver_pid=$!
await 5 test -f "$work/held" || fail 'WSS subscription was not established (held-wss.log)'
await 215 grep -Fq 'fastr: ACME certificate installed' "$work/relay.log" || fail 'Automatic renewal did not install a certificate'
new_serial=$(leaf_serial) || fail 'Could not read renewed leaf serial'
[[ $new_serial != "$first_serial" ]] || fail 'Automatic renewal did not change the served serial'
[[ $(openssl x509 -in "$state/live.pem" -noout -serial) == "$new_serial" ]] || fail 'Renewed leaf differs from live.pem'
[[ $(account_fingerprint) == "$first_account" ]] || fail 'Renewal changed the account key'
check_installed_state
touch "$work/rotated"
wait "$driver_pid" || fail 'Held WSS connection did not survive renewal (held-wss.log)'
driver_pid=

podman stop --time 2 "$ca_name" >"$work/pebble-stop.log" 2>&1 || fail 'Could not stop the test CA (pebble-stop.log)'
kill -HUP "$relay_pid"
await 30 grep -Fq 'fastr: ACME attempt failed' "$work/relay.log" || fail 'Offline renewal did not log an attempt failure'
acme_nip11 || fail 'CA outage interrupted HTTPS'
[[ $(leaf_serial) == "$new_serial" ]] || fail 'Failed renewal replaced the valid leaf'
await 2 private_file "$state/retry-until" || fail 'Unsafe or missing retry-until'
IFS= read -r retry_until <"$state/retry-until" || fail 'Unreadable retry-until'
[[ $retry_until =~ ^[1-9][0-9]{0,18}$ ]] && ((retry_until > $(date +%s))) || fail 'Retry deadline is not in the future'
stop_relay
mv "$work/relay.log" "$work/offline.log"

start_relay acme-data "${managed[@]}" "$consent"
await 5 acme_nip11 || fail 'CA outage interrupted cached startup'
[[ $(leaf_serial) == "$new_serial" ]] || fail 'Offline restart did not reuse the valid leaf'
kill -HUP "$relay_pid"
retried() {
    grep -Fq 'fastr: ACME attempt failed' "$work/relay.log" || ! no_attempt ||
        [[ $(<"$state/retry-until") != "$retry_until" ]]
}
if await 5 retried; then fail 'Restart or SIGHUP bypassed the persisted retry deadline'; fi
printf 'ACME issuance, automatic renewal, and offline restart passed\n'
