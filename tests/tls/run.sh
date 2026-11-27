#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

port_free "$relay_port"
port_free 8971
build_tls
odin build tests/grasp -o:speed -out:"$work/fastr-graspsmoke"

make_ca() {
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$1" \
        -keyout "$work/$1.key" -out "$work/$1.pem" 2>"$work/openssl.log"
}
make_ca ca
make_ca unrelated
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' >"$work/leaf.ext"
for leaf in A B; do
    mkdir "$work/$leaf"
    serial=0xA1
    if [[ $leaf == B ]]; then serial=0xB2; fi
    openssl req -new -newkey rsa:2048 -nodes -subj /CN=localhost \
        -keyout "$work/$leaf/key.pem" -out "$work/$leaf/req.pem" 2>"$work/openssl.log"
    openssl x509 -req -days 1 -set_serial "$serial" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
        -extfile "$work/leaf.ext" -in "$work/$leaf/req.pem" -out "$work/$leaf/fullchain.pem" 2>>"$work/openssl.log"
    cat "$work/ca.pem" >>"$work/$leaf/fullchain.pem"
done
ln -s "$work/A" "$work/live"
mkdir "$work/encrypted"
ln -s "$work/B/fullchain.pem" "$work/encrypted/fullchain.pem"
openssl pkey -in "$work/B/key.pem" -aes256 -passout pass: -out "$work/encrypted/key.pem"
cert="$work/live/fullchain.pem" key="$work/live/key.pem"
export SSL_CERT_FILE="$work/ca.pem" GIT_SSL_CAINFO="$work/ca.pem"
export FASTR_SMOKE_URL="wss://localhost:$relay_port"
https="https://localhost:$relay_port/"
manual=(FASTR_TLS_CERT_FILE="$cert" FASTR_TLS_KEY_FILE="$key" FASTR_URL="$FASTR_SMOKE_URL")
member=79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798

printf 'invalid PEM\n' >"$work/bad.pem"
reject_startup 'set both FASTR_TLS_CERT_FILE and FASTR_TLS_KEY_FILE' FASTR_TLS_CERT_FILE="$cert"
reject_startup 'set both FASTR_TLS_CERT_FILE and FASTR_TLS_KEY_FILE' FASTR_TLS_CERT_FILE= FASTR_TLS_KEY_FILE="$key"
reject_startup 'TLS certificate setup failed: Certificate' FASTR_TLS_CERT_FILE="$work/bad.pem" FASTR_TLS_KEY_FILE="$key"
reject_startup 'TLS certificate setup failed: Key_Mismatch' FASTR_TLS_CERT_FILE="$cert" FASTR_TLS_KEY_FILE="$work/B/key.pem"
reject_startup 'TLS certificate setup failed: Private_Key' FASTR_TLS_CERT_FILE="$work/encrypted/fullchain.pem" FASTR_TLS_KEY_FILE="$work/encrypted/key.pem"

nip11() {
    "${curl_tls[@]}" --max-time 2 --cacert "$SSL_CERT_FILE" -H 'Accept: application/nostr+json' \
        -D "$work/headers" "$https" >"$work/nip11.json" 2>"$work/curl.log" &&
        grep -iq '^Content-Type: application/nostr+json' "$work/headers" &&
        jq -e '.supported_nips | index(11) != null' "$work/nip11.json" >/dev/null
}

start_relay public "${manual[@]}"
await 5 nip11 || fail 'No verified NIP-11 response'
if curl --disable --noproxy '*' --fail --silent --max-time 2 "http://127.0.0.1:$relay_port/" >/dev/null; then
    fail 'TLS listener accepted plaintext HTTP'
fi
timeout 30 "$work/fastr-smoke"
invalid_wss() {
    if timeout 20 env "$@" "$work/fastr-smoke" >"$work/untrusted.log" 2>&1; then
        fail 'Untrusted WSS upgrade succeeded'
    fi
    grep -Fq 'with NIP-11 Accept: Tls' "$work/untrusted.log" || fail 'WSS did not reject the TLS handshake'
}
invalid_wss SSL_CERT_FILE="$work/unrelated.pem"
invalid_wss FASTR_SMOKE_URL="wss://127.0.0.1:$relay_port"

leaf_serial() {
    timeout 4 openssl s_client -connect "127.0.0.1:$relay_port" -servername localhost \
        -verify_hostname localhost -verify_return_error -CAfile "$SSL_CERT_FILE" </dev/null 2>"$work/verify.log" |
        openssl x509 -noout -serial
}
rotate_to() {
    ln -s "$1" "$work/live.next"
    mv -Tf "$work/live.next" "$work/live"
    kill -HUP "$relay_pid"
}
[[ $(leaf_serial) == serial=A1 ]] || fail 'Expected leaf A1'
timeout 25 "$work/fastr-smoke" tls-reload "$work" 15 &
driver_pid=$!
await 5 test -f "$work/held" || fail 'WSS subscription was not established'
rotate_to "$work/encrypted"
await 5 grep -Fq 'keeping current certificate (Private_Key)' "$work/relay.log" || fail 'Encrypted reload not rejected'
[[ $(leaf_serial) == serial=A1 ]] || fail 'Encrypted reload replaced A1'
mkdir "$work/wrong"
ln -s "$work/B/fullchain.pem" "$work/wrong/fullchain.pem"
ln -s "$work/A/key.pem" "$work/wrong/key.pem"
rotate_to "$work/wrong"
await 5 grep -Fq 'keeping current certificate (Key_Mismatch)' "$work/relay.log" || fail 'Mismatched reload not rejected'
[[ $(leaf_serial) == serial=A1 ]] || fail 'Failed reload replaced A1'
rotate_to "$work/B"
await 5 grep -Fq 'TLS certificate reloaded' "$work/relay.log" || fail 'Successful reload not logged'
[[ $(leaf_serial) == serial=B2 ]] || fail 'Expected leaf B2 after SIGHUP'
touch "$work/rotated"
wait "$driver_pid"
driver_pid=
stop_relay

start_relay whitelist "${manual[@]}" FASTR_WHITELIST="$member"
await 5 nip11 || fail 'Whitelist relay not ready'
FASTR_WHITELIST="$member" timeout 30 "$work/fastr-smoke"
stop_relay

FASTR_TLS_CERT_FILE="$cert" FASTR_TLS_KEY_FILE="$key" timeout 80 "$work/fastr-graspsmoke" "$work/fastr"

read -r _ _ send_max </proc/sys/net/ipv4/tcp_wmem
((send_max <= 8 * 1024 * 1024)) || fail 'Backpressure fixture requires tcp_wmem maximum <= 8 MiB'
start_relay backpressure "${manual[@]}"
await 5 nip11 || fail 'Backpressure relay not ready'
timeout 150 "$work/fastr-smoke" backpressure
stop_relay

start_relay capped "${manual[@]}" FASTR_MAX_CONNECTIONS=1
await 5 nip11 || fail 'Capped relay not ready'
timeout 14 bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1"; : >"$2"; read -ru 3 || :' _ "$relay_port" "$work/raw-open" &
driver_pid=$!
await 2 test -f "$work/raw-open" || fail 'Silent TCP client did not connect'
if nip11; then fail 'Incomplete TLS handshake did not occupy the only slot'; fi
await 12 nip11 || fail 'Silent ClientHello did not release its slot'
wait "$driver_pid"
driver_pid=

mkfifo "$work/no-head"
exec 9<>"$work/no-head"
timeout 14 openssl s_client -quiet -brief -ign_eof -connect "127.0.0.1:$relay_port" -servername localhost \
    -verify_hostname localhost -verify_return_error -CAfile "$SSL_CERT_FILE" <&9 >"$work/idle.out" 2>"$work/idle.log" &
driver_pid=$!
await 2 grep -Fq 'CONNECTION ESTABLISHED' "$work/idle.log" || fail 'Silent HTTPS handshake did not complete'
if nip11; then fail 'Incomplete HTTP head did not occupy the only slot'; fi
await 12 nip11 || fail 'Silent HTTP head did not release its slot'
if ! wait "$driver_pid"; then
    grep -Fq 'unexpected eof' "$work/idle.log" || fail 'Silent HTTPS client did not receive EOF'
fi
driver_pid=
exec 9>&-
printf 'Native TLS integration passed\n'
