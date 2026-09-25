#!/usr/bin/env bash
# Sequential, isolated relay comparisons, locally via PATH or in the Podman image.
# RELAYS: space/comma-separated subset of fastr strfry rnostr nostr-rs-relay chorus n0str.
# REPEATS=3 EVENTS=10000 QUERIES=500 CONCURRENCY=8 TIMEOUT=600s
# RESULTS_FILE defaults to the user cache; artifacts persist beside the report.
set -euo pipefail
set +m # Each setsid child must retain $! as its process-group leader.
export LC_ALL=C

RELAYS="${RELAYS:-fastr strfry n0str}"
REPEATS="${REPEATS:-3}"
EVENTS="${EVENTS:-10000}"
QUERIES="${QUERIES:-500}"
CONCURRENCY="${CONCURRENCY:-8}"
TIMEOUT="${TIMEOUT:-600s}"
RESULTS_FILE="${RESULTS_FILE:-${XDG_CACHE_HOME:-$HOME/.cache}/fastr-bench/results.md}"
log() { printf '[bench] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

for name in REPEATS EVENTS QUERIES CONCURRENCY; do
  [[ "${!name}" =~ ^[1-9][0-9]*$ ]] || die "${name} must be a positive integer"
done
[[ "$TIMEOUT" =~ ^[0-9]+([.][0-9]+)?[smhd]?$ ]] &&
  awk -v t="$TIMEOUT" 'BEGIN { exit !(t + 0 > 0) }' || die "TIMEOUT must be a positive duration, e.g. 600s or 10m"
read -r -a selected <<<"${RELAYS//,/ }"
((${#selected[@]})) || die "RELAYS must select at least one relay"
declare -A ports=([fastr]=18080 [strfry]=18081 [rnostr]=18082 [nostr-rs-relay]=18083 [chorus]=18084 [n0str]=18085)
declare -A seen=()
for relay in "${selected[@]}"; do
  [[ -v "ports[$relay]" ]] || die "Unknown relay: $relay"
  [[ ! -v "seen[$relay]" ]] || die "Duplicate relay: $relay"
  seen[$relay]=1
done
for tool in fastr-bench timeout setsid awk mktemp sha256sum du realpath; do
  command -v "$tool" >/dev/null || die "Required command not in PATH: $tool"
done

mkdir -p "$(dirname "$RESULTS_FILE")"
RESULTS_FILE="$(realpath -m "$RESULTS_FILE")"
mkdir -p "${RESULTS_FILE%.md}.runs"
ARTIFACTS="$(mktemp -d "${RESULTS_FILE%.md}.runs/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
MANIFEST="$ARTIFACTS/workloads.tsv"
RAW="$ARTIFACTS/results.tsv"
STATUS="$ARTIFACTS/status.tsv"
RESOURCES="$ARTIFACTS/resources.tsv"
TIMESTAMP="$(($(date +%s) - 60))"
printf 'relay\trepeat\tworkload\toperations\twall_ms\tthroughput\tp50_us\tp99_us\terrors\treturned_events\n' >"$RAW"
printf 'relay\trepeat\tstatus\texit_code\n' >"$STATUS"
printf 'relay\trepeat\trss_after_kib\tdb_allocated_after_bytes\tprocess_write_bytes_delta\n' >"$RESOURCES"
fastr-bench suite --list-workloads >"$MANIFEST" 2>"$ARTIFACTS/manifest.log"
awk -F '\t' '
  NF != 2 || $1 != "WORKLOAD" || $2 !~ /^[a-z][a-z0-9_]*$/ || seen[$2]++ { bad=1 }
  END { exit (bad || NR == 0) }
' "$MANIFEST" || die "Invalid suite workload manifest; see $ARTIFACTS"
{
  printf 'UTC: '; date -u +%FT%TZ
  printf 'Kernel: '; uname -srmo
  printf 'Available CPUs: '; nproc
  for f in /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpuset.cpus.effective; do
    if [[ -r "$f" ]]; then printf '%s: ' "$f"; cat "$f"; fi
  done
  printf 'RELAYS=%s REPEATS=%s EVENTS=%s QUERIES=%s CONCURRENCY=%s TIMEOUT=%s TIMESTAMP=%s\n' \
    "${selected[*]}" "$REPEATS" "$EVENTS" "$QUERIES" "$CONCURRENCY" "$TIMEOUT" "$TIMESTAMP"
  if [[ -r /usr/local/share/fastr-bench/versions.txt ]]; then
    cat /usr/local/share/fastr-bench/versions.txt
  else
    printf 'Build version metadata unavailable (local PATH run); binary SHA-256 follows.\n'
  fi
  sha256sum "$0"
  for binary in fastr-bench "${selected[@]}"; do
    if path="$(command -v "$binary")"; then sha256sum "$path"; else printf '%s: MISSING\n' "$binary"; fi
  done
} >"$ARTIFACTS/provenance.txt"

RELAY_PID="" DRIVER_PID="" DATA="" ACTIVE="" RUN_DIR="" COLLECTED=""
FAILED=0
stop_process() {
  local pid="$1" i
  [[ -n "$pid" ]] || return 0
  kill -TERM -- "-$pid" 2>/dev/null || true
  for ((i=0; i<50; i++)); do
    kill -0 -- "-$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL -- "-$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  stop_process "$DRIVER_PID"; DRIVER_PID=""
  stop_process "$RELAY_PID"; RELAY_PID=""
  if [[ -n "$DATA" ]]; then rm -rf -- "$DATA"; DATA=""; fi
}
record_status() {
  printf '%s\t%s\t%s\t%s\n' "$relay" "$repeat" "$1" "$2" >>"$STATUS"
  log "$relay repeat $repeat: $1 (exit $2); logs: $RUN_DIR"
  [[ "$1" == ok ]] || FAILED=1
  ACTIVE=""
}
collect_rows() {
  # Preserve even malformed machine rows; the stdout log also retains progress.
  awk -F '\t' '$1 == "RESULT"' "$RUN_DIR/driver.stdout.log" >"$RUN_DIR/results.tsv"
  awk -F '\t' -v OFS='\t' -v r="$relay" -v n="$repeat" '
    { sub(/^RESULT\t/, ""); print r, n, $0 }
  ' "$RUN_DIR/results.tsv" >>"$RAW"
  COLLECTED=1
}
valid_rows() {
  awk -F '\t' '
    function error(message) { print message; bad=1 }
    FILENAME == ARGV[1] { expected[$2]=1; next }
    {
      if (NF != 9) { error("Malformed RESULT row at line " FNR); next }
      if (!($2 in expected) || seen[$2]++) error("Unexpected or duplicate workload: " $2)
      for (i=3; i<=9; i++)
        if ($i !~ /^[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$/) error("Non-numeric metric: " $2)
      if ($3 !~ /^[0-9]+$/ || $8 !~ /^[0-9]+$/ || $9 !~ /^[0-9]+$/)
        error("Non-integer count: " $2)
      if ($3 + 0 <= 0 || $4 + 0 <= 0 || $7 + 0 < $6 + 0 || $8 + 0 > $3 + 0)
        error("Invalid workload metrics: " $2)
      if (($8 + 0 < $3 + 0 && $5 + 0 <= 0) || ($8 + 0 == $3 + 0 && $5 + 0 != 0))
        error("Throughput contradicts successful operation count: " $2)
      if ($8 + 0 > 0) { print "Workload failed: " $2 " (" $8 " errors)"; failed=1 }
    }
    END {
      for (w in expected) if (!(w in seen)) error("Missing workload: " w)
      exit (bad ? 2 : failed)
    }
  ' "$MANIFEST" "$RUN_DIR/results.tsv" >"$RUN_DIR/validation.log"
}

report() {
  {
    printf '\n## %s - relay suite\n\n' "$(date -u '+%Y-%m-%d %H:%M UTC')"
    printf 'Events=%s; queries/workload=%s; concurrency=%s; repeats=%s; timeout/suite=%s; dataset timestamp=%s.\n\n' \
      "$EVENTS" "$QUERIES" "$CONCURRENCY" "$REPEATS" "$TIMEOUT" "$TIMESTAMP"
    printf 'Artifacts (raw TSV, per-repeat logs/configs, binary provenance): `%s`\n\n' "$ARTIFACTS"
    printf 'Each repeat starts an empty database; relays run sequentially, rotating the starting relay by one each repeat. Execution order is recorded in provenance below. Rates count successful operations. '
    printf 'Medians below aggregate independent repeats; latency columns are medians of per-repeat percentiles, not pooled percentiles. '
    printf 'Each workload needs every repeat to succeed before aggregation. Query rows also require all ingest workloads to succeed in that repeat. '
    printf 'A complete, schema-valid suite with workload errors retains other valid comparisons, but the runner still exits nonzero. '
    printf 'Startup failures, timeouts, unexpected exits, malformed rows and incomplete suites invalidate the entire repeat. Partial measurements remain in the raw files. No winners are assigned.\n\n'
    printf '| Relay | Repeat | Status | Exit code |\n|---|---:|---|---:|\n'
    awk -F '\t' 'NR>1 { printf "| %s | %s | %s | %s |\n", $1,$2,$3,$4 }' "$STATUS"
    printf '\n| Workload | Relay | Valid repeats | Median ops/s | Median p50 (us) | Median p99 (us) |\n'
    printf '|---|---|---:|---:|---:|---:|\n'
    awk -F '\t' -v relays="${selected[*]}" -v repeats="$REPEATS" '
      function median(key, col, n,    i,j,t,a) {
        for (i=1; i<=n; i++) a[i]=values[key,col,i]
        for (i=2; i<=n; i++) {
          t=a[i]; j=i-1
          while (j>0 && a[j]>t) { a[j+1]=a[j]; j-- }
          a[j+1]=t
        }
        return n%2 ? a[(n+1)/2] : (a[n/2]+a[n/2+1])/2
      }
      FILENAME == ARGV[1] {
        workloads[++wc]=$2
        if ($2 ~ /^ingest_/) { ingest[$2]=1; ingest_count++ }
        next
      }
      FNR == 1 { next }
      FILENAME == ARGV[2] {
        usable[$1,$2]=($3=="ok" || $3=="workload_failed")
        next
      }
      {
        run=$1 SUBSEP $2; key=$1 SUBSEP $3
        present[run,$3]++; errors[run,$3]=$9+0
        if (($3 in ingest) && $9+0==0) ingest_good[run]++
        for (i=6; i<=8; i++) values[key,i,$2]=$i+0
      }
      END {
        rc=split(relays, names, " ")
        for (w=1; w<=wc; w++) for (r=1; r<=rc; r++) {
          name=names[r]; workload=workloads[w]; key=name SUBSEP workload; good=0
          for (n=1; n<=repeats; n++) {
            run=name SUBSEP n
            if (usable[run] && present[run,workload]==1 && errors[run,workload]==0 &&
                ((workload in ingest) || ingest_good[run]==ingest_count)) good++
          }
          printf "| %s | %s | %d/%d | ", workload,name,good,repeats
          if (good!=repeats)
            print "N/A (FAILED/INCOMPLETE) | N/A | N/A |"
          else printf "%.2f | %.2f | %.2f |\n",median(key,6,repeats),median(key,7,repeats),median(key,8,repeats)
        }
      }
    ' "$MANIFEST" "$STATUS" "$RAW"
    printf '\n### Post-suite resource observations (not peaks)\n\n'
    printf 'RSS is the relay process snapshot immediately after its driver exits. Database bytes are allocated disk blocks while the relay is running, including preallocation. '
    printf 'Write bytes are the Linux `/proc/PID/io` delta for the relay PID during the suite, not device-wide writes, durable bytes, or all mmap writeback. '
    printf 'These are observations even for failed runs; unavailable values are N/A.\n\n'
    printf '| Relay | Repeat | RSS snapshot (KiB) | DB allocated bytes | Process write bytes delta |\n|---|---:|---:|---:|---:|\n'
    awk -F '\t' 'NR>1 { printf "| %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5 }' "$RESOURCES"
    printf '\n<details><summary>Version and environment provenance</summary>\n\n```text\n'
    cat "$ARTIFACTS/provenance.txt"
    printf '```\n\n</details>\n'
  } >"$ARTIFACTS/report.md" || return 1
  cat "$ARTIFACTS/report.md" >>"$RESULTS_FILE" || return 1
  cat "$ARTIFACTS/report.md"
}
finish() {
  local code=$?
  trap - EXIT INT TERM
  # Terminate writers before preserving a partially emitted suite after interruption.
  cleanup
  if [[ -n "$ACTIVE" ]]; then
    if [[ -z "$COLLECTED" && -f "$RUN_DIR/driver.stdout.log" ]]; then collect_rows; fi
    record_status interrupted "$code"
  fi
  report || { log "Could not append report; artifacts remain at $ARTIFACTS"; code=1; }
  exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
wait_ready() {
  local i
  for ((i=0; i<150; i++)); do
    kill -0 "$RELAY_PID" 2>/dev/null || return 1
    port_open "$port" && return 0
    sleep 0.2
  done
  return 1
}
proc_value() {
  local file="$1" key="$2" value
  value="$(awk -v key="$key" '$1 == key { print $2; exit }' "$file" 2>/dev/null)" || true
  printf '%s\n' "${value:-N/A}"
}

launch_relay() {
  local config="$RUN_DIR/relay.conf"
  local -a command
  case "$relay" in
    fastr)
      command=(env FASTR_ADDR=127.0.0.1 "FASTR_PORT=$port" "FASTR_DATA_DIR=$DATA" fastr)
      ;;
    strfry)
      cat >"$config" <<CFG
db = "$DATA"
relay {
    bind = "127.0.0.1"
    port = $port
    nofiles = 0
    compression {
        enabled = false
        slidingWindow = false
    }
}
CFG
      command=(strfry --config "$config" relay)
      ;;
    rnostr)
      config="$RUN_DIR/relay.toml"
      cat >"$config" <<CFG
[information]
name = "rnostr-bench"
[data]
path = "$DATA"
[network]
host = "127.0.0.1"
port = $port
[limitation]
max_limit = 500
[auth]
enabled = false
[rate_limiter]
enabled = false
CFG
      command=(rnostr relay -c "$config")
      ;;
    nostr-rs-relay)
      config="$RUN_DIR/relay.toml"
      cat >"$config" <<CFG
[info]
name = "nostr-rs-relay-bench"
[database]
engine = "sqlite"
data_directory = "$DATA"
[network]
address = "127.0.0.1"
port = $port
[limits]
messages_per_sec = 0
subscriptions_per_min = 0
limit_scrapers = false
[authorization]
nip42_auth = false
nip42_dms = false
CFG
      command=(nostr-rs-relay --config "$config")
      ;;
    chorus)
      cat >"$config" <<CFG
data_directory = "$DATA"
ip_address = "127.0.0.1"
port = $port
hostname = "localhost"
chorus_is_behind_a_proxy = false
use_tls = false
name = "chorus-bench"
open_relay = true
verify_events = true
allow_scraping = true
enable_ip_blocking = false
max_connections_per_ip = $((CONCURRENCY + 16))
throttling_bytes_per_second = 1073741824
throttling_burst = 1073741824
CFG
      command=(chorus "$config")
      ;;
    n0str)
      config="$RUN_DIR/relay.json"
      printf '{"name":"n0str-bench"}\n' >"$config"
      # Keep upstream signature validation and SQLite durability settings.
      command=(n0str --port "$port" --database "$DATA/nostr.db" --config "$config")
      ;;
  esac
  printf '%q ' "${command[@]}" >"$RUN_DIR/command.txt"
  printf '\n' >>"$RUN_DIR/command.txt"
  setsid "${command[@]}" >"$RUN_DIR/relay.log" 2>&1 &
  RELAY_PID=$!
}

for ((repeat=1; repeat<=REPEATS; repeat++)); do
  offset=$(((repeat - 1) % ${#selected[@]}))
  run_order=("${selected[@]:offset}" "${selected[@]:0:offset}")
  printf 'Repeat %s execution order: %s\n' "$repeat" "${run_order[*]}" >>"$ARTIFACTS/provenance.txt"
  for relay in "${run_order[@]}"; do
    port="${ports[$relay]}"
    RUN_DIR="$ARTIFACTS/$relay/$repeat"
    mkdir -p "$RUN_DIR"
    ACTIVE=1
    COLLECTED=""
    if ! command -v "$relay" >/dev/null; then
      record_status missing_binary 127
      continue
    fi
    if port_open "$port"; then
      record_status port_in_use 1
      continue
    fi
    DATA="$(mktemp -d "${TMPDIR:-/tmp}/fastr-bench-${relay}-XXXXXX")"
    launch_relay
    if ! wait_ready; then
      record_status startup_failed 1
      cleanup
      continue
    fi
    io_before="$(proc_value "/proc/$RELAY_PID/io" write_bytes:)"
    log "$relay repeat $repeat/$REPEATS: running suite"
    driver=(fastr-bench suite --url "ws://127.0.0.1:$port" --events "$EVENTS" \
      --queries "$QUERIES" --concurrency "$CONCURRENCY" --timestamp "$TIMESTAMP")
    printf '%q ' timeout --kill-after=5s "$TIMEOUT" "${driver[@]}" >>"$RUN_DIR/command.txt"
    printf '\n' >>"$RUN_DIR/command.txt"
    setsid timeout --kill-after=5s "$TIMEOUT" "${driver[@]}" \
      >"$RUN_DIR/driver.stdout.log" 2>"$RUN_DIR/driver.stderr.log" &
    DRIVER_PID=$!
    code=0
    wait "$DRIVER_PID" || code=$?
    DRIVER_PID=""
    rss="$(proc_value "/proc/$RELAY_PID/status" VmRSS:)"
    io_after="$(proc_value "/proc/$RELAY_PID/io" write_bytes:)"
    io_delta=N/A
    if [[ "$io_before" =~ ^[0-9]+$ && "$io_after" =~ ^[0-9]+$ ]] && ((io_after >= io_before)); then
      io_delta=$((io_after - io_before))
    fi
    disk="$(du -s -B1 "$DATA" 2>"$RUN_DIR/disk.log" | awk '{print $1}')" || disk=N/A
    printf '%s\t%s\t%s\t%s\t%s\n' "$relay" "$repeat" "$rss" "${disk:-N/A}" "$io_delta" >>"$RESOURCES"
    collect_rows
    row_code=0
    valid_rows || row_code=$?
    if ((code == 124 || code == 137)); then state=timeout
    elif ! kill -0 "$RELAY_PID" 2>/dev/null; then state=relay_exited
    elif ((row_code == 2)); then state=invalid_results
    elif ((code != 0 && !(code == 1 && row_code == 1))); then state=driver_failed
    elif ((row_code == 1)); then state=workload_failed
    else state=ok
    fi
    record_status "$state" "$code"
    cleanup
  done
done
exit "$FAILED"
