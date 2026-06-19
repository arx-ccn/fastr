#!/usr/bin/env bash
# run_bench.sh - benchmark runner executed inside the fastr-bench Docker container.
#
# Runs fastr, strfry, and rnostr sequentially on isolated ports, drives each
# with the fastr-bench driver (ingest + query + RSS sample), then appends a
# timestamped markdown result table to RESULTS_FILE.
#
# Environment variables (with defaults):
#   EVENTS        number of events to ingest per relay  (default: 50000)
#   QUERIES       number of REQ queries per relay        (default: 5000)
#   CONCURRENCY   parallel benchmark workers             (default: 8)
#   RESULTS_FILE  file to append the markdown table to  (default: /results/BENCHMARKS.md)

set -euo pipefail

EVENTS="${EVENTS:-50000}"
QUERIES="${QUERIES:-5000}"
CONCURRENCY="${CONCURRENCY:-8}"
RESULTS_FILE="${RESULTS_FILE:-/results/BENCHMARKS.md}"

FASTR_PORT=8080
STRFRY_PORT=7777
RNOSTR_PORT=7778

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log() { printf '[bench] %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Wait until a TCP port accepts connections (up to 30 s).
# ---------------------------------------------------------------------------

wait_for_port() {
  local label="$1" host="$2" port="$3" logfile="${4:-}"
  local tries=0 max=150 # 150 * 0.2 s = 30 s
  log "Waiting for ${label} on ${host}:${port}..."
  while ! bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; do
    sleep 0.01
    tries=$((tries + 1))
    if ((tries >= max)); then
      log "ERROR: ${label} did not accept connections within 30 s"
      if [[ -n "${logfile}" && -f "${logfile}" ]]; then
        log "--- ${label} log (last 40 lines) ---"
        tail -40 "${logfile}" >&2
        log "--- end log ---"
      fi
      exit 1
    fi
  done
  log "${label} is ready."
}

# ---------------------------------------------------------------------------
# Snapshot VmRSS for a PID (returns KB).
# ---------------------------------------------------------------------------

rss_kb() {
  local pid="$1"
  awk '/^VmRSS:/{print $2; exit}' "/proc/${pid}/status" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# Snapshot write_bytes from /proc/<pid>/io (returns bytes).
# ---------------------------------------------------------------------------

io_write_bytes() {
  local pid="$1"
  awk '/^write_bytes:/{print $2; exit}' "/proc/${pid}/io" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# Count open file descriptors for a PID.
# ---------------------------------------------------------------------------

fd_count() {
  local pid="$1"
  ls "/proc/${pid}/fd" 2>/dev/null | wc -l
}

# ---------------------------------------------------------------------------
# CPU cycle measurement via perf stat.
#
# Uses `perf stat -e cycles:u,cycles:k -p <pid>` to collect user and kernel
# cycle counts for the relay process over the entire benchmark run.
#
# Requires: linux-perf, plus CAP_PERFMON or kernel.perf_event_paranoid <= 1.
# Docker: run with --privileged or --cap-add SYS_PTRACE --cap-add PERFMON.
#
# Usage:
#   start_cpu_sampler <pid>
#   stop_cpu_sampler   # sets CPU_CYCLES_USER, CPU_CYCLES_KERNEL
# ---------------------------------------------------------------------------

start_cpu_sampler() {
  local pid="$1"
  _CPU_PERF_RAW="/tmp/perf_raw_${pid}_$$"
  : >"${_CPU_PERF_RAW}"

  # perf stat with -x, outputs CSV to stderr.  Events:
  #   <count>,,cycles:u,...
  #   <count>,,cycles:k,...
  #   <count>,,raw_syscalls:sys_enter,...
  #   <count>,,context-switches,...
  #   <count>,,minor-faults,...
  perf stat -e cycles:u,cycles:k,raw_syscalls:sys_enter,context-switches,minor-faults \
    -p "${pid}" -x, 2>"${_CPU_PERF_RAW}" &
  _CPU_SAMPLER_PID=$!
}

stop_cpu_sampler() {
  # perf stat prints its summary on SIGINT, not SIGTERM.
  kill -INT "${_CPU_SAMPLER_PID}" 2>/dev/null || true
  wait "${_CPU_SAMPLER_PID}" 2>/dev/null || true

  log "perf raw output:"
  cat "${_CPU_PERF_RAW}" >&2

  # Parse summary lines from perf's CSV output.
  # Field 1 is the count; skip lines with "<not supported>" or "<not counted>".
  local raw_user raw_kernel raw_syscalls raw_ctxsw raw_faults
  raw_user="$(awk -F, '/cycles:u/ && $1 ~ /^[0-9]+$/ {print $1; exit}' "${_CPU_PERF_RAW}")"
  raw_kernel="$(awk -F, '/cycles:k/ && $1 ~ /^[0-9]+$/ {print $1; exit}' "${_CPU_PERF_RAW}")"
  raw_syscalls="$(awk -F, '/raw_syscalls:sys_enter/ && $1 ~ /^[0-9]+$/ {print $1; exit}' "${_CPU_PERF_RAW}")"
  raw_ctxsw="$(awk -F, '/context-switches/ && $1 ~ /^[0-9]+$/ {print $1; exit}' "${_CPU_PERF_RAW}")"
  raw_faults="$(awk -F, '/minor-faults/ && $1 ~ /^[0-9]+$/ {print $1; exit}' "${_CPU_PERF_RAW}")"

  CPU_CYCLES_USER=$(((${raw_user:-0} + 500000) / 1000000))
  CPU_CYCLES_KERNEL=$(((${raw_kernel:-0} + 500000) / 1000000))
  PERF_SYSCALLS="${raw_syscalls:-0}"
  PERF_CTX_SWITCHES="${raw_ctxsw:-0}"
  PERF_MINOR_FAULTS="${raw_faults:-0}"

  rm -f "${_CPU_PERF_RAW}"
}

# ---------------------------------------------------------------------------
# Run the full ingest + query suite against one relay endpoint.
# Writes key=value pairs to stdout so the caller can eval them.
#
# Usage: bench_relay <label> <ws_url> <pid> <data_dir> <neg|noneg>
# bench_relay runs ingest, neg-sync, and query benchmarks against a relay process, samples resource metrics (RSS, open fds, disk I/O delta, and CPU cycles via perf), and emits structured KEY=value results to stdout.
# Pass "noneg" for relays without NIP-77 support: the neg-sync driver has no
# timeout and would block forever waiting for a NEG-MSG that never comes.

bench_relay() {
  local label="$1"
  local ws_url="$2"
  local pid="$3"
  local data_dir="$4"
  local neg_mode="${5:-neg}"

  # Snapshot disk I/O before benchmark.
  local io_write_before
  io_write_before="$(io_write_bytes "${pid}")"

  # Start CPU cycle counting for the relay process.
  start_cpu_sampler "${pid}"

  log "--- ${label}: ingest (${EVENTS} events, concurrency ${CONCURRENCY}) ---"
  local ingest_out
  ingest_out="$(fastr-bench ingest \
    --url "${ws_url}" \
    --events "${EVENTS}" \
    --concurrency "${CONCURRENCY}" 2>&1)" ||
    log "WARNING: ${label} ingest driver exited non-zero"
  log "${ingest_out}"

  # fastr-bench ingest output lines look like:
  #   Throughput:  12345 events/sec    ($2 = number)
  #   OK p50:      456µs              ($NF = last field, strip non-digits)
  #   OK p99:      789µs
  local ingest_throughput ingest_p50 ingest_p99
  ingest_throughput="$(printf '%s\n' "${ingest_out}" |
    awk '/^Throughput:/{gsub(/[^0-9]/,"",$2); print $2; exit}')"
  ingest_p50="$(printf '%s\n' "${ingest_out}" |
    awk '/p50:/{gsub(/[^0-9]/,"",$NF); print $NF; exit}')"
  ingest_p99="$(printf '%s\n' "${ingest_out}" |
    awk '/p99:/{gsub(/[^0-9]/,"",$NF); print $NF; exit}')"

  local neg_wall_ms=""
  if [[ "${neg_mode}" == "neg" ]]; then
    log "--- ${label}: neg-sync (${EVENTS} events, half overlap) ---"
    local neg_out
    neg_out="$(fastr-bench neg-sync \
      --url "${ws_url}" \
      --filter '{"kinds":[1]}' \
      --have $((EVENTS / 2)) 2>&1)" ||
      log "WARNING: ${label} neg-sync driver exited non-zero"
    log "${neg_out}"

    neg_wall_ms="$(printf '%s\n' "${neg_out}" |
      awk '/^Wall time:/{gsub(/[^0-9.]/,"",$NF); printf "%.0f\n", $NF; exit}')"
  else
    log "--- ${label}: neg-sync skipped (no NIP-77 support) ---"
  fi

  log "--- ${label}: query (${QUERIES} queries, concurrency ${CONCURRENCY}) ---"
  local query_out
  query_out="$(fastr-bench query \
    --url "${ws_url}" \
    --queries "${QUERIES}" \
    --concurrency "${CONCURRENCY}" 2>&1)" ||
    log "WARNING: ${label} query driver exited non-zero"
  log "${query_out}"

  # fastr-bench query output lines look like:
  #   Throughput:       12345 queries/sec    ($2 = number)
  #   REQ->EOSE p50:    456µs               ($NF = last field, strip non-digits)
  #   REQ->EOSE p99:    789µs
  local query_throughput query_p50 query_p99
  query_throughput="$(printf '%s\n' "${query_out}" |
    awk '/^Throughput:/{gsub(/[^0-9]/,"",$2); print $2; exit}')"
  query_p50="$(printf '%s\n' "${query_out}" |
    awk '/p50:/{gsub(/[^0-9]/,"",$NF); print $NF; exit}')"
  query_p99="$(printf '%s\n' "${query_out}" |
    awk '/p99:/{gsub(/[^0-9]/,"",$NF); print $NF; exit}')"

  # RSS snapshot after load (settle for 1 s).
  sleep 1
  local peak_rss_kb
  peak_rss_kb="$(rss_kb "${pid}")"
  local peak_rss_mb=$((peak_rss_kb / 1024))

  # FD count at peak load.
  local peak_fds
  peak_fds="$(fd_count "${pid}")"

  # Disk I/O delta.
  local io_write_after io_write_delta io_write_mb
  io_write_after="$(io_write_bytes "${pid}")"
  io_write_delta=$((io_write_after - io_write_before))
  io_write_mb=$((io_write_delta / 1024 / 1024))

  # Disk usage of data directory.
  local disk_bytes disk_kb
  disk_bytes="$(du -sb "${data_dir}" 2>/dev/null | awk '{print $1}')"
  disk_kb=$((${disk_bytes:-0} / 1024))

  # Stop CPU sampler and collect results.
  stop_cpu_sampler

  # Parse error count from ingest output.
  local ingest_errors
  ingest_errors="$(printf '%s\n' "${ingest_out}" |
    awk '/^Errors:/{gsub(/[^0-9]/,"",$2); print $2; exit}')"

  # Emit structured key=value output.
  printf 'INGEST_THROUGHPUT=%s\n' "${ingest_throughput:-0}"
  printf 'INGEST_P50=%s\n' "${ingest_p50:-0}"
  printf 'INGEST_P99=%s\n' "${ingest_p99:-0}"
  printf 'QUERY_THROUGHPUT=%s\n' "${query_throughput:-0}"
  printf 'QUERY_P50=%s\n' "${query_p50:-0}"
  printf 'QUERY_P99=%s\n' "${query_p99:-0}"
  printf 'PEAK_RSS_KB=%s\n' "${peak_rss_kb}"
  printf 'PEAK_RSS_MB=%s\n' "${peak_rss_mb}"
  printf 'CPU_CYCLES_USER=%s\n' "${CPU_CYCLES_USER}"
  printf 'CPU_CYCLES_KERNEL=%s\n' "${CPU_CYCLES_KERNEL}"
  printf 'PERF_SYSCALLS=%s\n' "${PERF_SYSCALLS}"
  printf 'PERF_CTX_SW=%s\n' "${PERF_CTX_SWITCHES}"
  printf 'PERF_MINOR_FAULTS=%s\n' "${PERF_MINOR_FAULTS}"
  printf 'DISK_USAGE_KB=%s\n' "${disk_kb}"
  printf 'IO_WRITE_MB=%s\n' "${io_write_mb}"
  printf 'PEAK_FDS=%s\n' "${peak_fds}"
  printf 'INGEST_ERRORS=%s\n' "${ingest_errors:-0}"
  printf 'NEG_WALL_MS=%s\n' "${neg_wall_ms:-0}"
}

# ---------------------------------------------------------------------------
# Parse a key=value field out of bench_relay output.
# ---------------------------------------------------------------------------

field() {
  local data="$1" key="$2"
  printf '%s\n' "${data}" | awk -F= "/^${key}=/{print \$2; exit}"
}

# ---------------------------------------------------------------------------
# Winner helpers. Take (name value) pairs and print the winning name or "tie".
#
# Usage: winner_higher fastr "${F_IT}" strfry "${S_IT}" rnostr "${R_IT}"
# ---------------------------------------------------------------------------

winner_higher() {
  local best_name="" best_val="" tied=0 name val
  while (($# >= 2)); do
    name="$1" val="${2:-0}"
    shift 2
    if [[ -z "${best_val}" ]] || ((val > best_val)); then
      best_name="${name}" best_val="${val}" tied=0
    elif ((val == best_val)); then
      tied=1
    fi
  done
  if ((tied)); then echo "tie"; else echo "${best_name}"; fi
}

# Lowest non-zero value wins; zero means "no measurement" and never wins.
winner_lower() {
  local best_name="" best_val="" tied=0 name val
  while (($# >= 2)); do
    name="$1" val="${2:-0}"
    shift 2
    ((val == 0)) && continue
    if [[ -z "${best_val}" ]] || ((val < best_val)); then
      best_name="${name}" best_val="${val}" tied=0
    elif ((val == best_val)); then
      tied=1
    fi
  done
  if [[ -z "${best_val}" ]] || ((tied)); then echo "tie"; else echo "${best_name}"; fi
}

# Like winner_lower, but zero is a valid (best possible) value. Use for
# counts like errors, where 0 means "none occurred", not "no measurement".
winner_fewest() {
  local best_name="" best_val="" tied=0 name val
  while (($# >= 2)); do
    name="$1" val="${2:-0}"
    shift 2
    if [[ -z "${best_val}" ]] || ((val < best_val)); then
      best_name="${name}" best_val="${val}" tied=0
    elif ((val == best_val)); then
      tied=1
    fi
  done
  if ((tied)); then echo "tie"; else echo "${best_name}"; fi
}

# ---------------------------------------------------------------------------
# Machine spec for the table header.
# Read CPU and memory from cgroup limits when inside Docker; fall back to
# host /proc values if cgroup limits are not set (unlimited).
# ---------------------------------------------------------------------------

_cgroup_cpu() {
  # cgroup v2: cpu.max = "quota period" - quota/period = allowed CPUs
  local f="/sys/fs/cgroup/cpu.max"
  if [[ -f "${f}" ]]; then
    local quota period
    read -r quota period <"${f}"
    if [[ "${quota}" != "max" ]]; then
      printf '%d' "$((quota / period))"
      return
    fi
  fi
  # cgroup v1 fallback
  local quota_f="/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
  local period_f="/sys/fs/cgroup/cpu/cpu.cfs_period_us"
  if [[ -f "${quota_f}" && -f "${period_f}" ]]; then
    local quota period
    quota="$(cat "${quota_f}")"
    period="$(cat "${period_f}")"
    if ((quota > 0)); then
      printf '%d' "$((quota / period))"
      return
    fi
  fi
  nproc
}

_cgroup_mem_mb() {
  # cgroup v2
  local f="/sys/fs/cgroup/memory.max"
  if [[ -f "${f}" ]]; then
    local val
    val="$(cat "${f}")"
    if [[ "${val}" != "max" ]]; then
      printf '%dMB' "$((val / 1024 / 1024))"
      return
    fi
  fi
  # cgroup v1 fallback
  local f1="/sys/fs/cgroup/memory/memory.limit_in_bytes"
  if [[ -f "${f1}" ]]; then
    local val
    val="$(cat "${f1}")"
    # 9223372036854771712 = "unlimited" sentinel on v1
    if ((val < 9000000000000000000)); then
      printf '%dMB' "$((val / 1024 / 1024))"
      return
    fi
  fi
  awk '/^MemTotal:/{printf "%dMB", $2/1024; exit}' /proc/meminfo
}

_NUM_CPUS="$(_cgroup_cpu)"
MACHINE_SPEC="$(uname -m) ${_NUM_CPUS}cpu $(_cgroup_mem_mb)"
RUN_DATE="$(date -u '+%Y-%m-%d %H:%M UTC')"

# ---------------------------------------------------------------------------
# Run fastr
# ---------------------------------------------------------------------------

log "======== Starting fastr ========"
FASTR_DATA="$(mktemp -d)"
FASTR_START_US="$(date +%s%6N)"
FASTR_DATA_DIR="${FASTR_DATA}" FASTR_PORT="${FASTR_PORT}" \
  fastr >/tmp/fastr.log 2>&1 &
FASTR_PID=$!
wait_for_port fastr 127.0.0.1 "${FASTR_PORT}" /tmp/fastr.log
FASTR_COLD_US="$(($(date +%s%6N) - FASTR_START_US))"

FASTR_RESULT="$(bench_relay fastr "ws://127.0.0.1:${FASTR_PORT}" "${FASTR_PID}" "${FASTR_DATA}" neg)"

kill "${FASTR_PID}" 2>/dev/null || true
wait "${FASTR_PID}" 2>/dev/null || true
rm -rf "${FASTR_DATA}"
log "fastr stopped."

# ---------------------------------------------------------------------------
# Run strfry
# ---------------------------------------------------------------------------

log "======== Starting strfry ========"
STRFRY_DATA="$(mktemp -d)"

# Write a per-run config pointing at the temp DB directory so runs are isolated.
# strfry uses its own config syntax (NOT TOML): top-level keys + block sections.
STRFRY_CFG="$(mktemp --suffix=.conf)"
cat >"${STRFRY_CFG}" <<STRFRYCFG
db = "${STRFRY_DATA}"

relay {
    bind = "127.0.0.1"
    port = ${STRFRY_PORT}
    nofiles = 0

    info {
        name = "strfry-bench"
        description = "benchmark instance"
        pubkey = ""
    }

    compression {
        enabled = false
        slidingWindow = false
    }
}
STRFRYCFG

log "strfry config:"
cat "${STRFRY_CFG}" >&2

STRFRY_START_US="$(date +%s%6N)"
strfry --config "${STRFRY_CFG}" relay >/tmp/strfry.log 2>&1 &
STRFRY_PID=$!
wait_for_port strfry 127.0.0.1 "${STRFRY_PORT}" /tmp/strfry.log
STRFRY_COLD_US="$(($(date +%s%6N) - STRFRY_START_US))"

STRFRY_RESULT="$(bench_relay strfry "ws://127.0.0.1:${STRFRY_PORT}" "${STRFRY_PID}" "${STRFRY_DATA}" neg)"

kill "${STRFRY_PID}" 2>/dev/null || true
wait "${STRFRY_PID}" 2>/dev/null || true
rm -rf "${STRFRY_DATA}" "${STRFRY_CFG}"
log "strfry stopped."

# ---------------------------------------------------------------------------
# Run rnostr
# ---------------------------------------------------------------------------

log "======== Starting rnostr ========"
RNOSTR_DATA="$(mktemp -d)"

# Per-run TOML config pointing at the temp DB directory.
# max_event_time_older_than_now is raised because fastr-bench generates
# events with a fixed created_at (BASE_TS = 1.7e9); rnostr's ~3-year default
# would start rejecting them in late 2026. The value must stay BELOW the
# current unix time: rnostr computes `now - limit` with unsigned arithmetic,
# so a larger value underflows and rejects every event. 1.7e9 keeps the
# cutoff in 1970-land until ~2080 without ever exceeding `now`.
RNOSTR_CFG="$(mktemp --suffix=.toml)"
cat >"${RNOSTR_CFG}" <<RNOSTRCFG
[information]
name = "rnostr-bench"
description = "benchmark instance"

[data]
path = "${RNOSTR_DATA}"

[network]
host = "127.0.0.1"
port = ${RNOSTR_PORT}

[limitation]
max_event_time_older_than_now = 1700000000
RNOSTRCFG

log "rnostr config:"
cat "${RNOSTR_CFG}" >&2

RNOSTR_START_US="$(date +%s%6N)"
rnostr relay -c "${RNOSTR_CFG}" >/tmp/rnostr.log 2>&1 &
RNOSTR_PID=$!
wait_for_port rnostr 127.0.0.1 "${RNOSTR_PORT}" /tmp/rnostr.log
RNOSTR_COLD_US="$(($(date +%s%6N) - RNOSTR_START_US))"

# rnostr does not implement NIP-77 negentropy sync - skip that phase.
RNOSTR_RESULT="$(bench_relay rnostr "ws://127.0.0.1:${RNOSTR_PORT}" "${RNOSTR_PID}" "${RNOSTR_DATA}" noneg)"

kill "${RNOSTR_PID}" 2>/dev/null || true
wait "${RNOSTR_PID}" 2>/dev/null || true
rm -rf "${RNOSTR_DATA}" "${RNOSTR_CFG}"
log "rnostr stopped."

# ---------------------------------------------------------------------------
# Extract results
# ---------------------------------------------------------------------------

F_IT="$(field "${FASTR_RESULT}" INGEST_THROUGHPUT)"
F_IP50="$(field "${FASTR_RESULT}" INGEST_P50)"
F_IP99="$(field "${FASTR_RESULT}" INGEST_P99)"
F_QT="$(field "${FASTR_RESULT}" QUERY_THROUGHPUT)"
F_QP50="$(field "${FASTR_RESULT}" QUERY_P50)"
F_QP99="$(field "${FASTR_RESULT}" QUERY_P99)"
F_RSS="$(field "${FASTR_RESULT}" PEAK_RSS_MB)"
F_CU="$(field "${FASTR_RESULT}" CPU_CYCLES_USER)"
F_CK="$(field "${FASTR_RESULT}" CPU_CYCLES_KERNEL)"
F_SC="$(field "${FASTR_RESULT}" PERF_SYSCALLS)"
F_CS="$(field "${FASTR_RESULT}" PERF_CTX_SW)"
F_MF="$(field "${FASTR_RESULT}" PERF_MINOR_FAULTS)"
F_DU="$(field "${FASTR_RESULT}" DISK_USAGE_KB)"
F_IO="$(field "${FASTR_RESULT}" IO_WRITE_MB)"
F_FD="$(field "${FASTR_RESULT}" PEAK_FDS)"
F_ER="$(field "${FASTR_RESULT}" INGEST_ERRORS)"

F_NW="$(field "${FASTR_RESULT}" NEG_WALL_MS)"

S_IT="$(field "${STRFRY_RESULT}" INGEST_THROUGHPUT)"
S_IP50="$(field "${STRFRY_RESULT}" INGEST_P50)"
S_IP99="$(field "${STRFRY_RESULT}" INGEST_P99)"
S_QT="$(field "${STRFRY_RESULT}" QUERY_THROUGHPUT)"
S_QP50="$(field "${STRFRY_RESULT}" QUERY_P50)"
S_QP99="$(field "${STRFRY_RESULT}" QUERY_P99)"
S_RSS="$(field "${STRFRY_RESULT}" PEAK_RSS_MB)"
S_CU="$(field "${STRFRY_RESULT}" CPU_CYCLES_USER)"
S_CK="$(field "${STRFRY_RESULT}" CPU_CYCLES_KERNEL)"
S_SC="$(field "${STRFRY_RESULT}" PERF_SYSCALLS)"
S_CS="$(field "${STRFRY_RESULT}" PERF_CTX_SW)"
S_MF="$(field "${STRFRY_RESULT}" PERF_MINOR_FAULTS)"
S_DU="$(field "${STRFRY_RESULT}" DISK_USAGE_KB)"
S_IO="$(field "${STRFRY_RESULT}" IO_WRITE_MB)"
S_FD="$(field "${STRFRY_RESULT}" PEAK_FDS)"
S_ER="$(field "${STRFRY_RESULT}" INGEST_ERRORS)"
S_NW="$(field "${STRFRY_RESULT}" NEG_WALL_MS)"

R_IT="$(field "${RNOSTR_RESULT}" INGEST_THROUGHPUT)"
R_IP50="$(field "${RNOSTR_RESULT}" INGEST_P50)"
R_IP99="$(field "${RNOSTR_RESULT}" INGEST_P99)"
R_QT="$(field "${RNOSTR_RESULT}" QUERY_THROUGHPUT)"
R_QP50="$(field "${RNOSTR_RESULT}" QUERY_P50)"
R_QP99="$(field "${RNOSTR_RESULT}" QUERY_P99)"
R_RSS="$(field "${RNOSTR_RESULT}" PEAK_RSS_MB)"
R_CU="$(field "${RNOSTR_RESULT}" CPU_CYCLES_USER)"
R_CK="$(field "${RNOSTR_RESULT}" CPU_CYCLES_KERNEL)"
R_SC="$(field "${RNOSTR_RESULT}" PERF_SYSCALLS)"
R_CS="$(field "${RNOSTR_RESULT}" PERF_CTX_SW)"
R_MF="$(field "${RNOSTR_RESULT}" PERF_MINOR_FAULTS)"
R_DU="$(field "${RNOSTR_RESULT}" DISK_USAGE_KB)"
R_IO="$(field "${RNOSTR_RESULT}" IO_WRITE_MB)"
R_FD="$(field "${RNOSTR_RESULT}" PEAK_FDS)"
R_ER="$(field "${RNOSTR_RESULT}" INGEST_ERRORS)"

# ---------------------------------------------------------------------------
# Validity check: a relay that rejected half or more of the ingest was
# benchmarked against an empty database - every other number it produced is
# an artifact (fast rejections, instant empty queries, tiny RSS, zero disk).
# Exclude it from winner computation and flag the run in the output.
# ---------------------------------------------------------------------------

F_VALID=1
S_VALID=1
R_VALID=1
INVALID_NOTE=""

check_validity() {
  local name="$1" errors="${2:-0}" flag_var="$3"
  if ((errors > 0 && errors * 2 >= EVENTS)); then
    printf -v "${flag_var}" 0
    INVALID_NOTE="${INVALID_NOTE}> **INVALID RUN:** ${name} rejected ${errors}/${EVENTS} ingest events - its other numbers are artifacts of an empty database and are excluded from the winner column.
"
    log "WARNING: ${name} rejected ${errors}/${EVENTS} ingest events - excluded from winners"
  fi
}

check_validity fastr "${F_ER:-0}" F_VALID
check_validity strfry "${S_ER:-0}" S_VALID
check_validity rnostr "${R_ER:-0}" R_VALID

# A relay whose ingest produced no stats at all is equally invalid: the
# driver aborted mid-run (e.g. the relay dropped the connection) and the
# zeros that remain are not measurements.
check_stats() {
  local name="$1" throughput="${2:-0}" flag_var="$3"
  if ((throughput == 0)); then
    printf -v "${flag_var}" 0
    INVALID_NOTE="${INVALID_NOTE}> **INVALID RUN:** ${name} ingest produced no stats (driver aborted mid-run?) - it is excluded from the winner column.
"
    log "WARNING: ${name} ingest produced no stats - excluded from winners"
  fi
}

check_stats fastr "${F_IT:-0}" F_VALID
check_stats strfry "${S_IT:-0}" S_VALID
check_stats rnostr "${R_IT:-0}" R_VALID

# Populate PAIRS with (name value) for valid relays only.
# Call as: pairs_for "<fastr-val>" "<strfry-val>" "<rnostr-val>"
pairs_for() {
  PAIRS=()
  ((F_VALID)) && PAIRS+=(fastr "${1:-0}")
  ((S_VALID)) && PAIRS+=(strfry "${2:-0}")
  ((R_VALID)) && PAIRS+=(rnostr "${3:-0}")
  return 0 # an invalid last relay must not fail the && chain at the call site
}

# ---------------------------------------------------------------------------
# Determine winners
# ---------------------------------------------------------------------------

W_IT="$(pairs_for "${F_IT}" "${S_IT}" "${R_IT}" && winner_higher "${PAIRS[@]}")"
W_IP50="$(pairs_for "${F_IP50}" "${S_IP50}" "${R_IP50}" && winner_lower "${PAIRS[@]}")"
W_IP99="$(pairs_for "${F_IP99}" "${S_IP99}" "${R_IP99}" && winner_lower "${PAIRS[@]}")"
W_QT="$(pairs_for "${F_QT}" "${S_QT}" "${R_QT}" && winner_higher "${PAIRS[@]}")"
W_QP50="$(pairs_for "${F_QP50}" "${S_QP50}" "${R_QP50}" && winner_lower "${PAIRS[@]}")"
W_QP99="$(pairs_for "${F_QP99}" "${S_QP99}" "${R_QP99}" && winner_lower "${PAIRS[@]}")"
W_RSS="$(pairs_for "${F_RSS}" "${S_RSS}" "${R_RSS}" && winner_lower "${PAIRS[@]}")"
W_CU="$(pairs_for "${F_CU}" "${S_CU}" "${R_CU}" && winner_lower "${PAIRS[@]}")"
W_CK="$(pairs_for "${F_CK}" "${S_CK}" "${R_CK}" && winner_lower "${PAIRS[@]}")"
W_COLD="$(pairs_for "${FASTR_COLD_US}" "${STRFRY_COLD_US}" "${RNOSTR_COLD_US}" && winner_lower "${PAIRS[@]}")"
W_SC="$(pairs_for "${F_SC}" "${S_SC}" "${R_SC}" && winner_lower "${PAIRS[@]}")"
W_CSW="$(pairs_for "${F_CS}" "${S_CS}" "${R_CS}" && winner_lower "${PAIRS[@]}")"
W_MF="$(pairs_for "${F_MF}" "${S_MF}" "${R_MF}" && winner_lower "${PAIRS[@]}")"
W_DU="$(pairs_for "${F_DU}" "${S_DU}" "${R_DU}" && winner_lower "${PAIRS[@]}")"
W_IO="$(pairs_for "${F_IO}" "${S_IO}" "${R_IO}" && winner_lower "${PAIRS[@]}")"
W_FD="$(pairs_for "${F_FD}" "${S_FD}" "${R_FD}" && winner_lower "${PAIRS[@]}")"
W_ER="$(winner_fewest fastr "${F_ER:-0}" strfry "${S_ER:-0}" rnostr "${R_ER:-0}")"
# Neg-sync only compares fastr and strfry: rnostr has no NIP-77 support.
W_NW="$(pairs_for "${F_NW}" "${S_NW}" 0 && winner_lower "${PAIRS[@]}")"

# ---------------------------------------------------------------------------
# Build the markdown table
# ---------------------------------------------------------------------------

TABLE="
## ${RUN_DATE} - ${MACHINE_SPEC}

> events=${EVENTS}  queries=${QUERIES}  concurrency=${CONCURRENCY}

${INVALID_NOTE}| Metric                              | fastr              | strfry             | rnostr             | winner   |
|-------------------------------------|--------------------|--------------------|--------------------|----------|
| Ingest throughput (ev/s)            | ${F_IT:--}        | ${S_IT:--}        | ${R_IT:--}        | ${W_IT}  |
| Ingest OK p50 latency (µs)          | ${F_IP50:--}      | ${S_IP50:--}      | ${R_IP50:--}      | ${W_IP50} |
| Ingest OK p99 latency (µs)          | ${F_IP99:--}      | ${S_IP99:--}      | ${R_IP99:--}      | ${W_IP99} |
| Ingest errors                       | ${F_ER:-0}        | ${S_ER:-0}        | ${R_ER:-0}        | ${W_ER}  |
| Neg-sync wall time (ms)             | ${F_NW:--}        | ${S_NW:--}        | n/a               | ${W_NW}  |
| REQ query throughput (q/s)          | ${F_QT:--}        | ${S_QT:--}        | ${R_QT:--}        | ${W_QT}  |
| REQ->EOSE p50 latency (µs)           | ${F_QP50:--}      | ${S_QP50:--}      | ${R_QP50:--}      | ${W_QP50} |
| REQ->EOSE p99 latency (µs)           | ${F_QP99:--}      | ${S_QP99:--}      | ${R_QP99:--}      | ${W_QP99} |
| Peak RSS @ ${EVENTS} events (MB)    | ${F_RSS:--}       | ${S_RSS:--}       | ${R_RSS:--}       | ${W_RSS} |
| Disk usage @ ${EVENTS} events (KB)  | ${F_DU:--}        | ${S_DU:--}        | ${R_DU:--}        | ${W_DU}  |
| Disk I/O written (MB)               | ${F_IO:--}        | ${S_IO:--}        | ${R_IO:--}        | ${W_IO}  |
| CPU Mcycles (user)                  | ${F_CU:--}        | ${S_CU:--}        | ${R_CU:--}        | ${W_CU}  |
| CPU Mcycles (kernel)                | ${F_CK:--}        | ${S_CK:--}        | ${R_CK:--}        | ${W_CK}  |
| Syscalls                            | ${F_SC:--}        | ${S_SC:--}        | ${R_SC:--}        | ${W_SC}  |
| Context switches                    | ${F_CS:--}        | ${S_CS:--}        | ${R_CS:--}        | ${W_CSW} |
| Minor page faults                   | ${F_MF:--}        | ${S_MF:--}        | ${R_MF:--}        | ${W_MF}  |
| Open file descriptors (peak)        | ${F_FD:--}        | ${S_FD:--}        | ${R_FD:--}        | ${W_FD}  |
| Cold start time (µs)                | ${FASTR_COLD_US:--} | ${STRFRY_COLD_US:--} | ${RNOSTR_COLD_US:--} | ${W_COLD} |
"

# ---------------------------------------------------------------------------
# Append to results file
# ---------------------------------------------------------------------------

mkdir -p "$(dirname "${RESULTS_FILE}")"
printf '%s\n' "${TABLE}" >>"${RESULTS_FILE}"
log "Results appended to ${RESULTS_FILE}"

# Echo to stdout so the operator sees results without inspecting the volume.
printf '\n%s\n' "================================================================"
printf '%s\n' "${TABLE}"
printf '%s\n' "================================================================"