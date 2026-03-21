#!/usr/bin/env bash
# run_bench.sh - benchmark runner executed inside the fastr-bench Docker container.
#
# Runs fastr and strfry sequentially on isolated ports, drives each with the
# fastr-bench driver (ingest + query + RSS sample), then appends a timestamped
# markdown result table to RESULTS_FILE.
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
# Usage: bench_relay <label> <ws_url> <pid>
# bench_relay runs ingest, neg-sync, and query benchmarks against a relay process, samples resource metrics (RSS, open fds, disk I/O delta, and CPU cycles via perf), and emits structured KEY=value results to stdout.

bench_relay() {
  local label="$1"
  local ws_url="$2"
  local pid="$3"
  local data_dir="$4"

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
    --concurrency "${CONCURRENCY}" 2>&1)"
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

  log "--- ${label}: neg-sync (${EVENTS} events, half overlap) ---"
  local neg_out
  neg_out="$(fastr-bench neg-sync \
    --url "${ws_url}" \
    --filter '{"kinds":[1]}' \
    --have $((EVENTS / 2)) 2>&1)"
  log "${neg_out}"

  local neg_wall_ms
  neg_wall_ms="$(printf '%s\n' "${neg_out}" |
    awk '/^Wall time:/{gsub(/[^0-9.]/,"",$NF); printf "%.0f\n", $NF; exit}')"

  log "--- ${label}: query (${QUERIES} queries, concurrency ${CONCURRENCY}) ---"
  local query_out
  query_out="$(fastr-bench query \
    --url "${ws_url}" \
    --queries "${QUERIES}" \
    --concurrency "${CONCURRENCY}" 2>&1)"
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
  local disk_bytes disk_mb
  disk_bytes="$(du -sb "${data_dir}" 2>/dev/null | awk '{print $1}')"
  disk_mb=$((${disk_bytes:-0} / 1024 / 1024))

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
  printf 'DISK_USAGE_MB=%s\n' "${disk_mb}"
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
# Winner helpers: "fastr" | "strfry" | "tie"
# ---------------------------------------------------------------------------

winner_higher() {
  local a="${1:-0}" b="${2:-0}"
  if ((a > b)); then
    echo "fastr"
  elif ((b > a)); then
    echo "strfry"
  else
    echo "tie"
  fi
}

winner_lower() {
  local a="${1:-0}" b="${2:-0}"
  if ((a < b && a > 0)); then
    echo "fastr"
  elif ((b < a && b > 0)); then
    echo "strfry"
  elif ((a == b)); then
    echo "tie"
  elif ((a == 0)); then
    echo "strfry"
  else
    echo "fastr"
  fi
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

FASTR_RESULT="$(bench_relay fastr "ws://127.0.0.1:${FASTR_PORT}" "${FASTR_PID}" "${FASTR_DATA}")"

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

STRFRY_RESULT="$(bench_relay strfry "ws://127.0.0.1:${STRFRY_PORT}" "${STRFRY_PID}" "${STRFRY_DATA}")"

kill "${STRFRY_PID}" 2>/dev/null || true
wait "${STRFRY_PID}" 2>/dev/null || true
rm -rf "${STRFRY_DATA}" "${STRFRY_CFG}"
log "strfry stopped."

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
F_DU="$(field "${FASTR_RESULT}" DISK_USAGE_MB)"
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
S_DU="$(field "${STRFRY_RESULT}" DISK_USAGE_MB)"
S_IO="$(field "${STRFRY_RESULT}" IO_WRITE_MB)"
S_FD="$(field "${STRFRY_RESULT}" PEAK_FDS)"
S_ER="$(field "${STRFRY_RESULT}" INGEST_ERRORS)"
S_NW="$(field "${STRFRY_RESULT}" NEG_WALL_MS)"

# ---------------------------------------------------------------------------
# Determine winners
# ---------------------------------------------------------------------------

W_IT="$(winner_higher "${F_IT}" "${S_IT}")"
W_IP50="$(winner_lower "${F_IP50}" "${S_IP50}")"
W_IP99="$(winner_lower "${F_IP99}" "${S_IP99}")"
W_QT="$(winner_higher "${F_QT}" "${S_QT}")"
W_QP50="$(winner_lower "${F_QP50}" "${S_QP50}")"
W_QP99="$(winner_lower "${F_QP99}" "${S_QP99}")"
W_RSS="$(winner_lower "${F_RSS}" "${S_RSS}")"
W_CU="$(winner_lower "${F_CU:-0}" "${S_CU:-0}")"
W_CK="$(winner_lower "${F_CK:-0}" "${S_CK:-0}")"
W_COLD="$(winner_lower "${FASTR_COLD_US:-0}" "${STRFRY_COLD_US:-0}")"
W_SC="$(winner_lower "${F_SC:-0}" "${S_SC:-0}")"
W_CSW="$(winner_lower "${F_CS:-0}" "${S_CS:-0}")"
W_MF="$(winner_lower "${F_MF:-0}" "${S_MF:-0}")"
W_DU="$(winner_lower "${F_DU:-0}" "${S_DU:-0}")"
W_IO="$(winner_lower "${F_IO:-0}" "${S_IO:-0}")"
W_FD="$(winner_lower "${F_FD:-0}" "${S_FD:-0}")"
W_ER="$(winner_lower "${F_ER:-0}" "${S_ER:-0}")"
W_NW="$(winner_lower "${F_NW:-0}" "${S_NW:-0}")"

# ---------------------------------------------------------------------------
# Build the markdown table
# ---------------------------------------------------------------------------

TABLE="
## ${RUN_DATE} - ${MACHINE_SPEC}

> events=${EVENTS}  queries=${QUERIES}  concurrency=${CONCURRENCY}

| Metric                              | fastr              | strfry             | winner   |
|-------------------------------------|--------------------|--------------------|----------|
| Ingest throughput (ev/s)            | ${F_IT:--}        | ${S_IT:--}        | ${W_IT}  |
| Ingest OK p50 latency (µs)          | ${F_IP50:--}      | ${S_IP50:--}      | ${W_IP50} |
| Ingest OK p99 latency (µs)          | ${F_IP99:--}      | ${S_IP99:--}      | ${W_IP99} |
| Ingest errors                       | ${F_ER:-0}        | ${S_ER:-0}        | ${W_ER}  |
| Neg-sync wall time (ms)             | ${F_NW:--}        | ${S_NW:--}        | ${W_NW}  |
| REQ query throughput (q/s)          | ${F_QT:--}        | ${S_QT:--}        | ${W_QT}  |
| REQ->EOSE p50 latency (µs)           | ${F_QP50:--}      | ${S_QP50:--}      | ${W_QP50} |
| REQ->EOSE p99 latency (µs)           | ${F_QP99:--}      | ${S_QP99:--}      | ${W_QP99} |
| Peak RSS @ ${EVENTS} events (MB)    | ${F_RSS:--}       | ${S_RSS:--}       | ${W_RSS} |
| Disk usage @ ${EVENTS} events (MB)  | ${F_DU:--}        | ${S_DU:--}        | ${W_DU}  |
| Disk I/O written (MB)               | ${F_IO:--}        | ${S_IO:--}        | ${W_IO}  |
| CPU Mcycles (user)                  | ${F_CU:--}        | ${S_CU:--}        | ${W_CU}  |
| CPU Mcycles (kernel)                | ${F_CK:--}        | ${S_CK:--}        | ${W_CK}  |
| Syscalls                            | ${F_SC:--}        | ${S_SC:--}        | ${W_SC}  |
| Context switches                    | ${F_CS:--}        | ${S_CS:--}        | ${W_CSW} |
| Minor page faults                   | ${F_MF:--}        | ${S_MF:--}        | ${W_MF}  |
| Open file descriptors (peak)        | ${F_FD:--}        | ${S_FD:--}        | ${W_FD}  |
| Cold start time (µs)                | ${FASTR_COLD_US:--} | ${STRFRY_COLD_US:--} | ${W_COLD} |
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