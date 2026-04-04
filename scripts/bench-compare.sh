#!/usr/bin/env bash
#
# bench-compare.sh — Parse Criterion benchmark results and compare against baselines.
#
# Usage:
#   bench-compare.sh --parse   --output <path>
#   bench-compare.sh --compare --baseline <path> --current <path>
#   bench-compare.sh --markdown --current <path>
#   bench-compare.sh --help
#
# Requires: jq, awk, git

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() {
    echo "error: $*" >&2
    exit 2
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found in PATH"
}

usage() {
    cat <<'USAGE'
bench-compare.sh — Parse Criterion results and compare benchmarks.

MODES:
  --parse                 Scan target/criterion/ for estimates.json files,
                          extract median point estimates, and write a JSON
                          results file.
      --output <path>     (required) Path for the output JSON file.

  --compare               Compare two JSON result files and print a markdown
                          table showing regressions / improvements.
      --baseline <path>   (required) Previous results JSON.
      --current  <path>   (required) Current results JSON.

  --markdown              Print a simple markdown table of current results
                          (no comparison).
      --current  <path>   (required) Current results JSON.

  --help                  Show this message.

EXIT CODES:
  0   All benchmarks within tolerance (< 10% regression), or non-compare mode.
  1   At least one benchmark regressed > 10%.
  2   Usage / runtime error.

EXAMPLES:
  # After running: cargo bench
  ./scripts/bench-compare.sh --parse --output bench-results.json

  # Compare against saved baseline
  ./scripts/bench-compare.sh --compare \
      --baseline baseline.json \
      --current  bench-results.json

  # Simple table for documentation
  ./scripts/bench-compare.sh --markdown --current bench-results.json
USAGE
}

# Format nanoseconds into a human-readable string with appropriate unit.
format_ns() {
    local ns="$1"
    awk -v ns="$ns" 'BEGIN {
        if (ns >= 1000000000)      printf "%.2f s\n",  ns / 1000000000
        else if (ns >= 1000000)    printf "%.2f ms\n", ns / 1000000
        else if (ns >= 1000)       printf "%.2f us\n", ns / 1000
        else                       printf "%.1f ns\n", ns
    }'
}

# Compute percentage change: (current - baseline) / baseline * 100
calc_pct_change() {
    local baseline="$1"
    local current="$2"
    awk -v b="$baseline" -v c="$current" 'BEGIN { printf "%.2f\n", (c - b) / b * 100 }'
}

# Compare a float against a threshold. Returns 0 (true) if val > threshold.
float_gt() {
    local val="$1"
    local threshold="$2"
    awk -v a="$val" -v b="$threshold" 'BEGIN { exit !(a > b) }'
}

# Check if a float is >= 0
float_gte_zero() {
    local val="$1"
    awk -v a="$val" 'BEGIN { exit !(a >= 0) }'
}

# ---------------------------------------------------------------------------
# --parse: scan Criterion output and produce a JSON results file
# ---------------------------------------------------------------------------

do_parse() {
    local output="$1"
    local criterion_dir="target/criterion"

    if [ ! -d "$criterion_dir" ]; then
        die "Criterion output directory not found: $criterion_dir"
    fi

    require_cmd jq

    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    local commit
    commit="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

    # Collect all estimates.json files. Criterion stores results at:
    #   target/criterion/<name>/new/estimates.json            (flat benchmarks)
    #   target/criterion/<group>/<name>/new/estimates.json    (grouped benchmarks)
    #   target/criterion/<g1>/<g2>/<name>/new/estimates.json  (deeply nested)
    #
    # We discover them by finding estimates.json under */new/ and derive the
    # benchmark name from the path between criterion/ and /new/.

    local benchmarks_json="{}"

    while IFS= read -r estimates_file; do
        # Strip leading criterion_dir/ and trailing /new/estimates.json
        local rel_path="${estimates_file#${criterion_dir}/}"
        local bench_name="${rel_path%/new/estimates.json}"

        # Skip the top-level report directory if present
        if [ "$bench_name" = "report" ] || [[ "$bench_name" == report/* ]]; then
            continue
        fi

        # Extract median.point_estimate
        local median_ns
        median_ns="$(jq -r '.median.point_estimate' "$estimates_file" 2>/dev/null)" || continue

        # Validate we got a number
        if [ -z "$median_ns" ] || [ "$median_ns" = "null" ]; then
            echo "warning: skipping $bench_name — no median.point_estimate" >&2
            continue
        fi

        benchmarks_json="$(echo "$benchmarks_json" | jq \
            --arg name "$bench_name" \
            --argjson median "$median_ns" \
            '. + {($name): {"median_ns": $median}}'
        )"
    done < <(find "$criterion_dir" -path "*/new/estimates.json" -type f 2>/dev/null | sort)

    # Build final JSON
    jq -n \
        --arg ts "$timestamp" \
        --arg commit "$commit" \
        --argjson benchmarks "$benchmarks_json" \
        '{
            timestamp: $ts,
            commit: $commit,
            benchmarks: $benchmarks
        }' > "$output"

    local count
    count="$(echo "$benchmarks_json" | jq 'length')"
    echo "Parsed $count benchmarks -> $output"
}

# ---------------------------------------------------------------------------
# --compare: diff two result files and print a markdown table
# ---------------------------------------------------------------------------

do_compare() {
    local baseline_file="$1"
    local current_file="$2"

    require_cmd jq

    [ -f "$baseline_file" ] || die "baseline file not found: $baseline_file"
    [ -f "$current_file" ]  || die "current file not found: $current_file"

    local baseline_commit current_commit
    baseline_commit="$(jq -r '.commit' "$baseline_file")"
    current_commit="$(jq -r '.commit' "$current_file")"

    echo "## Benchmark Comparison"
    echo ""
    echo "Baseline: \`$baseline_commit\` | Current: \`$current_commit\`"
    echo ""
    echo "| Benchmark | Baseline | Current | Change (%) | Status |"
    echo "|-----------|----------|---------|------------|--------|"

    local has_regression=0

    # Iterate over all benchmarks in current results
    while IFS=$'\t' read -r bench_name current_ns; do
        local baseline_ns
        baseline_ns="$(jq -r --arg name "$bench_name" \
            '.benchmarks[$name].median_ns // empty' "$baseline_file")"

        local current_fmt
        current_fmt="$(format_ns "$current_ns")"

        if [ -z "$baseline_ns" ]; then
            echo "| $bench_name | — | $current_fmt | NEW | — |"
            continue
        fi

        local baseline_fmt
        baseline_fmt="$(format_ns "$baseline_ns")"

        local pct_change
        pct_change="$(calc_pct_change "$baseline_ns" "$current_ns")"

        # Determine status — only flag regressions (positive = got slower)
        local status
        if float_gt "$pct_change" "10"; then
            status=$'\xe2\x9d\x8c'
            has_regression=1
        elif float_gt "$pct_change" "5"; then
            status=$'\xe2\x9a\xa0\xef\xb8\x8f'
        else
            status=$'\xe2\x9c\x85'
        fi

        # Format the change with a sign
        local sign=""
        if float_gte_zero "$pct_change"; then
            sign="+"
        fi

        echo "| $bench_name | $baseline_fmt | $current_fmt | ${sign}${pct_change}% | $status |"
    done < <(jq -r '.benchmarks | to_entries[] | [.key, (.value.median_ns | tostring)] | @tsv' "$current_file" | sort)

    # Check for benchmarks in baseline but missing from current
    while IFS=$'\t' read -r bench_name baseline_ns; do
        local in_current
        in_current="$(jq -r --arg name "$bench_name" \
            '.benchmarks[$name].median_ns // empty' "$current_file")"

        if [ -z "$in_current" ]; then
            local baseline_fmt
            baseline_fmt="$(format_ns "$baseline_ns")"
            echo "| $bench_name | $baseline_fmt | — | REMOVED | — |"
        fi
    done < <(jq -r '.benchmarks | to_entries[] | [.key, (.value.median_ns | tostring)] | @tsv' "$baseline_file" | sort)

    echo ""

    if [ "$has_regression" -eq 1 ]; then
        echo "**Result: REGRESSION DETECTED** — one or more benchmarks regressed >10%."
        exit 1
    else
        echo "**Result: OK** — no significant regressions detected."
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# --markdown: simple table of current results (no comparison)
# ---------------------------------------------------------------------------

do_markdown() {
    local current_file="$1"

    require_cmd jq

    [ -f "$current_file" ] || die "current file not found: $current_file"

    local commit timestamp
    commit="$(jq -r '.commit' "$current_file")"
    timestamp="$(jq -r '.timestamp' "$current_file")"

    echo "## Benchmark Results"
    echo ""
    echo "Commit: \`$commit\` | Date: $timestamp"
    echo ""
    echo "| Benchmark | Median |"
    echo "|-----------|--------|"

    while IFS=$'\t' read -r bench_name median_ns; do
        local formatted
        formatted="$(format_ns "$median_ns")"
        echo "| $bench_name | $formatted |"
    done < <(jq -r '.benchmarks | to_entries[] | [.key, (.value.median_ns | tostring)] | @tsv' "$current_file" | sort)
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

main() {
    local mode=""
    local output=""
    local baseline=""
    local current=""

    if [ $# -eq 0 ]; then
        usage
        exit 0
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            --parse)
                mode="parse"
                shift
                ;;
            --compare)
                mode="compare"
                shift
                ;;
            --markdown)
                mode="markdown"
                shift
                ;;
            --output)
                [ $# -ge 2 ] || die "--output requires an argument"
                output="$2"
                shift 2
                ;;
            --baseline)
                [ $# -ge 2 ] || die "--baseline requires an argument"
                baseline="$2"
                shift 2
                ;;
            --current)
                [ $# -ge 2 ] || die "--current requires an argument"
                current="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                die "unknown option: $1"
                ;;
        esac
    done

    case "$mode" in
        parse)
            [ -n "$output" ] || die "--parse requires --output <path>"
            do_parse "$output"
            ;;
        compare)
            [ -n "$baseline" ] || die "--compare requires --baseline <path>"
            [ -n "$current" ]  || die "--compare requires --current <path>"
            do_compare "$baseline" "$current"
            ;;
        markdown)
            [ -n "$current" ] || die "--markdown requires --current <path>"
            do_markdown "$current"
            ;;
        "")
            die "no mode specified. Use --parse, --compare, or --markdown."
            ;;
    esac
}

main "$@"
