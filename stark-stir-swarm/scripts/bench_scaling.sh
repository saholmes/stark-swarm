#!/usr/bin/env bash
#
# bench_scaling.sh — STARK-DNS bandwidth-scaling characterisation
#
# Runs the three bandwidth-bound benches (ECDSA-P256 single-sig,
# Ed25519 streaming-merge K-sweep, TLD-scale sharded prover) and
# produces a clean comparison table.  Use this on each candidate AWS
# instance size to characterise the bandwidth-vs-vCPU scaling curve.
#
# Hardware-context detection:
#   - AWS instance-type (via IMDSv2; fallback "unknown")
#   - Physical CPU count + total RAM
#   - RAYON_NUM_THREADS auto-tuned to physical cores
#   - mimalloc auto-linked if libmimalloc is present
#
# Modes:
#   ./scripts/bench_scaling.sh single        # single-worker bandwidth scan (~10 min)
#   ./scripts/bench_scaling.sh concurrent N  # launch N concurrent ECDSA proves
#   ./scripts/bench_scaling.sh both N        # single-worker + concurrent (default N=4)
#
# Outputs:
#   bench_results/scaling/<instance>-<timestamp>/{bench}.log
#   bench_results/scaling/<instance>-<timestamp>/scaling.tsv
#   bench_results/scaling/<instance>-<timestamp>/scaling.txt
#

set -euo pipefail

# ─────────────────────────────────────────────────────────────────
# Setup + hardware detection
# ─────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
FEATURES="${BENCH_FEATURES:-parallel,sha3-256}"

cd "$REPO_DIR"

# Detect AWS instance type via IMDSv2.
detect_instance_type() {
    local token instance_type
    if command -v curl >/dev/null; then
        token=$(curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null) || token=""
        if [[ -n "$token" ]]; then
            instance_type=$(curl -s --max-time 2 \
                -H "X-aws-ec2-metadata-token: $token" \
                http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null) || instance_type=""
            [[ -n "$instance_type" ]] && { echo "$instance_type"; return; }
        fi
    fi
    # Fallback: detect macOS / generic
    if [[ "$(uname -s)" == "Darwin" ]]; then
        echo "mac-$(sysctl -n hw.model 2>/dev/null | tr ' /' '--' | tr '[:upper:]' '[:lower:]')"
    else
        echo "unknown-$(uname -m)"
    fi
}

INSTANCE_TYPE="$(detect_instance_type)"

# Physical CPU count.
detect_phys_cores() {
    if command -v nproc >/dev/null; then
        nproc --all
    elif command -v sysctl >/dev/null; then
        sysctl -n hw.physicalcpu 2>/dev/null || sysctl -n hw.ncpu
    else
        echo 1
    fi
}
PHYS_CORES="$(detect_phys_cores)"
: "${RAYON_NUM_THREADS:=$PHYS_CORES}"
export RAYON_NUM_THREADS

# Total RAM (GiB).
detect_total_ram_gib() {
    if [[ -r /proc/meminfo ]]; then
        awk '/MemTotal/ { printf "%.1f", $2 / 1024 / 1024 }' /proc/meminfo
    elif command -v sysctl >/dev/null; then
        local b
        b=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
        awk -v b="$b" 'BEGIN { printf "%.1f", b / 1024 / 1024 / 1024 }'
    else
        echo "?"
    fi
}
TOTAL_RAM="$(detect_total_ram_gib)"

# Detect mimalloc.
MIMALLOC_LIB=""
for candidate in \
    /usr/lib/x86_64-linux-gnu/libmimalloc.so \
    /usr/lib/aarch64-linux-gnu/libmimalloc.so \
    /usr/lib/libmimalloc.so \
    /usr/local/lib/libmimalloc.so \
    /opt/homebrew/lib/libmimalloc.dylib \
    /usr/local/lib/libmimalloc.dylib
do
    if [[ -r "$candidate" ]]; then
        MIMALLOC_LIB="$candidate"
        break
    fi
done

# Detect time(1).
TIMECMD=""
if command -v /usr/bin/time >/dev/null && /usr/bin/time -v true >/dev/null 2>&1; then
    TIMECMD="/usr/bin/time -v"
elif command -v gtime >/dev/null && gtime -v true >/dev/null 2>&1; then
    TIMECMD="gtime -v"
fi

# Output dirs.
RESULTS_DIR="$REPO_DIR/bench_results/scaling/${INSTANCE_TYPE}-${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"
SUMMARY_TSV="$RESULTS_DIR/scaling.tsv"
SUMMARY_TXT="$RESULTS_DIR/scaling.txt"
printf 'bench\tstatus\twall_seconds\tpeak_rss_KiB\tinstance\tcores\trss_per_core\n' > "$SUMMARY_TSV"

# Colours.
if [[ -t 1 ]]; then
    C_BLUE=$'\033[1;34m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'
    C_RED=$'\033[1;31m';  C_DIM=$'\033[2m';    C_RST=$'\033[0m'
else
    C_BLUE=""; C_GRN=""; C_YEL=""; C_RED=""; C_DIM=""; C_RST=""
fi

# ─────────────────────────────────────────────────────────────────
# Print configuration
# ─────────────────────────────────────────────────────────────────

cat <<INFO
${C_BLUE}══════════════════════════════════════════════════════════════════${C_RST}
${C_BLUE}  STARK-DNS bandwidth-scaling bench${C_RST}
${C_BLUE}══════════════════════════════════════════════════════════════════${C_RST}
  Instance type      : ${C_YEL}${INSTANCE_TYPE}${C_RST}
  Physical cores     : ${C_YEL}${PHYS_CORES}${C_RST}
  RAYON_NUM_THREADS  : ${C_YEL}${RAYON_NUM_THREADS}${C_RST}  (auto-set from physical cores)
  Total RAM          : ${C_YEL}${TOTAL_RAM} GiB${C_RST}
  mimalloc           : ${C_YEL}${MIMALLOC_LIB:-(not found, using system allocator)}${C_RST}
  GNU time           : ${C_YEL}${TIMECMD:-(builtin time, no RSS capture)}${C_RST}
  Cargo features     : ${C_YEL}${FEATURES}${C_RST}
  Results dir        : ${C_YEL}${RESULTS_DIR}${C_RST}
INFO
echo

# Sanity-check: warn if vCPU > nproc by 2× (likely SMT/hyperthreading on x86).
if [[ "$INSTANCE_TYPE" == c7i* || "$INSTANCE_TYPE" == c6i* || \
      "$INSTANCE_TYPE" == r7i* || "$INSTANCE_TYPE" == m7i* ]]; then
    echo "${C_YEL}NOTE${C_RST}: x86 SMT instances may benefit from RAYON_NUM_THREADS=$((PHYS_CORES / 2)) for memory-bandwidth-bound workloads."
    echo
fi

# ─────────────────────────────────────────────────────────────────
# Build once
# ─────────────────────────────────────────────────────────────────

echo "${C_BLUE}══ build (release, --features $FEATURES) ══${C_RST}"
cargo build --release -p swarm-dns --features "$FEATURES" --examples \
    > "$RESULTS_DIR/_build.log" 2>&1
echo "${C_GRN}✓${C_RST} build complete"
echo

# ─────────────────────────────────────────────────────────────────
# Bench runner
# ─────────────────────────────────────────────────────────────────

run_bench() {
    local name="$1"
    shift
    local env_prefix=("$@")

    local log="$RESULTS_DIR/$name.log"
    local timing="$RESULTS_DIR/$name.timing"
    local rss="(n/a)"

    echo "${C_BLUE}── $name ──${C_RST}"
    [[ ${#env_prefix[@]} -gt 0 ]] && echo "${C_DIM}  env: ${env_prefix[*]}${C_RST}"

    local t0 rc=0
    t0="$(date +%s)"

    # Build env array including LD_PRELOAD for mimalloc if available.
    local env_args=("${env_prefix[@]}" "RAYON_NUM_THREADS=$RAYON_NUM_THREADS")
    if [[ -n "$MIMALLOC_LIB" ]]; then
        env_args+=("LD_PRELOAD=$MIMALLOC_LIB")
    fi

    if [[ -n "$TIMECMD" ]]; then
        if ! env "${env_args[@]}" $TIMECMD -o "$timing" \
              cargo run --release -p swarm-dns --features "$FEATURES" \
              --example "$name" >"$log" 2>&1; then
            rc=$?
        fi
        if [[ -f "$timing" ]]; then
            rss=$(awk '/Maximum resident set size/ {print $NF}' "$timing")
            [[ -z "$rss" ]] && rss="(n/a)"
        fi
    else
        if ! env "${env_args[@]}" \
              cargo run --release -p swarm-dns --features "$FEATURES" \
              --example "$name" >"$log" 2>&1; then
            rc=$?
        fi
    fi

    local wall_sec=$(( $(date +%s) - t0 ))
    local rss_per_core="(n/a)"
    if [[ "$rss" != "(n/a)" ]]; then
        rss_per_core=$(awk -v r="$rss" -v c="$RAYON_NUM_THREADS" 'BEGIN { printf "%.0f", r / c }')
    fi

    if [[ "$rc" -eq 0 ]]; then
        echo "${C_GRN}  ✓${C_RST} ${wall_sec}s  rss=${rss} KiB  rss/core=${rss_per_core} KiB"
    else
        echo "${C_RED}  ✗${C_RST} ${wall_sec}s  rc=$rc"
        tail -5 "$log" | sed 's/^/    /'
    fi

    local status_str="OK"
    [[ $rc -ne 0 ]] && status_str="FAIL_${rc}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$status_str" \
        "$wall_sec" "$rss" "$INSTANCE_TYPE" "$RAYON_NUM_THREADS" "$rss_per_core" \
        >> "$SUMMARY_TSV"
}

# ─────────────────────────────────────────────────────────────────
# Modes
# ─────────────────────────────────────────────────────────────────

run_single_worker() {
    echo "${C_YEL}═══ Single-worker bandwidth-scaling probe ═══${C_RST}"
    echo "${C_DIM}  Three bandwidth-bound benches at full RAYON_NUM_THREADS=$RAYON_NUM_THREADS${C_RST}"
    echo
    run_bench prove_ecdsa_record_v1
    run_bench ed25519_streaming_merge_bench
    run_bench tld_sharded_prover_demo
}

run_concurrent_workers() {
    local N="${1:-4}"
    echo "${C_YEL}═══ Concurrent-worker scaling probe (N=$N) ═══${C_RST}"
    echo "${C_DIM}  $N parallel prove_ecdsa_record_v1 invocations${C_RST}"
    echo "${C_DIM}  Each worker uses RAYON_NUM_THREADS=$((PHYS_CORES / N))${C_RST}"
    echo

    local per_worker_threads=$((PHYS_CORES / N))
    [[ $per_worker_threads -lt 1 ]] && per_worker_threads=1

    local agg_log="$RESULTS_DIR/concurrent_${N}_aggregate.log"
    local t0 rc=0
    t0="$(date +%s)"

    for i in $(seq 1 "$N"); do
        local log="$RESULTS_DIR/concurrent_${N}_w${i}.log"
        local env_args=("RAYON_NUM_THREADS=$per_worker_threads")
        [[ -n "$MIMALLOC_LIB" ]] && env_args+=("LD_PRELOAD=$MIMALLOC_LIB")
        ( env "${env_args[@]}" cargo run --release -p swarm-dns \
              --features "$FEATURES" --example prove_ecdsa_record_v1 \
              > "$log" 2>&1 ) &
    done
    wait || rc=$?

    local agg_wall=$(( $(date +%s) - t0 ))

    echo "${C_GRN}  ✓${C_RST} N=$N concurrent workers: ${agg_wall}s aggregate"

    # Aggregate throughput per worker (single-worker reference is wall_sec
    # of single-worker prove_ecdsa from the SAME instance).
    local single_ref
    single_ref=$(awk -F'\t' '$1 == "prove_ecdsa_record_v1" {print $3}' "$SUMMARY_TSV" | tail -1)
    if [[ -n "$single_ref" ]]; then
        local efficiency
        efficiency=$(awk -v ref="$single_ref" -v agg="$agg_wall" -v n="$N" 'BEGIN {
            printf "%.2f", (ref * n) / (agg * n) * 100 / 1.0
        }')
        echo "${C_DIM}  Per-worker bandwidth efficiency vs single: ${efficiency}%${C_RST}"
        echo "${C_DIM}  (100%% = perfect linear scaling; <100%% = bandwidth-bound)${C_RST}"
    fi

    local status_str="OK"
    [[ $rc -ne 0 ]] && status_str="FAIL_${rc}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "concurrent_${N}_workers" "$status_str" \
        "$agg_wall" "(n/a)" "$INSTANCE_TYPE" \
        "$N x $per_worker_threads" "(n/a)" \
        >> "$SUMMARY_TSV"
}

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────

write_summary() {
    {
        printf '%s\n' "STARK-DNS bandwidth-scaling summary"
        printf '%s\n' "Instance: $INSTANCE_TYPE   cores: $PHYS_CORES   RAM: $TOTAL_RAM GiB"
        printf '%s\n' "Timestamp: $TIMESTAMP UTC   Logs: $RESULTS_DIR"
        printf '%s\n' "RAYON_NUM_THREADS=$RAYON_NUM_THREADS  mimalloc: ${MIMALLOC_LIB:-no}"
        printf '\n'
        printf '%-40s %-10s %12s %14s %18s\n' \
            "bench" "status" "wall_sec" "peak_rss_KiB" "rss_per_core_KiB"
        printf '%s\n' "──────────────────────────────────────────────────────────────────────────────────────────────"
        tail -n +2 "$SUMMARY_TSV" | \
            awk -F'\t' '{ printf "%-40s %-10s %12s %14s %18s\n", $1, $2, $3, $4, $7 }'
        printf '\n'
        printf '%s\n' "Compare against r8g.xlarge baseline:"
        printf '  prove_ecdsa_record_v1            : %s\n' "99 s"
        printf '  ed25519_streaming_merge_bench    : %s\n' "281 s"
        printf '  tld_sharded_prover_demo          : %s\n' "187 s"
    } | tee "$SUMMARY_TXT"
}

# ─────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────

usage() {
    cat <<USAGE
bench_scaling.sh — STARK-DNS bandwidth-scaling characterisation

USAGE:
    $0 single             # single-worker bandwidth scan (~10 min)
    $0 concurrent N       # launch N concurrent ECDSA proves
    $0 both [N]           # single-worker + concurrent (default N=$PHYS_CORES/4)

The script auto-detects:
  * AWS instance type (via IMDSv2)
  * Physical CPU count (sets RAYON_NUM_THREADS)
  * Total RAM
  * mimalloc presence (LD_PRELOAD-injected if found)

Outputs are written to bench_results/scaling/<instance>-<ts>/.
USAGE
    exit 1
}

[[ $# -lt 1 ]] && usage
MODE="$1"
N_ARG="${2:-$((PHYS_CORES / 4))}"
[[ "$N_ARG" -lt 1 ]] && N_ARG=1

case "$MODE" in
    single)      run_single_worker ;;
    concurrent)
        [[ -z "${2:-}" ]] && { echo "concurrent N required"; usage; }
        run_concurrent_workers "$2"
        ;;
    both)
        run_single_worker
        echo
        run_concurrent_workers "$N_ARG"
        ;;
    *) usage ;;
esac

echo
echo "${C_BLUE}═══ Summary ═══${C_RST}"
write_summary
echo
echo "${C_GRN}Done.${C_RST}  Results: $RESULTS_DIR"
