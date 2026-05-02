#!/usr/bin/env bash
#
# bench_thread_sweep.sh — STARK-DNS thread-count sensitivity probe
#
# Experiment 1: Single-bench RAYON_NUM_THREADS sweep
#     For each bench in {ed25519, ecdsa, crossalg, mixed_zone, dns_chain},
#     run at T = 4, 8, 12, max-cores.  Produces a curve that exposes
#     the cache-thrashing sweet-spot below `nproc` for Ed25519-heavy
#     workloads, and confirms ECDSA scales further.
#
# Experiment 2: Concurrent-worker throughput scan
#     For W in {1, 2, 4} workers, launch W parallel prove_ecdsa_record_v1
#     instances, each with RAYON_NUM_THREADS = floor(PHYS_CORES / W).
#     Reports aggregate throughput (proofs/min) and per-worker efficiency.
#     This is the deployment-shape recommendation test: same instance budget,
#     different worker layout.
#
# USAGE:
#   ./scripts/bench_thread_sweep.sh sweep      # ~30 min  Experiment 1 only
#   ./scripts/bench_thread_sweep.sh concurrent # ~10 min  Experiment 2 only
#   ./scripts/bench_thread_sweep.sh full       # ~40 min  both
#
# OUTPUT:
#   bench_results/thread_sweep/<instance>-<ts>/
#       sweep.tsv              one row per (bench, T)
#       concurrent.tsv         one row per (W, agg_wall, throughput, eff%)
#       summary.txt            human-readable side-by-side
#

set -euo pipefail

# ─────────────────────────────────────────────────────────────────
# Setup + hardware detection (mirrors bench_scaling.sh)
# ─────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
FEATURES="${BENCH_FEATURES:-parallel,sha3-256}"

cd "$REPO_DIR"

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
    if [[ "$(uname -s)" == "Darwin" ]]; then
        echo "mac-$(sysctl -n hw.model 2>/dev/null | tr ' /' '--' | tr '[:upper:]' '[:lower:]')"
    else
        echo "unknown-$(uname -m)"
    fi
}

detect_phys_cores() {
    if command -v nproc >/dev/null; then
        nproc --all
    elif command -v sysctl >/dev/null; then
        sysctl -n hw.physicalcpu 2>/dev/null || sysctl -n hw.ncpu
    else
        echo 1
    fi
}

INSTANCE_TYPE="$(detect_instance_type)"
PHYS_CORES="$(detect_phys_cores)"

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
    [[ -r "$candidate" ]] && { MIMALLOC_LIB="$candidate"; break; }
done

# Detect time(1).
TIMECMD=""
if command -v /usr/bin/time >/dev/null && /usr/bin/time -v true >/dev/null 2>&1; then
    TIMECMD="/usr/bin/time -v"
elif command -v gtime >/dev/null && gtime -v true >/dev/null 2>&1; then
    TIMECMD="gtime -v"
fi

# Early-exit usage check: do this BEFORE creating dirs / building so that
# `bench_thread_sweep.sh` with no args (or bad args) doesn't waste a build.
usage() {
    cat <<USAGE
bench_thread_sweep.sh — STARK-DNS thread-count sensitivity probe

USAGE:
    \$0 sweep         # ~30 min   Exp 1 only (5 benches × thread counts)
    \$0 concurrent    # ~10 min   Exp 2 only (concurrent ECDSA workers)
    \$0 full          # ~40 min   both

Auto-detects:
  * AWS instance type (IMDSv2)
  * Physical CPU count (sets the thread sweep set: 4, 8, 12, nproc)
  * mimalloc presence (LD_PRELOAD)

Outputs to bench_results/thread_sweep/<instance>-<ts>/.
USAGE
    exit 1
}
[[ $# -lt 1 ]] && usage
case "$1" in
    sweep|concurrent|full) ;;
    *) usage ;;
esac
MODE="$1"

# Output dirs.
RESULTS_DIR="$REPO_DIR/bench_results/thread_sweep/${INSTANCE_TYPE}-${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"
SWEEP_TSV="$RESULTS_DIR/sweep.tsv"
CONC_TSV="$RESULTS_DIR/concurrent.tsv"
SUMMARY_TXT="$RESULTS_DIR/summary.txt"
printf 'bench\tthreads\tstatus\twall_seconds\tpeak_rss_KiB\n' > "$SWEEP_TSV"
printf 'workers\tthreads_per_worker\tstatus\tagg_wall_seconds\tthroughput_per_min\tefficiency_pct\n' > "$CONC_TSV"

# Colours.
if [[ -t 1 ]]; then
    C_BLUE=$'\033[1;34m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'
    C_RED=$'\033[1;31m';  C_DIM=$'\033[2m';    C_RST=$'\033[0m'
else
    C_BLUE=""; C_GRN=""; C_YEL=""; C_RED=""; C_DIM=""; C_RST=""
fi

# Build the thread-count list: include 4, 8, 12, PHYS_CORES — dedup, drop > nproc.
build_thread_list() {
    local cands=(4 8 12 "$PHYS_CORES")
    local out=() seen=""
    for t in "${cands[@]}"; do
        [[ "$t" -le 0 || "$t" -gt "$PHYS_CORES" ]] && continue
        case " $seen " in *" $t "*) continue;; esac
        seen="$seen $t"
        out+=("$t")
    done
    # Sort ascending.
    printf '%s\n' "${out[@]}" | sort -n | uniq | tr '\n' ' '
}
THREAD_LIST=($(build_thread_list))

# ─────────────────────────────────────────────────────────────────
# Print configuration
# ─────────────────────────────────────────────────────────────────

cat <<INFO
${C_BLUE}══════════════════════════════════════════════════════════════════${C_RST}
${C_BLUE}  STARK-DNS thread-sweep / concurrent-worker probe${C_RST}
${C_BLUE}══════════════════════════════════════════════════════════════════${C_RST}
  Instance type      : ${C_YEL}${INSTANCE_TYPE}${C_RST}
  Physical cores     : ${C_YEL}${PHYS_CORES}${C_RST}
  Thread sweep set   : ${C_YEL}${THREAD_LIST[*]}${C_RST}
  mimalloc           : ${C_YEL}${MIMALLOC_LIB:-(not found)}${C_RST}
  GNU time           : ${C_YEL}${TIMECMD:-(builtin)}${C_RST}
  Cargo features     : ${C_YEL}${FEATURES}${C_RST}
  Results dir        : ${C_YEL}${RESULTS_DIR}${C_RST}
INFO
echo

# ─────────────────────────────────────────────────────────────────
# Build once
# ─────────────────────────────────────────────────────────────────

echo "${C_BLUE}══ build (release, --features $FEATURES) ══${C_RST}"
cargo build --release -p swarm-dns --features "$FEATURES" --examples \
    > "$RESULTS_DIR/_build.log" 2>&1
echo "${C_GRN}✓${C_RST} build complete"
echo

# ─────────────────────────────────────────────────────────────────
# Single-bench runner pinned to a thread count
# ─────────────────────────────────────────────────────────────────

run_at_threads() {
    local name="$1" threads="$2"
    local tag="${name}_T${threads}"
    local log="$RESULTS_DIR/$tag.log"
    local timing="$RESULTS_DIR/$tag.timing"
    local rss="(n/a)"

    echo "${C_BLUE}── $name @ T=$threads ──${C_RST}"

    local env_args=("RAYON_NUM_THREADS=$threads")
    [[ -n "$MIMALLOC_LIB" ]] && env_args+=("LD_PRELOAD=$MIMALLOC_LIB")

    local t0 rc=0
    t0="$(date +%s)"
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

    if [[ "$rc" -eq 0 ]]; then
        echo "${C_GRN}  ✓${C_RST} ${wall_sec}s  rss=${rss} KiB"
    else
        echo "${C_RED}  ✗${C_RST} ${wall_sec}s  rc=$rc"
        tail -5 "$log" | sed 's/^/    /'
    fi

    local status_str="OK"
    [[ $rc -ne 0 ]] && status_str="FAIL_${rc}"
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$threads" "$status_str" \
        "$wall_sec" "$rss" >> "$SWEEP_TSV"
}

# ─────────────────────────────────────────────────────────────────
# Experiment 1 — thread-count sweep across the five paper benches
# ─────────────────────────────────────────────────────────────────
#
# Bench selection rationale:
#   ed25519_streaming_merge_bench  — pure Ed25519, K-sweep, exposes the
#                                    cache-thrashing curve cleanly.
#   prove_ecdsa_record_v1          — pure ECDSA, control: should scale OK.
#   crossalg_three_signature_bench — sequential RSA+Ed25519+ECDSA: shows
#                                    Ed25519 regression in mixed setting.
#   mixed_algorithm_zone_rollup    — sequential mixed + outer rollup: the
#                                    most extreme regression on r8g.4xlarge.
#   dns_chain_multirecord_bench    — N-record chain: amplifies Ed25519
#                                    regression because Ed25519 sigs dominate.

run_sweep() {
    echo "${C_YEL}═══ Experiment 1: single-bench RAYON_NUM_THREADS sweep ═══${C_RST}"
    local benches=(
        ed25519_streaming_merge_bench
        prove_ecdsa_record_v1
        crossalg_three_signature_bench
        mixed_algorithm_zone_rollup
        dns_chain_multirecord_bench
    )
    for bench in "${benches[@]}"; do
        for t in "${THREAD_LIST[@]}"; do
            run_at_threads "$bench" "$t"
        done
        echo
    done
}

# ─────────────────────────────────────────────────────────────────
# Experiment 2 — concurrent ECDSA workers
# ─────────────────────────────────────────────────────────────────
#
# Spawns W parallel prove_ecdsa_record_v1 invocations, each with
# floor(PHYS_CORES / W) Rayon threads.  Reports:
#   agg_wall      = wall-clock until ALL W workers finish
#   throughput    = W proofs / agg_wall (proofs/min normalised)
#   efficiency    = (W × single_ref) / (agg_wall × W) × 100
#                 = single_ref / agg_wall × 100   (per-worker speedup)
#
# Target: W=4 on r8g.4xlarge should give agg_wall ≈ single_ref (i.e. 4×
# throughput on the same instance budget).  Lower efficiency means
# bandwidth saturation prevents further per-worker scaling.

run_concurrent() {
    echo "${C_YEL}═══ Experiment 2: concurrent ECDSA workers ═══${C_RST}"

    # Single-worker reference at full thread count.
    echo "${C_BLUE}── reference: 1 worker × $PHYS_CORES threads ──${C_RST}"
    run_at_threads prove_ecdsa_record_v1 "$PHYS_CORES"
    local single_ref
    single_ref=$(awk -F'\t' \
        -v t="$PHYS_CORES" \
        '$1 == "prove_ecdsa_record_v1" && $2 == t {print $4}' \
        "$SWEEP_TSV" | tail -1)
    echo "${C_DIM}  single-worker reference: ${single_ref}s${C_RST}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        1 "$PHYS_CORES" "OK" "$single_ref" \
        "$(awk -v s="$single_ref" 'BEGIN { printf "%.2f", 60 / s }')" "100.0" \
        >> "$CONC_TSV"
    echo

    # Multi-worker scans.
    local worker_counts=(2 4)
    [[ "$PHYS_CORES" -ge 16 ]] && worker_counts+=(8)

    for W in "${worker_counts[@]}"; do
        [[ "$W" -gt "$PHYS_CORES" ]] && continue
        local per_worker=$((PHYS_CORES / W))
        [[ "$per_worker" -lt 1 ]] && per_worker=1

        echo "${C_BLUE}── $W workers × $per_worker threads each ──${C_RST}"
        local t0 rc=0
        t0="$(date +%s)"
        local pids=()
        for i in $(seq 1 "$W"); do
            local log="$RESULTS_DIR/conc_W${W}_w${i}.log"
            local env_args=("RAYON_NUM_THREADS=$per_worker")
            [[ -n "$MIMALLOC_LIB" ]] && env_args+=("LD_PRELOAD=$MIMALLOC_LIB")
            ( env "${env_args[@]}" cargo run --release -p swarm-dns \
                --features "$FEATURES" --example prove_ecdsa_record_v1 \
                > "$log" 2>&1 ) &
            pids+=($!)
        done
        for pid in "${pids[@]}"; do
            wait "$pid" || rc=$?
        done
        local agg_wall=$(( $(date +%s) - t0 ))

        # Throughput = W proofs / agg_wall (per minute).
        local throughput="(n/a)"
        local efficiency="(n/a)"
        if [[ "$agg_wall" -gt 0 ]]; then
            throughput=$(awk -v w="$W" -v a="$agg_wall" \
                'BEGIN { printf "%.2f", (w * 60) / a }')
        fi
        if [[ -n "$single_ref" && "$single_ref" -gt 0 && "$agg_wall" -gt 0 ]]; then
            efficiency=$(awk -v s="$single_ref" -v a="$agg_wall" \
                'BEGIN { printf "%.1f", (s / a) * 100 }')
        fi

        if [[ "$rc" -eq 0 ]]; then
            echo "${C_GRN}  ✓${C_RST} agg_wall=${agg_wall}s throughput=${throughput}/min efficiency=${efficiency}%"
        else
            echo "${C_RED}  ✗${C_RST} agg_wall=${agg_wall}s rc=$rc"
        fi
        local status_str="OK"
        [[ $rc -ne 0 ]] && status_str="FAIL_${rc}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$W" "$per_worker" "$status_str" \
            "$agg_wall" "$throughput" "$efficiency" \
            >> "$CONC_TSV"
        echo
    done
}

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────

write_summary() {
    {
        printf '%s\n' "STARK-DNS thread-sweep summary"
        printf '%s\n' "Instance: $INSTANCE_TYPE   cores: $PHYS_CORES"
        printf '%s\n' "Timestamp: $TIMESTAMP UTC"
        printf '%s\n' "Logs: $RESULTS_DIR"
        printf '\n'

        if [[ -s "$SWEEP_TSV" ]] && [[ "$(wc -l < "$SWEEP_TSV")" -gt 1 ]]; then
            printf '%s\n' "── Experiment 1: thread sweep (wall_seconds at each T) ──"
            printf '%-40s' "bench"
            for t in "${THREAD_LIST[@]}"; do printf ' %8s' "T=$t"; done
            printf '\n'
            printf '%s\n' "──────────────────────────────────────────────────────────────────────────"
            local last_bench=""
            for bench in ed25519_streaming_merge_bench prove_ecdsa_record_v1 \
                         crossalg_three_signature_bench mixed_algorithm_zone_rollup \
                         dns_chain_multirecord_bench; do
                printf '%-40s' "$bench"
                for t in "${THREAD_LIST[@]}"; do
                    local wall
                    wall=$(awk -F'\t' \
                        -v b="$bench" -v t="$t" \
                        '$1 == b && $2 == t {print $4}' \
                        "$SWEEP_TSV" | tail -1)
                    printf ' %8s' "${wall:--}"
                done
                printf '\n'
            done
            printf '\n'
            printf '%s\n' "Interpret: monotone increase with T → cache thrashing dominates."
            printf '%s\n' "           monotone decrease with T → bandwidth-scaling holds."
            printf '%s\n' "           U-curve  → optimal T is below nproc."
            printf '\n'
        fi

        if [[ -s "$CONC_TSV" ]] && [[ "$(wc -l < "$CONC_TSV")" -gt 1 ]]; then
            printf '%s\n' "── Experiment 2: concurrent ECDSA workers (per-instance throughput) ──"
            printf '%-8s %-12s %-8s %-12s %-16s %-12s\n' \
                "workers" "threads/wkr" "status" "agg_wall_s" "thru_proofs/min" "eff_%"
            printf '%s\n' "─────────────────────────────────────────────────────────────────────────"
            tail -n +2 "$CONC_TSV" | \
                awk -F'\t' '{ printf "%-8s %-12s %-8s %-12s %-16s %-12s\n", $1,$2,$3,$4,$5,$6 }'
            printf '\n'
            printf '%s\n' "Interpret: efficiency=100% means each worker runs at single-worker speed."
            printf '%s\n' "           If W=4 efficiency≥80%, deploy as 4 workers × $((PHYS_CORES/4)) threads."
        fi
    } | tee "$SUMMARY_TXT"
}

# ─────────────────────────────────────────────────────────────────
# Dispatch (mode validated up top before the build)
# ─────────────────────────────────────────────────────────────────

case "$MODE" in
    sweep)       run_sweep ;;
    concurrent)  run_concurrent ;;
    full)
        run_sweep
        echo
        run_concurrent
        ;;
esac

echo
echo "${C_BLUE}═══ Summary ═══${C_RST}"
write_summary
echo
echo "${C_GRN}Done.${C_RST}  Results: $RESULTS_DIR"
