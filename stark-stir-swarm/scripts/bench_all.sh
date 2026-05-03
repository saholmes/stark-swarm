#!/usr/bin/env bash
#
# bench_all.sh — STARK-DNS reproducibility driver
#
# Orchestrates every benchmark cited in main-24.tex.  Captures
# per-bench wall time + full stdout/stderr to bench_results/, and
# prints a final summary table.  Designed for AWS Linux + macOS;
# falls back gracefully if `/usr/bin/time -v` or `mimalloc` are
# absent.
#
# USAGE:
#   ./scripts/bench_all.sh smoke      # ~5 min: verify install + crypto round-trip
#   ./scripts/bench_all.sh single     # ~25 min: per-algorithm + cross-algo
#   ./scripts/bench_all.sh edge       # ~30 min: edge consumer + airgapped + TLD
#   ./scripts/bench_all.sh scaling    # ~30 min: multi-record + streaming + gadgets
#   ./scripts/bench_all.sh full       # ~90 min: everything except long-N
#   ./scripts/bench_all.sh paper      # 90 min:  every bench cited in the paper
#   ./scripts/bench_all.sh long-n     # 8 hr:    multi-record at large N (RSA=100, ED=5, EC=5)
#
# OUTPUT:
#   bench_results/$timestamp/<bench>.log    full stdout/stderr
#   bench_results/$timestamp/_summary.tsv   tab-separated bench / wall-clock / status
#   bench_results/$timestamp/_summary.txt   human-readable summary
#
# ENV OVERRIDES:
#   RAYON_NUM_THREADS=N    pin parallelism (default: physical cores)
#   BENCH_OUT=/path/dir    override results directory
#   BENCH_FEATURES=...     extra cargo --features (default: parallel,sha3-256)
#

set -euo pipefail

# ─────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
BENCH_OUT="${BENCH_OUT:-$REPO_DIR/bench_results/$TIMESTAMP}"
FEATURES="${BENCH_FEATURES:-parallel,sha3-256}"

# Detect physical core count (avoid SMT noise) — Linux + macOS friendly.
detect_phys_cores() {
    if command -v nproc >/dev/null; then
        nproc --all
    elif command -v sysctl >/dev/null; then
        sysctl -n hw.physicalcpu 2>/dev/null || sysctl -n hw.ncpu
    else
        echo 1
    fi
}
: "${RAYON_NUM_THREADS:=$(detect_phys_cores)}"
export RAYON_NUM_THREADS

# Detect a usable wall-clock-with-RSS timer.
TIMECMD=""
if command -v /usr/bin/time >/dev/null && /usr/bin/time -v true >/dev/null 2>&1; then
    TIMECMD="/usr/bin/time -v"      # Linux GNU time (gives peak RSS)
elif command -v gtime >/dev/null && gtime -v true >/dev/null 2>&1; then
    TIMECMD="gtime -v"              # macOS coreutils GNU time (brew install gnu-time)
fi
# (If neither is present we use bash builtin `time` and skip RSS.)

mkdir -p "$BENCH_OUT"
SUMMARY_TSV="$BENCH_OUT/_summary.tsv"
SUMMARY_TXT="$BENCH_OUT/_summary.txt"
printf 'bench\tstatus\twall_seconds\tpeak_rss_KiB\tlog\n' > "$SUMMARY_TSV"

cd "$REPO_DIR"

# Colours (suppress on non-tty).
if [[ -t 1 ]]; then
    C_BLUE=$'\033[1;34m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'
    C_RED=$'\033[1;31m';  C_DIM=$'\033[2m';    C_RST=$'\033[0m'
else
    C_BLUE=""; C_GRN=""; C_YEL=""; C_RED=""; C_DIM=""; C_RST=""
fi

# ─────────────────────────────────────────────────────────────────
# One-time build (covers every example used below)
# ─────────────────────────────────────────────────────────────────

build_once() {
    echo "${C_BLUE}═══ Building (release, --features $FEATURES) ═══${C_RST}"
    cargo build --release -p swarm-dns --features "$FEATURES" --examples \
        2>&1 | tee "$BENCH_OUT/_build.log" | tail -5
    echo "${C_GRN}✓${C_RST} build complete; logs at $BENCH_OUT/_build.log"
    echo
}

# ─────────────────────────────────────────────────────────────────
# Bench runner — one example, time it, capture log + summary line
# ─────────────────────────────────────────────────────────────────

run_bench() {
    local name="$1"
    shift
    local env_prefix=("$@")    # e.g. RSA_N=100  ED_N=5

    local log="$BENCH_OUT/$name.log"
    local timing="$BENCH_OUT/$name.timing"
    local rss="(n/a)"
    local wall_sec="0"
    local status="OK"

    echo "${C_BLUE}─── $name ───${C_RST}"
    if [[ ${#env_prefix[@]} -gt 0 ]]; then
        echo "${C_DIM}  env: ${env_prefix[*]}${C_RST}"
    fi
    local t0
    t0="$(date +%s)"

    local rc=0
    if [[ -n "$TIMECMD" ]]; then
        # GNU time: capture wall + max-resident-set
        if ! env "${env_prefix[@]}" $TIMECMD -o "$timing" \
              cargo run --release -p swarm-dns --features "$FEATURES" \
              --example "$name" >"$log" 2>&1; then
            rc=$?
        fi
        if [[ -f "$timing" ]]; then
            rss=$(awk '/Maximum resident set size/ {print $NF}' "$timing")
            [[ -z "$rss" ]] && rss="(n/a)"
        fi
    else
        if ! env "${env_prefix[@]}" \
              cargo run --release -p swarm-dns --features "$FEATURES" \
              --example "$name" >"$log" 2>&1; then
            rc=$?
        fi
    fi

    wall_sec=$(( $(date +%s) - t0 ))

    if [[ "$rc" -eq 0 ]]; then
        echo "${C_GRN}  ✓${C_RST} ${wall_sec}s  rss=${rss} KiB"
    else
        status="FAIL($rc)"
        echo "${C_RED}  ✗${C_RST} ${wall_sec}s  rss=${rss} KiB  rc=$rc"
        echo "${C_RED}    last 10 lines of $log:${C_RST}"
        tail -10 "$log" | sed 's/^/    /'
    fi

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$status" "$wall_sec" "$rss" "$log" >> "$SUMMARY_TSV"

    return 0    # never abort the suite on one bench failure
}

# ─────────────────────────────────────────────────────────────────
# Bench tiers
# ─────────────────────────────────────────────────────────────────

run_smoke() {
    echo "${C_YEL}=== SMOKE TEST (~5 min) ===${C_RST}"
    run_bench rsa2048_native_roundtrip
    run_bench prove_rsa2048_record_v1
    run_bench rsa2048_streaming_vs_rowmajor_bench
    run_bench quantum_mitm_attack_demo
}

run_single() {
    echo "${C_YEL}=== PER-ALGORITHM SINGLE-RECORD PROVES (~10 min) ===${C_RST}"
    run_bench prove_rsa2048_record_v1
    run_bench prove_ecdsa_record_v1
    echo "${C_YEL}=== CROSS-ALGORITHM REPRODUCIBILITY HARNESS (~6 min) ===${C_RST}"
    run_bench crossalg_three_signature_bench
}

run_edge() {
    echo "${C_YEL}=== EDGE CONSUMER + ARCHITECTURAL DEMOS (~30 min) ===${C_RST}"
    run_bench edge_consumer_full_demo
    run_bench airgapped_resolver_demo
    run_bench mixed_algorithm_zone_rollup
    run_bench epoch_artefact_size_bench
    run_bench tld_sharded_prover_demo
    run_bench stacked_rsa_zone_prover
}

run_scaling() {
    echo "${C_YEL}=== MULTI-RECORD + STREAMING + GADGET MICRO (~35 min) ===${C_RST}"
    run_bench dns_chain_multirecord_bench
    run_bench rsa2048_streaming_vs_rowmajor_bench
    run_bench ed25519_streaming_merge_bench
    run_bench p256_gadget_microbench
    run_bench p256_multirow_stark_prove
    run_bench p256_full_ecdsa_stark_bench
}

run_quantum() {
    echo "${C_YEL}=== QUANTUM-MITM ATTACK DEMO (~8 min) ===${C_RST}"
    run_bench quantum_mitm_attack_demo
}

run_long_n() {
    echo "${C_YEL}=== LONG-N MULTI-RECORD (RSA=100, ED=5, EC=5; ~8 hr) ===${C_RST}"
    run_bench dns_chain_multirecord_bench RSA_N=100 ED_N=5 EC_N=5
}

# Run concurrent-worker scaling probe via bench_thread_sweep.sh.
# Captures cost-parity numbers (η_W=2, η_W=4) on the same hardware run.
run_concurrent() {
    echo "${C_YEL}=== CONCURRENT-WORKER SCALING (~10 min) ===${C_RST}"
    local sweep_script="$SCRIPT_DIR/bench_thread_sweep.sh"
    if [[ ! -x "$sweep_script" ]]; then
        echo "${C_RED}  skipped: $sweep_script not found or not executable${C_RST}"
        return 0
    fi
    # bench_thread_sweep.sh writes its own results dir under
    # bench_results/thread_sweep/<instance>-<ts>/.  We copy its summary
    # into our run dir for easy retrieval and append a pointer line.
    local sweep_log="$BENCH_OUT/concurrent_sweep.log"
    local rc=0
    if ! bash "$sweep_script" concurrent > "$sweep_log" 2>&1; then
        rc=$?
    fi
    # Locate and copy the produced summary.
    local sweep_dir
    sweep_dir=$(ls -1td "$REPO_DIR/bench_results/thread_sweep"/* 2>/dev/null | head -1)
    if [[ -n "$sweep_dir" && -f "$sweep_dir/summary.txt" ]]; then
        cp "$sweep_dir/summary.txt"     "$BENCH_OUT/concurrent_summary.txt"
        cp "$sweep_dir/concurrent.tsv"  "$BENCH_OUT/concurrent.tsv" 2>/dev/null || true
        echo "${C_GRN}  ✓${C_RST} concurrent results copied to $BENCH_OUT/concurrent_summary.txt"
    else
        echo "${C_RED}  ✗${C_RST} concurrent run did not produce a summary (rc=$rc)"
    fi
    # Append a pointer row to the main TSV so it appears in the final summary.
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "concurrent_worker_sweep" \
        "$([[ $rc -eq 0 ]] && echo OK || echo FAIL_${rc})" \
        "(see concurrent_summary.txt)" "(n/a)" "$sweep_log" \
        >> "$SUMMARY_TSV"
}

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────

write_summary() {
    {
        printf '%s\n' "STARK-DNS bench summary  ($TIMESTAMP UTC)"
        printf '%s\n' "Repo: $REPO_DIR"
        printf '%s\n' "Logs: $BENCH_OUT"
        printf '%s\n' "Cores: RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
        printf '%s\n' "Features: $FEATURES"
        printf '\n'
        printf '%-45s %-9s %12s %14s\n' "bench" "status" "wall_sec" "peak_rss_KiB"
        printf '%s\n' "─────────────────────────────────────────────────────────────────────────────────"
        # Skip header row of TSV
        tail -n +2 "$SUMMARY_TSV" | \
            awk -F'\t' '{ printf "%-45s %-9s %12s %14s\n", $1, $2, $3, $4 }'
        # Append concurrent-worker block if produced.
        if [[ -f "$BENCH_OUT/concurrent_summary.txt" ]]; then
            printf '\n'
            printf '%s\n' "── Concurrent-worker scaling ──"
            cat "$BENCH_OUT/concurrent_summary.txt"
        fi
    } | tee "$SUMMARY_TXT"
}

# ─────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────

usage() {
    cat <<USAGE
bench_all.sh — STARK-DNS reproducibility driver

USAGE:
    $0 <tier>

TIERS:
    smoke       ~5 min   verify install + crypto round-trip
    single     ~16 min   per-algorithm + cross-algo benchmarks
    edge       ~30 min   edge consumer + airgapped + TLD demos
    scaling    ~35 min   multi-record + streaming-merge + gadgets
    quantum     ~8 min   quantum-MITM attack demo
    concurrent ~10 min   concurrent-worker cost-parity (W=1,2,4,8)
    full      ~100 min   smoke + single + edge + scaling + quantum + concurrent
    paper     ~100 min   every bench cited in main-25.tex (alias for 'full')
    long-n      ~8 hr    multi-record at large N (RSA=100, ED=5, EC=5)

ENV:
    RAYON_NUM_THREADS=N    pin parallelism (default: physical cores)
    BENCH_OUT=/path/dir    override results directory
    BENCH_FEATURES=...     extra cargo --features (default: parallel,sha3-256)
USAGE
    exit 1
}

if [[ $# -lt 1 ]]; then usage; fi
TIER="$1"

build_once

case "$TIER" in
    smoke)       run_smoke ;;
    single)      run_single ;;
    edge)        run_edge ;;
    scaling)     run_scaling ;;
    quantum)     run_quantum ;;
    concurrent)  run_concurrent ;;
    full|paper)
        run_smoke
        run_single
        run_edge
        run_scaling
        run_quantum
        run_concurrent
        ;;
    long-n)      run_long_n ;;
    *) usage ;;
esac

echo
echo "${C_BLUE}═══ Summary ═══${C_RST}"
write_summary
echo
echo "${C_GRN}Done.${C_RST}  Results in: $BENCH_OUT"
