//! Helper library for `cairo-bench`.
//!
//! Provides:
//!   - Field adapters between Cairo's Felt252 and Goldilocks.
//!   - StarkWare-format JSON trace builder for all synthetic AIRs.
//!   - Optional `cairo-vm-trace` feature for running real Cairo 0 programs.
//!
//! DNS-rollup helpers and the megazone demo previously lived here; they
//! moved to the dedicated `swarm-dns` crate when this workspace was
//! refactored for swarm proving.

use ark_ff::PrimeField;
use ark_goldilocks::Goldilocks as F;

// ─────────────────────────────────────────────────────────────────────────────
//  Felt252 ↔ Goldilocks field adapter
// ─────────────────────────────────────────────────────────────────────────────

/// Goldilocks prime p = 2^64 − 2^32 + 1.
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Reduce a 64-bit Cairo field value to Goldilocks by taking the value mod p.
///
/// Cairo 0 uses STARK prime (2^251 + 17·2^192 + 1).  Field elements that fit
/// in 64 bits can be taken directly; larger elements need the full bigint path.
#[inline]
pub fn felt_u64_to_goldilocks(val: u64) -> F {
    F::from(val % GOLDILOCKS_PRIME)
}

/// Reduce a Felt252 represented as four 64-bit limbs (little-endian) to Goldilocks.
///
/// Uses Barrett reduction: compute the 256-bit value mod p via 64-bit arithmetic.
/// This is not constant-time and is intended for trace import, not cryptography.
pub fn felt_limbs_to_goldilocks(limbs: &[u64; 4]) -> F {
    // Goldilocks prime p = 2^64 - 2^32 + 1.
    // Reduce each limb: F::from correctly handles values up to u64::MAX by
    // computing them mod p internally via the ark-ff FromStr/From path.
    let p = GOLDILOCKS_PRIME as u128;
    let mut result: u128 = 0;
    let base: u128 = (u64::MAX as u128) + 1; // 2^64
    for i in (0..4).rev() {
        result = (result * (base % p) + limbs[i] as u128) % p;
    }
    F::from(result as u64)
}

// ─────────────────────────────────────────────────────────────────────────────
//  StarkWare JSON trace exporter
// ─────────────────────────────────────────────────────────────────────────────

/// Serialize a synthetic AIR trace (column-major) as StarkWare-format JSON.
///
/// Column names are taken from `col_names`; if shorter than `trace.len()`,
/// synthetic names `"c{i}"` are appended.
pub fn trace_to_starkware_json(trace: &[Vec<F>], col_names: &[&str]) -> String {
    let n_cols = trace.len();
    let n_rows = if n_cols > 0 { trace[0].len() } else { 0 };

    let mut obj = String::from("{\n");
    obj.push_str(&format!("  \"format\": \"starkware-v1\",\n"));
    obj.push_str(&format!("  \"width\": {},\n", n_cols));
    obj.push_str(&format!("  \"length\": {},\n", n_rows));
    obj.push_str("  \"columns\": {\n");

    for (i, col) in trace.iter().enumerate() {
        let name = if i < col_names.len() {
            col_names[i].to_string()
        } else {
            format!("c{i}")
        };
        let values: Vec<String> = col
            .iter()
            .map(|f| f.into_bigint().0[0].to_string())
            .collect();
        let sep = if i + 1 < n_cols { "," } else { "" };
        obj.push_str(&format!("    \"{name}\": [{}]{sep}\n", values.join(",")));
    }

    obj.push_str("  }\n}\n");
    obj
}

// ─────────────────────────────────────────────────────────────────────────────
//  Optional: Cairo VM real-trace extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Run a compiled Cairo 0 JSON program and return the execution trace as
/// Goldilocks columns.
///
/// The trace column ordering is: `[pc, ap, fp, op0, op1, res, dst, ...]`.
/// Field elements are reduced to Goldilocks via `felt_u64_to_goldilocks`.
///
/// Requires the `cairo-vm-trace` feature and a compiled `.json` program from
/// `cairo-compile`.  Use `cairo-run --trace_file` to see intermediate output.
#[cfg(feature = "cairo-vm-trace")]
pub fn run_cairo_program(compiled_json_path: &str) -> Result<Vec<Vec<F>>, String> {
    use cairo_vm::{
        cairo_run::{cairo_run, CairoRunConfig},
        types::layout_name::LayoutName,
    };
    use std::fs;

    let program_bytes = fs::read(compiled_json_path)
        .map_err(|e| format!("cannot read {compiled_json_path}: {e}"))?;

    let config = CairoRunConfig {
        layout: LayoutName::plain,
        relocate_mem: true,
        trace_enabled: true,
        ..Default::default()
    };

    let (runner, vm) = cairo_run(&program_bytes, &config, &mut Default::default())
        .map_err(|e| format!("cairo-vm error: {e:?}"))?;

    let trace = vm
        .get_relocated_trace()
        .map_err(|e| format!("trace error: {e:?}"))?;

    let n = trace.len();
    let mut pc_col = Vec::with_capacity(n);
    let mut ap_col = Vec::with_capacity(n);
    let mut fp_col = Vec::with_capacity(n);

    for entry in trace {
        pc_col.push(felt_u64_to_goldilocks(entry.pc as u64));
        ap_col.push(felt_u64_to_goldilocks(entry.ap as u64));
        fp_col.push(felt_u64_to_goldilocks(entry.fp as u64));
    }

    Ok(vec![pc_col, ap_col, fp_col])
}

// ─────────────────────────────────────────────────────────────────────────────
//  Benchmark result record (shared between bench and tests)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct BenchRecord {
    pub air_label:    String,
    pub n_trace:      usize,
    pub blowup:       usize,
    pub n_queries:    usize,
    pub proof_bytes:  usize,
    pub prove_ms:     f64,
    pub verify_us:    f64,
    pub throughput:   f64, // rows / second
}

impl BenchRecord {
    pub fn header() -> &'static str {
        "air,n_trace,blowup,n_queries,proof_bytes,prove_ms,verify_us,rows_per_sec"
    }
    pub fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{:.3},{:.1},{:.0}",
            self.air_label,
            self.n_trace,
            self.blowup,
            self.n_queries,
            self.proof_bytes,
            self.prove_ms,
            self.verify_us,
            self.throughput,
        )
    }
    pub fn print_row(&self) {
        println!("{}", self.to_csv());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cairo source program strings (documentation / re-compilation)
// ─────────────────────────────────────────────────────────────────────────────

/// Cairo 0 Fibonacci program source.  Matches the Fibonacci AIR (w=2).
/// Compile: cairo-compile cairo/fibonacci.cairo --output fibonacci.json
/// Run:     cairo-run --program fibonacci.json --print_output
pub const CAIRO_FIBONACCI_SOURCE: &str = include_str!("../cairo/fibonacci.cairo");

/// Cairo 0 hash-chain program source.  Mimics the PoseidonChain AIR (w=16).
pub const CAIRO_HASH_CHAIN_SOURCE: &str = include_str!("../cairo/hash_chain.cairo");

/// Cairo 0 simple CPU trace source.  Matches the CairoSimple AIR (w=8).
pub const CAIRO_CPU_TRACE_SOURCE: &str = include_str!("../cairo/cpu_trace.cairo");

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn felt_u64_identity_small() {
        let val = 12345u64;
        let f = felt_u64_to_goldilocks(val);
        assert_eq!(f.into_bigint().0[0], val);
    }

    #[test]
    fn felt_u64_wraps_at_prime() {
        let f = felt_u64_to_goldilocks(GOLDILOCKS_PRIME);
        assert!(f.is_zero());
    }

    #[test]
    fn felt_limbs_zero() {
        let f = felt_limbs_to_goldilocks(&[0, 0, 0, 0]);
        assert!(f.is_zero());
    }

    #[test]
    fn starkware_json_round_trip() {
        let trace = vec![
            vec![F::from(0u64), F::from(1u64), F::from(2u64)],
            vec![F::from(100u64), F::from(101u64), F::from(102u64)],
        ];
        let json = trace_to_starkware_json(&trace, &["pc", "ap"]);
        assert!(json.contains("\"format\": \"starkware-v1\""));
        assert!(json.contains("\"length\": 3"));
        assert!(json.contains("\"pc\""));
        assert!(json.contains("\"ap\""));
    }
}
