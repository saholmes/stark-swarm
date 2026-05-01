// src/trace_import.rs

use ark_goldilocks::Goldilocks as F;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use std::collections::HashMap;

/// Four evaluation vectors over the FRI domain, derived from a real
/// execution trace rather than random sampling.
///
/// Each vector contains evaluations of a polynomial with degree < n0/rate_inv
/// on an n0-point domain.  This gives FRI the same algebraic structure
/// (bounded-degree polynomials evaluated on a larger domain) as a real STARK,
/// which random vectors do NOT have — random vectors are full-rank, so they
/// don't exercise the degree-testing logic that FRI actually performs.
pub struct RealTraceInputs {
    pub a_eval: Vec<F>,
    pub s_eval: Vec<F>,
    pub e_eval: Vec<F>,
    pub t_eval: Vec<F>,
}

/// Build 4 Fibonacci trace columns over Goldilocks, interpolate, and
/// LDE-evaluate on an n0-point domain.
///
/// `n0`:       FRI domain size (power of 2)
/// `rate_inv`: blowup factor (2, 4, 8, 16…).  Polynomials have degree < n0/rate_inv.
pub fn real_trace_inputs(n0: usize, rate_inv: usize) -> RealTraceInputs {
    assert!(n0.is_power_of_two());
    assert!(rate_inv >= 2 && rate_inv.is_power_of_two());
    let trace_len = n0 / rate_inv;
    assert!(trace_len >= 2, "trace too short");

    // Four Fibonacci-like columns with different seeds.
    // Each column satisfies col[i] = col[i-1] + col[i-2],
    // so it's a valid execution trace of a degree-1 transition constraint.
    let seeds: [(u64, u64); 4] = [
        (1, 1),
        (2, 3),
        (5, 8),
        (13, 21),
    ];

    let trace_dom = Domain::<F>::new(trace_len).unwrap();
    let lde_dom   = Domain::<F>::new(n0).unwrap();

    let mut evals = Vec::with_capacity(4);

    for &(s0, s1) in &seeds {
        // 1. Build trace column
        let mut col = Vec::with_capacity(trace_len);
        col.push(F::from(s0));
        col.push(F::from(s1));
        for i in 2..trace_len {
            col.push(col[i - 1] + col[i - 2]);
        }

        // 2. Interpolate: IFFT over trace domain → coefficients
        //    Polynomial has degree trace_len - 1 = n0/rate_inv - 1
        let coeffs = trace_dom.ifft(&col);

        // 3. LDE: pad coefficients to n0 (zeros for high degrees),
        //    then FFT over the larger domain
        let mut padded = coeffs;
        padded.resize(n0, F::zero());
        evals.push(lde_dom.fft(&padded));
    }

    RealTraceInputs {
        a_eval: evals.remove(0),
        s_eval: evals.remove(0),
        e_eval: evals.remove(0),
        t_eval: evals.remove(0),
    }
}

/// Convert an arbitrary execution trace (produced by an AIR workload)
/// into `RealTraceInputs` by interpolating each column and LDE-evaluating
/// on the extended domain.
///
/// `trace_columns`: each inner Vec is one column of length `n0 / blowup`.
/// `n0`:            FRI / extended-evaluation domain size (power of 2).
/// `blowup`:        rate inverse (typically 4).
///
/// The function maps the first four columns to `a_eval … t_eval`.
/// If the trace has fewer than four columns, columns are reused with
/// wraparound (same strategy as `import_winterfell_trace`).
/// If the trace has more than four columns, the extra columns are ignored.
pub fn trace_inputs_from_air(
    trace_columns: Vec<Vec<F>>,
    n0: usize,
    blowup: usize,
) -> RealTraceInputs {
    let num_cols = trace_columns.len();
    assert!(num_cols >= 1, "need at least 1 trace column");
    assert!(n0.is_power_of_two());
    assert!(blowup >= 2 && blowup.is_power_of_two());

    let trace_len = n0 / blowup;
    assert!(trace_len >= 2, "trace too short");

    // Sanity-check that every column has the expected length
    for (i, col) in trace_columns.iter().enumerate() {
        assert_eq!(
            col.len(),
            trace_len,
            "column {} has length {} but expected {}",
            i,
            col.len(),
            trace_len
        );
    }

    let trace_dom = Domain::<F>::new(trace_len).unwrap();
    let lde_dom   = Domain::<F>::new(n0).unwrap();

    let lde = |col: &[F]| -> Vec<F> {
        let coeffs = trace_dom.ifft(col);
        let mut padded = coeffs;
        padded.resize(n0, F::zero());
        lde_dom.fft(&padded)
    };

    // Map columns to the four required vectors with wraparound
    let a_eval = lde(&trace_columns[0]);
    let s_eval = lde(&trace_columns[1 % num_cols]);
    let e_eval = lde(&trace_columns[2 % num_cols]);
    let t_eval = lde(&trace_columns[3 % num_cols]);

    RealTraceInputs { a_eval, s_eval, e_eval, t_eval }
}

/// Same as above but reads trace columns from a binary file exported
/// by Winterfell's FibSmall example (f64 = Goldilocks).
///
/// File format (produced by the export binary in Path B):
///   Header line:  "TRACE <trace_len> <num_cols> <field_bits>\n"
///   Body:         column-major, each element as u64 little-endian (8 bytes)
pub fn import_winterfell_trace(path: &str, n0: usize) -> RealTraceInputs {
    use std::io::{BufRead, BufReader, Read};
    use std::fs::File;

    let file = File::open(path).expect("cannot open trace file");
    let mut reader = BufReader::new(file);

    // Parse header
    let mut header = String::new();
    reader.read_line(&mut header).unwrap();
    let parts: Vec<&str> = header.trim().split_whitespace().collect();
    assert_eq!(parts[0], "TRACE");
    let trace_len: usize = parts[1].parse().unwrap();
    let num_cols: usize  = parts[2].parse().unwrap();
    assert!(num_cols >= 2, "need at least 2 trace columns");

    // Read columns (u64 LE → Goldilocks)
    let mut columns: Vec<Vec<F>> = Vec::with_capacity(num_cols);
    let mut buf = [0u8; 8];

    for _col in 0..num_cols {
        let mut column = Vec::with_capacity(trace_len);
        for _row in 0..trace_len {
            reader.read_exact(&mut buf).unwrap();
            let val = u64::from_le_bytes(buf);
            column.push(F::from(val));
        }
        columns.push(column);
    }

    // Interpolate and LDE, same as above
    let trace_dom = Domain::<F>::new(trace_len).unwrap();
    let lde_dom   = Domain::<F>::new(n0).unwrap();

    let lde = |col: &[F]| -> Vec<F> {
        let coeffs = trace_dom.ifft(col);
        let mut padded = coeffs;
        padded.resize(n0, F::zero());
        lde_dom.fft(&padded)
    };

    // Map columns to the four vectors.
    // With 2 trace columns we duplicate; with 4+ we use the first 4.
    let a_eval = lde(&columns[0]);
    let s_eval = lde(&columns[1 % num_cols]);
    let e_eval = lde(&columns[2 % num_cols]);
    let t_eval = lde(&columns[3 % num_cols]);

    RealTraceInputs { a_eval, s_eval, e_eval, t_eval }
}
// ═══════════════════════════════════════════════════════════════════
//  StarkWare column-major JSON trace import
// ═══════════════════════════════════════════════════════════════════

/// Import a StarkWare column-major JSON string.
///
/// Column values are u64 Goldilocks field elements.
/// Column ordering follows `column_order` when provided, otherwise sorted by name.
/// Returns raw trace columns as `Vec<Vec<F>>` (not LDE-evaluated).
/// Call `lde_trace_columns` on the result before `deep_ali_merge_general`.
pub fn import_starkware_json(
    json_str: &str,
    column_order: Option<&[&str]>,
) -> Result<Vec<Vec<F>>, String> {
    let v: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {e}"))?;

    let length = v["length"].as_u64()
        .ok_or("missing 'length' field")? as usize;
    let cols_val = v["columns"].as_object()
        .ok_or("'columns' must be an object")?;

    let extract = |name: &str| -> Result<Vec<F>, String> {
        let arr = cols_val.get(name)
            .ok_or_else(|| format!("column '{name}' not found"))?
            .as_array()
            .ok_or_else(|| format!("column '{name}' must be an array"))?;
        if arr.len() != length {
            return Err(format!("column '{name}': expected {length} rows, got {}", arr.len()));
        }
        arr.iter().map(|v| {
            v.as_u64()
                .ok_or_else(|| format!("column '{name}' has non-u64 value: {v}"))
                .map(F::from)
        }).collect()
    };

    let names: Vec<String> = if let Some(order) = column_order {
        order.iter().map(|s| s.to_string()).collect()
    } else {
        let mut names: Vec<String> = cols_val.keys().cloned().collect();
        names.sort();
        names
    };

    names.iter().map(|name| extract(name)).collect()
}

/// Import a StarkWare JSON trace file from disk.
pub fn import_starkware_json_file(
    path: &str,
    column_order: Option<&[&str]>,
) -> Result<Vec<Vec<F>>, String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read '{path}': {e}"))?;
    import_starkware_json(&s, column_order)
}

/// LDE-evaluate all columns of a raw trace.
///
/// Each column must have `trace_len` elements.  Returns columns evaluated
/// on an `n0 = trace_len * blowup`-point domain, ready for `deep_ali_merge_general`.
pub fn lde_trace_columns(
    columns: &[Vec<F>],
    trace_len: usize,
    blowup: usize,
) -> Result<Vec<Vec<F>>, String> {
    if columns.is_empty() {
        return Err("no columns provided".into());
    }
    for (i, col) in columns.iter().enumerate() {
        if col.len() != trace_len {
            return Err(format!("column {i}: expected {trace_len} rows, got {}", col.len()));
        }
    }
    if !trace_len.is_power_of_two() {
        return Err(format!("trace_len {trace_len} must be a power of 2"));
    }
    if blowup < 2 || !blowup.is_power_of_two() {
        return Err(format!("blowup {blowup} must be a power-of-2 >= 2"));
    }

    let n0 = trace_len * blowup;
    let trace_dom = Domain::<F>::new(trace_len).unwrap();
    let lde_dom = Domain::<F>::new(n0).unwrap();

    columns.iter().map(|col| {
        let coeffs = trace_dom.ifft(col);
        let mut padded = coeffs;
        padded.resize(n0, F::zero());
        Ok(lde_dom.fft(&padded))
    }).collect()
}

#[cfg(test)]
mod starkware_tests {
    use super::*;

    #[test]
    fn import_starkware_json_basic() {
        let json = r#"{
            "format": "starkware-v1",
            "width": 3,
            "length": 4,
            "columns": {
                "pc": [0, 1, 2, 3],
                "ap": [100, 101, 102, 103],
                "fp": [100, 100, 100, 100]
            }
        }"#;
        let cols = import_starkware_json(json, None).unwrap();
        assert_eq!(cols.len(), 3);
        assert_eq!(cols[0].len(), 4);
    }

    #[test]
    fn import_starkware_json_ordered() {
        let json = r#"{
            "format": "starkware-v1",
            "width": 3,
            "length": 4,
            "columns": {
                "pc": [10, 11, 12, 13],
                "ap": [100, 101, 102, 103],
                "fp": [200, 200, 200, 200]
            }
        }"#;
        let order = ["pc", "ap", "fp"];
        let cols = import_starkware_json(json, Some(&order)).unwrap();
        assert_eq!(cols.len(), 3);
        assert_eq!(cols[0][0], F::from(10u64));
        assert_eq!(cols[1][0], F::from(100u64));
    }

    #[test]
    fn lde_trace_columns_produces_correct_size() {
        let cols: Vec<Vec<F>> = vec![
            (0u64..8).map(F::from).collect(),
            (0u64..8).map(F::from).collect(),
        ];
        let lde = lde_trace_columns(&cols, 8, 4).unwrap();
        assert_eq!(lde.len(), 2);
        assert_eq!(lde[0].len(), 32);
    }
}
