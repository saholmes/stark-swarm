//! Cairo-style public inputs for STARK proving.
//!
//! Public inputs define the boundary constraints the trace must satisfy.
//! They are committed into the Fiat-Shamir transcript before any challenges
//! are derived, binding the proof to these specific inputs.

use serde::{Deserialize, Serialize};
use sha3::Digest as _;

/// A public memory cell: address → value mapping.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MemoryEntry {
    pub address: u64,
    pub value: u64,
}

/// A contiguous segment of the memory layout.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MemorySegment {
    pub start: u64,
    pub stop: u64,
}

/// Cairo-style public inputs, matching the ethSTARK/StarkWare prover format.
///
/// Models the public I/O for a Cairo program execution:
/// - Initial and final register values (PC, AP, FP)
/// - Public memory: cells whose address and value are both revealed to the verifier
/// - Memory layout segments (program, execution, builtins)
/// - Range check bounds
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CairoPublicInputs {
    /// SHA3-256 hash of the Cairo program bytecode (hex string).
    pub program_hash: String,

    /// Initial program counter (entry point address).
    pub initial_pc: u64,

    /// Initial allocation pointer.
    pub initial_ap: u64,

    /// Initial frame pointer.
    pub initial_fp: u64,

    /// Expected final program counter (return/halt address).
    pub final_pc: u64,

    /// Expected final allocation pointer.
    pub final_ap: u64,

    /// Memory segments: program, execution, builtins, etc.
    pub memory_segments: Vec<MemorySegment>,

    /// Public memory cells whose address and value are revealed to the verifier.
    pub public_memory: Vec<MemoryEntry>,

    /// Minimum value in the range-check builtin.
    pub range_check_min: u64,

    /// Maximum value in the range-check builtin.
    pub range_check_max: u64,
}

impl CairoPublicInputs {
    /// Compute a 32-byte commitment using SHA3-256.
    ///
    /// This is absorbed into the Fiat-Shamir transcript before any challenges
    /// are derived, binding the proof to these specific public inputs.
    pub fn to_commitment_bytes(&self) -> [u8; 32] {
        let mut h = sha3::Sha3_256::new();

        sha3::Digest::update(&mut h, b"CAIRO-PI-V1");
        sha3::Digest::update(&mut h, self.program_hash.as_bytes());

        sha3::Digest::update(&mut h, &self.initial_pc.to_le_bytes());
        sha3::Digest::update(&mut h, &self.initial_ap.to_le_bytes());
        sha3::Digest::update(&mut h, &self.initial_fp.to_le_bytes());
        sha3::Digest::update(&mut h, &self.final_pc.to_le_bytes());
        sha3::Digest::update(&mut h, &self.final_ap.to_le_bytes());

        for seg in &self.memory_segments {
            sha3::Digest::update(&mut h, &seg.start.to_le_bytes());
            sha3::Digest::update(&mut h, &seg.stop.to_le_bytes());
        }

        for entry in &self.public_memory {
            sha3::Digest::update(&mut h, &entry.address.to_le_bytes());
            sha3::Digest::update(&mut h, &entry.value.to_le_bytes());
        }

        sha3::Digest::update(&mut h, &self.range_check_min.to_le_bytes());
        sha3::Digest::update(&mut h, &self.range_check_max.to_le_bytes());

        sha3::Digest::finalize(h).into()
    }

    /// Validate that the trace satisfies Cairo boundary constraints.
    ///
    /// For the CairoSimple AIR (8 columns): col 0=pc, col 1=ap, col 2=fp.
    /// Checks initial and final register values match public inputs.
    pub fn validate_trace_boundaries(
        &self,
        trace_columns: &[Vec<u64>],
    ) -> Result<(), BoundaryError> {
        if trace_columns.len() < 3 {
            return Err(BoundaryError::InsufficientColumns {
                needed: 3,
                got: trace_columns.len(),
            });
        }

        let n = trace_columns[0].len();
        if n == 0 {
            return Err(BoundaryError::EmptyTrace);
        }

        if trace_columns[0][0] != self.initial_pc {
            return Err(BoundaryError::InitialPcMismatch {
                expected: self.initial_pc,
                got: trace_columns[0][0],
            });
        }
        if trace_columns[1][0] != self.initial_ap {
            return Err(BoundaryError::InitialApMismatch {
                expected: self.initial_ap,
                got: trace_columns[1][0],
            });
        }
        if trace_columns[2][0] != self.initial_fp {
            return Err(BoundaryError::InitialFpMismatch {
                expected: self.initial_fp,
                got: trace_columns[2][0],
            });
        }
        if trace_columns[0][n - 1] != self.final_pc {
            return Err(BoundaryError::FinalPcMismatch {
                expected: self.final_pc,
                got: trace_columns[0][n - 1],
            });
        }
        if trace_columns[1][n - 1] != self.final_ap {
            return Err(BoundaryError::FinalApMismatch {
                expected: self.final_ap,
                got: trace_columns[1][n - 1],
            });
        }

        Ok(())
    }

    /// Build Cairo public inputs that match the CairoSimple AIR trace
    /// generated by `build_execution_trace(AirType::CairoSimple, n_trace)`.
    pub fn for_cairo_simple_air(initial_pc: u64, initial_ap: u64, n_trace: usize) -> Self {
        let n = n_trace as u64;
        CairoPublicInputs {
            program_hash: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .into(),
            initial_pc,
            initial_ap,
            initial_fp: initial_ap,
            final_pc: initial_pc + n - 1,
            final_ap: initial_ap + n - 1,
            memory_segments: vec![
                MemorySegment { start: initial_pc, stop: initial_pc + n },
                MemorySegment { start: initial_ap, stop: initial_ap + n },
            ],
            public_memory: vec![
                MemoryEntry { address: initial_pc, value: 1 },
                MemoryEntry { address: initial_pc + 1, value: 2 },
            ],
            range_check_min: 0,
            range_check_max: 65535,
        }
    }
}

/// Errors during boundary constraint validation.
#[derive(Debug)]
pub enum BoundaryError {
    EmptyTrace,
    InsufficientColumns { needed: usize, got: usize },
    InitialPcMismatch { expected: u64, got: u64 },
    InitialApMismatch { expected: u64, got: u64 },
    InitialFpMismatch { expected: u64, got: u64 },
    FinalPcMismatch { expected: u64, got: u64 },
    FinalApMismatch { expected: u64, got: u64 },
}

impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundaryError::EmptyTrace => write!(f, "trace is empty"),
            BoundaryError::InsufficientColumns { needed, got } =>
                write!(f, "need {needed} columns, got {got}"),
            BoundaryError::InitialPcMismatch { expected, got } =>
                write!(f, "initial PC: expected {expected}, got {got}"),
            BoundaryError::InitialApMismatch { expected, got } =>
                write!(f, "initial AP: expected {expected}, got {got}"),
            BoundaryError::InitialFpMismatch { expected, got } =>
                write!(f, "initial FP: expected {expected}, got {got}"),
            BoundaryError::FinalPcMismatch { expected, got } =>
                write!(f, "final PC: expected {expected}, got {got}"),
            BoundaryError::FinalApMismatch { expected, got } =>
                write!(f, "final AP: expected {expected}, got {got}"),
        }
    }
}

impl std::error::Error for BoundaryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic() {
        let pi = CairoPublicInputs::for_cairo_simple_air(0, 100, 64);
        let h1 = pi.to_commitment_bytes();
        let h2 = pi.to_commitment_bytes();
        assert_eq!(h1, h2);
    }

    #[test]
    fn commitment_differs_on_different_inputs() {
        let pi1 = CairoPublicInputs::for_cairo_simple_air(0, 100, 64);
        let pi2 = CairoPublicInputs::for_cairo_simple_air(0, 200, 64);
        assert_ne!(pi1.to_commitment_bytes(), pi2.to_commitment_bytes());
    }

    #[test]
    fn boundary_validation_passes_on_correct_trace() {
        let n = 8usize;
        let pi = CairoPublicInputs::for_cairo_simple_air(0, 100, n);
        let trace: Vec<Vec<u64>> = vec![
            (0..n as u64).collect(),         // pc: 0..n-1
            (100..100 + n as u64).collect(), // ap: 100..100+n-1
            vec![100u64; n],                  // fp: constant 100
        ];
        assert!(pi.validate_trace_boundaries(&trace).is_ok());
    }

    #[test]
    fn boundary_validation_fails_on_wrong_final_pc() {
        let n = 8usize;
        let pi = CairoPublicInputs::for_cairo_simple_air(0, 100, n);
        let mut trace: Vec<Vec<u64>> = vec![
            (0..n as u64).collect(),
            (100..100 + n as u64).collect(),
            vec![100u64; n],
        ];
        trace[0][n - 1] = 999; // wrong final pc
        assert!(matches!(
            pi.validate_trace_boundaries(&trace),
            Err(BoundaryError::FinalPcMismatch { .. })
        ));
    }
}
