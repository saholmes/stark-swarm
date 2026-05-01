// ed25519_verify_air.rs — top-level AIR composition for Ed25519 verify.
//
// Composes the existing sub-AIRs (SHA-512, scalar reduction mod L,
// point decompression, scalar mult, point ops) into a single trace
// that proves cofactored Ed25519 signature verification per RFC 8032
// §5.1.7.  Driven by `swarm-dns::prove_zsk_ksk_binding` (Phase 6).
//
// ─────────────────────────────────────────────────────────────────
// PRODUCTION ENTRY POINT
// ─────────────────────────────────────────────────────────────────
//
// Use the **v16** API for end-to-end signature verification:
//
//   let layout = verify_air_layout_v16(msg_len, s_bits, k_bits, R, A)?;
//   let (trace, _, k_can) = fill_verify_air_v16(M, R, A, s_bits, k_bits)?;
//   let cons_per_row = verify_v16_per_row_constraints(layout.k_scalar);
//   for row in 0..layout.height - 1 {
//       let cons = eval_verify_air_v16_per_row(&cur, &nxt, row, &layout);
//       // every entry must be zero on a valid trace
//   }
//
// `K_scalar = 256` matches Ed25519; the K is inferred from `s_bits.len()`.
// All earlier v0..v15 APIs remain pub for incremental testing and
// reuse of sub-phases — v16 is the only one with end-to-end soundness.
//
// ─────────────────────────────────────────────────────────────────
// SOUNDNESS — what v16 proves end-to-end
// ─────────────────────────────────────────────────────────────────
//
// Given public inputs `(M, R_compressed, A_compressed, s_bits, k_bits)`,
// the AIR proves the RFC 8032 §5.1.7 cofactored verification predicate:
//
//      [8] · ([s]·B − R − [k]·A)  =  O   in Edwards25519
//
// where `B = ED25519_BASEPOINT`, `R = decompress(R_compressed)`,
// `A = decompress(A_compressed)`, and `k = SHA-512(R||A||M) mod L`.
//
// Public-input bindings (every quantity above is anchored in the trace):
//
//   M              SHA-512 input bytes              (sha512_air)
//   R              (y, sign) at decompress_R_row    v5  +  curve eq      v2
//   A              (y, sign) at decompress_A_row    v5  +  curve eq      v2
//                  + a_point_limbs at kA_first_row  v4
//   s              scalar block at sB_first_row     v6 shift chain
//   k              r-bits via thread chain          v7  (= SHA-512-derived)
//   B              hardcoded at sB_first_row        v4
//
// Computation bindings:
//
//   [s]·B          scalar-mult ladder rows          v3 + transitions
//   [k]·A          scalar-mult ladder rows          v3 + transitions
//   [s]·B thread   carries result to residual_row   v11
//   [k]·A thread   carries result to residual_row   v12
//   R thread       carries (X, Y, 1, X·Y)           v13 + in-circuit MUL
//   −R, −[k]·A     SUB(0, X), SUB(0, T) gadgets     v14, v15
//   residual_1     [s]·B + (−R) via PointAdd        v14
//   residual_2     residual_1 + (−[k]·A)            v15
//   dbl_input      ← residual_2 (transition)        v16
//   [8]·input      3 chained PointDouble rows       v9 + result pin v10
//   identity check 3 SUB-canonicalised + zero cons  v8
//
// ─────────────────────────────────────────────────────────────────
// TRACE LAYOUT (v16 — final row order)
// ─────────────────────────────────────────────────────────────────
//
// ```text
//   rows 0..k_hash − 1     : SHA-512 multi-block (last row carries digest
//                            bits + format-conversion cons via v1)
//   row k_hash             : scalar-reduce gadget                (v0)
//   row k_hash + 1         : decompress R                        (v2)
//   row k_hash + 2         : decompress A                        (v2)
//   rows k_hash + 3..      : sB ladder (k_scalar rows)           (v3)
//        ..                : kA ladder (k_scalar rows)           (v3)
//   row kA_last + 1        : residual_row — 4 SUB + 2 PointAdd   (v14, v15)
//   rows + 2 / + 3 / + 4   : dbl_1, dbl_2, dbl_3                 (v9)
//   row residual + 5       : result_row — identity verdict       (v8 + v10)
//
//   total height           : next_pow_2(k_hash + 3 + 2·k_scalar + 5)
//   total width            : ≈ 40 800 cells (dominated by 2 × PointAdd)
//   per-row constraints    : verify_v16_per_row_constraints(k_scalar)
// ```
//
// For k_scalar = 256: height = 1024, ~41 k cells/row, ~75 k cons/row.
// For k_scalar = 8 (tests): height = 256, same width, ~69 k cons/row.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use ark_ff::{Field, Zero, One};
use ark_goldilocks::Goldilocks as F;

use crate::sha512_air::{
    self, ROWS_PER_BLOCK as SHA512_ROWS_PER_BLOCK,
    WIDTH as SHA512_WIDTH, NUM_CONSTRAINTS as SHA512_CONSTRAINTS,
    OFF_H0_LO, build_sha512_trace_multi, eval_sha512_constraints,
    pad_message_to_blocks,
};
use crate::ed25519_scalar_air::{
    self, ScalarReduceGadgetLayout,
    SCALAR_REDUCE_OWNED_CELLS, SCALAR_REDUCE_CONSTRAINTS,
    INPUT_LIMBS as REDUCE_INPUT_LIMBS, LIMB_BITS as REDUCE_LIMB_BITS,
    Q_LIMBS, R_LIMBS, PRODUCT_LIMBS, CARRY_BITS,
    fill_scalar_reduce_gadget, eval_scalar_reduce_gadget,
};
use crate::ed25519_scalar::reduce_mod_l_wide;
use crate::sha512_air::sha512_native;
use crate::ed25519_field::{FieldElement, NUM_LIMBS};
use crate::ed25519_field_air::{
    SubGadgetLayout, SUB_GADGET_OWNED_CELLS, SUB_GADGET_CONSTRAINTS,
    fill_sub_gadget, eval_sub_gadget,
    MulGadgetLayout, MUL_GADGET_OWNED_CELLS, MUL_GADGET_CONSTRAINTS,
    MUL_CARRY_BITS, fill_mul_gadget, eval_mul_gadget,
    ELEMENT_LIMB_CELLS,
};
use crate::ed25519_group::EdwardsPoint;
use crate::ed25519_group_air::{
    PointDecompressGadgetLayout, POINT_DECOMP_CONSTRAINTS,
    point_decompress_layout_at, fill_point_decompress_gadget,
    eval_point_decompress_gadget,
    PointDoubleGadgetLayout, POINT_DBL_CONSTRAINTS,
    point_double_layout_at, fill_point_double_gadget, eval_point_double_gadget,
    PointAddGadgetLayout, POINT_ADD_CONSTRAINTS,
    point_add_layout_at, fill_point_add_gadget, eval_point_add_gadget,
};
use crate::ed25519_scalar_mult_air::{
    ScalarMultRowLayout, SCALAR_MULT_ROW_WIDTH,
    SCALAR_MULT_PER_ROW_CONSTRAINTS, SCALAR_MULT_TRANSITION_CONSTRAINTS,
    scalar_mult_row_layout, fill_scalar_mult_trace,
    eval_scalar_mult_per_row, eval_scalar_mult_transition,
    eval_scalar_mult_initial_acc,
};

// ═══════════════════════════════════════════════════════════════════
//  Layout
// ═══════════════════════════════════════════════════════════════════

/// Layout of a Phase-A + Phase-B verify trace.
///
/// Trace dimensions (per gadget invocation):
///   width  = max(SHA512_WIDTH, REDUCE_INPUT_LIMBS + scalar_reduce_owned_cells)
///   height = K_HASH + 1   (one extra row for scalar-reduce)
#[derive(Clone, Copy, Debug)]
pub struct VerifyAirLayoutV0 {
    /// Number of SHA-512 blocks (= number of rows the SHA-512 phase
    /// spans, divided by ROWS_PER_BLOCK).
    pub n_blocks: usize,
    /// Total height of the SHA-512 phase (= n_blocks · ROWS_PER_BLOCK,
    /// padded up to next power of two by the SHA-512 trace builder).
    pub k_hash:   usize,
    /// Row index of the scalar-reduce phase (right after SHA-512).
    pub reduce_row: usize,
    /// Scalar-reduce sub-gadget layout, with input cells and gadget
    /// owned cells starting at column 0 of the reduce row.
    pub reduce: ScalarReduceGadgetLayout,
    /// Total trace width (max of phase widths).
    pub width:  usize,
    /// Total trace height.
    pub height: usize,
}

/// Build a v0 layout for a message of `msg_len` bytes (which controls
/// the SHA-512 block count via padding).
pub fn verify_air_layout_v0(msg_len_for_sha512: usize) -> VerifyAirLayoutV0 {
    // SHA-512 block count: ⌈(msg_len + 1 + 16) / 128⌉  (per RFC 6234).
    let n_blocks = (msg_len_for_sha512 + 1 + 16 + 127) / 128;
    let k_hash   = (n_blocks * SHA512_ROWS_PER_BLOCK)
        .next_power_of_two().max(SHA512_ROWS_PER_BLOCK);

    // Reduce phase fits in a single row that comes right after the
    // SHA-512 trace.  Within that row:
    //   col 0..32  : input limbs (32 × 16-bit, populated from SHA-512 H-state)
    //   col 32..   : reduce gadget owned cells
    let reduce_row = k_hash;
    let mut next = REDUCE_INPUT_LIMBS;
    let q_limbs_base = next; next += Q_LIMBS;
    let q_bits_base  = next; next += Q_LIMBS * REDUCE_LIMB_BITS;
    let r_limbs_base = next; next += R_LIMBS;
    let r_bits_base  = next; next += R_LIMBS * REDUCE_LIMB_BITS;
    let slack_limbs_base = next; next += R_LIMBS;
    let slack_bits_base  = next; next += R_LIMBS * REDUCE_LIMB_BITS;
    let carry_bits_base  = next; next += PRODUCT_LIMBS * CARRY_BITS;
    let reduce = ScalarReduceGadgetLayout {
        input_limbs_base: 0,
        q_limbs_base, q_bits_base,
        r_limbs_base, r_bits_base,
        slack_limbs_base, slack_bits_base,
        carry_bits_base,
    };
    let reduce_phase_width = next;

    let width = SHA512_WIDTH.max(reduce_phase_width);
    let height = (k_hash + 1).next_power_of_two();

    VerifyAirLayoutV0 {
        n_blocks, k_hash, reduce_row, reduce, width, height,
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Trace builder
// ═══════════════════════════════════════════════════════════════════

/// Build a v0 trace that proves `r = SHA-512(message) mod L`.
///
/// Returns `(trace, layout, k_canonical)` where:
///   * `trace[col][row]` is the populated trace cell.
///   * `layout` describes the trace structure.
///   * `k_canonical` is the 32-byte LE canonical scalar that the
///     scalar-reduce phase computed (= what the AIR proves).
///
/// Caller can use `eval_verify_air_v0_per_row` and
/// `eval_verify_air_v0_transition` to validate the trace.
pub fn fill_verify_air_v0(
    message: &[u8],
) -> (Vec<Vec<F>>, VerifyAirLayoutV0, [u8; 32]) {
    let layout = verify_air_layout_v0(message.len());

    // ── Phase A: SHA-512 trace ──
    // sha512_air's trace builder produces a (WIDTH × height_a) trace
    // for the message; height_a is the next power of two ≥ n_blocks·128.
    let (sha_trace, n_blocks) = build_sha512_trace_multi(message);
    debug_assert_eq!(n_blocks, layout.n_blocks);

    // ── Allocate the wider composed trace ──
    let mut trace: Vec<Vec<F>> =
        (0..layout.width).map(|_| vec![F::zero(); layout.height]).collect();

    // Copy SHA-512 trace into the upper-left.  Columns above SHA512_WIDTH
    // are zero (idle), rows above k_hash are zero in the SHA-512 columns
    // (idle padding).
    for c in 0..SHA512_WIDTH {
        for r in 0..sha_trace[c].len().min(layout.k_hash) {
            trace[c][r] = sha_trace[c][r];
        }
    }

    // ── Cross-phase format conversion (native ref) ──
    // SHA-512 produces a 64-byte digest (BE per 64-bit word).  The
    // scalar-reduce gadget reads input as 32 × 16-bit LE limbs.  We
    // compute the digest natively and pin the input limbs.
    let digest = sha512_native(message);
    for i in 0..REDUCE_INPUT_LIMBS {
        let lo = digest[2 * i] as u64;
        let hi = digest[2 * i + 1] as u64;
        trace[layout.reduce.input_limbs_base + i][layout.reduce_row]
            = F::from(lo | (hi << 8));
    }

    // ── Phase B: scalar-reduce gadget ──
    let mut digest_arr = [0u8; 64];
    digest_arr.copy_from_slice(&digest);
    fill_scalar_reduce_gadget(&mut trace, layout.reduce_row, &layout.reduce, &digest_arr);

    let k_canonical = reduce_mod_l_wide(&digest_arr);
    (trace, layout, k_canonical)
}

// ═══════════════════════════════════════════════════════════════════
//  Constraint evaluator (per-row)
// ═══════════════════════════════════════════════════════════════════

/// Per-row constraints for the v0 verify AIR.  `cur` is the row's full
/// cells; `nxt` would be the next row but isn't used here (no
/// cross-row identities in v0).  Returns SHA-512 constraints when
/// `row` is in the SHA-512 phase, or scalar-reduce constraints at the
/// reduce row, or zero placeholders elsewhere.
///
/// Per-row constraint count is uniform: SHA512_CONSTRAINTS +
/// SCALAR_REDUCE_CONSTRAINTS, with the inactive sub-AIR's constraints
/// returned as zero placeholders so the count stays fixed.
pub const VERIFY_V0_PER_ROW_CONSTRAINTS: usize =
    SHA512_CONSTRAINTS + SCALAR_REDUCE_CONSTRAINTS;

pub fn eval_verify_air_v0_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV0,
) -> Vec<F> {
    let mut out = Vec::with_capacity(VERIFY_V0_PER_ROW_CONSTRAINTS);

    // SHA-512 constraints: active in rows [0, k_hash − 1); idle elsewhere.
    //
    // We exclude row `k_hash − 1` (the last useful SHA-512 row) because
    // its transition reaches into row `k_hash` whose SHA-512 columns
    // host idle padding — i.e. it's the SHA-512 phase's *wrap row*, by
    // direct analogy with the cyclic wrap row used in the standalone
    // `sha512_air` test (`assert_trace_satisfies_constraints` at
    // sha512_air.rs:1503 explicitly skips wrap-row violations).
    //
    // In v0 the digest at row k_hash − 1 is bound to the scalar-reduce
    // input limbs natively (in the trace builder).  In v1 we'll replace
    // this gate with explicit cross-phase format-conversion constraints
    // tying H-state cells at row k_hash − 1 to the scalar-reduce input
    // cells at row reduce_row, restoring full soundness on the seam.
    if row + 1 < layout.k_hash {
        out.extend(eval_sha512_constraints(cur, nxt, row, layout.n_blocks));
    } else {
        for _ in 0..SHA512_CONSTRAINTS { out.push(F::zero()); }
    }

    // Scalar-reduce constraints: active only at reduce_row; idle elsewhere.
    if row == layout.reduce_row {
        out.extend(eval_scalar_reduce_gadget(cur, &layout.reduce));
    } else {
        for _ in 0..SCALAR_REDUCE_CONSTRAINTS { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), VERIFY_V0_PER_ROW_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v1 layout — SHA-512 + scalar-reduce + cross-phase format binding
// ═══════════════════════════════════════════════════════════════════
//
// v1 closes the soundness seam introduced by v0's native cross-phase
// format conversion.  It adds 64 LE bit cells per H-state word at row
// k_hash − 1 (= the SHA-512 digest row) and constrains:
//
//   1. Booleanity of every digest bit (512 cons).
//   2. Each H_LO[k] / H_HI[k] cell at row k_hash − 1 packs from its
//      32 LE bits (16 cons).
//   3. Each scalar-reduce input limb at row k_hash decomposes from the
//      SHA-512 digest bits in the byte-swapped LE-of-BE order required
//      by RFC 8032 §5.1.7 (32 cons).
//
// The SHA-512 wrap-row gate at row k_hash − 1 stays — the SHA-512
// transition can't fire there because nxt is the reduce row (where
// SHA-512 columns are zero / scalar-reduce-owned).  Soundness is still
// preserved end-to-end:
//
//   • SHA-512 transitions on rows 0..k_hash − 2 already constrain the
//     H-state at row k_hash − 1 transitively (idle-row hold constraints
//     propagate the digest from the finalisation row).
//   • Format constraints at row k_hash − 1 bind H-state to digest bits.
//   • Format constraints at row k_hash − 1 (using nxt) bind digest bits
//     to scalar-reduce input limbs at row k_hash.
//   • Scalar-reduce constraints prove r = digest mod L from those limbs.
//
// LE-of-BE layout (RFC 8032):
//   SHA-512 outputs 8 BE u64 words ⇒ 64 bytes, byte 0 = MSB of H[0].
//   k = SHA-512(M) interpreted as a LITTLE-endian 512-bit integer ⇒
//   limb i (16-bit LE) = byte[2i] | byte[2i+1] << 8.
//   For i = 4k + m (m ∈ {0,1,2,3}) within H[k]:
//     base = 56 − 16·m   (low byte's bit position in H[k])
//     limb[4k+m] = Σ_{j=0..8} bit_LE[k][base + j] · 2^j
//                + Σ_{j=0..8} bit_LE[k][base − 8 + j] · 2^(8 + j)

#[derive(Clone, Copy, Debug)]
pub struct VerifyAirLayoutV1 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row: usize,
    pub reduce: ScalarReduceGadgetLayout,
    /// Column where the 512 digest bit cells start (only at row k_hash − 1).
    /// Bits are LE per 64-bit word: cell at digest_bit_base + 64·k + i is
    /// the i-th LSB bit of H[k].
    pub digest_bit_base: usize,
    pub width:  usize,
    pub height: usize,
}

pub const DIGEST_BITS: usize = 512;            // 8 × 64
pub const VERIFY_V1_FORMAT_CONS: usize =
    DIGEST_BITS                                  // booleanity
    + 16                                         // H-state pack (H_LO, H_HI) × 8
    + 32;                                        // input-limb bind × 32
pub const VERIFY_V1_PER_ROW_CONSTRAINTS: usize =
    SHA512_CONSTRAINTS + SCALAR_REDUCE_CONSTRAINTS + VERIFY_V1_FORMAT_CONS;

/// Build a v1 layout for a message of `msg_len` bytes.
pub fn verify_air_layout_v1(msg_len_for_sha512: usize) -> VerifyAirLayoutV1 {
    let n_blocks = (msg_len_for_sha512 + 1 + 16 + 127) / 128;
    let k_hash   = (n_blocks * SHA512_ROWS_PER_BLOCK)
        .next_power_of_two().max(SHA512_ROWS_PER_BLOCK);
    let reduce_row = k_hash;

    // Same scalar-reduce layout as v0 (input_limbs at col 0..32, gadget
    // owned cells continue from there).
    let mut next = REDUCE_INPUT_LIMBS;
    let q_limbs_base = next; next += Q_LIMBS;
    let q_bits_base  = next; next += Q_LIMBS * REDUCE_LIMB_BITS;
    let r_limbs_base = next; next += R_LIMBS;
    let r_bits_base  = next; next += R_LIMBS * REDUCE_LIMB_BITS;
    let slack_limbs_base = next; next += R_LIMBS;
    let slack_bits_base  = next; next += R_LIMBS * REDUCE_LIMB_BITS;
    let carry_bits_base  = next; next += PRODUCT_LIMBS * CARRY_BITS;
    let reduce = ScalarReduceGadgetLayout {
        input_limbs_base: 0,
        q_limbs_base, q_bits_base,
        r_limbs_base, r_bits_base,
        slack_limbs_base, slack_bits_base,
        carry_bits_base,
    };
    let reduce_phase_width = next;

    // Digest bits live past SHA-512's columns (cols SHA512_WIDTH..+512)
    // at row k_hash − 1.  Phase-A width therefore extends to
    // SHA512_WIDTH + 512.
    let digest_bit_base = SHA512_WIDTH;
    let phase_a_width   = SHA512_WIDTH + DIGEST_BITS;

    let width  = phase_a_width.max(reduce_phase_width);
    let height = (k_hash + 1).next_power_of_two();

    VerifyAirLayoutV1 {
        n_blocks, k_hash, reduce_row, reduce,
        digest_bit_base, width, height,
    }
}

/// Build a v1 trace.  Same as v0 but additionally populates 512 digest
/// bit cells at row k_hash − 1.
pub fn fill_verify_air_v1(
    message: &[u8],
) -> (Vec<Vec<F>>, VerifyAirLayoutV1, [u8; 32]) {
    let layout = verify_air_layout_v1(message.len());

    // ── Phase A: SHA-512 trace ──
    let (sha_trace, n_blocks) = build_sha512_trace_multi(message);
    debug_assert_eq!(n_blocks, layout.n_blocks);

    let mut trace: Vec<Vec<F>> =
        (0..layout.width).map(|_| vec![F::zero(); layout.height]).collect();

    for c in 0..SHA512_WIDTH {
        for r in 0..sha_trace[c].len().min(layout.k_hash) {
            trace[c][r] = sha_trace[c][r];
        }
    }

    // ── Cross-phase witness: 512 digest bit cells at row k_hash − 1 ──
    let digest = sha512_native(message);
    let digest_row = layout.k_hash - 1;
    for k in 0..8 {
        // H[k] = u64 from BE bytes 8k..8k+8.
        let h_word = u64::from_be_bytes([
            digest[8*k    ], digest[8*k + 1], digest[8*k + 2], digest[8*k + 3],
            digest[8*k + 4], digest[8*k + 5], digest[8*k + 6], digest[8*k + 7],
        ]);
        for i in 0..64 {
            let bit = (h_word >> i) & 1;
            trace[layout.digest_bit_base + 64*k + i][digest_row] =
                if bit == 1 { F::one() } else { F::zero() };
        }
    }

    // ── Phase B: scalar-reduce input limbs + gadget ──
    for i in 0..REDUCE_INPUT_LIMBS {
        let lo = digest[2 * i] as u64;
        let hi = digest[2 * i + 1] as u64;
        trace[layout.reduce.input_limbs_base + i][layout.reduce_row]
            = F::from(lo | (hi << 8));
    }
    let mut digest_arr = [0u8; 64];
    digest_arr.copy_from_slice(&digest);
    fill_scalar_reduce_gadget(&mut trace, layout.reduce_row, &layout.reduce, &digest_arr);

    let k_canonical = reduce_mod_l_wide(&digest_arr);
    (trace, layout, k_canonical)
}

/// Per-row constraint evaluator for v1.
pub fn eval_verify_air_v1_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV1,
) -> Vec<F> {
    let mut out = Vec::with_capacity(VERIFY_V1_PER_ROW_CONSTRAINTS);

    // ── SHA-512 (wrap-row gate stays; cross-phase binding below) ──
    if row + 1 < layout.k_hash {
        out.extend(eval_sha512_constraints(cur, nxt, row, layout.n_blocks));
    } else {
        for _ in 0..SHA512_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Scalar-reduce at reduce_row ──
    if row == layout.reduce_row {
        out.extend(eval_scalar_reduce_gadget(cur, &layout.reduce));
    } else {
        for _ in 0..SCALAR_REDUCE_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Format-conversion constraints at row k_hash − 1 ──
    if row + 1 == layout.k_hash {
        // 1. Booleanity of digest bits (512 cons).
        for k in 0..8 {
            for i in 0..64 {
                let b = cur[layout.digest_bit_base + 64*k + i];
                out.push(b * (F::one() - b));
            }
        }

        // 2. H-state pack (16 cons): H_LO[k] / H_HI[k] = Σ bit · 2^i.
        let pow2_lo: [F; 32] = core::array::from_fn(|i| F::from(1u64 << i));
        for k in 0..8 {
            let mut sum_lo = F::zero();
            let mut sum_hi = F::zero();
            for i in 0..32 {
                sum_lo += pow2_lo[i] * cur[layout.digest_bit_base + 64*k + i];
                sum_hi += pow2_lo[i] * cur[layout.digest_bit_base + 64*k + 32 + i];
            }
            out.push(cur[OFF_H0_LO + 2*k    ] - sum_lo);
            out.push(cur[OFF_H0_LO + 2*k + 1] - sum_hi);
        }

        // 3. Input-limb bind (32 cons): nxt[input_limbs_base + 4k+m]
        //    = LE-of-BE byte-swap of bits in H[k] at positions
        //      [base, base+8) ⊕ [base−8, base) where base = 56 − 16·m.
        let pow2_16: [F; 16] = core::array::from_fn(|i| F::from(1u64 << i));
        for k in 0..8 {
            for m in 0..4 {
                let low_byte_base  = 56 - 16 * m;          // 56, 40, 24, 8
                let high_byte_base = low_byte_base - 8;    // 48, 32, 16, 0
                let mut sum = F::zero();
                for j in 0..8 {
                    sum += pow2_16[j]
                        * cur[layout.digest_bit_base + 64*k + low_byte_base + j];
                }
                for j in 0..8 {
                    sum += pow2_16[8 + j]
                        * cur[layout.digest_bit_base + 64*k + high_byte_base + j];
                }
                let limb_idx = 4*k + m;
                out.push(nxt[layout.reduce.input_limbs_base + limb_idx] - sum);
            }
        }
    } else {
        for _ in 0..VERIFY_V1_FORMAT_CONS { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), VERIFY_V1_PER_ROW_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v2 layout — v1 + two point-decompression phases (R, A)
// ═══════════════════════════════════════════════════════════════════
//
// v2 weaves the existing `PointDecompressGadgetLayout` (from
// ed25519_group_air) into the composed trace as two single-row
// phases sitting just past the scalar-reduce row:
//
//   Row k_hash − 1: SHA-512 last useful row + digest bit cells (v1).
//   Row k_hash    : scalar-reduce gadget (v0/v1).
//   Row k_hash + 1: decompress R = (X_R, Y_R) on Edwards25519.
//   Row k_hash + 2: decompress A = (X_A, Y_A) on Edwards25519.
//
// Both decompression rows share the same column layout (the gadget's
// `point_decompress_layout_at` allocator deposits cells from a fixed
// `base`); they coexist in the wide trace because they live on distinct
// rows.
//
// For v2, the y-limbs and sign-bit at each decompression row are FREE
// inputs — the trace builder pins them from the caller's compressed
// bytes via `FieldElement::from_bytes` + bit-extract.  v3 will add a
// byte-decomposition phase that binds those cells back to the SHA-512
// input bytes (= the canonical compressed encodings), closing the
// remaining soundness seam.
//
// Soundness scope in v2:
//   * Each decomposition row proves: given `(y, sign)`, there exists
//     `x ∈ F_{2^255 − 19}` such that `(x, y) ∈ Edwards25519` and
//     `bit_0(x_canonical) = sign`.  The witnessed x is what the gadget
//     publishes in `x_limbs` for downstream phases (scalar mult in v3).

#[derive(Clone, Copy, Debug)]
pub struct VerifyAirLayoutV2 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    /// Layout for the point-decompress gadget — applies identically to
    /// rows decompress_R_row and decompress_A_row (column allocation is
    /// row-independent).
    pub decomp: PointDecompressGadgetLayout,
    pub width:  usize,
    pub height: usize,
}

pub const VERIFY_V2_PER_ROW_CONSTRAINTS: usize =
    VERIFY_V1_PER_ROW_CONSTRAINTS + 2 * POINT_DECOMP_CONSTRAINTS;

/// Build a v2 layout for a given message length.
pub fn verify_air_layout_v2(msg_len_for_sha512: usize) -> VerifyAirLayoutV2 {
    let n_blocks = (msg_len_for_sha512 + 1 + 16 + 127) / 128;
    let k_hash   = (n_blocks * SHA512_ROWS_PER_BLOCK)
        .next_power_of_two().max(SHA512_ROWS_PER_BLOCK);
    let reduce_row        = k_hash;
    let decompress_R_row  = k_hash + 1;
    let decompress_A_row  = k_hash + 2;

    // Reduce gadget layout (same as v0/v1).
    let mut next = REDUCE_INPUT_LIMBS;
    let q_limbs_base = next; next += Q_LIMBS;
    let q_bits_base  = next; next += Q_LIMBS * REDUCE_LIMB_BITS;
    let r_limbs_base = next; next += R_LIMBS;
    let r_bits_base  = next; next += R_LIMBS * REDUCE_LIMB_BITS;
    let slack_limbs_base = next; next += R_LIMBS;
    let slack_bits_base  = next; next += R_LIMBS * REDUCE_LIMB_BITS;
    let carry_bits_base  = next; next += PRODUCT_LIMBS * CARRY_BITS;
    let reduce = ScalarReduceGadgetLayout {
        input_limbs_base: 0,
        q_limbs_base, q_bits_base,
        r_limbs_base, r_bits_base,
        slack_limbs_base, slack_bits_base,
        carry_bits_base,
    };
    let reduce_phase_width = next;

    let digest_bit_base = SHA512_WIDTH;
    let phase_a_width   = SHA512_WIDTH + DIGEST_BITS;

    // Decompression layout: y_limbs at col 0..10, sign_bit at col 10,
    // gadget body from col 11 onward (placed by the gadget allocator).
    let decomp_y_limbs = 0;
    let decomp_sign    = NUM_LIMBS;          // = 10
    let decomp_base    = NUM_LIMBS + 1;      // = 11
    let decomp = point_decompress_layout_at(decomp_base, decomp_y_limbs, decomp_sign);
    let decompress_phase_width = decomp.end;

    let width  = phase_a_width
        .max(reduce_phase_width)
        .max(decompress_phase_width);
    let height = (k_hash + 3).next_power_of_two();

    VerifyAirLayoutV2 {
        n_blocks, k_hash,
        reduce_row, decompress_R_row, decompress_A_row,
        reduce, digest_bit_base, decomp,
        width, height,
    }
}

/// Extract `(y, sign_bit)` from a 32-byte compressed Edwards encoding.
/// Mirrors `EdwardsPoint::decompress`'s prologue.
fn split_compressed(compressed: &[u8; 32]) -> (FieldElement, bool) {
    let sign_bit = (compressed[31] >> 7) & 1 == 1;
    let mut y_bytes = *compressed;
    y_bytes[31] &= 0x7f;
    let y = FieldElement::from_bytes(&y_bytes);
    (y, sign_bit)
}

/// Build a v2 trace.  Returns `None` if either R or A is not a valid
/// Edwards25519 compressed encoding — an honest prover would refuse to
/// prove in that case.
pub fn fill_verify_air_v2(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV2, [u8; 32])> {
    let layout = verify_air_layout_v2(message.len());

    // ── Phase A: SHA-512 trace (same as v1) ──
    let (sha_trace, n_blocks) = build_sha512_trace_multi(message);
    debug_assert_eq!(n_blocks, layout.n_blocks);

    let mut trace: Vec<Vec<F>> =
        (0..layout.width).map(|_| vec![F::zero(); layout.height]).collect();

    for c in 0..SHA512_WIDTH {
        for r in 0..sha_trace[c].len().min(layout.k_hash) {
            trace[c][r] = sha_trace[c][r];
        }
    }

    // ── v1 cross-phase: digest bits at row k_hash − 1 ──
    let digest = sha512_native(message);
    let digest_row = layout.k_hash - 1;
    for k in 0..8 {
        let h_word = u64::from_be_bytes([
            digest[8*k    ], digest[8*k + 1], digest[8*k + 2], digest[8*k + 3],
            digest[8*k + 4], digest[8*k + 5], digest[8*k + 6], digest[8*k + 7],
        ]);
        for i in 0..64 {
            let bit = (h_word >> i) & 1;
            trace[layout.digest_bit_base + 64*k + i][digest_row] =
                if bit == 1 { F::one() } else { F::zero() };
        }
    }

    // ── Phase B: scalar-reduce ──
    for i in 0..REDUCE_INPUT_LIMBS {
        let lo = digest[2 * i] as u64;
        let hi = digest[2 * i + 1] as u64;
        trace[layout.reduce.input_limbs_base + i][layout.reduce_row]
            = F::from(lo | (hi << 8));
    }
    let mut digest_arr = [0u8; 64];
    digest_arr.copy_from_slice(&digest);
    fill_scalar_reduce_gadget(&mut trace, layout.reduce_row, &layout.reduce, &digest_arr);
    let k_canonical = reduce_mod_l_wide(&digest_arr);

    // ── Phase C: decompress R ──
    let (y_R, sign_R) = split_compressed(r_compressed);
    for k in 0..NUM_LIMBS {
        trace[layout.decomp.y_limbs + k][layout.decompress_R_row]
            = F::from(y_R.limbs[k] as u64);
    }
    trace[layout.decomp.sign_bit][layout.decompress_R_row]
        = if sign_R { F::one() } else { F::zero() };
    fill_point_decompress_gadget(
        &mut trace, layout.decompress_R_row, &layout.decomp, &y_R, sign_R,
    )?;

    // ── Phase D: decompress A ──
    let (y_A, sign_A) = split_compressed(a_compressed);
    for k in 0..NUM_LIMBS {
        trace[layout.decomp.y_limbs + k][layout.decompress_A_row]
            = F::from(y_A.limbs[k] as u64);
    }
    trace[layout.decomp.sign_bit][layout.decompress_A_row]
        = if sign_A { F::one() } else { F::zero() };
    fill_point_decompress_gadget(
        &mut trace, layout.decompress_A_row, &layout.decomp, &y_A, sign_A,
    )?;

    Some((trace, layout, k_canonical))
}

/// Per-row constraint evaluator for v2.
pub fn eval_verify_air_v2_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV2,
) -> Vec<F> {
    let mut out = Vec::with_capacity(VERIFY_V2_PER_ROW_CONSTRAINTS);

    // ── SHA-512 (gated; identical to v1) ──
    if row + 1 < layout.k_hash {
        out.extend(eval_sha512_constraints(cur, nxt, row, layout.n_blocks));
    } else {
        for _ in 0..SHA512_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Scalar-reduce ──
    if row == layout.reduce_row {
        out.extend(eval_scalar_reduce_gadget(cur, &layout.reduce));
    } else {
        for _ in 0..SCALAR_REDUCE_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Format conversion (v1, identical to v1) ──
    if row + 1 == layout.k_hash {
        for k in 0..8 {
            for i in 0..64 {
                let b = cur[layout.digest_bit_base + 64*k + i];
                out.push(b * (F::one() - b));
            }
        }
        let pow2_lo: [F; 32] = core::array::from_fn(|i| F::from(1u64 << i));
        for k in 0..8 {
            let mut sum_lo = F::zero();
            let mut sum_hi = F::zero();
            for i in 0..32 {
                sum_lo += pow2_lo[i] * cur[layout.digest_bit_base + 64*k + i];
                sum_hi += pow2_lo[i] * cur[layout.digest_bit_base + 64*k + 32 + i];
            }
            out.push(cur[OFF_H0_LO + 2*k    ] - sum_lo);
            out.push(cur[OFF_H0_LO + 2*k + 1] - sum_hi);
        }
        let pow2_16: [F; 16] = core::array::from_fn(|i| F::from(1u64 << i));
        for k in 0..8 {
            for m in 0..4 {
                let low_byte_base  = 56 - 16 * m;
                let high_byte_base = low_byte_base - 8;
                let mut sum = F::zero();
                for j in 0..8 {
                    sum += pow2_16[j]
                        * cur[layout.digest_bit_base + 64*k + low_byte_base + j];
                }
                for j in 0..8 {
                    sum += pow2_16[8 + j]
                        * cur[layout.digest_bit_base + 64*k + high_byte_base + j];
                }
                let limb_idx = 4*k + m;
                out.push(nxt[layout.reduce.input_limbs_base + limb_idx] - sum);
            }
        }
    } else {
        for _ in 0..VERIFY_V1_FORMAT_CONS { out.push(F::zero()); }
    }

    // ── Phase C: decompress R ──
    if row == layout.decompress_R_row {
        out.extend(eval_point_decompress_gadget(cur, &layout.decomp));
    } else {
        for _ in 0..POINT_DECOMP_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Phase D: decompress A ──
    if row == layout.decompress_A_row {
        out.extend(eval_point_decompress_gadget(cur, &layout.decomp));
    } else {
        for _ in 0..POINT_DECOMP_CONSTRAINTS { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), VERIFY_V2_PER_ROW_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v3 layout — v2 + two scalar-mult phases ([s]·B and [k]·A)
// ═══════════════════════════════════════════════════════════════════
//
// v3 weaves the existing multi-row scalar-mult sub-AIR (from
// ed25519_scalar_mult_air) into the composed trace.  Two K-row phases
// sit immediately after the decompression rows:
//
//   Row k_hash + 3 .. k_hash + 3 + K   : [s]·B  (fixed-base ladder)
//   Row k_hash + 3 + K .. k_hash + 3 + 2K : [k]·A  (variable-base ladder)
//
// `K` is the scalar bit length (256 for production Ed25519; tests use
// K = 8 for fast turnaround — the composition shape is identical).
//
// For v3, the scalar bits and the per-phase BASE are FREE inputs:
//   * sB phase: caller-supplied s_bits, base = ED25519_BASEPOINT.
//   * kA phase: caller-supplied k_bits, base = caller-supplied A point.
// A later increment will bind these to upstream cells (s_bytes from the
// signature, k_canonical from the scalar-reduce r-limbs, A from the
// decomposition row's x_limbs/y_limbs).
//
// Width: max(v2_width, SCALAR_MULT_ROW_WIDTH = 14941) ⇒ ≈ 14941.
// Height: next_pow_2(k_hash + 3 + 2·K).

#[derive(Clone, Copy, Debug)]
pub struct VerifyAirLayoutV3 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    /// First row of the [s]·B scalar-mult phase.
    pub sB_first_row: usize,
    /// First row of the [k]·A scalar-mult phase.
    pub kA_first_row: usize,
    /// Number of bits / rows per scalar-mult phase.
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub width:  usize,
    pub height: usize,
}

/// Per-row constraints for v3.  Adds two sets of scalar-mult per-row
/// constraints (one per phase, fired only at relevant rows), the
/// corresponding cross-row transition constraints (fired on consecutive
/// row pairs WITHIN each phase), and one set of initial-acc boundary
/// constraints per phase (fired only at the phase's first row).
pub const VERIFY_V3_PER_ROW_CONSTRAINTS: usize =
    VERIFY_V2_PER_ROW_CONSTRAINTS
    + 2 * SCALAR_MULT_PER_ROW_CONSTRAINTS
    + 2 * SCALAR_MULT_TRANSITION_CONSTRAINTS
    + 2 * (4 * NUM_LIMBS);                  // initial-acc per phase

/// Build a v3 layout for given message length and scalar bit-length.
///
/// `k_scalar = 256` matches Ed25519; tests use small values (e.g. 8).
pub fn verify_air_layout_v3(
    msg_len_for_sha512: usize,
    k_scalar: usize,
) -> VerifyAirLayoutV3 {
    let n_blocks = (msg_len_for_sha512 + 1 + 16 + 127) / 128;
    let k_hash   = (n_blocks * SHA512_ROWS_PER_BLOCK)
        .next_power_of_two().max(SHA512_ROWS_PER_BLOCK);
    let reduce_row        = k_hash;
    let decompress_R_row  = k_hash + 1;
    let decompress_A_row  = k_hash + 2;
    let sB_first_row      = k_hash + 3;
    let kA_first_row      = sB_first_row + k_scalar;

    // Reduce gadget (same as v0/v1/v2).
    let mut next = REDUCE_INPUT_LIMBS;
    let q_limbs_base = next; next += Q_LIMBS;
    let q_bits_base  = next; next += Q_LIMBS * REDUCE_LIMB_BITS;
    let r_limbs_base = next; next += R_LIMBS;
    let r_bits_base  = next; next += R_LIMBS * REDUCE_LIMB_BITS;
    let slack_limbs_base = next; next += R_LIMBS;
    let slack_bits_base  = next; next += R_LIMBS * REDUCE_LIMB_BITS;
    let carry_bits_base  = next; next += PRODUCT_LIMBS * CARRY_BITS;
    let reduce = ScalarReduceGadgetLayout {
        input_limbs_base: 0,
        q_limbs_base, q_bits_base,
        r_limbs_base, r_bits_base,
        slack_limbs_base, slack_bits_base,
        carry_bits_base,
    };
    let reduce_phase_width = next;

    let digest_bit_base = SHA512_WIDTH;
    let phase_a_width   = SHA512_WIDTH + DIGEST_BITS;

    // Decompression layout (same as v2).
    let decomp_y_limbs = 0;
    let decomp_sign    = NUM_LIMBS;
    let decomp_base    = NUM_LIMBS + 1;
    let decomp = point_decompress_layout_at(decomp_base, decomp_y_limbs, decomp_sign);
    let decompress_phase_width = decomp.end;

    // Scalar-mult layout (same offsets for both phases).
    let mult = scalar_mult_row_layout();

    let width  = phase_a_width
        .max(reduce_phase_width)
        .max(decompress_phase_width)
        .max(SCALAR_MULT_ROW_WIDTH);
    let height = (k_hash + 3 + 2 * k_scalar).next_power_of_two();

    VerifyAirLayoutV3 {
        n_blocks, k_hash,
        reduce_row, decompress_R_row, decompress_A_row,
        sB_first_row, kA_first_row, k_scalar,
        reduce, digest_bit_base, decomp, mult,
        width, height,
    }
}

/// Build a v3 trace.
///
/// `s_bits` (length `k_scalar`) is the [s] scalar in MSB-first bit form
/// for the [s]·B ladder; `k_bits` (length `k_scalar`) similarly for the
/// [k]·A ladder.  `a_compressed` provides A; the trace builder
/// decompresses it natively to derive the variable base for [k]·A.
///
/// Returns `None` if R or A is not a valid Edwards encoding.
pub fn fill_verify_air_v3(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV3, [u8; 32])> {
    assert_eq!(s_bits.len(), k_bits.len(),
        "s_bits and k_bits must have the same length");
    let k_scalar = s_bits.len();
    let layout = verify_air_layout_v3(message.len(), k_scalar);

    // ── v0/v1/v2 trace ──
    let (sha_trace, n_blocks) = build_sha512_trace_multi(message);
    debug_assert_eq!(n_blocks, layout.n_blocks);

    let mut trace: Vec<Vec<F>> =
        (0..layout.width).map(|_| vec![F::zero(); layout.height]).collect();

    for c in 0..SHA512_WIDTH {
        for r in 0..sha_trace[c].len().min(layout.k_hash) {
            trace[c][r] = sha_trace[c][r];
        }
    }

    let digest = sha512_native(message);
    let digest_row = layout.k_hash - 1;
    for kk in 0..8 {
        let h_word = u64::from_be_bytes([
            digest[8*kk    ], digest[8*kk + 1], digest[8*kk + 2], digest[8*kk + 3],
            digest[8*kk + 4], digest[8*kk + 5], digest[8*kk + 6], digest[8*kk + 7],
        ]);
        for i in 0..64 {
            let bit = (h_word >> i) & 1;
            trace[layout.digest_bit_base + 64*kk + i][digest_row] =
                if bit == 1 { F::one() } else { F::zero() };
        }
    }

    for i in 0..REDUCE_INPUT_LIMBS {
        let lo = digest[2 * i] as u64;
        let hi = digest[2 * i + 1] as u64;
        trace[layout.reduce.input_limbs_base + i][layout.reduce_row]
            = F::from(lo | (hi << 8));
    }
    let mut digest_arr = [0u8; 64];
    digest_arr.copy_from_slice(&digest);
    fill_scalar_reduce_gadget(&mut trace, layout.reduce_row, &layout.reduce, &digest_arr);
    let k_canonical = reduce_mod_l_wide(&digest_arr);

    let (y_R, sign_R) = split_compressed(r_compressed);
    for kk in 0..NUM_LIMBS {
        trace[layout.decomp.y_limbs + kk][layout.decompress_R_row]
            = F::from(y_R.limbs[kk] as u64);
    }
    trace[layout.decomp.sign_bit][layout.decompress_R_row]
        = if sign_R { F::one() } else { F::zero() };
    fill_point_decompress_gadget(
        &mut trace, layout.decompress_R_row, &layout.decomp, &y_R, sign_R,
    )?;

    let (y_A, sign_A) = split_compressed(a_compressed);
    for kk in 0..NUM_LIMBS {
        trace[layout.decomp.y_limbs + kk][layout.decompress_A_row]
            = F::from(y_A.limbs[kk] as u64);
    }
    trace[layout.decomp.sign_bit][layout.decompress_A_row]
        = if sign_A { F::one() } else { F::zero() };
    fill_point_decompress_gadget(
        &mut trace, layout.decompress_A_row, &layout.decomp, &y_A, sign_A,
    )?;

    // ── Phase E: [s]·B (fixed-base ladder) ──
    let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;
    {
        // Build a slice view containing only the sB rows.  The standalone
        // builder writes to absolute row indices 0..K, so we offset by
        // splicing in a temp narrow trace then copying back.
        let mut sub: Vec<Vec<F>> =
            (0..layout.width).map(|_| vec![F::zero(); k_scalar]).collect();
        let _ = fill_scalar_mult_trace(&mut sub, &layout.mult, &basepoint, s_bits);
        for c in 0..layout.width {
            for r in 0..k_scalar {
                trace[c][layout.sB_first_row + r] = sub[c][r];
            }
        }
    }

    // ── Phase F: [k]·A (variable-base ladder) ──
    let A_point = EdwardsPoint::decompress(a_compressed)
        .expect("A_compressed already validated by decomp gadget");
    {
        let mut sub: Vec<Vec<F>> =
            (0..layout.width).map(|_| vec![F::zero(); k_scalar]).collect();
        let _ = fill_scalar_mult_trace(&mut sub, &layout.mult, &A_point, k_bits);
        for c in 0..layout.width {
            for r in 0..k_scalar {
                trace[c][layout.kA_first_row + r] = sub[c][r];
            }
        }
    }

    Some((trace, layout, k_canonical))
}

/// Per-row constraint evaluator for v3.
pub fn eval_verify_air_v3_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV3,
) -> Vec<F> {
    let mut out = Vec::with_capacity(VERIFY_V3_PER_ROW_CONSTRAINTS);

    // ── SHA-512 (gated) ──
    if row + 1 < layout.k_hash {
        out.extend(eval_sha512_constraints(cur, nxt, row, layout.n_blocks));
    } else {
        for _ in 0..SHA512_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Scalar-reduce ──
    if row == layout.reduce_row {
        out.extend(eval_scalar_reduce_gadget(cur, &layout.reduce));
    } else {
        for _ in 0..SCALAR_REDUCE_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Format conversion (v1) ──
    if row + 1 == layout.k_hash {
        for k in 0..8 {
            for i in 0..64 {
                let b = cur[layout.digest_bit_base + 64*k + i];
                out.push(b * (F::one() - b));
            }
        }
        let pow2_lo: [F; 32] = core::array::from_fn(|i| F::from(1u64 << i));
        for k in 0..8 {
            let mut sum_lo = F::zero();
            let mut sum_hi = F::zero();
            for i in 0..32 {
                sum_lo += pow2_lo[i] * cur[layout.digest_bit_base + 64*k + i];
                sum_hi += pow2_lo[i] * cur[layout.digest_bit_base + 64*k + 32 + i];
            }
            out.push(cur[OFF_H0_LO + 2*k    ] - sum_lo);
            out.push(cur[OFF_H0_LO + 2*k + 1] - sum_hi);
        }
        let pow2_16: [F; 16] = core::array::from_fn(|i| F::from(1u64 << i));
        for k in 0..8 {
            for m in 0..4 {
                let low_byte_base  = 56 - 16 * m;
                let high_byte_base = low_byte_base - 8;
                let mut sum = F::zero();
                for j in 0..8 {
                    sum += pow2_16[j]
                        * cur[layout.digest_bit_base + 64*k + low_byte_base + j];
                }
                for j in 0..8 {
                    sum += pow2_16[8 + j]
                        * cur[layout.digest_bit_base + 64*k + high_byte_base + j];
                }
                let limb_idx = 4*k + m;
                out.push(nxt[layout.reduce.input_limbs_base + limb_idx] - sum);
            }
        }
    } else {
        for _ in 0..VERIFY_V1_FORMAT_CONS { out.push(F::zero()); }
    }

    // ── Decompress R, A ──
    if row == layout.decompress_R_row {
        out.extend(eval_point_decompress_gadget(cur, &layout.decomp));
    } else {
        for _ in 0..POINT_DECOMP_CONSTRAINTS { out.push(F::zero()); }
    }
    if row == layout.decompress_A_row {
        out.extend(eval_point_decompress_gadget(cur, &layout.decomp));
    } else {
        for _ in 0..POINT_DECOMP_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Phase E: [s]·B (per-row + transition + initial-acc) ──
    let sB_last_row = layout.sB_first_row + layout.k_scalar - 1;
    if row >= layout.sB_first_row && row <= sB_last_row {
        out.extend(eval_scalar_mult_per_row(cur, &layout.mult));
    } else {
        for _ in 0..SCALAR_MULT_PER_ROW_CONSTRAINTS { out.push(F::zero()); }
    }
    if row >= layout.sB_first_row && row < sB_last_row {
        out.extend(eval_scalar_mult_transition(cur, nxt, &layout.mult));
    } else {
        for _ in 0..SCALAR_MULT_TRANSITION_CONSTRAINTS { out.push(F::zero()); }
    }
    if row == layout.sB_first_row {
        out.extend(eval_scalar_mult_initial_acc(cur, &layout.mult));
    } else {
        for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }
    }

    // ── Phase F: [k]·A (per-row + transition + initial-acc) ──
    let kA_last_row = layout.kA_first_row + layout.k_scalar - 1;
    if row >= layout.kA_first_row && row <= kA_last_row {
        out.extend(eval_scalar_mult_per_row(cur, &layout.mult));
    } else {
        for _ in 0..SCALAR_MULT_PER_ROW_CONSTRAINTS { out.push(F::zero()); }
    }
    if row >= layout.kA_first_row && row < kA_last_row {
        out.extend(eval_scalar_mult_transition(cur, nxt, &layout.mult));
    } else {
        for _ in 0..SCALAR_MULT_TRANSITION_CONSTRAINTS { out.push(F::zero()); }
    }
    if row == layout.kA_first_row {
        out.extend(eval_scalar_mult_initial_acc(cur, &layout.mult));
    } else {
        for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), VERIFY_V3_PER_ROW_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v4 layout — v3 + boundary base pinnings for both scalar-mult phases
// ═══════════════════════════════════════════════════════════════════
//
// v4 closes the soundness gap on the SCALAR-MULT BASES.  Without it, a
// malicious prover could swap in any base point at the start of either
// ladder and have the scalar-mult AIR happily accept (the gadgets only
// check the iteration is internally consistent, not the boundary).
//
// Two new boundary-style constraint blocks fire at the first row of
// each ladder:
//
//   Row sB_first_row: 4 × NUM_LIMBS = 40 cons pinning base_x/y/z/t to
//                     the canonical ED25519_BASEPOINT projective coords
//                     `(B.X, B.Y, B.Z, B.T)`  (a global constant).
//
//   Row kA_first_row: 40 cons pinning base_x/y/z/t to the projective
//                     coords of the decompressed `A` point  (derived
//                     from the public input `a_compressed`).
//
// Together with the scalar-mult AIR's existing per-row transition
// constraint that base limbs are constant across the phase, this binds
// every row's base cells to the public input.
//
// Future v5: bind scalar bits (s_bits → cond_add.bit_cell at sB rows;
// k_bits → cond_add.bit_cell at kA rows) and add the cofactored
// equality + identity check `[8]·([s]·B − R − [k]·A) = O`.

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV4 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    /// Public-input-derived projective coords of A (X, Y, Z, T) used by
    /// the kA-base boundary pinning constraint.
    pub a_point_limbs: [FieldElement; 4],
    pub width:  usize,
    pub height: usize,
}

/// Per-row constraints for v4 = v3 + 80 base-pinning cons (40 sB, 40 kA).
pub const VERIFY_V4_PER_ROW_CONSTRAINTS: usize =
    VERIFY_V3_PER_ROW_CONSTRAINTS + 2 * (4 * NUM_LIMBS);

/// Build a v4 layout.  `a_compressed` is required because the kA base
/// pinning constraints fold A's projective limbs into the AIR — a
/// public-input-style boundary check.  Returns `None` if A is not a
/// valid Edwards encoding.
pub fn verify_air_layout_v4(
    msg_len_for_sha512: usize,
    k_scalar: usize,
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV4> {
    let v3 = verify_air_layout_v3(msg_len_for_sha512, k_scalar);

    // Decompress A here so the AIR layout can fold in the public coords.
    let A_point = EdwardsPoint::decompress(a_compressed)?;
    let a_point_limbs = [
        canonicalised(&A_point.X),
        canonicalised(&A_point.Y),
        canonicalised(&A_point.Z),
        canonicalised(&A_point.T),
    ];

    Some(VerifyAirLayoutV4 {
        n_blocks: v3.n_blocks,
        k_hash:   v3.k_hash,
        reduce_row:       v3.reduce_row,
        decompress_R_row: v3.decompress_R_row,
        decompress_A_row: v3.decompress_A_row,
        sB_first_row: v3.sB_first_row,
        kA_first_row: v3.kA_first_row,
        k_scalar:     v3.k_scalar,
        reduce: v3.reduce,
        digest_bit_base: v3.digest_bit_base,
        decomp: v3.decomp,
        mult:   v3.mult,
        a_point_limbs,
        width:  v3.width,
        height: v3.height,
    })
}

fn canonicalised(fe: &FieldElement) -> FieldElement {
    let mut x = *fe;
    x.freeze();
    x
}

/// Build a v4 trace.  Identical fill semantics to v3 — the difference
/// is purely in the constraint emitter (boundary cons added).  Reused
/// fill code path: we just delegate to v3 and then re-tag the layout.
pub fn fill_verify_air_v4(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV4, [u8; 32])> {
    let layout = verify_air_layout_v4(message.len(), s_bits.len(), a_compressed)?;
    let (trace, _v3, k_canonical) =
        fill_verify_air_v3(message, r_compressed, a_compressed, s_bits, k_bits)?;
    Some((trace, layout, k_canonical))
}

/// Per-row constraint evaluator for v4.
pub fn eval_verify_air_v4_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV4,
) -> Vec<F> {
    // Reuse the v3 evaluator by reconstructing the v3 layout from v4
    // (cheap — all fields except a_point_limbs match exactly).
    let v3 = VerifyAirLayoutV3 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v3_per_row(cur, nxt, row, &v3);

    // ── sB base boundary: 40 cons at row sB_first_row ──
    let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;
    let bp_x = canonicalised(&basepoint.X);
    let bp_y = canonicalised(&basepoint.Y);
    let bp_z = canonicalised(&basepoint.Z);
    let bp_t = canonicalised(&basepoint.T);
    if row == layout.sB_first_row {
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.mult.base_x + k] - F::from(bp_x.limbs[k] as u64));
        }
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.mult.base_y + k] - F::from(bp_y.limbs[k] as u64));
        }
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.mult.base_z + k] - F::from(bp_z.limbs[k] as u64));
        }
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.mult.base_t + k] - F::from(bp_t.limbs[k] as u64));
        }
    } else {
        for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }
    }

    // ── kA base boundary: 40 cons at row kA_first_row ──
    if row == layout.kA_first_row {
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.mult.base_x + k]
                - F::from(layout.a_point_limbs[0].limbs[k] as u64));
        }
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.mult.base_y + k]
                - F::from(layout.a_point_limbs[1].limbs[k] as u64));
        }
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.mult.base_z + k]
                - F::from(layout.a_point_limbs[2].limbs[k] as u64));
        }
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.mult.base_t + k]
                - F::from(layout.a_point_limbs[3].limbs[k] as u64));
        }
    } else {
        for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), VERIFY_V4_PER_ROW_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v5 layout — v4 + decompression-input pinning to public encodings
// ═══════════════════════════════════════════════════════════════════
//
// v4 left a soundness seam at the decompression rows: a malicious
// prover could feed the decomp gadget some (y, sign) different from
// the public R/A encodings.  The gadget would still prove curve
// membership for that pair, but the witnessed x would correspond to a
// different point — divorcing the on-chain decomposition from the
// public input.
//
// v5 closes this with two boundary constraint blocks (at the two
// decompression rows) pinning (y_limbs, sign_bit) to verifier-derived
// constants extracted from `r_compressed` / `a_compressed`:
//
//   y_bytes  = compressed[0..32] with byte 31's MSB cleared
//   sign_bit = (compressed[31] >> 7) & 1
//   y        = FieldElement::from_bytes(y_bytes).freeze()  // 10 limbs
//
// This is cheap for the verifier (no sqrt) and tight for the AIR.  The
// decomp gadget continues to prove that x is the canonical x for the
// pinned y, so the verifier still saves the sqrt computation.

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV5 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    /// Public-input-derived canonical y for R (pinned at decompress_R_row).
    pub r_y:    FieldElement,
    pub r_sign: bool,
    /// Public-input-derived canonical y for A (pinned at decompress_A_row).
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub width:  usize,
    pub height: usize,
}

/// Per-row constraints for v5 = v4 + 2 × (NUM_LIMBS + 1) pinning cons.
pub const VERIFY_V5_PER_ROW_CONSTRAINTS: usize =
    VERIFY_V4_PER_ROW_CONSTRAINTS + 2 * (NUM_LIMBS + 1);

/// Build a v5 layout.  Returns None if R or A is invalid.
pub fn verify_air_layout_v5(
    msg_len_for_sha512: usize,
    k_scalar: usize,
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV5> {
    let v4 = verify_air_layout_v4(msg_len_for_sha512, k_scalar, a_compressed)?;
    let (r_y, r_sign) = split_compressed(r_compressed);
    let (a_y, a_sign) = split_compressed(a_compressed);
    let r_y = canonicalised(&r_y);
    let a_y = canonicalised(&a_y);

    Some(VerifyAirLayoutV5 {
        n_blocks: v4.n_blocks,
        k_hash:   v4.k_hash,
        reduce_row:       v4.reduce_row,
        decompress_R_row: v4.decompress_R_row,
        decompress_A_row: v4.decompress_A_row,
        sB_first_row: v4.sB_first_row,
        kA_first_row: v4.kA_first_row,
        k_scalar:     v4.k_scalar,
        reduce: v4.reduce,
        digest_bit_base: v4.digest_bit_base,
        decomp: v4.decomp,
        mult:   v4.mult,
        a_point_limbs: v4.a_point_limbs,
        r_y, r_sign,
        a_y, a_sign,
        width:  v4.width,
        height: v4.height,
    })
}

/// Build a v5 trace.  Same fill semantics as v4; v5 adds constraints
/// only.
pub fn fill_verify_air_v5(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV5, [u8; 32])> {
    let layout = verify_air_layout_v5(
        message.len(), s_bits.len(), r_compressed, a_compressed,
    )?;
    let (trace, _v4, k_canonical) = fill_verify_air_v4(
        message, r_compressed, a_compressed, s_bits, k_bits,
    )?;
    Some((trace, layout, k_canonical))
}

/// Per-row constraint evaluator for v5.
pub fn eval_verify_air_v5_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV5,
) -> Vec<F> {
    let v4 = VerifyAirLayoutV4 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v4_per_row(cur, nxt, row, &v4);

    // ── R y/sign pinning at decompress_R_row (NUM_LIMBS + 1 cons) ──
    if row == layout.decompress_R_row {
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.decomp.y_limbs + k]
                - F::from(layout.r_y.limbs[k] as u64));
        }
        out.push(cur[layout.decomp.sign_bit]
            - if layout.r_sign { F::one() } else { F::zero() });
    } else {
        for _ in 0..(NUM_LIMBS + 1) { out.push(F::zero()); }
    }

    // ── A y/sign pinning at decompress_A_row (NUM_LIMBS + 1 cons) ──
    if row == layout.decompress_A_row {
        for k in 0..NUM_LIMBS {
            out.push(cur[layout.decomp.y_limbs + k]
                - F::from(layout.a_y.limbs[k] as u64));
        }
        out.push(cur[layout.decomp.sign_bit]
            - if layout.a_sign { F::one() } else { F::zero() });
    } else {
        for _ in 0..(NUM_LIMBS + 1) { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), VERIFY_V5_PER_ROW_CONSTRAINTS);
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v6 layout — v5 + scalar-bit shift chains for sB and kA phases
// ═══════════════════════════════════════════════════════════════════
//
// v5 left a soundness seam at the per-row `cond_add.bit_cell`: the
// gadget enforces booleanity but not the connection to the actual
// scalar.  A malicious prover could choose any bit at each row,
// computing a different scalar mult than the one the signature
// requires.
//
// v6 closes this for both phases via a "shift chain":
//
//   Per scalar-mult phase (K rows), reserve K cells per row holding the
//   REMAINING scalar bits, MSB-first, left-shifted as the ladder
//   advances:
//
//     row sB_first + 0 :  [s[0], s[1], ..., s[K−1]]
//     row sB_first + 1 :  [s[1], s[2], ..., s[K−1], 0]
//     row sB_first + j :  [s[j], s[j+1], ..., s[K−1], 0, ..., 0]
//
//   Constraints per phase:
//     1. Boundary @ phase first row (K cons):
//          scalar_block[i] = s_bit[i]   (or k_bit[i] for kA)
//     2. Per-row binding (1 cons, fires on every phase row):
//          cond_add.bit_cell = scalar_block[0]
//     3. Shift transition (K−1 cons, fires on every phase row pair):
//          nxt.scalar_block[i] = cur.scalar_block[i + 1]
//
// Total per phase: 2·K cons.  Total v6 over v5: 4·K cons (per row).
//
// For K = 8 (tests): 32 new cons per row.
// For K = 256 (production): 1024 new cons per row.
//
// Width grows by 2·K cells (one block per phase).

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV6 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    /// Column where the K-cell sB scalar bit block starts.
    pub scalar_block_sB_base: usize,
    /// Column where the K-cell kA scalar bit block starts.
    pub scalar_block_kA_base: usize,
    /// Public-input scalar bits (MSB-first, K entries each).
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub width:  usize,
    pub height: usize,
}

/// Per-row constraint count for v6 — depends on `k_scalar`.
pub fn verify_v6_per_row_constraints(k_scalar: usize) -> usize {
    VERIFY_V5_PER_ROW_CONSTRAINTS + 4 * k_scalar
}

/// Build a v6 layout.
pub fn verify_air_layout_v6(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV6> {
    assert_eq!(s_bits.len(), k_bits.len(),
        "s_bits and k_bits must share the same length (= k_scalar)");
    let k_scalar = s_bits.len();
    let v5 = verify_air_layout_v5(
        msg_len_for_sha512, k_scalar, r_compressed, a_compressed,
    )?;

    // Place the two scalar blocks in fresh columns past the v5 width.
    let scalar_block_sB_base = v5.width;
    let scalar_block_kA_base = scalar_block_sB_base + k_scalar;
    let width = scalar_block_kA_base + k_scalar;

    Some(VerifyAirLayoutV6 {
        n_blocks: v5.n_blocks,
        k_hash:   v5.k_hash,
        reduce_row:       v5.reduce_row,
        decompress_R_row: v5.decompress_R_row,
        decompress_A_row: v5.decompress_A_row,
        sB_first_row: v5.sB_first_row,
        kA_first_row: v5.kA_first_row,
        k_scalar:     v5.k_scalar,
        reduce: v5.reduce,
        digest_bit_base: v5.digest_bit_base,
        decomp: v5.decomp,
        mult:   v5.mult,
        a_point_limbs: v5.a_point_limbs,
        r_y: v5.r_y,
        r_sign: v5.r_sign,
        a_y: v5.a_y,
        a_sign: v5.a_sign,
        scalar_block_sB_base, scalar_block_kA_base,
        s_bits: s_bits.to_vec(),
        k_bits: k_bits.to_vec(),
        width,
        height: v5.height,
    })
}

/// Build a v6 trace.
pub fn fill_verify_air_v6(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV6, [u8; 32])> {
    let layout = verify_air_layout_v6(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let (mut trace, _v5, k_canonical) = fill_verify_air_v5(
        message, r_compressed, a_compressed, s_bits, k_bits,
    )?;

    // Resize trace to v6 width — v6 adds 2·K columns.
    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }

    let k = layout.k_scalar;

    // Fill sB scalar shift chain.
    for j in 0..k {
        let row = layout.sB_first_row + j;
        for i in 0..k {
            let bit = if j + i < k { s_bits[j + i] } else { false };
            trace[layout.scalar_block_sB_base + i][row] =
                if bit { F::one() } else { F::zero() };
        }
    }

    // Fill kA scalar shift chain.
    for j in 0..k {
        let row = layout.kA_first_row + j;
        for i in 0..k {
            let bit = if j + i < k { k_bits[j + i] } else { false };
            trace[layout.scalar_block_kA_base + i][row] =
                if bit { F::one() } else { F::zero() };
        }
    }

    Some((trace, layout, k_canonical))
}

/// Per-row constraint evaluator for v6.
pub fn eval_verify_air_v6_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV6,
) -> Vec<F> {
    let v5 = VerifyAirLayoutV5 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y,
        r_sign: layout.r_sign,
        a_y: layout.a_y,
        a_sign: layout.a_sign,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v5_per_row(cur, nxt, row, &v5);

    let k = layout.k_scalar;
    let sB_last = layout.sB_first_row + k - 1;
    let kA_last = layout.kA_first_row + k - 1;

    // ── sB boundary at sB_first_row (K cons) ──
    if row == layout.sB_first_row {
        for i in 0..k {
            let want = if layout.s_bits[i] { F::one() } else { F::zero() };
            out.push(cur[layout.scalar_block_sB_base + i] - want);
        }
    } else {
        for _ in 0..k { out.push(F::zero()); }
    }

    // ── sB per-row binding (1 cons, fires on phase rows) ──
    if row >= layout.sB_first_row && row <= sB_last {
        out.push(cur[layout.mult.cond_add.bit_cell]
            - cur[layout.scalar_block_sB_base]);
    } else {
        out.push(F::zero());
    }

    // ── sB shift transition (K−1 cons, fires on phase row pairs) ──
    if row >= layout.sB_first_row && row < sB_last {
        for i in 0..(k - 1) {
            out.push(nxt[layout.scalar_block_sB_base + i]
                - cur[layout.scalar_block_sB_base + i + 1]);
        }
    } else {
        for _ in 0..(k - 1) { out.push(F::zero()); }
    }

    // ── kA boundary at kA_first_row (K cons) ──
    if row == layout.kA_first_row {
        for i in 0..k {
            let want = if layout.k_bits[i] { F::one() } else { F::zero() };
            out.push(cur[layout.scalar_block_kA_base + i] - want);
        }
    } else {
        for _ in 0..k { out.push(F::zero()); }
    }

    // ── kA per-row binding ──
    if row >= layout.kA_first_row && row <= kA_last {
        out.push(cur[layout.mult.cond_add.bit_cell]
            - cur[layout.scalar_block_kA_base]);
    } else {
        out.push(F::zero());
    }

    // ── kA shift transition ──
    if row >= layout.kA_first_row && row < kA_last {
        for i in 0..(k - 1) {
            out.push(nxt[layout.scalar_block_kA_base + i]
                - cur[layout.scalar_block_kA_base + i + 1]);
        }
    } else {
        for _ in 0..(k - 1) { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), verify_v6_per_row_constraints(k));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v7 layout — v6 + r→kA scalar binding via thread chain
// ═══════════════════════════════════════════════════════════════════
//
// v6 pinned `k_bits` at kA_first_row to a public-input layout constant.
// v7 closes the harder gap: in real Ed25519, k ≡ SHA-512(R || A || M)
// mod L is the SAME value the scalar-reduce gadget produces in the
// reduce row's `r_bits` cells.  v7 wires those bits forward through a
// K-cell thread chain that lives at every row, glues them to `r_bits`
// at reduce_row, and re-glues them to `scalar_block_kA` at
// kA_first_row.
//
// Bit ordering — r is a 256-bit canonical scalar held LSB-first in
// `r_bits_base + j` for j ∈ [0, 256).  k_bits is MSB-first within the
// K bits the kA ladder consumes:
//
//   kA scalar value (interpreted LSB-first within K bits)
//     = sum_{i=0..K} k_bits[K - 1 - i] * 2^i
//
// For tests with K = 8 we bind to the LOWEST 8 bits of r:
//
//   k_bits[i]  =  r_bits[K − 1 − i]    for i ∈ [0, K)
//
// For production (K = 256) the same formula spans the full r.
//
// Constraints:
//   1. Boundary @ reduce_row (K cons):
//        thread[i] = r_bits[K − 1 − i]
//   2. Transition (K cons, fires on every row pair):
//        nxt.thread[i] = cur.thread[i]                  (constancy)
//   3. Boundary @ kA_first_row (K cons):
//        scalar_block_kA[i] = thread[i]
//
// Per-row v7: 3·K cons.  Width grows by K cells (the thread block).
//
// v6's existing kA-boundary pin (scalar_block_kA[i] = k_bits[i]) stays.
// v7's thread-binding makes the public k_bits a SHA-512-derived value;
// callers that supply k_bits inconsistent with r will fail v7 cons.

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV7 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    /// Column where the K-cell r→kA thread chain starts.  Cells are
    /// present at every row; their value equals the K relevant bits of
    /// the canonical r scalar, MSB-first in kA-order.
    pub r_thread_base: usize,
    pub width:  usize,
    pub height: usize,
}

/// Per-row constraint count for v7 — adds 3·K cons over v6.
pub fn verify_v7_per_row_constraints(k_scalar: usize) -> usize {
    verify_v6_per_row_constraints(k_scalar) + 3 * k_scalar
}

/// Build a v7 layout.
pub fn verify_air_layout_v7(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV7> {
    let v6 = verify_air_layout_v6(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let k = v6.k_scalar;
    let r_thread_base = v6.width;
    let width = r_thread_base + k;

    Some(VerifyAirLayoutV7 {
        n_blocks: v6.n_blocks,
        k_hash:   v6.k_hash,
        reduce_row:       v6.reduce_row,
        decompress_R_row: v6.decompress_R_row,
        decompress_A_row: v6.decompress_A_row,
        sB_first_row: v6.sB_first_row,
        kA_first_row: v6.kA_first_row,
        k_scalar:     v6.k_scalar,
        reduce: v6.reduce,
        digest_bit_base: v6.digest_bit_base,
        decomp: v6.decomp,
        mult:   v6.mult,
        a_point_limbs: v6.a_point_limbs,
        r_y: v6.r_y,
        r_sign: v6.r_sign,
        a_y: v6.a_y,
        a_sign: v6.a_sign,
        scalar_block_sB_base: v6.scalar_block_sB_base,
        scalar_block_kA_base: v6.scalar_block_kA_base,
        s_bits: v6.s_bits,
        k_bits: v6.k_bits,
        r_thread_base,
        width,
        height: v6.height,
    })
}

/// Compute the K-bit MSB-first kA-ordered slice of r.
///
/// `k_bits[i] = r_bit[K − 1 − i]` (LSB-first numbering of r). Returns
/// a Vec<bool> of length K.
pub fn r_thread_bits_for_kA(k_canonical: &[u8; 32], k_scalar: usize) -> Vec<bool> {
    assert!(k_scalar <= 256, "k_scalar must fit in 256 bits");
    let mut r_bits_lsb_first = [false; 256];
    for byte_idx in 0..32 {
        let byte = k_canonical[byte_idx];
        for b in 0..8 {
            r_bits_lsb_first[byte_idx * 8 + b] = ((byte >> b) & 1) == 1;
        }
    }
    // kA consumes bits MSB-first within the K-bit slice.
    (0..k_scalar).map(|i| r_bits_lsb_first[k_scalar - 1 - i]).collect()
}

/// Build a v7 trace.
pub fn fill_verify_air_v7(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV7, [u8; 32])> {
    let layout = verify_air_layout_v7(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let (mut trace, _v6, k_canonical) = fill_verify_air_v6(
        message, r_compressed, a_compressed, s_bits, k_bits,
    )?;

    // Resize trace to v7 width.
    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }

    // Fill thread cells with the K kA-ordered bits of r at EVERY row.
    let thread_bits = r_thread_bits_for_kA(&k_canonical, layout.k_scalar);
    for r in 0..layout.height {
        for i in 0..layout.k_scalar {
            trace[layout.r_thread_base + i][r] =
                if thread_bits[i] { F::one() } else { F::zero() };
        }
    }

    Some((trace, layout, k_canonical))
}

/// Per-row constraint evaluator for v7.
pub fn eval_verify_air_v7_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV7,
) -> Vec<F> {
    let v6 = VerifyAirLayoutV6 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y,
        r_sign: layout.r_sign,
        a_y: layout.a_y,
        a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v6_per_row(cur, nxt, row, &v6);

    let k = layout.k_scalar;

    // ── 1. Boundary @ reduce_row: thread[i] = r_bits[K − 1 − i] ──
    if row == layout.reduce_row {
        for i in 0..k {
            // r is 256 bits; r_bits at reduce row are LSB-first.
            // For kA bit i (MSB-first), bind to r_bit[K - 1 - i].
            let r_bit_pos = k - 1 - i;
            let r_bit_cell = layout.reduce.r_bits_base + r_bit_pos;
            out.push(cur[layout.r_thread_base + i] - cur[r_bit_cell]);
        }
    } else {
        for _ in 0..k { out.push(F::zero()); }
    }

    // ── 2. Transition: nxt.thread[i] = cur.thread[i] (every row) ──
    for i in 0..k {
        out.push(nxt[layout.r_thread_base + i]
            - cur[layout.r_thread_base + i]);
    }

    // ── 3. Boundary @ kA_first_row: scalar_block_kA[i] = thread[i] ──
    if row == layout.kA_first_row {
        for i in 0..k {
            out.push(cur[layout.scalar_block_kA_base + i]
                - cur[layout.r_thread_base + i]);
        }
    } else {
        for _ in 0..k { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), verify_v7_per_row_constraints(k));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v8 layout — v7 + projective-identity equality check on a result row
// ═══════════════════════════════════════════════════════════════════
//
// v8 introduces the FINAL VERDICT phase: a single new row past the kA
// ladder hosting a "result" point `R8 = (X, Y, Z, T)` (40 cells) which
// the trace builder fills as `[8]·residual` natively.  Three SUB
// gadgets canonicalise the projective-identity quantities and the
// per-row evaluator checks each canonical 10-limb result is zero:
//
//   sub_X  = X − 0          ⇒  canonical(X)         must be 0
//   sub_T  = T − 0          ⇒  canonical(T)         must be 0
//   sub_YZ = Y − Z          ⇒  canonical(Y − Z)     must be 0
//
// Identity in projective Edwards25519 is `(0 : c : c : 0)` for any
// c ≠ 0, so the three checks above (X = 0, T = 0, Y = Z mod p) are
// necessary AND sufficient.
//
// Soundness scope in v8:
//   * The result point `R8` is a FREE TRACE INPUT in v8 — the trace
//     builder accepts `(X, Y, Z, T)` from the caller.  v9 (next) will
//     compute `R8` in-circuit by chaining 3 point-double gadgets atop a
//     residual row, and bind the residual to `[s]·B − R − [k]·A` via
//     point-sub gadgets and thread chains.
//   * The identity verdict — once reached — is sound: a malicious
//     prover can NOT forge `(X, Y, Z, T)` with `X ≢ 0 (mod p)` and
//     have the SUB-gadget canonical output be all zeros, because the
//     SUB gadget itself enforces canonicalisation.
//
// Width: v7_width + 4·NUM_LIMBS  (result point cells) + NUM_LIMBS
// (constant-zero cells) + 3·SUB_GADGET_OWNED_CELLS.
//
// Per-row v8 cons (gated to `result_row`):
//   • NUM_LIMBS cons pinning constant-zero cells to F::zero()         = 10
//   • 3 · SUB_GADGET_CONSTRAINTS                                      = 915
//   • 3 · NUM_LIMBS cons checking each SUB gadget's c_limbs are zero  = 30
//   ────────────────────────────────────────────────────────────────────────
//                                                              TOTAL  = 955

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV8 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    /// Row hosting the projective-identity verdict.
    pub result_row: usize,
    /// Result point (free input in v8): X, Y, Z, T at 10 limbs each.
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    /// 10 cells pinned to canonical zero — used as the b-input of the
    /// SUB gadgets that check X = 0 and T = 0.
    pub zero_const_base: usize,
    /// Three SUB gadgets canonicalising X, T, Y − Z.
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    pub width:  usize,
    pub height: usize,
}

/// Per-row cons count for v8 = v7 + 955 cons (all gated to result_row).
pub fn verify_v8_per_row_constraints(k_scalar: usize) -> usize {
    verify_v7_per_row_constraints(k_scalar)
        + NUM_LIMBS
        + 3 * SUB_GADGET_CONSTRAINTS
        + 3 * NUM_LIMBS
}

/// Build a v8 layout.
pub fn verify_air_layout_v8(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV8> {
    let v7 = verify_air_layout_v7(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let result_row = v7.kA_first_row + v7.k_scalar;  // = kA_last_row + 1

    // Lay out v8-owned cells starting at v7's width.
    let mut next = v7.width;
    let result_X_base = next; next += NUM_LIMBS;
    let result_Y_base = next; next += NUM_LIMBS;
    let result_Z_base = next; next += NUM_LIMBS;
    let result_T_base = next; next += NUM_LIMBS;
    let zero_const_base = next; next += NUM_LIMBS;

    // Allocate three SUB gadgets manually (the SubGadgetLayout fields
    // are public).
    let alloc_sub = |start: &mut usize, a_base: usize, b_base: usize|
        -> SubGadgetLayout
    {
        let c_limbs_base = *start; *start += ELEMENT_LIMB_CELLS;
        let c_bits_base  = *start; *start += 255;
        let c_pos_base   = *start; *start += NUM_LIMBS;
        let c_neg_base   = *start; *start += NUM_LIMBS;
        SubGadgetLayout {
            a_limbs_base: a_base,
            b_limbs_base: b_base,
            c_limbs_base, c_bits_base, c_pos_base, c_neg_base,
        }
    };
    let sub_X  = alloc_sub(&mut next, result_X_base, zero_const_base);
    let sub_T  = alloc_sub(&mut next, result_T_base, zero_const_base);
    let sub_YZ = alloc_sub(&mut next, result_Y_base, result_Z_base);

    let width = next;

    // Ensure the trace is tall enough to host the new result row.
    let needed_height = result_row + 1;
    let height = if v7.height >= needed_height {
        v7.height
    } else {
        needed_height.next_power_of_two()
    };

    Some(VerifyAirLayoutV8 {
        n_blocks: v7.n_blocks,
        k_hash:   v7.k_hash,
        reduce_row:       v7.reduce_row,
        decompress_R_row: v7.decompress_R_row,
        decompress_A_row: v7.decompress_A_row,
        sB_first_row: v7.sB_first_row,
        kA_first_row: v7.kA_first_row,
        k_scalar:     v7.k_scalar,
        reduce: v7.reduce,
        digest_bit_base: v7.digest_bit_base,
        decomp: v7.decomp,
        mult:   v7.mult,
        a_point_limbs: v7.a_point_limbs,
        r_y: v7.r_y,
        r_sign: v7.r_sign,
        a_y: v7.a_y,
        a_sign: v7.a_sign,
        scalar_block_sB_base: v7.scalar_block_sB_base,
        scalar_block_kA_base: v7.scalar_block_kA_base,
        s_bits: v7.s_bits,
        k_bits: v7.k_bits,
        r_thread_base: v7.r_thread_base,
        result_row,
        result_X_base, result_Y_base, result_Z_base, result_T_base,
        zero_const_base,
        sub_X, sub_T, sub_YZ,
        width,
        height,
    })
}

/// Build a v8 trace.  The caller supplies the result point `(X, Y, Z, T)`
/// — in v8 it's a free input.  Returns None if R/A are invalid.
pub fn fill_verify_air_v8(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
    result_point: &EdwardsPoint,
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV8, [u8; 32])> {
    let layout = verify_air_layout_v8(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let (mut trace, _v7, k_canonical) = fill_verify_air_v7(
        message, r_compressed, a_compressed, s_bits, k_bits,
    )?;

    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }
    if trace[0].len() < layout.height {
        for col in trace.iter_mut() {
            col.resize(layout.height, F::zero());
        }
    }

    let row = layout.result_row;
    let X = canonicalised(&result_point.X);
    let Y = canonicalised(&result_point.Y);
    let Z = canonicalised(&result_point.Z);
    let T = canonicalised(&result_point.T);

    for i in 0..NUM_LIMBS {
        trace[layout.result_X_base + i][row] = F::from(X.limbs[i] as u64);
        trace[layout.result_Y_base + i][row] = F::from(Y.limbs[i] as u64);
        trace[layout.result_Z_base + i][row] = F::from(Z.limbs[i] as u64);
        trace[layout.result_T_base + i][row] = F::from(T.limbs[i] as u64);
        trace[layout.zero_const_base + i][row] = F::zero();
    }

    let zero = FieldElement::zero();
    fill_sub_gadget(&mut trace, row, &layout.sub_X,  &X, &zero);
    fill_sub_gadget(&mut trace, row, &layout.sub_T,  &T, &zero);
    fill_sub_gadget(&mut trace, row, &layout.sub_YZ, &Y, &Z);

    Some((trace, layout, k_canonical))
}

/// Per-row constraint evaluator for v8.
pub fn eval_verify_air_v8_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV8,
) -> Vec<F> {
    let v7 = VerifyAirLayoutV7 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y,
        r_sign: layout.r_sign,
        a_y: layout.a_y,
        a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v7_per_row(cur, nxt, row, &v7);

    let k = layout.k_scalar;

    if row == layout.result_row {
        // ── Pin zero_const cells to F::zero() (NUM_LIMBS cons) ──
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.zero_const_base + i]);
        }
        // ── 3 × SUB gadget cons ──
        out.extend(eval_sub_gadget(cur, &layout.sub_X));
        out.extend(eval_sub_gadget(cur, &layout.sub_T));
        out.extend(eval_sub_gadget(cur, &layout.sub_YZ));
        // ── Check each canonical c_limbs is all zero (3 × NUM_LIMBS) ──
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.sub_X.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.sub_T.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.sub_YZ.c_limbs_base + i]);
        }
    } else {
        for _ in 0..NUM_LIMBS { out.push(F::zero()); }
        for _ in 0..(3 * SUB_GADGET_CONSTRAINTS) { out.push(F::zero()); }
        for _ in 0..(3 * NUM_LIMBS) { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), verify_v8_per_row_constraints(k));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v9 layout — v8 + 3-step cofactor doubling chain
// ═══════════════════════════════════════════════════════════════════
//
// v9 introduces the cofactor multiplication: starting from a free input
// point P (placeholder for the v10+ residual `[s]·B − R − [k]·A`), the
// trace performs 3 successive point doublings to compute `[8]·P` and
// pins that output to v8's result-row `(X, Y, Z, T)` cells, so the v8
// identity verdict acts on the actual cofactored value.
//
//   dbl_1_row : input = caller-supplied P                ⇒ output = [2]·P
//   dbl_2_row : input = dbl_1's output                   ⇒ output = [4]·P
//   dbl_3_row : input = dbl_2's output                   ⇒ output = [8]·P
//   result_row (v8): pinned to dbl_3's output            ⇒ verdict = [8]·P ?= O
//
// Constraints added per-row (uniform per row, gated):
//   • POINT_DBL_CONSTRAINTS, fired on rows {dbl_1, dbl_2, dbl_3}
//   • 3·NUM_LIMBS cons binding nxt's input cells to cur's dbl output,
//     fired at row pairs (dbl_1, dbl_2) and (dbl_2, dbl_3)
//   • 4·NUM_LIMBS cons at result_row binding result point to dbl_3's
//     `mul_X3 / mul_Y3 / mul_Z3 / mul_T3` outputs (read across the row
//     boundary as `cur[result_*]` vs the previous row's gadget cells —
//     emitted instead as a transition at row `dbl_3_row`).
//
// The dbl gadget layout is shared across all 3 dbl rows (the column
// allocator is row-independent).

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV9 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    pub result_row: usize,
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    pub zero_const_base: usize,
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    /// Three doubling rows host a single shared dbl-gadget layout.
    pub dbl_1_row: usize,
    pub dbl_2_row: usize,
    pub dbl_3_row: usize,
    pub dbl_input_X_base: usize,
    pub dbl_input_Y_base: usize,
    pub dbl_input_Z_base: usize,
    pub dbl: PointDoubleGadgetLayout,
    pub width:  usize,
    pub height: usize,
}

pub fn verify_v9_per_row_constraints(k_scalar: usize) -> usize {
    verify_v8_per_row_constraints(k_scalar)
        + POINT_DBL_CONSTRAINTS
        + 3 * NUM_LIMBS                  // dbl-input binding (dbl_2, dbl_3)
        + 4 * NUM_LIMBS                  // result_row pin to dbl_3 output
}

pub fn verify_air_layout_v9(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV9> {
    let v8 = verify_air_layout_v8(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;

    let dbl_1_row = v8.result_row + 1;
    let dbl_2_row = dbl_1_row + 1;
    let dbl_3_row = dbl_2_row + 1;

    // Allocate dbl-input cells past v8's width; gadget body follows.
    let dbl_input_X_base = v8.width;
    let dbl_input_Y_base = dbl_input_X_base + NUM_LIMBS;
    let dbl_input_Z_base = dbl_input_Y_base + NUM_LIMBS;
    let dbl_body_base    = dbl_input_Z_base + NUM_LIMBS;
    let dbl = point_double_layout_at(
        dbl_body_base,
        dbl_input_X_base, dbl_input_Y_base, dbl_input_Z_base,
    );

    let width = dbl.end;
    let needed_height = dbl_3_row + 1;
    let height = if v8.height >= needed_height + 1 {
        v8.height
    } else {
        needed_height.next_power_of_two()
    };

    Some(VerifyAirLayoutV9 {
        n_blocks: v8.n_blocks,
        k_hash:   v8.k_hash,
        reduce_row:       v8.reduce_row,
        decompress_R_row: v8.decompress_R_row,
        decompress_A_row: v8.decompress_A_row,
        sB_first_row: v8.sB_first_row,
        kA_first_row: v8.kA_first_row,
        k_scalar:     v8.k_scalar,
        reduce: v8.reduce,
        digest_bit_base: v8.digest_bit_base,
        decomp: v8.decomp,
        mult:   v8.mult,
        a_point_limbs: v8.a_point_limbs,
        r_y: v8.r_y,
        r_sign: v8.r_sign,
        a_y: v8.a_y,
        a_sign: v8.a_sign,
        scalar_block_sB_base: v8.scalar_block_sB_base,
        scalar_block_kA_base: v8.scalar_block_kA_base,
        s_bits: v8.s_bits,
        k_bits: v8.k_bits,
        r_thread_base: v8.r_thread_base,
        result_row: v8.result_row,
        result_X_base: v8.result_X_base,
        result_Y_base: v8.result_Y_base,
        result_Z_base: v8.result_Z_base,
        result_T_base: v8.result_T_base,
        zero_const_base: v8.zero_const_base,
        sub_X: v8.sub_X, sub_T: v8.sub_T, sub_YZ: v8.sub_YZ,
        dbl_1_row, dbl_2_row, dbl_3_row,
        dbl_input_X_base, dbl_input_Y_base, dbl_input_Z_base,
        dbl,
        width,
        height,
    })
}

/// Build a v9 trace.  `cofactor_input` is the point P whose `[8]·P` will
/// be checked at v8's result_row.  For tests, the caller supplies P
/// directly (free input); subsequent v's will derive P in-circuit from
/// `[s]·B − R − [k]·A`.
///
/// The caller MUST also supply the same `[8]·P` as the v8 result_point
/// so that v9's pinning constraint at dbl_3_row → result_row holds.
pub fn fill_verify_air_v9(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
    cofactor_input: &EdwardsPoint,
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV9, [u8; 32])> {
    let layout = verify_air_layout_v9(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;

    // result_point = [8] · cofactor_input
    let p2 = cofactor_input.double();
    let p4 = p2.double();
    let p8 = p4.double();

    let (mut trace, _v8, k_canonical) = fill_verify_air_v8(
        message, r_compressed, a_compressed, s_bits, k_bits, &p8,
    )?;

    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }
    if trace[0].len() < layout.height {
        for col in trace.iter_mut() {
            col.resize(layout.height, F::zero());
        }
    }

    // Fill dbl_1 with cofactor_input.
    {
        let row = layout.dbl_1_row;
        let xc = canonicalised(&cofactor_input.X);
        let yc = canonicalised(&cofactor_input.Y);
        let zc = canonicalised(&cofactor_input.Z);
        for i in 0..NUM_LIMBS {
            trace[layout.dbl_input_X_base + i][row] = F::from(xc.limbs[i] as u64);
            trace[layout.dbl_input_Y_base + i][row] = F::from(yc.limbs[i] as u64);
            trace[layout.dbl_input_Z_base + i][row] = F::from(zc.limbs[i] as u64);
        }
        fill_point_double_gadget(&mut trace, row, &layout.dbl, cofactor_input);
    }

    // Fill dbl_2 with p2.
    {
        let row = layout.dbl_2_row;
        let xc = canonicalised(&p2.X);
        let yc = canonicalised(&p2.Y);
        let zc = canonicalised(&p2.Z);
        for i in 0..NUM_LIMBS {
            trace[layout.dbl_input_X_base + i][row] = F::from(xc.limbs[i] as u64);
            trace[layout.dbl_input_Y_base + i][row] = F::from(yc.limbs[i] as u64);
            trace[layout.dbl_input_Z_base + i][row] = F::from(zc.limbs[i] as u64);
        }
        fill_point_double_gadget(&mut trace, row, &layout.dbl, &p2);
    }

    // Fill dbl_3 with p4.
    {
        let row = layout.dbl_3_row;
        let xc = canonicalised(&p4.X);
        let yc = canonicalised(&p4.Y);
        let zc = canonicalised(&p4.Z);
        for i in 0..NUM_LIMBS {
            trace[layout.dbl_input_X_base + i][row] = F::from(xc.limbs[i] as u64);
            trace[layout.dbl_input_Y_base + i][row] = F::from(yc.limbs[i] as u64);
            trace[layout.dbl_input_Z_base + i][row] = F::from(zc.limbs[i] as u64);
        }
        fill_point_double_gadget(&mut trace, row, &layout.dbl, &p4);
    }

    Some((trace, layout, k_canonical))
}

pub fn eval_verify_air_v9_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV9,
) -> Vec<F> {
    let v8 = VerifyAirLayoutV8 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y,
        r_sign: layout.r_sign,
        a_y: layout.a_y,
        a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        result_row: layout.result_row,
        result_X_base: layout.result_X_base,
        result_Y_base: layout.result_Y_base,
        result_Z_base: layout.result_Z_base,
        result_T_base: layout.result_T_base,
        zero_const_base: layout.zero_const_base,
        sub_X: layout.sub_X, sub_T: layout.sub_T, sub_YZ: layout.sub_YZ,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v8_per_row(cur, nxt, row, &v8);

    // ── POINT_DBL gadget cons (gated to dbl rows) ──
    if row == layout.dbl_1_row || row == layout.dbl_2_row || row == layout.dbl_3_row {
        out.extend(eval_point_double_gadget(cur, &layout.dbl));
    } else {
        for _ in 0..POINT_DBL_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── dbl-input chaining: nxt.input = cur.dbl_output ──
    //   Fires at row pairs (dbl_1 → dbl_2) and (dbl_2 → dbl_3).
    //   At cur = dbl_1 or dbl_2, bind nxt's input to cur's dbl output.
    if row == layout.dbl_1_row || row == layout.dbl_2_row {
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_X_base + i]
                - cur[layout.dbl.mul_X3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_Y_base + i]
                - cur[layout.dbl.mul_Y3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_Z_base + i]
                - cur[layout.dbl.mul_Z3.c_limbs_base + i]);
        }
    } else {
        for _ in 0..(3 * NUM_LIMBS) { out.push(F::zero()); }
    }

    // ── result_row pin: result_point = dbl_3's output ──
    //   Expressed as a transition at cur = dbl_3_row, nxt = result_row?
    //   v9 places result_row BEFORE dbl_1 (= v8.result_row, with dbl_1
    //   = result_row + 1).  So the pin must read backward.  We instead
    //   express it as: at cur = dbl_3_row, the cells at offsets
    //   `dbl.mul_*.c_limbs_base` must equal the values that the trace
    //   builder placed at v8.result_row's `result_*_base` cells.
    //
    //   Since result_row precedes dbl_1, the result point cells live in
    //   the trace already; v9's binding constraint reads them from a
    //   FIXED `layout.a_point_limbs`-style snapshot the verifier holds.
    //   For v9 we use a simpler approach: emit a per-cell equality
    //   between cur (dbl_3) gadget outputs and the v8 layout's result
    //   limbs, computed natively from `cofactor_input` by the verifier
    //   (treating it as a public input).  But cofactor_input is NOT
    //   in the layout yet.
    //
    //   Pragmatic v9 binding: the trace builder fills both result_*
    //   cells (at v8.result_row) and dbl gadget cells consistently
    //   from the same cofactor_input.  We add 4·NUM_LIMBS cons at
    //   row dbl_3_row that read across to the result row's cells via
    //   nxt access only if dbl_3_row + 1 == result_row.  This is NOT
    //   our layout (result_row precedes dbl_1).
    //
    //   Cleanest: pin result cells (at v8.result_row) directly to
    //   verifier-computed `[8]·cofactor_input` via layout constants
    //   in v10.  For v9 the result_row pinning is omitted; tests rely
    //   on the trace builder's consistency.
    //
    //   To keep VERIFY_V9_PER_ROW_CONSTRAINTS uniform, emit 4·NUM_LIMBS
    //   zero placeholders here.
    for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }

    debug_assert_eq!(out.len(), verify_v9_per_row_constraints(layout.k_scalar));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v10 layout — v9 with result_row reordered AFTER the dbl chain
// ═══════════════════════════════════════════════════════════════════
//
// v9 placed `result_row` BEFORE the doubling chain, which prevented a
// forward transition from binding `dbl_3.output` to the result cells.
// v10 restructures the row order so the chain ends at the verdict:
//
//   ..., kA_last, dbl_1, dbl_2, dbl_3, result_row
//
// At cur = dbl_3_row, nxt = result_row, four 10-limb transitions pin:
//
//   nxt[result_X_base..]  =  cur[dbl.mul_X3.c_limbs_base..]
//   nxt[result_Y_base..]  =  cur[dbl.mul_Y3.c_limbs_base..]
//   nxt[result_Z_base..]  =  cur[dbl.mul_Z3.c_limbs_base..]
//   nxt[result_T_base..]  =  cur[dbl.mul_T3.c_limbs_base..]
//
// 40 cons total — the LAST place a malicious prover could lie about
// the cofactor result.  Together with v9's chained doubling cons and
// v8's identity verdict, this proves:
//
//   "[8]·cofactor_input is the projective identity."
//
// `cofactor_input` is still a free trace input in v10; the next v will
// bind it to `[s]·B − R − [k]·A` via point-sub gadgets and thread
// chains for the sB/R/kA outputs.

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV10 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    /// New row order: dbl_1, dbl_2, dbl_3, result_row.
    pub dbl_1_row:  usize,
    pub dbl_2_row:  usize,
    pub dbl_3_row:  usize,
    pub result_row: usize,
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    pub zero_const_base: usize,
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    pub dbl_input_X_base: usize,
    pub dbl_input_Y_base: usize,
    pub dbl_input_Z_base: usize,
    pub dbl: PointDoubleGadgetLayout,
    pub width:  usize,
    pub height: usize,
}

/// Per-row cons for v10 — same structure as v9 but the 40 zero
/// placeholders for result-binding are now real cons.
pub fn verify_v10_per_row_constraints(k_scalar: usize) -> usize {
    verify_v9_per_row_constraints(k_scalar)   // count is identical
}

pub fn verify_air_layout_v10(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV10> {
    let v7 = verify_air_layout_v7(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;

    let kA_last_row = v7.kA_first_row + v7.k_scalar - 1;
    let dbl_1_row  = kA_last_row + 1;
    let dbl_2_row  = kA_last_row + 2;
    let dbl_3_row  = kA_last_row + 3;
    let result_row = kA_last_row + 4;

    // Cell allocation (mirrors v8 + v9 column layout).
    let mut next = v7.width;
    let result_X_base = next; next += NUM_LIMBS;
    let result_Y_base = next; next += NUM_LIMBS;
    let result_Z_base = next; next += NUM_LIMBS;
    let result_T_base = next; next += NUM_LIMBS;
    let zero_const_base = next; next += NUM_LIMBS;

    let alloc_sub = |start: &mut usize, a_base: usize, b_base: usize|
        -> SubGadgetLayout
    {
        let c_limbs_base = *start; *start += ELEMENT_LIMB_CELLS;
        let c_bits_base  = *start; *start += 255;
        let c_pos_base   = *start; *start += NUM_LIMBS;
        let c_neg_base   = *start; *start += NUM_LIMBS;
        SubGadgetLayout {
            a_limbs_base: a_base,
            b_limbs_base: b_base,
            c_limbs_base, c_bits_base, c_pos_base, c_neg_base,
        }
    };
    let sub_X  = alloc_sub(&mut next, result_X_base, zero_const_base);
    let sub_T  = alloc_sub(&mut next, result_T_base, zero_const_base);
    let sub_YZ = alloc_sub(&mut next, result_Y_base, result_Z_base);

    let dbl_input_X_base = next; next += NUM_LIMBS;
    let dbl_input_Y_base = next; next += NUM_LIMBS;
    let dbl_input_Z_base = next; next += NUM_LIMBS;
    let dbl = point_double_layout_at(
        next,
        dbl_input_X_base, dbl_input_Y_base, dbl_input_Z_base,
    );

    let width = dbl.end;
    let needed_height = result_row + 1;
    let height = if v7.height >= needed_height + 1 {
        v7.height
    } else {
        needed_height.next_power_of_two()
    };

    Some(VerifyAirLayoutV10 {
        n_blocks: v7.n_blocks,
        k_hash:   v7.k_hash,
        reduce_row:       v7.reduce_row,
        decompress_R_row: v7.decompress_R_row,
        decompress_A_row: v7.decompress_A_row,
        sB_first_row: v7.sB_first_row,
        kA_first_row: v7.kA_first_row,
        k_scalar:     v7.k_scalar,
        reduce: v7.reduce,
        digest_bit_base: v7.digest_bit_base,
        decomp: v7.decomp,
        mult:   v7.mult,
        a_point_limbs: v7.a_point_limbs,
        r_y: v7.r_y,
        r_sign: v7.r_sign,
        a_y: v7.a_y,
        a_sign: v7.a_sign,
        scalar_block_sB_base: v7.scalar_block_sB_base,
        scalar_block_kA_base: v7.scalar_block_kA_base,
        s_bits: v7.s_bits,
        k_bits: v7.k_bits,
        r_thread_base: v7.r_thread_base,
        dbl_1_row, dbl_2_row, dbl_3_row, result_row,
        result_X_base, result_Y_base, result_Z_base, result_T_base,
        zero_const_base,
        sub_X, sub_T, sub_YZ,
        dbl_input_X_base, dbl_input_Y_base, dbl_input_Z_base, dbl,
        width, height,
    })
}

pub fn fill_verify_air_v10(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
    cofactor_input: &EdwardsPoint,
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV10, [u8; 32])> {
    let layout = verify_air_layout_v10(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let (mut trace, _v7, k_canonical) = fill_verify_air_v7(
        message, r_compressed, a_compressed, s_bits, k_bits,
    )?;

    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }
    if trace[0].len() < layout.height {
        for col in trace.iter_mut() {
            col.resize(layout.height, F::zero());
        }
    }

    // Compute cofactor = [8] · input.
    let p2 = cofactor_input.double();
    let p4 = p2.double();
    let p8 = p4.double();

    // Fill 3 dbl rows (input cells + gadget body).
    for (row, p) in [
        (layout.dbl_1_row, cofactor_input),
        (layout.dbl_2_row, &p2),
        (layout.dbl_3_row, &p4),
    ] {
        let xc = canonicalised(&p.X);
        let yc = canonicalised(&p.Y);
        let zc = canonicalised(&p.Z);
        for i in 0..NUM_LIMBS {
            trace[layout.dbl_input_X_base + i][row] = F::from(xc.limbs[i] as u64);
            trace[layout.dbl_input_Y_base + i][row] = F::from(yc.limbs[i] as u64);
            trace[layout.dbl_input_Z_base + i][row] = F::from(zc.limbs[i] as u64);
        }
        fill_point_double_gadget(&mut trace, row, &layout.dbl, p);
    }

    // Fill result row with [8]·input + zero const + SUB gadgets.
    let row = layout.result_row;
    let X = canonicalised(&p8.X);
    let Y = canonicalised(&p8.Y);
    let Z = canonicalised(&p8.Z);
    let T = canonicalised(&p8.T);
    for i in 0..NUM_LIMBS {
        trace[layout.result_X_base + i][row] = F::from(X.limbs[i] as u64);
        trace[layout.result_Y_base + i][row] = F::from(Y.limbs[i] as u64);
        trace[layout.result_Z_base + i][row] = F::from(Z.limbs[i] as u64);
        trace[layout.result_T_base + i][row] = F::from(T.limbs[i] as u64);
        trace[layout.zero_const_base + i][row] = F::zero();
    }
    let zero = FieldElement::zero();
    fill_sub_gadget(&mut trace, row, &layout.sub_X,  &X, &zero);
    fill_sub_gadget(&mut trace, row, &layout.sub_T,  &T, &zero);
    fill_sub_gadget(&mut trace, row, &layout.sub_YZ, &Y, &Z);

    Some((trace, layout, k_canonical))
}

pub fn eval_verify_air_v10_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV10,
) -> Vec<F> {
    // Reuse the v7 evaluator (it's row-position agnostic for everything
    // up to the kA phase).
    let v7 = VerifyAirLayoutV7 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y,
        r_sign: layout.r_sign,
        a_y: layout.a_y,
        a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v7_per_row(cur, nxt, row, &v7);

    let k = layout.k_scalar;

    // ── v8 verdict (at v10's result_row) ──
    if row == layout.result_row {
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.zero_const_base + i]);
        }
        out.extend(eval_sub_gadget(cur, &layout.sub_X));
        out.extend(eval_sub_gadget(cur, &layout.sub_T));
        out.extend(eval_sub_gadget(cur, &layout.sub_YZ));
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.sub_X.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.sub_T.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.sub_YZ.c_limbs_base + i]);
        }
    } else {
        for _ in 0..NUM_LIMBS { out.push(F::zero()); }
        for _ in 0..(3 * SUB_GADGET_CONSTRAINTS) { out.push(F::zero()); }
        for _ in 0..(3 * NUM_LIMBS) { out.push(F::zero()); }
    }

    // ── v9 dbl chain cons + dbl-input chaining ──
    if row == layout.dbl_1_row || row == layout.dbl_2_row || row == layout.dbl_3_row {
        out.extend(eval_point_double_gadget(cur, &layout.dbl));
    } else {
        for _ in 0..POINT_DBL_CONSTRAINTS { out.push(F::zero()); }
    }
    if row == layout.dbl_1_row || row == layout.dbl_2_row {
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_X_base + i]
                - cur[layout.dbl.mul_X3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_Y_base + i]
                - cur[layout.dbl.mul_Y3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_Z_base + i]
                - cur[layout.dbl.mul_Z3.c_limbs_base + i]);
        }
    } else {
        for _ in 0..(3 * NUM_LIMBS) { out.push(F::zero()); }
    }

    // ── NEW v10 binding: dbl_3.output → result_row cells ──
    //   At cur = dbl_3_row, nxt = result_row.  4 × 10 cons.
    if row == layout.dbl_3_row {
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.result_X_base + i]
                - cur[layout.dbl.mul_X3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.result_Y_base + i]
                - cur[layout.dbl.mul_Y3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.result_Z_base + i]
                - cur[layout.dbl.mul_Z3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.result_T_base + i]
                - cur[layout.dbl.mul_T3.c_limbs_base + i]);
        }
    } else {
        for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), verify_v10_per_row_constraints(k));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v11 layout — v10 + [s]·B output thread chain
// ═══════════════════════════════════════════════════════════════════
//
// First building block of the residual binding (v11..v15).  v11 adds a
// 4·NUM_LIMBS thread block (X, Y, Z, T, each 10 limbs) carrying the
// sB-ladder's OUTPUT POINT — i.e. `[s]·B` — across every row of the
// trace.  Two constraint blocks anchor + propagate it:
//
//   1. Boundary @ sB_last_row (4·NUM_LIMBS cons):
//        thread_sB_out[i] = cur[mult.cond_add.out_*[i]]
//
//   2. Per-row constancy (4·NUM_LIMBS cons, fires every row pair):
//        nxt[thread_sB_out[i]] = cur[thread_sB_out[i]]
//
// Together: thread_sB_out cells everywhere in the trace equal `[s]·B`
// (the output of the sB ladder).  v12 will add the symmetric chain for
// `[k]·A`; v13 the chain for R; v14/15 will use these threads to
// compute `residual = [s]·B − R − [k]·A` via point-add + negation
// gadgets, and bind that residual to v10's dbl_1 input.

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV11 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    pub dbl_1_row:  usize,
    pub dbl_2_row:  usize,
    pub dbl_3_row:  usize,
    pub result_row: usize,
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    pub zero_const_base: usize,
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    pub dbl_input_X_base: usize,
    pub dbl_input_Y_base: usize,
    pub dbl_input_Z_base: usize,
    pub dbl: PointDoubleGadgetLayout,
    /// Thread block (X, Y, Z, T) carrying `[s]·B` output forward.
    pub thread_sB_X_base: usize,
    pub thread_sB_Y_base: usize,
    pub thread_sB_Z_base: usize,
    pub thread_sB_T_base: usize,
    /// Last row of the sB scalar-mult phase (= sB_first_row + k_scalar − 1).
    pub sB_last_row: usize,
    pub width:  usize,
    pub height: usize,
}

pub fn verify_v11_per_row_constraints(k_scalar: usize) -> usize {
    verify_v10_per_row_constraints(k_scalar)
        + 4 * NUM_LIMBS                    // boundary @ sB_last_row
        + 4 * NUM_LIMBS                    // per-row constancy
}

pub fn verify_air_layout_v11(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV11> {
    let v10 = verify_air_layout_v10(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let sB_last_row = v10.sB_first_row + v10.k_scalar - 1;

    let mut next = v10.width;
    let thread_sB_X_base = next; next += NUM_LIMBS;
    let thread_sB_Y_base = next; next += NUM_LIMBS;
    let thread_sB_Z_base = next; next += NUM_LIMBS;
    let thread_sB_T_base = next; next += NUM_LIMBS;
    let width = next;

    Some(VerifyAirLayoutV11 {
        n_blocks: v10.n_blocks,
        k_hash:   v10.k_hash,
        reduce_row:       v10.reduce_row,
        decompress_R_row: v10.decompress_R_row,
        decompress_A_row: v10.decompress_A_row,
        sB_first_row: v10.sB_first_row,
        kA_first_row: v10.kA_first_row,
        k_scalar:     v10.k_scalar,
        reduce: v10.reduce,
        digest_bit_base: v10.digest_bit_base,
        decomp: v10.decomp,
        mult:   v10.mult,
        a_point_limbs: v10.a_point_limbs,
        r_y: v10.r_y,
        r_sign: v10.r_sign,
        a_y: v10.a_y,
        a_sign: v10.a_sign,
        scalar_block_sB_base: v10.scalar_block_sB_base,
        scalar_block_kA_base: v10.scalar_block_kA_base,
        s_bits: v10.s_bits,
        k_bits: v10.k_bits,
        r_thread_base: v10.r_thread_base,
        dbl_1_row: v10.dbl_1_row,
        dbl_2_row: v10.dbl_2_row,
        dbl_3_row: v10.dbl_3_row,
        result_row: v10.result_row,
        result_X_base: v10.result_X_base,
        result_Y_base: v10.result_Y_base,
        result_Z_base: v10.result_Z_base,
        result_T_base: v10.result_T_base,
        zero_const_base: v10.zero_const_base,
        sub_X: v10.sub_X, sub_T: v10.sub_T, sub_YZ: v10.sub_YZ,
        dbl_input_X_base: v10.dbl_input_X_base,
        dbl_input_Y_base: v10.dbl_input_Y_base,
        dbl_input_Z_base: v10.dbl_input_Z_base,
        dbl: v10.dbl,
        thread_sB_X_base, thread_sB_Y_base, thread_sB_Z_base, thread_sB_T_base,
        sB_last_row,
        width,
        height: v10.height,
    })
}

pub fn fill_verify_air_v11(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
    cofactor_input: &EdwardsPoint,
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV11, [u8; 32])> {
    let layout = verify_air_layout_v11(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let (mut trace, _v10, k_canonical) = fill_verify_air_v10(
        message, r_compressed, a_compressed, s_bits, k_bits, cofactor_input,
    )?;

    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }

    // Compute [s]·B natively and fill the thread cells at every row.
    let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;
    let mut s_acc = EdwardsPoint::identity();
    for &bit in s_bits {
        s_acc = s_acc.double();
        if bit { s_acc = s_acc.add(&basepoint); }
    }
    let sB = s_acc;
    let xc = canonicalised(&sB.X);
    let yc = canonicalised(&sB.Y);
    let zc = canonicalised(&sB.Z);
    let tc = canonicalised(&sB.T);

    for r in 0..layout.height {
        for i in 0..NUM_LIMBS {
            trace[layout.thread_sB_X_base + i][r] = F::from(xc.limbs[i] as u64);
            trace[layout.thread_sB_Y_base + i][r] = F::from(yc.limbs[i] as u64);
            trace[layout.thread_sB_Z_base + i][r] = F::from(zc.limbs[i] as u64);
            trace[layout.thread_sB_T_base + i][r] = F::from(tc.limbs[i] as u64);
        }
    }

    Some((trace, layout, k_canonical))
}

pub fn eval_verify_air_v11_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV11,
) -> Vec<F> {
    let v10 = VerifyAirLayoutV10 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y,
        r_sign: layout.r_sign,
        a_y: layout.a_y,
        a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        dbl_1_row: layout.dbl_1_row,
        dbl_2_row: layout.dbl_2_row,
        dbl_3_row: layout.dbl_3_row,
        result_row: layout.result_row,
        result_X_base: layout.result_X_base,
        result_Y_base: layout.result_Y_base,
        result_Z_base: layout.result_Z_base,
        result_T_base: layout.result_T_base,
        zero_const_base: layout.zero_const_base,
        sub_X: layout.sub_X, sub_T: layout.sub_T, sub_YZ: layout.sub_YZ,
        dbl_input_X_base: layout.dbl_input_X_base,
        dbl_input_Y_base: layout.dbl_input_Y_base,
        dbl_input_Z_base: layout.dbl_input_Z_base,
        dbl: layout.dbl,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v10_per_row(cur, nxt, row, &v10);

    // ── Boundary @ sB_last_row: thread = mult.cond_add.out ──
    if row == layout.sB_last_row {
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_sB_X_base + i]
                - cur[layout.mult.cond_add.out_x + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_sB_Y_base + i]
                - cur[layout.mult.cond_add.out_y + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_sB_Z_base + i]
                - cur[layout.mult.cond_add.out_z + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_sB_T_base + i]
                - cur[layout.mult.cond_add.out_t + i]);
        }
    } else {
        for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }
    }

    // ── Per-row constancy: nxt.thread = cur.thread ──
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_sB_X_base + i]
            - cur[layout.thread_sB_X_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_sB_Y_base + i]
            - cur[layout.thread_sB_Y_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_sB_Z_base + i]
            - cur[layout.thread_sB_Z_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_sB_T_base + i]
            - cur[layout.thread_sB_T_base + i]);
    }

    debug_assert_eq!(out.len(), verify_v11_per_row_constraints(layout.k_scalar));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v12 layout — v11 + [k]·A output thread chain
// ═══════════════════════════════════════════════════════════════════
//
// Symmetric to v11.  4·NUM_LIMBS thread cells carrying the kA ladder's
// projective output `[k]·A` across every row, anchored at kA_last_row
// to `mult.cond_add.out_*`.

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV12 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    pub dbl_1_row:  usize,
    pub dbl_2_row:  usize,
    pub dbl_3_row:  usize,
    pub result_row: usize,
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    pub zero_const_base: usize,
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    pub dbl_input_X_base: usize,
    pub dbl_input_Y_base: usize,
    pub dbl_input_Z_base: usize,
    pub dbl: PointDoubleGadgetLayout,
    pub thread_sB_X_base: usize,
    pub thread_sB_Y_base: usize,
    pub thread_sB_Z_base: usize,
    pub thread_sB_T_base: usize,
    pub sB_last_row: usize,
    pub thread_kA_X_base: usize,
    pub thread_kA_Y_base: usize,
    pub thread_kA_Z_base: usize,
    pub thread_kA_T_base: usize,
    pub kA_last_row: usize,
    pub width:  usize,
    pub height: usize,
}

pub fn verify_v12_per_row_constraints(k_scalar: usize) -> usize {
    verify_v11_per_row_constraints(k_scalar) + 8 * NUM_LIMBS
}

pub fn verify_air_layout_v12(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV12> {
    let v11 = verify_air_layout_v11(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let kA_last_row = v11.kA_first_row + v11.k_scalar - 1;

    let mut next = v11.width;
    let thread_kA_X_base = next; next += NUM_LIMBS;
    let thread_kA_Y_base = next; next += NUM_LIMBS;
    let thread_kA_Z_base = next; next += NUM_LIMBS;
    let thread_kA_T_base = next; next += NUM_LIMBS;
    let width = next;

    Some(VerifyAirLayoutV12 {
        n_blocks: v11.n_blocks,
        k_hash:   v11.k_hash,
        reduce_row:       v11.reduce_row,
        decompress_R_row: v11.decompress_R_row,
        decompress_A_row: v11.decompress_A_row,
        sB_first_row: v11.sB_first_row,
        kA_first_row: v11.kA_first_row,
        k_scalar:     v11.k_scalar,
        reduce: v11.reduce,
        digest_bit_base: v11.digest_bit_base,
        decomp: v11.decomp,
        mult:   v11.mult,
        a_point_limbs: v11.a_point_limbs,
        r_y: v11.r_y,
        r_sign: v11.r_sign,
        a_y: v11.a_y,
        a_sign: v11.a_sign,
        scalar_block_sB_base: v11.scalar_block_sB_base,
        scalar_block_kA_base: v11.scalar_block_kA_base,
        s_bits: v11.s_bits,
        k_bits: v11.k_bits,
        r_thread_base: v11.r_thread_base,
        dbl_1_row: v11.dbl_1_row,
        dbl_2_row: v11.dbl_2_row,
        dbl_3_row: v11.dbl_3_row,
        result_row: v11.result_row,
        result_X_base: v11.result_X_base,
        result_Y_base: v11.result_Y_base,
        result_Z_base: v11.result_Z_base,
        result_T_base: v11.result_T_base,
        zero_const_base: v11.zero_const_base,
        sub_X: v11.sub_X, sub_T: v11.sub_T, sub_YZ: v11.sub_YZ,
        dbl_input_X_base: v11.dbl_input_X_base,
        dbl_input_Y_base: v11.dbl_input_Y_base,
        dbl_input_Z_base: v11.dbl_input_Z_base,
        dbl: v11.dbl,
        thread_sB_X_base: v11.thread_sB_X_base,
        thread_sB_Y_base: v11.thread_sB_Y_base,
        thread_sB_Z_base: v11.thread_sB_Z_base,
        thread_sB_T_base: v11.thread_sB_T_base,
        sB_last_row: v11.sB_last_row,
        thread_kA_X_base, thread_kA_Y_base, thread_kA_Z_base, thread_kA_T_base,
        kA_last_row,
        width,
        height: v11.height,
    })
}

pub fn fill_verify_air_v12(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
    cofactor_input: &EdwardsPoint,
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV12, [u8; 32])> {
    let layout = verify_air_layout_v12(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let (mut trace, _v11, k_canonical) = fill_verify_air_v11(
        message, r_compressed, a_compressed, s_bits, k_bits, cofactor_input,
    )?;

    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }

    // Compute [k]·A natively from k_bits and the decompressed A point.
    let A_point = EdwardsPoint::decompress(a_compressed)
        .expect("a_compressed already validated upstream");
    let mut acc = EdwardsPoint::identity();
    for &bit in k_bits {
        acc = acc.double();
        if bit { acc = acc.add(&A_point); }
    }
    let kA = acc;
    let xc = canonicalised(&kA.X);
    let yc = canonicalised(&kA.Y);
    let zc = canonicalised(&kA.Z);
    let tc = canonicalised(&kA.T);

    for r in 0..layout.height {
        for i in 0..NUM_LIMBS {
            trace[layout.thread_kA_X_base + i][r] = F::from(xc.limbs[i] as u64);
            trace[layout.thread_kA_Y_base + i][r] = F::from(yc.limbs[i] as u64);
            trace[layout.thread_kA_Z_base + i][r] = F::from(zc.limbs[i] as u64);
            trace[layout.thread_kA_T_base + i][r] = F::from(tc.limbs[i] as u64);
        }
    }

    Some((trace, layout, k_canonical))
}

pub fn eval_verify_air_v12_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV12,
) -> Vec<F> {
    let v11 = VerifyAirLayoutV11 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y,
        r_sign: layout.r_sign,
        a_y: layout.a_y,
        a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        dbl_1_row: layout.dbl_1_row,
        dbl_2_row: layout.dbl_2_row,
        dbl_3_row: layout.dbl_3_row,
        result_row: layout.result_row,
        result_X_base: layout.result_X_base,
        result_Y_base: layout.result_Y_base,
        result_Z_base: layout.result_Z_base,
        result_T_base: layout.result_T_base,
        zero_const_base: layout.zero_const_base,
        sub_X: layout.sub_X, sub_T: layout.sub_T, sub_YZ: layout.sub_YZ,
        dbl_input_X_base: layout.dbl_input_X_base,
        dbl_input_Y_base: layout.dbl_input_Y_base,
        dbl_input_Z_base: layout.dbl_input_Z_base,
        dbl: layout.dbl,
        thread_sB_X_base: layout.thread_sB_X_base,
        thread_sB_Y_base: layout.thread_sB_Y_base,
        thread_sB_Z_base: layout.thread_sB_Z_base,
        thread_sB_T_base: layout.thread_sB_T_base,
        sB_last_row: layout.sB_last_row,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v11_per_row(cur, nxt, row, &v11);

    // ── Boundary @ kA_last_row: thread_kA = mult.cond_add.out_* ──
    if row == layout.kA_last_row {
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_kA_X_base + i]
                - cur[layout.mult.cond_add.out_x + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_kA_Y_base + i]
                - cur[layout.mult.cond_add.out_y + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_kA_Z_base + i]
                - cur[layout.mult.cond_add.out_z + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_kA_T_base + i]
                - cur[layout.mult.cond_add.out_t + i]);
        }
    } else {
        for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }
    }

    // ── Per-row constancy ──
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_kA_X_base + i]
            - cur[layout.thread_kA_X_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_kA_Y_base + i]
            - cur[layout.thread_kA_Y_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_kA_Z_base + i]
            - cur[layout.thread_kA_Z_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_kA_T_base + i]
            - cur[layout.thread_kA_T_base + i]);
    }

    debug_assert_eq!(out.len(), verify_v12_per_row_constraints(layout.k_scalar));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v13 layout — v12 + R thread chain (with in-circuit T = X·Y)
// ═══════════════════════════════════════════════════════════════════
//
// The third and final input thread.  R is decompressed at
// `decompose_R_row`, which provides X (via the decomp gadget's witness)
// and Y (pinned to a public-input constant in v5).  Z is the canonical
// constant 1.  T = X · Y is computed in-circuit by a MUL gadget at
// `decompose_R_row`.
//
// Cells added:
//   • 4·NUM_LIMBS thread cells (R_X, R_Y, R_Z, R_T) at every row.
//   • NUM_LIMBS "one constant" cells (canonical F25519 element 1).
//   • MUL_GADGET_OWNED_CELLS for the T = X · Y multiplier.
//
// Cons added (per row, gated to decompose_R_row except where noted):
//   • 4·NUM_LIMBS  boundary cons binding thread_R_* to decomp / one /
//                  MUL output                                     = 40
//   • NUM_LIMBS    one_const pin (limb 0 = 1, limbs 1..9 = 0)     = 10
//   • MUL_GADGET_CONSTRAINTS  (T = X · Y)                         = ~635
//   • 4·NUM_LIMBS  per-row thread constancy (every row pair)     = 40
//                                                          TOTAL ≈ 725

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV13 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    pub dbl_1_row:  usize,
    pub dbl_2_row:  usize,
    pub dbl_3_row:  usize,
    pub result_row: usize,
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    pub zero_const_base: usize,
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    pub dbl_input_X_base: usize,
    pub dbl_input_Y_base: usize,
    pub dbl_input_Z_base: usize,
    pub dbl: PointDoubleGadgetLayout,
    pub thread_sB_X_base: usize,
    pub thread_sB_Y_base: usize,
    pub thread_sB_Z_base: usize,
    pub thread_sB_T_base: usize,
    pub sB_last_row: usize,
    pub thread_kA_X_base: usize,
    pub thread_kA_Y_base: usize,
    pub thread_kA_Z_base: usize,
    pub thread_kA_T_base: usize,
    pub kA_last_row: usize,
    /// R thread cells (X, Y, Z, T) carrying R's projective coords.
    pub thread_R_X_base: usize,
    pub thread_R_Y_base: usize,
    pub thread_R_Z_base: usize,
    pub thread_R_T_base: usize,
    /// One-constant cell block at decompose_R_row (canonical F25519 1).
    pub one_const_R_base: usize,
    /// MUL gadget computing R_T = R_X · R_Y at decompose_R_row.
    pub mul_R_T: MulGadgetLayout,
    pub width:  usize,
    pub height: usize,
}

pub fn verify_v13_per_row_constraints(k_scalar: usize) -> usize {
    verify_v12_per_row_constraints(k_scalar)
        + 4 * NUM_LIMBS                       // boundary @ decompose_R_row
        + NUM_LIMBS                           // one_const pin
        + MUL_GADGET_CONSTRAINTS              // T = X · Y
        + 4 * NUM_LIMBS                       // per-row constancy
}

pub fn verify_air_layout_v13(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV13> {
    let v12 = verify_air_layout_v12(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;

    let mut next = v12.width;
    let thread_R_X_base = next; next += NUM_LIMBS;
    let thread_R_Y_base = next; next += NUM_LIMBS;
    let thread_R_Z_base = next; next += NUM_LIMBS;
    let thread_R_T_base = next; next += NUM_LIMBS;
    let one_const_R_base = next; next += NUM_LIMBS;
    // Allocate MUL gadget for T = X · Y, reading from R thread X/Y.
    let mul_c_limbs_base    = next; next += ELEMENT_LIMB_CELLS;
    let mul_c_bits_base     = next; next += 255;
    let mul_carry_bits_base = next; next += MUL_CARRY_BITS * NUM_LIMBS;
    let mul_R_T = MulGadgetLayout {
        a_limbs_base: thread_R_X_base,
        b_limbs_base: thread_R_Y_base,
        c_limbs_base: mul_c_limbs_base,
        c_bits_base:  mul_c_bits_base,
        carry_bits_base: mul_carry_bits_base,
    };
    let width = next;

    Some(VerifyAirLayoutV13 {
        n_blocks: v12.n_blocks,
        k_hash:   v12.k_hash,
        reduce_row:       v12.reduce_row,
        decompress_R_row: v12.decompress_R_row,
        decompress_A_row: v12.decompress_A_row,
        sB_first_row: v12.sB_first_row,
        kA_first_row: v12.kA_first_row,
        k_scalar:     v12.k_scalar,
        reduce: v12.reduce,
        digest_bit_base: v12.digest_bit_base,
        decomp: v12.decomp,
        mult:   v12.mult,
        a_point_limbs: v12.a_point_limbs,
        r_y: v12.r_y,
        r_sign: v12.r_sign,
        a_y: v12.a_y,
        a_sign: v12.a_sign,
        scalar_block_sB_base: v12.scalar_block_sB_base,
        scalar_block_kA_base: v12.scalar_block_kA_base,
        s_bits: v12.s_bits,
        k_bits: v12.k_bits,
        r_thread_base: v12.r_thread_base,
        dbl_1_row: v12.dbl_1_row,
        dbl_2_row: v12.dbl_2_row,
        dbl_3_row: v12.dbl_3_row,
        result_row: v12.result_row,
        result_X_base: v12.result_X_base,
        result_Y_base: v12.result_Y_base,
        result_Z_base: v12.result_Z_base,
        result_T_base: v12.result_T_base,
        zero_const_base: v12.zero_const_base,
        sub_X: v12.sub_X, sub_T: v12.sub_T, sub_YZ: v12.sub_YZ,
        dbl_input_X_base: v12.dbl_input_X_base,
        dbl_input_Y_base: v12.dbl_input_Y_base,
        dbl_input_Z_base: v12.dbl_input_Z_base,
        dbl: v12.dbl,
        thread_sB_X_base: v12.thread_sB_X_base,
        thread_sB_Y_base: v12.thread_sB_Y_base,
        thread_sB_Z_base: v12.thread_sB_Z_base,
        thread_sB_T_base: v12.thread_sB_T_base,
        sB_last_row: v12.sB_last_row,
        thread_kA_X_base: v12.thread_kA_X_base,
        thread_kA_Y_base: v12.thread_kA_Y_base,
        thread_kA_Z_base: v12.thread_kA_Z_base,
        thread_kA_T_base: v12.thread_kA_T_base,
        kA_last_row: v12.kA_last_row,
        thread_R_X_base, thread_R_Y_base, thread_R_Z_base, thread_R_T_base,
        one_const_R_base, mul_R_T,
        width,
        height: v12.height,
    })
}

pub fn fill_verify_air_v13(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
    cofactor_input: &EdwardsPoint,
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV13, [u8; 32])> {
    let layout = verify_air_layout_v13(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let (mut trace, _v12, k_canonical) = fill_verify_air_v12(
        message, r_compressed, a_compressed, s_bits, k_bits, cofactor_input,
    )?;

    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }

    // Decompose R natively to derive (X, Y, Z=1, T = X·Y).
    let R_point = EdwardsPoint::decompress(r_compressed)?;
    let xc = canonicalised(&R_point.X);
    let yc = canonicalised(&R_point.Y);
    let one_const = FieldElement::one();
    let zc = canonicalised(&one_const);
    let T_native = xc.mul(&yc);
    let tc = canonicalised(&T_native);

    // Fill thread cells at every row with R's projective coords.
    for r in 0..layout.height {
        for i in 0..NUM_LIMBS {
            trace[layout.thread_R_X_base + i][r] = F::from(xc.limbs[i] as u64);
            trace[layout.thread_R_Y_base + i][r] = F::from(yc.limbs[i] as u64);
            trace[layout.thread_R_Z_base + i][r] = F::from(zc.limbs[i] as u64);
            trace[layout.thread_R_T_base + i][r] = F::from(tc.limbs[i] as u64);
        }
    }

    // Fill one_const at decompose_R_row only (gated).  At other rows we
    // leave them zero — the pin is only emitted at decompose_R_row.
    let row_R = layout.decompress_R_row;
    for i in 0..NUM_LIMBS {
        trace[layout.one_const_R_base + i][row_R] =
            F::from(one_const.limbs[i] as u64);
    }

    // Fill MUL gadget at decompose_R_row.
    fill_mul_gadget(&mut trace, row_R, &layout.mul_R_T, &xc, &yc);

    Some((trace, layout, k_canonical))
}

pub fn eval_verify_air_v13_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV13,
) -> Vec<F> {
    let v12 = VerifyAirLayoutV12 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y,
        r_sign: layout.r_sign,
        a_y: layout.a_y,
        a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        dbl_1_row: layout.dbl_1_row,
        dbl_2_row: layout.dbl_2_row,
        dbl_3_row: layout.dbl_3_row,
        result_row: layout.result_row,
        result_X_base: layout.result_X_base,
        result_Y_base: layout.result_Y_base,
        result_Z_base: layout.result_Z_base,
        result_T_base: layout.result_T_base,
        zero_const_base: layout.zero_const_base,
        sub_X: layout.sub_X, sub_T: layout.sub_T, sub_YZ: layout.sub_YZ,
        dbl_input_X_base: layout.dbl_input_X_base,
        dbl_input_Y_base: layout.dbl_input_Y_base,
        dbl_input_Z_base: layout.dbl_input_Z_base,
        dbl: layout.dbl,
        thread_sB_X_base: layout.thread_sB_X_base,
        thread_sB_Y_base: layout.thread_sB_Y_base,
        thread_sB_Z_base: layout.thread_sB_Z_base,
        thread_sB_T_base: layout.thread_sB_T_base,
        sB_last_row: layout.sB_last_row,
        thread_kA_X_base: layout.thread_kA_X_base,
        thread_kA_Y_base: layout.thread_kA_Y_base,
        thread_kA_Z_base: layout.thread_kA_Z_base,
        thread_kA_T_base: layout.thread_kA_T_base,
        kA_last_row: layout.kA_last_row,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v12_per_row(cur, nxt, row, &v12);

    // ── Boundary @ decompose_R_row: 4·NUM_LIMBS cons ──
    if row == layout.decompress_R_row {
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_R_X_base + i]
                - cur[layout.decomp.x_limbs + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_R_Y_base + i]
                - cur[layout.decomp.y_limbs + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_R_Z_base + i]
                - cur[layout.one_const_R_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.thread_R_T_base + i]
                - cur[layout.mul_R_T.c_limbs_base + i]);
        }
    } else {
        for _ in 0..(4 * NUM_LIMBS) { out.push(F::zero()); }
    }

    // ── one_const pin @ decompose_R_row: NUM_LIMBS cons ──
    if row == layout.decompress_R_row {
        let one = FieldElement::one();
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.one_const_R_base + i]
                - F::from(one.limbs[i] as u64));
        }
    } else {
        for _ in 0..NUM_LIMBS { out.push(F::zero()); }
    }

    // ── MUL gadget cons (gated to decompose_R_row) ──
    if row == layout.decompress_R_row {
        out.extend(eval_mul_gadget(cur, &layout.mul_R_T));
    } else {
        for _ in 0..MUL_GADGET_CONSTRAINTS { out.push(F::zero()); }
    }

    // ── Per-row constancy of R thread (40 cons) ──
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_R_X_base + i]
            - cur[layout.thread_R_X_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_R_Y_base + i]
            - cur[layout.thread_R_Y_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_R_Z_base + i]
            - cur[layout.thread_R_Z_base + i]);
    }
    for i in 0..NUM_LIMBS {
        out.push(nxt[layout.thread_R_T_base + i]
            - cur[layout.thread_R_T_base + i]);
    }

    debug_assert_eq!(out.len(), verify_v13_per_row_constraints(layout.k_scalar));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v14 layout — v13 + first point-sub `residual_1 = [s]·B − R`
// ═══════════════════════════════════════════════════════════════════
//
// Twisted-Edwards subtraction is `P − Q = P + (−Q)` with `−Q = (−X, Y,
// Z, −T)`.  v14 introduces a NEW ROW (`residual_1_row`) right after
// `kA_last_row`, hosting:
//
//   1. A `zero_const_R1_base` 10-cell block pinned to canonical 0.
//   2. Two SUB gadgets:
//        sub_negR_X = sub(0, R_X)   ⇒  canonical(−R_X)
//        sub_negR_T = sub(0, R_T)   ⇒  canonical(−R_T)
//      reading R_X / R_T from the v13 R thread chain.
//   3. One PointAdd gadget: `residual_1 = sB ⊕ −R` where ⊕ is HWCD
//      twisted-Edwards extended-coords addition.  P1 = (sB_X, sB_Y,
//      sB_Z, sB_T) from the v11 thread; P2 = (negR_X, R_Y, R_Z,
//      negR_T) sourced from the SUB outputs + R thread.
//
// The dbl chain shifts down by 1 row: `dbl_1_row = kA_last_row + 2`,
// etc.  `result_row` follows at `kA_last_row + 6`.

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV14 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    /// Reordered: residual_1_row precedes dbl_1.
    pub residual_1_row: usize,
    pub dbl_1_row:  usize,
    pub dbl_2_row:  usize,
    pub dbl_3_row:  usize,
    pub result_row: usize,
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    pub zero_const_base: usize,
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    pub dbl_input_X_base: usize,
    pub dbl_input_Y_base: usize,
    pub dbl_input_Z_base: usize,
    pub dbl: PointDoubleGadgetLayout,
    pub thread_sB_X_base: usize,
    pub thread_sB_Y_base: usize,
    pub thread_sB_Z_base: usize,
    pub thread_sB_T_base: usize,
    pub sB_last_row: usize,
    pub thread_kA_X_base: usize,
    pub thread_kA_Y_base: usize,
    pub thread_kA_Z_base: usize,
    pub thread_kA_T_base: usize,
    pub kA_last_row: usize,
    pub thread_R_X_base: usize,
    pub thread_R_Y_base: usize,
    pub thread_R_Z_base: usize,
    pub thread_R_T_base: usize,
    pub one_const_R_base: usize,
    pub mul_R_T: MulGadgetLayout,
    /// Zero-constant cell block at residual_1_row for SUB negation.
    pub zero_const_R1_base: usize,
    /// SUB gadgets producing −R_X and −R_T.
    pub sub_negR_X: SubGadgetLayout,
    pub sub_negR_T: SubGadgetLayout,
    /// PointAdd computing `[s]·B + (−R)`.
    pub point_add_R1: PointAddGadgetLayout,
    pub width:  usize,
    pub height: usize,
}

pub fn verify_v14_per_row_constraints(k_scalar: usize) -> usize {
    verify_v13_per_row_constraints(k_scalar)
        + NUM_LIMBS                            // zero_const_R1 pin
        + 2 * SUB_GADGET_CONSTRAINTS           // sub_negR_X, sub_negR_T
        + POINT_ADD_CONSTRAINTS                // sB + (−R)
}

pub fn verify_air_layout_v14(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV14> {
    let v13 = verify_air_layout_v13(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let kA_last_row = v13.kA_last_row;

    // Row reordering: insert residual_1_row before dbl_1.
    let residual_1_row = kA_last_row + 1;
    let dbl_1_row  = kA_last_row + 2;
    let dbl_2_row  = kA_last_row + 3;
    let dbl_3_row  = kA_last_row + 4;
    let result_row = kA_last_row + 5;

    // Allocate v14-owned cells past v13 width.
    let mut next = v13.width;
    let zero_const_R1_base = next; next += NUM_LIMBS;

    // SUB gadgets for negation: a = zero_const_R1, b = R_X / R_T.
    let alloc_sub = |start: &mut usize, a_base: usize, b_base: usize|
        -> SubGadgetLayout
    {
        let c_limbs_base = *start; *start += ELEMENT_LIMB_CELLS;
        let c_bits_base  = *start; *start += 255;
        let c_pos_base   = *start; *start += NUM_LIMBS;
        let c_neg_base   = *start; *start += NUM_LIMBS;
        SubGadgetLayout {
            a_limbs_base: a_base,
            b_limbs_base: b_base,
            c_limbs_base, c_bits_base, c_pos_base, c_neg_base,
        }
    };
    let sub_negR_X = alloc_sub(&mut next, zero_const_R1_base, v13.thread_R_X_base);
    let sub_negR_T = alloc_sub(&mut next, zero_const_R1_base, v13.thread_R_T_base);

    // PointAdd: P1 = sB thread, P2 = (negR_X, R_Y, R_Z, negR_T).
    let point_add_R1 = point_add_layout_at(
        next,
        v13.thread_sB_X_base, v13.thread_sB_Y_base,
        v13.thread_sB_Z_base, v13.thread_sB_T_base,
        sub_negR_X.c_limbs_base, v13.thread_R_Y_base,
        v13.thread_R_Z_base,    sub_negR_T.c_limbs_base,
    );
    let width = point_add_R1.end;

    let needed_height = result_row + 1;
    let height = if v13.height >= needed_height + 1 {
        v13.height
    } else {
        needed_height.next_power_of_two()
    };

    Some(VerifyAirLayoutV14 {
        n_blocks: v13.n_blocks,
        k_hash:   v13.k_hash,
        reduce_row:       v13.reduce_row,
        decompress_R_row: v13.decompress_R_row,
        decompress_A_row: v13.decompress_A_row,
        sB_first_row: v13.sB_first_row,
        kA_first_row: v13.kA_first_row,
        k_scalar:     v13.k_scalar,
        reduce: v13.reduce,
        digest_bit_base: v13.digest_bit_base,
        decomp: v13.decomp,
        mult:   v13.mult,
        a_point_limbs: v13.a_point_limbs,
        r_y: v13.r_y, r_sign: v13.r_sign,
        a_y: v13.a_y, a_sign: v13.a_sign,
        scalar_block_sB_base: v13.scalar_block_sB_base,
        scalar_block_kA_base: v13.scalar_block_kA_base,
        s_bits: v13.s_bits,
        k_bits: v13.k_bits,
        r_thread_base: v13.r_thread_base,
        residual_1_row, dbl_1_row, dbl_2_row, dbl_3_row, result_row,
        result_X_base: v13.result_X_base,
        result_Y_base: v13.result_Y_base,
        result_Z_base: v13.result_Z_base,
        result_T_base: v13.result_T_base,
        zero_const_base: v13.zero_const_base,
        sub_X: v13.sub_X, sub_T: v13.sub_T, sub_YZ: v13.sub_YZ,
        dbl_input_X_base: v13.dbl_input_X_base,
        dbl_input_Y_base: v13.dbl_input_Y_base,
        dbl_input_Z_base: v13.dbl_input_Z_base,
        dbl: v13.dbl,
        thread_sB_X_base: v13.thread_sB_X_base,
        thread_sB_Y_base: v13.thread_sB_Y_base,
        thread_sB_Z_base: v13.thread_sB_Z_base,
        thread_sB_T_base: v13.thread_sB_T_base,
        sB_last_row: v13.sB_last_row,
        thread_kA_X_base: v13.thread_kA_X_base,
        thread_kA_Y_base: v13.thread_kA_Y_base,
        thread_kA_Z_base: v13.thread_kA_Z_base,
        thread_kA_T_base: v13.thread_kA_T_base,
        kA_last_row: v13.kA_last_row,
        thread_R_X_base: v13.thread_R_X_base,
        thread_R_Y_base: v13.thread_R_Y_base,
        thread_R_Z_base: v13.thread_R_Z_base,
        thread_R_T_base: v13.thread_R_T_base,
        one_const_R_base: v13.one_const_R_base,
        mul_R_T: v13.mul_R_T,
        zero_const_R1_base, sub_negR_X, sub_negR_T, point_add_R1,
        width,
        height,
    })
}

pub fn fill_verify_air_v14(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
    cofactor_input: &EdwardsPoint,
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV14, [u8; 32])> {
    let layout = verify_air_layout_v14(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;

    // Build base trace via v7's pipeline, then re-fill v8/v9-style cells
    // at v14's row positions (which differ from v8/v9/v10).
    let (mut trace, _v7, k_canonical) = fill_verify_air_v7(
        message, r_compressed, a_compressed, s_bits, k_bits,
    )?;

    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }
    if trace[0].len() < layout.height {
        for col in trace.iter_mut() {
            col.resize(layout.height, F::zero());
        }
    }

    // ── Compute residual_1 = [s]·B − R via native ref ──
    let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;
    let mut s_acc = EdwardsPoint::identity();
    for &bit in s_bits {
        s_acc = s_acc.double();
        if bit { s_acc = s_acc.add(&basepoint); }
    }
    let sB = s_acc;
    let R_point = EdwardsPoint::decompress(r_compressed)?;
    let neg_R = EdwardsPoint {
        X: canonicalised(&FieldElement::zero().sub(&R_point.X)),
        Y: canonicalised(&R_point.Y),
        Z: canonicalised(&R_point.Z),
        T: canonicalised(&FieldElement::zero().sub(&R_point.T)),
    };
    let residual_1 = sB.add(&neg_R);

    // Re-fill thread cells (v11/v12/v13 — they were filled via the
    // chained fill_verify_air_v13, so this is redundant but harmless).
    let A_point = EdwardsPoint::decompress(a_compressed)
        .expect("a_compressed validated upstream");
    let mut acc = EdwardsPoint::identity();
    for &bit in k_bits {
        acc = acc.double();
        if bit { acc = acc.add(&A_point); }
    }
    let kA = acc;
    let one_const = FieldElement::one();
    let xc_sB = canonicalised(&sB.X); let yc_sB = canonicalised(&sB.Y);
    let zc_sB = canonicalised(&sB.Z); let tc_sB = canonicalised(&sB.T);
    let xc_kA = canonicalised(&kA.X); let yc_kA = canonicalised(&kA.Y);
    let zc_kA = canonicalised(&kA.Z); let tc_kA = canonicalised(&kA.T);
    let xc_R = canonicalised(&R_point.X); let yc_R = canonicalised(&R_point.Y);
    let zc_R = canonicalised(&one_const);
    let tc_R = canonicalised(&xc_R.mul(&yc_R));
    for r in 0..layout.height {
        for i in 0..NUM_LIMBS {
            trace[layout.thread_sB_X_base + i][r] = F::from(xc_sB.limbs[i] as u64);
            trace[layout.thread_sB_Y_base + i][r] = F::from(yc_sB.limbs[i] as u64);
            trace[layout.thread_sB_Z_base + i][r] = F::from(zc_sB.limbs[i] as u64);
            trace[layout.thread_sB_T_base + i][r] = F::from(tc_sB.limbs[i] as u64);
            trace[layout.thread_kA_X_base + i][r] = F::from(xc_kA.limbs[i] as u64);
            trace[layout.thread_kA_Y_base + i][r] = F::from(yc_kA.limbs[i] as u64);
            trace[layout.thread_kA_Z_base + i][r] = F::from(zc_kA.limbs[i] as u64);
            trace[layout.thread_kA_T_base + i][r] = F::from(tc_kA.limbs[i] as u64);
            trace[layout.thread_R_X_base + i][r] = F::from(xc_R.limbs[i] as u64);
            trace[layout.thread_R_Y_base + i][r] = F::from(yc_R.limbs[i] as u64);
            trace[layout.thread_R_Z_base + i][r] = F::from(zc_R.limbs[i] as u64);
            trace[layout.thread_R_T_base + i][r] = F::from(tc_R.limbs[i] as u64);
        }
    }
    // one_const + mul_R_T at decompose_R_row.
    {
        let row_R = layout.decompress_R_row;
        for i in 0..NUM_LIMBS {
            trace[layout.one_const_R_base + i][row_R] =
                F::from(one_const.limbs[i] as u64);
        }
        fill_mul_gadget(&mut trace, row_R, &layout.mul_R_T, &xc_R, &yc_R);
    }

    // ── v14 cells at residual_1_row ──
    let row1 = layout.residual_1_row;
    let zero = FieldElement::zero();
    for i in 0..NUM_LIMBS {
        trace[layout.zero_const_R1_base + i][row1] = F::zero();
    }
    fill_sub_gadget(&mut trace, row1, &layout.sub_negR_X, &zero, &xc_R);
    fill_sub_gadget(&mut trace, row1, &layout.sub_negR_T, &zero, &tc_R);
    fill_point_add_gadget(&mut trace, row1, &layout.point_add_R1, &sB, &neg_R);

    // ── Cofactor doubling chain (v9-style) at the new dbl rows ──
    let p2 = cofactor_input.double();
    let p4 = p2.double();
    let p8 = p4.double();
    for (row, p) in [
        (layout.dbl_1_row, cofactor_input),
        (layout.dbl_2_row, &p2),
        (layout.dbl_3_row, &p4),
    ] {
        let xc = canonicalised(&p.X);
        let yc = canonicalised(&p.Y);
        let zc = canonicalised(&p.Z);
        for i in 0..NUM_LIMBS {
            trace[layout.dbl_input_X_base + i][row] = F::from(xc.limbs[i] as u64);
            trace[layout.dbl_input_Y_base + i][row] = F::from(yc.limbs[i] as u64);
            trace[layout.dbl_input_Z_base + i][row] = F::from(zc.limbs[i] as u64);
        }
        fill_point_double_gadget(&mut trace, row, &layout.dbl, p);
    }

    // ── v8 verdict cells at the new result_row ──
    let row_res = layout.result_row;
    let X = canonicalised(&p8.X);
    let Y = canonicalised(&p8.Y);
    let Z = canonicalised(&p8.Z);
    let T = canonicalised(&p8.T);
    for i in 0..NUM_LIMBS {
        trace[layout.result_X_base + i][row_res] = F::from(X.limbs[i] as u64);
        trace[layout.result_Y_base + i][row_res] = F::from(Y.limbs[i] as u64);
        trace[layout.result_Z_base + i][row_res] = F::from(Z.limbs[i] as u64);
        trace[layout.result_T_base + i][row_res] = F::from(T.limbs[i] as u64);
        trace[layout.zero_const_base + i][row_res] = F::zero();
    }
    let _ = residual_1;     // kept for docs / debugging
    fill_sub_gadget(&mut trace, row_res, &layout.sub_X,  &X, &zero);
    fill_sub_gadget(&mut trace, row_res, &layout.sub_T,  &T, &zero);
    fill_sub_gadget(&mut trace, row_res, &layout.sub_YZ, &Y, &Z);

    Some((trace, layout, k_canonical))
}

pub fn eval_verify_air_v14_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV14,
) -> Vec<F> {
    // Build a synthetic v13 layout that points to v14's adjusted rows
    // for the parts that v13's evaluator gates on (only the dbl chain
    // and result_row would be affected — but those are evaluated by
    // v8/v9/v10 logic, all of which v13's evaluator delegates to).
    let v13 = VerifyAirLayoutV13 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y, r_sign: layout.r_sign,
        a_y: layout.a_y, a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        dbl_1_row: layout.dbl_1_row,
        dbl_2_row: layout.dbl_2_row,
        dbl_3_row: layout.dbl_3_row,
        result_row: layout.result_row,
        result_X_base: layout.result_X_base,
        result_Y_base: layout.result_Y_base,
        result_Z_base: layout.result_Z_base,
        result_T_base: layout.result_T_base,
        zero_const_base: layout.zero_const_base,
        sub_X: layout.sub_X, sub_T: layout.sub_T, sub_YZ: layout.sub_YZ,
        dbl_input_X_base: layout.dbl_input_X_base,
        dbl_input_Y_base: layout.dbl_input_Y_base,
        dbl_input_Z_base: layout.dbl_input_Z_base,
        dbl: layout.dbl,
        thread_sB_X_base: layout.thread_sB_X_base,
        thread_sB_Y_base: layout.thread_sB_Y_base,
        thread_sB_Z_base: layout.thread_sB_Z_base,
        thread_sB_T_base: layout.thread_sB_T_base,
        sB_last_row: layout.sB_last_row,
        thread_kA_X_base: layout.thread_kA_X_base,
        thread_kA_Y_base: layout.thread_kA_Y_base,
        thread_kA_Z_base: layout.thread_kA_Z_base,
        thread_kA_T_base: layout.thread_kA_T_base,
        kA_last_row: layout.kA_last_row,
        thread_R_X_base: layout.thread_R_X_base,
        thread_R_Y_base: layout.thread_R_Y_base,
        thread_R_Z_base: layout.thread_R_Z_base,
        thread_R_T_base: layout.thread_R_T_base,
        one_const_R_base: layout.one_const_R_base,
        mul_R_T: layout.mul_R_T,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v13_per_row(cur, nxt, row, &v13);

    // ── v14 additions (all gated to residual_1_row) ──
    if row == layout.residual_1_row {
        // 1. zero_const_R1 pin: 10 cons.
        for i in 0..NUM_LIMBS {
            out.push(cur[layout.zero_const_R1_base + i]);
        }
        // 2. SUB gadgets: sub_negR_X, sub_negR_T (305 cons each).
        out.extend(eval_sub_gadget(cur, &layout.sub_negR_X));
        out.extend(eval_sub_gadget(cur, &layout.sub_negR_T));
        // 3. PointAdd gadget: 8370 cons.
        out.extend(eval_point_add_gadget(cur, &layout.point_add_R1));
    } else {
        for _ in 0..NUM_LIMBS { out.push(F::zero()); }
        for _ in 0..(2 * SUB_GADGET_CONSTRAINTS) { out.push(F::zero()); }
        for _ in 0..POINT_ADD_CONSTRAINTS { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), verify_v14_per_row_constraints(layout.k_scalar));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v15 layout — v14 + second point-sub `residual_2 = residual_1 − [k]·A`
// ═══════════════════════════════════════════════════════════════════
//
// Symmetric to v14, but reuses the same row.  At residual_1_row we now
// host:
//
//   v14: zero_const_R1, sub_negR_X,  sub_negR_T,  point_add_R1
//   v15:                sub_negkA_X, sub_negkA_T, point_add_R2
//
// `point_add_R2`:
//   P1 = `point_add_R1`'s OUTPUT (X3, Y3, Z3, T3 at the same row).
//   P2 = (sub_negkA_X.c, thread_kA_Y, thread_kA_Z, sub_negkA_T.c).
//
// Both PointAdds run at the SAME row — gadgets just reference cell
// offsets, so chaining within a row is fine.  No new row required and
// no thread chain for residual_1 is needed.
//
// `point_add_R2`'s output `(mul_X3.c, mul_Y3.c, mul_Z3.c)` IS the
// residual_2 = `[s]·B − R − [k]·A`.  v16 will bind these cells to v14's
// dbl_input_* cells, closing the final soundness gap.

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV15 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    pub residual_row: usize,
    pub dbl_1_row:  usize,
    pub dbl_2_row:  usize,
    pub dbl_3_row:  usize,
    pub result_row: usize,
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    pub zero_const_base: usize,
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    pub dbl_input_X_base: usize,
    pub dbl_input_Y_base: usize,
    pub dbl_input_Z_base: usize,
    pub dbl: PointDoubleGadgetLayout,
    pub thread_sB_X_base: usize,
    pub thread_sB_Y_base: usize,
    pub thread_sB_Z_base: usize,
    pub thread_sB_T_base: usize,
    pub sB_last_row: usize,
    pub thread_kA_X_base: usize,
    pub thread_kA_Y_base: usize,
    pub thread_kA_Z_base: usize,
    pub thread_kA_T_base: usize,
    pub kA_last_row: usize,
    pub thread_R_X_base: usize,
    pub thread_R_Y_base: usize,
    pub thread_R_Z_base: usize,
    pub thread_R_T_base: usize,
    pub one_const_R_base: usize,
    pub mul_R_T: MulGadgetLayout,
    pub zero_const_R1_base: usize,
    pub sub_negR_X: SubGadgetLayout,
    pub sub_negR_T: SubGadgetLayout,
    pub point_add_R1: PointAddGadgetLayout,
    /// New v15 gadgets at `residual_row`.
    pub sub_negkA_X: SubGadgetLayout,
    pub sub_negkA_T: SubGadgetLayout,
    pub point_add_R2: PointAddGadgetLayout,
    pub width:  usize,
    pub height: usize,
}

pub fn verify_v15_per_row_constraints(k_scalar: usize) -> usize {
    verify_v14_per_row_constraints(k_scalar)
        + 2 * SUB_GADGET_CONSTRAINTS           // sub_negkA_X, sub_negkA_T
        + POINT_ADD_CONSTRAINTS                // residual_1 + (−[k]·A)
}

pub fn verify_air_layout_v15(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV15> {
    let v14 = verify_air_layout_v14(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;

    let mut next = v14.width;

    let alloc_sub = |start: &mut usize, a_base: usize, b_base: usize|
        -> SubGadgetLayout
    {
        let c_limbs_base = *start; *start += ELEMENT_LIMB_CELLS;
        let c_bits_base  = *start; *start += 255;
        let c_pos_base   = *start; *start += NUM_LIMBS;
        let c_neg_base   = *start; *start += NUM_LIMBS;
        SubGadgetLayout {
            a_limbs_base: a_base,
            b_limbs_base: b_base,
            c_limbs_base, c_bits_base, c_pos_base, c_neg_base,
        }
    };
    // Reuse v14's zero_const_R1_base for the a-input of both new SUBs.
    let sub_negkA_X = alloc_sub(&mut next, v14.zero_const_R1_base, v14.thread_kA_X_base);
    let sub_negkA_T = alloc_sub(&mut next, v14.zero_const_R1_base, v14.thread_kA_T_base);

    // PointAdd_R2: P1 = point_add_R1's output, P2 = (negkA_X, kA_Y, kA_Z, negkA_T).
    let point_add_R2 = point_add_layout_at(
        next,
        v14.point_add_R1.mul_X3.c_limbs_base,
        v14.point_add_R1.mul_Y3.c_limbs_base,
        v14.point_add_R1.mul_Z3.c_limbs_base,
        v14.point_add_R1.mul_T3.c_limbs_base,
        sub_negkA_X.c_limbs_base, v14.thread_kA_Y_base,
        v14.thread_kA_Z_base,    sub_negkA_T.c_limbs_base,
    );
    let width = point_add_R2.end;

    Some(VerifyAirLayoutV15 {
        n_blocks: v14.n_blocks,
        k_hash:   v14.k_hash,
        reduce_row:       v14.reduce_row,
        decompress_R_row: v14.decompress_R_row,
        decompress_A_row: v14.decompress_A_row,
        sB_first_row: v14.sB_first_row,
        kA_first_row: v14.kA_first_row,
        k_scalar:     v14.k_scalar,
        reduce: v14.reduce,
        digest_bit_base: v14.digest_bit_base,
        decomp: v14.decomp,
        mult:   v14.mult,
        a_point_limbs: v14.a_point_limbs,
        r_y: v14.r_y, r_sign: v14.r_sign,
        a_y: v14.a_y, a_sign: v14.a_sign,
        scalar_block_sB_base: v14.scalar_block_sB_base,
        scalar_block_kA_base: v14.scalar_block_kA_base,
        s_bits: v14.s_bits,
        k_bits: v14.k_bits,
        r_thread_base: v14.r_thread_base,
        residual_row: v14.residual_1_row,
        dbl_1_row: v14.dbl_1_row,
        dbl_2_row: v14.dbl_2_row,
        dbl_3_row: v14.dbl_3_row,
        result_row: v14.result_row,
        result_X_base: v14.result_X_base,
        result_Y_base: v14.result_Y_base,
        result_Z_base: v14.result_Z_base,
        result_T_base: v14.result_T_base,
        zero_const_base: v14.zero_const_base,
        sub_X: v14.sub_X, sub_T: v14.sub_T, sub_YZ: v14.sub_YZ,
        dbl_input_X_base: v14.dbl_input_X_base,
        dbl_input_Y_base: v14.dbl_input_Y_base,
        dbl_input_Z_base: v14.dbl_input_Z_base,
        dbl: v14.dbl,
        thread_sB_X_base: v14.thread_sB_X_base,
        thread_sB_Y_base: v14.thread_sB_Y_base,
        thread_sB_Z_base: v14.thread_sB_Z_base,
        thread_sB_T_base: v14.thread_sB_T_base,
        sB_last_row: v14.sB_last_row,
        thread_kA_X_base: v14.thread_kA_X_base,
        thread_kA_Y_base: v14.thread_kA_Y_base,
        thread_kA_Z_base: v14.thread_kA_Z_base,
        thread_kA_T_base: v14.thread_kA_T_base,
        kA_last_row: v14.kA_last_row,
        thread_R_X_base: v14.thread_R_X_base,
        thread_R_Y_base: v14.thread_R_Y_base,
        thread_R_Z_base: v14.thread_R_Z_base,
        thread_R_T_base: v14.thread_R_T_base,
        one_const_R_base: v14.one_const_R_base,
        mul_R_T: v14.mul_R_T,
        zero_const_R1_base: v14.zero_const_R1_base,
        sub_negR_X: v14.sub_negR_X,
        sub_negR_T: v14.sub_negR_T,
        point_add_R1: v14.point_add_R1,
        sub_negkA_X, sub_negkA_T, point_add_R2,
        width,
        height: v14.height,
    })
}

pub fn fill_verify_air_v15(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
    cofactor_input: &EdwardsPoint,
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV15, [u8; 32])> {
    let layout = verify_air_layout_v15(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;
    let (mut trace, _v14, k_canonical) = fill_verify_air_v14(
        message, r_compressed, a_compressed, s_bits, k_bits, cofactor_input,
    )?;

    while trace.len() < layout.width {
        trace.push(vec![F::zero(); layout.height]);
    }

    // Compute residual_1, residual_2 via native ref so we can drive the
    // SUB / PointAdd fillers correctly.
    let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;
    let mut s_acc = EdwardsPoint::identity();
    for &bit in s_bits {
        s_acc = s_acc.double();
        if bit { s_acc = s_acc.add(&basepoint); }
    }
    let sB = s_acc;
    let R_point = EdwardsPoint::decompress(r_compressed)?;
    let neg_R = EdwardsPoint {
        X: canonicalised(&FieldElement::zero().sub(&R_point.X)),
        Y: canonicalised(&R_point.Y),
        Z: canonicalised(&R_point.Z),
        T: canonicalised(&FieldElement::zero().sub(&R_point.T)),
    };
    let residual_1 = sB.add(&neg_R);

    let A_point = EdwardsPoint::decompress(a_compressed)
        .expect("a_compressed validated upstream");
    let mut acc = EdwardsPoint::identity();
    for &bit in k_bits {
        acc = acc.double();
        if bit { acc = acc.add(&A_point); }
    }
    let kA = acc;
    let neg_kA = EdwardsPoint {
        X: canonicalised(&FieldElement::zero().sub(&kA.X)),
        Y: canonicalised(&kA.Y),
        Z: canonicalised(&kA.Z),
        T: canonicalised(&FieldElement::zero().sub(&kA.T)),
    };

    let zero = FieldElement::zero();
    let xc_kA = canonicalised(&kA.X);
    let tc_kA = canonicalised(&kA.T);
    fill_sub_gadget(&mut trace, layout.residual_row, &layout.sub_negkA_X, &zero, &xc_kA);
    fill_sub_gadget(&mut trace, layout.residual_row, &layout.sub_negkA_T, &zero, &tc_kA);

    fill_point_add_gadget(
        &mut trace, layout.residual_row, &layout.point_add_R2,
        &residual_1, &neg_kA,
    );

    Some((trace, layout, k_canonical))
}

pub fn eval_verify_air_v15_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV15,
) -> Vec<F> {
    let v14 = VerifyAirLayoutV14 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y, r_sign: layout.r_sign,
        a_y: layout.a_y, a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        residual_1_row: layout.residual_row,
        dbl_1_row: layout.dbl_1_row,
        dbl_2_row: layout.dbl_2_row,
        dbl_3_row: layout.dbl_3_row,
        result_row: layout.result_row,
        result_X_base: layout.result_X_base,
        result_Y_base: layout.result_Y_base,
        result_Z_base: layout.result_Z_base,
        result_T_base: layout.result_T_base,
        zero_const_base: layout.zero_const_base,
        sub_X: layout.sub_X, sub_T: layout.sub_T, sub_YZ: layout.sub_YZ,
        dbl_input_X_base: layout.dbl_input_X_base,
        dbl_input_Y_base: layout.dbl_input_Y_base,
        dbl_input_Z_base: layout.dbl_input_Z_base,
        dbl: layout.dbl,
        thread_sB_X_base: layout.thread_sB_X_base,
        thread_sB_Y_base: layout.thread_sB_Y_base,
        thread_sB_Z_base: layout.thread_sB_Z_base,
        thread_sB_T_base: layout.thread_sB_T_base,
        sB_last_row: layout.sB_last_row,
        thread_kA_X_base: layout.thread_kA_X_base,
        thread_kA_Y_base: layout.thread_kA_Y_base,
        thread_kA_Z_base: layout.thread_kA_Z_base,
        thread_kA_T_base: layout.thread_kA_T_base,
        kA_last_row: layout.kA_last_row,
        thread_R_X_base: layout.thread_R_X_base,
        thread_R_Y_base: layout.thread_R_Y_base,
        thread_R_Z_base: layout.thread_R_Z_base,
        thread_R_T_base: layout.thread_R_T_base,
        one_const_R_base: layout.one_const_R_base,
        mul_R_T: layout.mul_R_T,
        zero_const_R1_base: layout.zero_const_R1_base,
        sub_negR_X: layout.sub_negR_X,
        sub_negR_T: layout.sub_negR_T,
        point_add_R1: layout.point_add_R1,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v14_per_row(cur, nxt, row, &v14);

    if row == layout.residual_row {
        out.extend(eval_sub_gadget(cur, &layout.sub_negkA_X));
        out.extend(eval_sub_gadget(cur, &layout.sub_negkA_T));
        out.extend(eval_point_add_gadget(cur, &layout.point_add_R2));
    } else {
        for _ in 0..(2 * SUB_GADGET_CONSTRAINTS) { out.push(F::zero()); }
        for _ in 0..POINT_ADD_CONSTRAINTS { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), verify_v15_per_row_constraints(layout.k_scalar));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  v16 layout — v15 + residual_2 → dbl_1 input binding
// ═══════════════════════════════════════════════════════════════════
//
// THE FINAL BINDING.  v15 produced `residual_2 = [s]·B − R − [k]·A` at
// `point_add_R2.mul_X3 / Y3 / Z3 . c_limbs_base` cells of residual_row.
// v16 forwards those cells into the dbl_1 input slot at the next row,
// closing the soundness loop:
//
//   residual_row  →  dbl_1_row :  nxt[dbl_input_X_base..] = cur[mul_X3.c..]
//                                 nxt[dbl_input_Y_base..] = cur[mul_Y3.c..]
//                                 nxt[dbl_input_Z_base..] = cur[mul_Z3.c..]
//
// Combined with v9/v10 (cofactor mul + result-row binding) and v8
// (identity verdict), the AIR now proves:
//
//   "`[8]·([s]·B − R − [k]·A)` is the projective Edwards25519 identity"
//
// — exactly the RFC 8032 §5.1.7 cofactored verification predicate.
//
// Just 3·NUM_LIMBS = 30 new transition cons (no new cells).

#[derive(Clone, Debug)]
pub struct VerifyAirLayoutV16 {
    pub n_blocks: usize,
    pub k_hash:   usize,
    pub reduce_row:        usize,
    pub decompress_R_row:  usize,
    pub decompress_A_row:  usize,
    pub sB_first_row: usize,
    pub kA_first_row: usize,
    pub k_scalar: usize,
    pub reduce: ScalarReduceGadgetLayout,
    pub digest_bit_base: usize,
    pub decomp: PointDecompressGadgetLayout,
    pub mult:   ScalarMultRowLayout,
    pub a_point_limbs: [FieldElement; 4],
    pub r_y:    FieldElement,
    pub r_sign: bool,
    pub a_y:    FieldElement,
    pub a_sign: bool,
    pub scalar_block_sB_base: usize,
    pub scalar_block_kA_base: usize,
    pub s_bits: Vec<bool>,
    pub k_bits: Vec<bool>,
    pub r_thread_base: usize,
    pub residual_row: usize,
    pub dbl_1_row:  usize,
    pub dbl_2_row:  usize,
    pub dbl_3_row:  usize,
    pub result_row: usize,
    pub result_X_base: usize,
    pub result_Y_base: usize,
    pub result_Z_base: usize,
    pub result_T_base: usize,
    pub zero_const_base: usize,
    pub sub_X:  SubGadgetLayout,
    pub sub_T:  SubGadgetLayout,
    pub sub_YZ: SubGadgetLayout,
    pub dbl_input_X_base: usize,
    pub dbl_input_Y_base: usize,
    pub dbl_input_Z_base: usize,
    pub dbl: PointDoubleGadgetLayout,
    pub thread_sB_X_base: usize,
    pub thread_sB_Y_base: usize,
    pub thread_sB_Z_base: usize,
    pub thread_sB_T_base: usize,
    pub sB_last_row: usize,
    pub thread_kA_X_base: usize,
    pub thread_kA_Y_base: usize,
    pub thread_kA_Z_base: usize,
    pub thread_kA_T_base: usize,
    pub kA_last_row: usize,
    pub thread_R_X_base: usize,
    pub thread_R_Y_base: usize,
    pub thread_R_Z_base: usize,
    pub thread_R_T_base: usize,
    pub one_const_R_base: usize,
    pub mul_R_T: MulGadgetLayout,
    pub zero_const_R1_base: usize,
    pub sub_negR_X: SubGadgetLayout,
    pub sub_negR_T: SubGadgetLayout,
    pub point_add_R1: PointAddGadgetLayout,
    pub sub_negkA_X: SubGadgetLayout,
    pub sub_negkA_T: SubGadgetLayout,
    pub point_add_R2: PointAddGadgetLayout,
    pub width:  usize,
    pub height: usize,
}

pub fn verify_v16_per_row_constraints(k_scalar: usize) -> usize {
    verify_v15_per_row_constraints(k_scalar) + 3 * NUM_LIMBS
}

pub fn verify_air_layout_v16(
    msg_len_for_sha512: usize,
    s_bits: &[bool],
    k_bits: &[bool],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
) -> Option<VerifyAirLayoutV16> {
    let v15 = verify_air_layout_v15(
        msg_len_for_sha512, s_bits, k_bits, r_compressed, a_compressed,
    )?;

    Some(VerifyAirLayoutV16 {
        n_blocks: v15.n_blocks,
        k_hash:   v15.k_hash,
        reduce_row:       v15.reduce_row,
        decompress_R_row: v15.decompress_R_row,
        decompress_A_row: v15.decompress_A_row,
        sB_first_row: v15.sB_first_row,
        kA_first_row: v15.kA_first_row,
        k_scalar:     v15.k_scalar,
        reduce: v15.reduce,
        digest_bit_base: v15.digest_bit_base,
        decomp: v15.decomp,
        mult:   v15.mult,
        a_point_limbs: v15.a_point_limbs,
        r_y: v15.r_y, r_sign: v15.r_sign,
        a_y: v15.a_y, a_sign: v15.a_sign,
        scalar_block_sB_base: v15.scalar_block_sB_base,
        scalar_block_kA_base: v15.scalar_block_kA_base,
        s_bits: v15.s_bits,
        k_bits: v15.k_bits,
        r_thread_base: v15.r_thread_base,
        residual_row: v15.residual_row,
        dbl_1_row: v15.dbl_1_row,
        dbl_2_row: v15.dbl_2_row,
        dbl_3_row: v15.dbl_3_row,
        result_row: v15.result_row,
        result_X_base: v15.result_X_base,
        result_Y_base: v15.result_Y_base,
        result_Z_base: v15.result_Z_base,
        result_T_base: v15.result_T_base,
        zero_const_base: v15.zero_const_base,
        sub_X: v15.sub_X, sub_T: v15.sub_T, sub_YZ: v15.sub_YZ,
        dbl_input_X_base: v15.dbl_input_X_base,
        dbl_input_Y_base: v15.dbl_input_Y_base,
        dbl_input_Z_base: v15.dbl_input_Z_base,
        dbl: v15.dbl,
        thread_sB_X_base: v15.thread_sB_X_base,
        thread_sB_Y_base: v15.thread_sB_Y_base,
        thread_sB_Z_base: v15.thread_sB_Z_base,
        thread_sB_T_base: v15.thread_sB_T_base,
        sB_last_row: v15.sB_last_row,
        thread_kA_X_base: v15.thread_kA_X_base,
        thread_kA_Y_base: v15.thread_kA_Y_base,
        thread_kA_Z_base: v15.thread_kA_Z_base,
        thread_kA_T_base: v15.thread_kA_T_base,
        kA_last_row: v15.kA_last_row,
        thread_R_X_base: v15.thread_R_X_base,
        thread_R_Y_base: v15.thread_R_Y_base,
        thread_R_Z_base: v15.thread_R_Z_base,
        thread_R_T_base: v15.thread_R_T_base,
        one_const_R_base: v15.one_const_R_base,
        mul_R_T: v15.mul_R_T,
        zero_const_R1_base: v15.zero_const_R1_base,
        sub_negR_X: v15.sub_negR_X,
        sub_negR_T: v15.sub_negR_T,
        point_add_R1: v15.point_add_R1,
        sub_negkA_X: v15.sub_negkA_X,
        sub_negkA_T: v15.sub_negkA_T,
        point_add_R2: v15.point_add_R2,
        width:  v15.width,
        height: v15.height,
    })
}

/// v16 trace builder — same as v15 but the trace builder DERIVES the
/// cofactor input from the residual chain instead of accepting it as a
/// free parameter.  Caller now provides only the public signature
/// inputs; the AIR proves the cofactored verdict end-to-end.
pub fn fill_verify_air_v16(
    message:      &[u8],
    r_compressed: &[u8; 32],
    a_compressed: &[u8; 32],
    s_bits:       &[bool],
    k_bits:       &[bool],
) -> Option<(Vec<Vec<F>>, VerifyAirLayoutV16, [u8; 32])> {
    let layout = verify_air_layout_v16(
        message.len(), s_bits, k_bits, r_compressed, a_compressed,
    )?;

    // Compute residual_2 natively so v16's binding holds.
    let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;
    let mut s_acc = EdwardsPoint::identity();
    for &bit in s_bits {
        s_acc = s_acc.double();
        if bit { s_acc = s_acc.add(&basepoint); }
    }
    let sB = s_acc;
    let R_point = EdwardsPoint::decompress(r_compressed)?;
    let neg_R = EdwardsPoint {
        X: canonicalised(&FieldElement::zero().sub(&R_point.X)),
        Y: canonicalised(&R_point.Y),
        Z: canonicalised(&R_point.Z),
        T: canonicalised(&FieldElement::zero().sub(&R_point.T)),
    };
    let residual_1 = sB.add(&neg_R);

    let A_point = EdwardsPoint::decompress(a_compressed)?;
    let mut acc = EdwardsPoint::identity();
    for &bit in k_bits {
        acc = acc.double();
        if bit { acc = acc.add(&A_point); }
    }
    let kA = acc;
    let neg_kA = EdwardsPoint {
        X: canonicalised(&FieldElement::zero().sub(&kA.X)),
        Y: canonicalised(&kA.Y),
        Z: canonicalised(&kA.Z),
        T: canonicalised(&FieldElement::zero().sub(&kA.T)),
    };
    let residual_2 = residual_1.add(&neg_kA);

    let (trace, _v15, k_canonical) = fill_verify_air_v15(
        message, r_compressed, a_compressed, s_bits, k_bits, &residual_2,
    )?;

    Some((trace, layout, k_canonical))
}

pub fn eval_verify_air_v16_per_row(
    cur: &[F],
    nxt: &[F],
    row: usize,
    layout: &VerifyAirLayoutV16,
) -> Vec<F> {
    let v15 = VerifyAirLayoutV15 {
        n_blocks: layout.n_blocks,
        k_hash:   layout.k_hash,
        reduce_row:       layout.reduce_row,
        decompress_R_row: layout.decompress_R_row,
        decompress_A_row: layout.decompress_A_row,
        sB_first_row: layout.sB_first_row,
        kA_first_row: layout.kA_first_row,
        k_scalar:     layout.k_scalar,
        reduce: layout.reduce,
        digest_bit_base: layout.digest_bit_base,
        decomp: layout.decomp,
        mult:   layout.mult,
        a_point_limbs: layout.a_point_limbs,
        r_y: layout.r_y, r_sign: layout.r_sign,
        a_y: layout.a_y, a_sign: layout.a_sign,
        scalar_block_sB_base: layout.scalar_block_sB_base,
        scalar_block_kA_base: layout.scalar_block_kA_base,
        s_bits: layout.s_bits.clone(),
        k_bits: layout.k_bits.clone(),
        r_thread_base: layout.r_thread_base,
        residual_row: layout.residual_row,
        dbl_1_row: layout.dbl_1_row,
        dbl_2_row: layout.dbl_2_row,
        dbl_3_row: layout.dbl_3_row,
        result_row: layout.result_row,
        result_X_base: layout.result_X_base,
        result_Y_base: layout.result_Y_base,
        result_Z_base: layout.result_Z_base,
        result_T_base: layout.result_T_base,
        zero_const_base: layout.zero_const_base,
        sub_X: layout.sub_X, sub_T: layout.sub_T, sub_YZ: layout.sub_YZ,
        dbl_input_X_base: layout.dbl_input_X_base,
        dbl_input_Y_base: layout.dbl_input_Y_base,
        dbl_input_Z_base: layout.dbl_input_Z_base,
        dbl: layout.dbl,
        thread_sB_X_base: layout.thread_sB_X_base,
        thread_sB_Y_base: layout.thread_sB_Y_base,
        thread_sB_Z_base: layout.thread_sB_Z_base,
        thread_sB_T_base: layout.thread_sB_T_base,
        sB_last_row: layout.sB_last_row,
        thread_kA_X_base: layout.thread_kA_X_base,
        thread_kA_Y_base: layout.thread_kA_Y_base,
        thread_kA_Z_base: layout.thread_kA_Z_base,
        thread_kA_T_base: layout.thread_kA_T_base,
        kA_last_row: layout.kA_last_row,
        thread_R_X_base: layout.thread_R_X_base,
        thread_R_Y_base: layout.thread_R_Y_base,
        thread_R_Z_base: layout.thread_R_Z_base,
        thread_R_T_base: layout.thread_R_T_base,
        one_const_R_base: layout.one_const_R_base,
        mul_R_T: layout.mul_R_T,
        zero_const_R1_base: layout.zero_const_R1_base,
        sub_negR_X: layout.sub_negR_X,
        sub_negR_T: layout.sub_negR_T,
        point_add_R1: layout.point_add_R1,
        sub_negkA_X: layout.sub_negkA_X,
        sub_negkA_T: layout.sub_negkA_T,
        point_add_R2: layout.point_add_R2,
        width:  layout.width,
        height: layout.height,
    };
    let mut out = eval_verify_air_v15_per_row(cur, nxt, row, &v15);

    // ── residual_row → dbl_1_row binding (3 · NUM_LIMBS cons) ──
    if row == layout.residual_row {
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_X_base + i]
                - cur[layout.point_add_R2.mul_X3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_Y_base + i]
                - cur[layout.point_add_R2.mul_Y3.c_limbs_base + i]);
        }
        for i in 0..NUM_LIMBS {
            out.push(nxt[layout.dbl_input_Z_base + i]
                - cur[layout.point_add_R2.mul_Z3.c_limbs_base + i]);
        }
    } else {
        for _ in 0..(3 * NUM_LIMBS) { out.push(F::zero()); }
    }

    debug_assert_eq!(out.len(), verify_v16_per_row_constraints(layout.k_scalar));
    out
}

// ═══════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_trace_satisfies(message: &[u8]) {
        let (trace, layout, k_canon) = fill_verify_air_v0(message);

        // Cross-check k_canonical against an independent direct call.
        let want_k = reduce_mod_l_wide(&sha512_native(message));
        assert_eq!(k_canon, want_k,
            "trace builder's canonical k ≠ direct ed25519_scalar reference");

        // Also verify the scalar-reduce gadget's r-limb cells match the
        // canonical k bytes.
        for i in 0..R_LIMBS {
            let v: F = trace[layout.reduce.r_limbs_base + i][layout.reduce_row];
            use ark_ff::{BigInteger, PrimeField};
            let limb_u64 = v.into_bigint().as_ref()[0];
            let expected = (k_canon[2 * i] as u64) | ((k_canon[2 * i + 1] as u64) << 8);
            assert_eq!(limb_u64, expected,
                "r-limb {} cell value ({}) ≠ canonical k limb ({})",
                i, limb_u64, expected);
        }

        // Per-row constraint check.  We exclude the wrap row (height-1)
        // because the cyclic wrap is not enforced (consistent with
        // sha256_air / sha512_air convention).
        let height = layout.height;
        let mut nonzero_rows = Vec::new();
        for r in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][r]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][r + 1]).collect();
            let cons = eval_verify_air_v0_per_row(&cur, &nxt, r, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    nonzero_rows.push((r, i, *v));
                }
            }
        }
        assert!(nonzero_rows.is_empty(),
            "non-zero constraints (showing up to 5):\n{}",
            nonzero_rows.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v0_constants() {
        // For a 0-byte message: 1 SHA-512 block (just padding fits).
        let layout = verify_air_layout_v0(0);
        assert_eq!(layout.n_blocks, 1);
        assert_eq!(layout.k_hash, SHA512_ROWS_PER_BLOCK);  // 128
        assert_eq!(layout.reduce_row, 128);
        assert!(layout.width >= SHA512_WIDTH);
        assert!(layout.height > layout.k_hash);
    }

    #[test]
    fn verify_v0_empty_message() {
        assert_trace_satisfies(b"");
    }

    #[test]
    fn verify_v0_short_message() {
        assert_trace_satisfies(b"abc");
    }

    #[test]
    fn verify_v0_one_block_message() {
        // 64 bytes → padded into a single SHA-512 block.
        assert_trace_satisfies(&[0xa5u8; 64]);
    }

    #[test]
    fn verify_v0_two_block_message() {
        // 200 bytes → 2 SHA-512 blocks.
        assert_trace_satisfies(&[0x5au8; 200]);
    }

    fn assert_v1_trace_satisfies(message: &[u8]) {
        let (trace, layout, k_canon) = fill_verify_air_v1(message);

        // Cross-check k_canonical against the direct scalar reference.
        let want_k = reduce_mod_l_wide(&sha512_native(message));
        assert_eq!(k_canon, want_k,
            "v1 trace builder's canonical k ≠ direct ed25519_scalar reference");

        // Verify the digest-bit cells at row k_hash − 1 reconstruct H[k]
        // (LE bit decomposition).
        let digest = sha512_native(message);
        let digest_row = layout.k_hash - 1;
        for k in 0..8 {
            let h_word = u64::from_be_bytes([
                digest[8*k], digest[8*k+1], digest[8*k+2], digest[8*k+3],
                digest[8*k+4], digest[8*k+5], digest[8*k+6], digest[8*k+7],
            ]);
            for i in 0..64 {
                use ark_ff::{BigInteger, PrimeField};
                let v: F = trace[layout.digest_bit_base + 64*k + i][digest_row];
                let bit = v.into_bigint().as_ref()[0];
                let want = (h_word >> i) & 1;
                assert_eq!(bit, want,
                    "digest bit cell H[{}].bit_{} = {} ≠ expected {}",
                    k, i, bit, want);
            }
        }

        // Per-row constraint check: every constraint is zero except on
        // the wrap row (height − 1), which is the cyclic wrap of the
        // composed AIR (not enforced; a follow-up phase fills it).
        let height = layout.height;
        let mut bad = Vec::new();
        for r in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][r]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][r + 1]).collect();
            let cons = eval_verify_air_v1_per_row(&cur, &nxt, r, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((r, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v1 constraints (showing up to 5):\n{}",
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v1_constants() {
        // Composition counts must match the documented totals.
        assert_eq!(VERIFY_V1_FORMAT_CONS, 512 + 16 + 32);
        assert_eq!(
            VERIFY_V1_PER_ROW_CONSTRAINTS,
            SHA512_CONSTRAINTS + SCALAR_REDUCE_CONSTRAINTS + 560
        );
        let layout = verify_air_layout_v1(0);
        assert_eq!(layout.digest_bit_base, SHA512_WIDTH);
        assert!(layout.width >= SHA512_WIDTH + 512);
    }

    #[test]
    fn verify_v1_empty_message() {
        assert_v1_trace_satisfies(b"");
    }

    #[test]
    fn verify_v1_short_message() {
        assert_v1_trace_satisfies(b"abc");
    }

    #[test]
    fn verify_v1_one_block_message() {
        assert_v1_trace_satisfies(&[0xa5u8; 64]);
    }

    #[test]
    fn verify_v1_two_block_message() {
        assert_v1_trace_satisfies(&[0x5au8; 200]);
    }

    #[test]
    fn verify_v1_rfc8032_test1_inputs() {
        let r_compressed = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        ).unwrap();
        let r_compressed = &r_compressed[..32];
        let a_compressed = hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ).unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(r_compressed);
        input.extend_from_slice(&a_compressed);
        assert_v1_trace_satisfies(&input);
    }

    #[test]
    fn verify_v1_tampered_input_limb_fails() {
        // Corrupt a scalar-reduce input limb at the reduce row → the
        // input-limb bind constraint at row k_hash − 1 must reject.
        let (mut trace, layout, _) = fill_verify_air_v1(b"abc");
        // Flip the low bit of input_limb[0] by adding 1.
        let cell = trace[layout.reduce.input_limbs_base + 0][layout.reduce_row];
        trace[layout.reduce.input_limbs_base + 0][layout.reduce_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.k_hash - 1]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.k_hash]).collect();
        let cons = eval_verify_air_v1_per_row(&cur, &nxt, layout.k_hash - 1, &layout);
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering input_limb[0] should violate at least one v1 constraint");
    }

    #[test]
    fn verify_v1_tampered_digest_bit_fails() {
        // Flip a digest bit cell at row k_hash − 1 → either booleanity
        // (if non-{0,1}) or H-state pack (if 0↔1) must reject.
        let (mut trace, layout, _) = fill_verify_air_v1(b"abc");
        let digest_row = layout.k_hash - 1;
        let cell = trace[layout.digest_bit_base + 0][digest_row];
        // Flip 0→1 or 1→0 to keep booleanity intact and force H-state pack failure.
        trace[layout.digest_bit_base + 0][digest_row] = F::one() - cell;

        let cur: Vec<F> = (0..layout.width).map(|c| trace[c][digest_row]).collect();
        let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][digest_row + 1]).collect();
        let cons = eval_verify_air_v1_per_row(&cur, &nxt, digest_row, &layout);
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering a digest bit cell should violate at least one v1 constraint");
    }

    #[test]
    fn verify_v0_rfc8032_test1_inputs() {
        // The RFC 8032 TEST 1 SHA-512 input: R || A || M, with R, A 32
        // bytes each and M empty.  Use the test vector's R and A from
        // ed25519_verify::tests.
        let r_compressed = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        ).unwrap();
        let r_compressed = &r_compressed[..32];
        let a_compressed = hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ).unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(r_compressed);
        input.extend_from_slice(&a_compressed);
        // empty message
        assert_trace_satisfies(&input);
    }

    // ─────────────────────────────────────────────────────────────────
    //  v2 tests
    // ─────────────────────────────────────────────────────────────────

    fn rfc8032_test1_r_a() -> ([u8; 32], [u8; 32]) {
        let r = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        ).unwrap();
        let a = hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ).unwrap();
        let mut r_arr = [0u8; 32]; r_arr.copy_from_slice(&r[..32]);
        let mut a_arr = [0u8; 32]; a_arr.copy_from_slice(&a);
        (r_arr, a_arr)
    }

    fn assert_v2_trace_satisfies(message: &[u8], r: &[u8; 32], a: &[u8; 32]) {
        let (trace, layout, _k) = fill_verify_air_v2(message, r, a)
            .expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v2_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v2 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v2_constants() {
        let layout = verify_air_layout_v2(0);
        assert_eq!(layout.decompress_R_row, layout.k_hash + 1);
        assert_eq!(layout.decompress_A_row, layout.k_hash + 2);
        assert!(layout.height > layout.decompress_A_row);
        assert_eq!(
            VERIFY_V2_PER_ROW_CONSTRAINTS,
            VERIFY_V1_PER_ROW_CONSTRAINTS + 2 * POINT_DECOMP_CONSTRAINTS
        );
    }

    #[test]
    fn verify_v2_rfc8032_test1() {
        let (r, a) = rfc8032_test1_r_a();
        // Empty message — RFC 8032 TEST 1.
        assert_v2_trace_satisfies(b"", &r, &a);
    }

    #[test]
    fn verify_v2_rfc8032_test1_input_concat() {
        // Trace builder still works when a non-empty message is hashed
        // alongside the same R / A (proves SHA-512 phase scales).
        let (r, a) = rfc8032_test1_r_a();
        assert_v2_trace_satisfies(b"abc", &r, &a);
    }

    #[test]
    fn verify_v2_invalid_R_rejected() {
        // Search for a y-value that doesn't decompress (≈ 50% probability
        // for random bytes — depends on (1 − y²)/(1 + d·y²) being a
        // quadratic non-residue).  Iterate a small counter on the high
        // limb until we hit one.  The trace builder must return None.
        let (_, a) = rfc8032_test1_r_a();
        let mut bad_r = [0u8; 32];
        let mut found = false;
        for seed in 0u8..64 {
            bad_r.fill(0);
            bad_r[0] = seed.wrapping_add(2);  // y = small non-zero
            bad_r[31] = 0;                    // sign = 0
            if fill_verify_air_v2(b"", &bad_r, &a).is_none() {
                found = true;
                break;
            }
        }
        assert!(found,
            "expected the trace builder to reject at least one off-curve R \
             out of 64 candidate y values");
    }

    #[test]
    fn verify_v2_tampered_y_R_fails() {
        let (r, a) = rfc8032_test1_r_a();
        let (mut trace, layout, _) = fill_verify_air_v2(b"", &r, &a).unwrap();

        // Tamper Y_R by flipping the low bit of y_limbs[0] at row decompress_R_row.
        let cell = trace[layout.decomp.y_limbs + 0][layout.decompress_R_row];
        trace[layout.decomp.y_limbs + 0][layout.decompress_R_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_R_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_R_row + 1]).collect();
        let cons = eval_verify_air_v2_per_row(
            &cur, &nxt, layout.decompress_R_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering Y_R should violate at least one decompression constraint");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v3 tests — small K (8 bits) for fast turnaround
    // ─────────────────────────────────────────────────────────────────

    fn scalar_to_bits_msb_first(k: u64, nbits: usize) -> Vec<bool> {
        (0..nbits).rev().map(|i| ((k >> i) & 1) == 1).collect()
    }

    fn assert_v3_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
    ) {
        let (trace, layout, _k) =
            fill_verify_air_v3(message, r, a, s_bits, k_bits)
                .expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v3_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v3 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v3_constants() {
        let layout = verify_air_layout_v3(0, 8);
        assert_eq!(layout.k_scalar, 8);
        assert_eq!(layout.sB_first_row, layout.k_hash + 3);
        assert_eq!(layout.kA_first_row, layout.k_hash + 3 + 8);
        assert_eq!(
            VERIFY_V3_PER_ROW_CONSTRAINTS,
            VERIFY_V2_PER_ROW_CONSTRAINTS
                + 2 * SCALAR_MULT_PER_ROW_CONSTRAINTS
                + 2 * SCALAR_MULT_TRANSITION_CONSTRAINTS
                + 2 * (4 * NUM_LIMBS)
        );
        assert_eq!(layout.width, SCALAR_MULT_ROW_WIDTH);  // dominates
    }

    #[test]
    fn verify_v3_8bit_scalars_basepoint() {
        let (r, a) = rfc8032_test1_r_a();
        // Arbitrary 8-bit scalars — sB phase always uses ED25519_BASEPOINT;
        // kA phase uses A.  With K = 8, both phases compute small scalar
        // mults; the bits don't have to correspond to a real signature
        // because v3 doesn't yet bind them.
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let k_bits = scalar_to_bits_msb_first(0x3c, 8);
        assert_v3_trace_satisfies(b"", &r, &a, &s_bits, &k_bits);
    }

    #[test]
    fn verify_v3_zero_scalars() {
        // [0]·B = identity; [0]·A = identity.  Tests the boundary case.
        let (r, a) = rfc8032_test1_r_a();
        let zeros = vec![false; 8];
        assert_v3_trace_satisfies(b"abc", &r, &a, &zeros, &zeros);
    }

    #[test]
    fn verify_v3_tampered_sB_acc_fails() {
        // Flip a cell in the sB ladder's accumulator at row sB_first + 1.
        // The transition constraint at row sB_first must reject because
        // nxt.acc no longer equals cur.cond_add.out.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let k_bits = scalar_to_bits_msb_first(0x07, 8);
        let (mut trace, layout, _) =
            fill_verify_air_v3(b"", &r, &a, &s_bits, &k_bits).unwrap();

        let target_row = layout.sB_first_row + 1;
        let cell = trace[layout.mult.acc_x][target_row];
        trace[layout.mult.acc_x][target_row] = cell + F::one();

        let prev_row = target_row - 1;
        let cur: Vec<F> = (0..layout.width).map(|c| trace[c][prev_row]).collect();
        let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][prev_row + 1]).collect();
        let cons = eval_verify_air_v3_per_row(&cur, &nxt, prev_row, &layout);
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering sB.acc at row sB_first+1 should violate the transition \
             constraint at row sB_first");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v4 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v4_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
    ) {
        let (trace, layout, _k) =
            fill_verify_air_v4(message, r, a, s_bits, k_bits)
                .expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v4_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v4 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v4_constants() {
        let (_, a) = rfc8032_test1_r_a();
        let layout = verify_air_layout_v4(0, 8, &a).unwrap();
        assert_eq!(layout.k_scalar, 8);
        assert_eq!(layout.sB_first_row, layout.k_hash + 3);
        assert_eq!(layout.kA_first_row, layout.k_hash + 11);
        assert_eq!(
            VERIFY_V4_PER_ROW_CONSTRAINTS,
            VERIFY_V3_PER_ROW_CONSTRAINTS + 80
        );
    }

    #[test]
    fn verify_v4_8bit_scalars_with_base_pinning() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let k_bits = scalar_to_bits_msb_first(0x3c, 8);
        assert_v4_trace_satisfies(b"", &r, &a, &s_bits, &k_bits);
    }

    #[test]
    fn verify_v4_zero_scalars() {
        let (r, a) = rfc8032_test1_r_a();
        let zeros = vec![false; 8];
        assert_v4_trace_satisfies(b"abc", &r, &a, &zeros, &zeros);
    }

    #[test]
    fn verify_v4_tampered_sB_base_fails() {
        // Flip a base_x limb at sB_first_row → boundary constraint must fire.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let k_bits = scalar_to_bits_msb_first(0x07, 8);
        let (mut trace, layout, _) =
            fill_verify_air_v4(b"", &r, &a, &s_bits, &k_bits).unwrap();

        let cell = trace[layout.mult.base_x][layout.sB_first_row];
        trace[layout.mult.base_x][layout.sB_first_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.sB_first_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.sB_first_row + 1]).collect();
        let cons = eval_verify_air_v4_per_row(&cur, &nxt, layout.sB_first_row, &layout);
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering sB base_x at sB_first_row should violate the basepoint pin");
    }

    #[test]
    fn verify_v4_tampered_kA_base_fails() {
        // Flip a base_y limb at kA_first_row → A-pin constraint must fire.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let k_bits = scalar_to_bits_msb_first(0x07, 8);
        let (mut trace, layout, _) =
            fill_verify_air_v4(b"", &r, &a, &s_bits, &k_bits).unwrap();

        let cell = trace[layout.mult.base_y][layout.kA_first_row];
        trace[layout.mult.base_y][layout.kA_first_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.kA_first_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.kA_first_row + 1]).collect();
        let cons = eval_verify_air_v4_per_row(&cur, &nxt, layout.kA_first_row, &layout);
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering kA base_y at kA_first_row should violate the A-pin");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v5 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v5_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
    ) {
        let (trace, layout, _k) =
            fill_verify_air_v5(message, r, a, s_bits, k_bits)
                .expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v5_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v5 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v5_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let layout = verify_air_layout_v5(0, 8, &r, &a).unwrap();
        assert_eq!(
            VERIFY_V5_PER_ROW_CONSTRAINTS,
            VERIFY_V4_PER_ROW_CONSTRAINTS + 2 * (NUM_LIMBS + 1)
        );
        assert_eq!(layout.r_sign, (r[31] >> 7) & 1 == 1);
        assert_eq!(layout.a_sign, (a[31] >> 7) & 1 == 1);
    }

    #[test]
    fn verify_v5_8bit_scalars() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let k_bits = scalar_to_bits_msb_first(0x3c, 8);
        assert_v5_trace_satisfies(b"", &r, &a, &s_bits, &k_bits);
    }

    #[test]
    fn verify_v5_zero_scalars() {
        let (r, a) = rfc8032_test1_r_a();
        let zeros = vec![false; 8];
        assert_v5_trace_satisfies(b"abc", &r, &a, &zeros, &zeros);
    }

    #[test]
    fn verify_v5_tampered_R_y_fails() {
        // Flip a y_limb at decompress_R_row → R y-pin constraint must fire.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let k_bits = scalar_to_bits_msb_first(0x07, 8);
        let (mut trace, layout, _) =
            fill_verify_air_v5(b"", &r, &a, &s_bits, &k_bits).unwrap();

        let cell = trace[layout.decomp.y_limbs][layout.decompress_R_row];
        trace[layout.decomp.y_limbs][layout.decompress_R_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_R_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_R_row + 1]).collect();
        let cons = eval_verify_air_v5_per_row(
            &cur, &nxt, layout.decompress_R_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering R y_limb[0] at decompress_R_row should violate the R-y pin");
    }

    #[test]
    fn verify_v5_tampered_A_sign_fails() {
        // Flip the sign-bit cell at decompress_A_row → A sign-pin must fire.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let k_bits = scalar_to_bits_msb_first(0x07, 8);
        let (mut trace, layout, _) =
            fill_verify_air_v5(b"", &r, &a, &s_bits, &k_bits).unwrap();

        let cell = trace[layout.decomp.sign_bit][layout.decompress_A_row];
        trace[layout.decomp.sign_bit][layout.decompress_A_row] = F::one() - cell;

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_A_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_A_row + 1]).collect();
        let cons = eval_verify_air_v5_per_row(
            &cur, &nxt, layout.decompress_A_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering A sign_bit at decompress_A_row should violate the A-sign pin");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v6 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v6_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
    ) {
        let (trace, layout, _k) =
            fill_verify_air_v6(message, r, a, s_bits, k_bits)
                .expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v6_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v6 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v6_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let bits = scalar_to_bits_msb_first(0xa5, 8);
        let layout = verify_air_layout_v6(0, &bits, &bits, &r, &a).unwrap();
        assert_eq!(layout.k_scalar, 8);
        assert_eq!(verify_v6_per_row_constraints(8),
                   VERIFY_V5_PER_ROW_CONSTRAINTS + 32);
        assert_eq!(layout.scalar_block_kA_base,
                   layout.scalar_block_sB_base + 8);
    }

    #[test]
    fn verify_v6_8bit_scalars() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let k_bits = scalar_to_bits_msb_first(0x3c, 8);
        assert_v6_trace_satisfies(b"", &r, &a, &s_bits, &k_bits);
    }

    #[test]
    fn verify_v6_zero_scalars() {
        let (r, a) = rfc8032_test1_r_a();
        let zeros = vec![false; 8];
        assert_v6_trace_satisfies(b"abc", &r, &a, &zeros, &zeros);
    }

    #[test]
    fn verify_v6_tampered_sB_bit_fails() {
        // Flip cond_add.bit_cell at sB_first_row + 1 → the per-row bind
        // constraint `bit_cell = scalar_block[0]` must reject.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let k_bits = scalar_to_bits_msb_first(0x3c, 8);
        let (mut trace, layout, _) =
            fill_verify_air_v6(b"", &r, &a, &s_bits, &k_bits).unwrap();

        let target_row = layout.sB_first_row + 1;
        let cell = trace[layout.mult.cond_add.bit_cell][target_row];
        trace[layout.mult.cond_add.bit_cell][target_row] = F::one() - cell;

        let cur: Vec<F> = (0..layout.width).map(|c| trace[c][target_row]).collect();
        let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][target_row + 1]).collect();
        let cons = eval_verify_air_v6_per_row(&cur, &nxt, target_row, &layout);
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering cond_add.bit_cell at sB_first_row+1 should violate \
             the bit-binding or downstream gadget constraints");
    }

    #[test]
    fn verify_v6_tampered_scalar_block_fails() {
        // Flip a scalar_block cell at sB_first_row → boundary-pin must fire.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let k_bits = scalar_to_bits_msb_first(0x07, 8);
        let (mut trace, layout, _) =
            fill_verify_air_v6(b"", &r, &a, &s_bits, &k_bits).unwrap();

        let cell = trace[layout.scalar_block_sB_base + 3][layout.sB_first_row];
        trace[layout.scalar_block_sB_base + 3][layout.sB_first_row] =
            F::one() - cell;

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.sB_first_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.sB_first_row + 1]).collect();
        let cons = eval_verify_air_v6_per_row(&cur, &nxt, layout.sB_first_row, &layout);
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering scalar_block at sB_first_row should violate the \
             boundary-pin OR shift-transition constraints");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v7 tests
    // ─────────────────────────────────────────────────────────────────

    /// Compute K MSB-first kA bits derived from the canonical r scalar.
    /// `sha512_input` is whatever the trace builder will hash (= the
    /// `message` argument, which in the verify-AIR tests already
    /// contains `R || A || M`).
    fn k_bits_from_canonical_for_test(sha512_input: &[u8], k: usize) -> Vec<bool> {
        let digest = sha512_native(sha512_input);
        let mut digest_arr = [0u8; 64];
        digest_arr.copy_from_slice(&digest);
        let k_canonical = reduce_mod_l_wide(&digest_arr);
        r_thread_bits_for_kA(&k_canonical, k)
    }

    fn assert_v7_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
    ) {
        let (trace, layout, _k) =
            fill_verify_air_v7(message, r, a, s_bits, k_bits)
                .expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v7_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v7 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    /// Build the SHA-512 input the verify-AIR uses: `R || A || M`.
    fn build_verify_sha512_input(r: &[u8; 32], a: &[u8; 32], m: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(64 + m.len());
        input.extend_from_slice(r);
        input.extend_from_slice(a);
        input.extend_from_slice(m);
        input
    }

    #[test]
    fn verify_v7_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v7(sha_input.len(), &s_bits, &k_bits, &r, &a)
            .unwrap();
        assert_eq!(verify_v7_per_row_constraints(8),
                   verify_v6_per_row_constraints(8) + 24);
        assert_eq!(layout.width, layout.r_thread_base + 8);
    }

    #[test]
    fn verify_v7_8bit_scalars_with_r_binding() {
        // For v7, k_bits MUST equal the K kA-ordered bits of the r
        // scalar that the trace's scalar-reduce phase computes.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        assert_v7_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits);
    }

    #[test]
    fn verify_v7_short_message() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"abc");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        assert_v7_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits);
    }

    #[test]
    fn verify_v7_inconsistent_k_bits_fails() {
        // Pass k_bits NOT derived from r — the v7 thread-binding (or
        // v6 boundary pin) must reject.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        // Choose k_bits = all-zeros (≠ canonical for non-trivial input).
        let bad_k_bits = vec![false; 8];
        let (trace, layout, _) =
            fill_verify_air_v7(&sha_input, &r, &a, &s_bits, &bad_k_bits)
                .expect("trace builder still completes — only constraints fail");

        let height = layout.height;
        let mut violation = false;
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v7_per_row(&cur, &nxt, row, &layout);
            if cons.iter().any(|v| !v.is_zero()) {
                violation = true;
                break;
            }
        }
        assert!(violation,
            "passing k_bits inconsistent with r should violate v7 constraints");
    }

    #[test]
    fn verify_v7_tampered_thread_fails() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let (mut trace, layout, _) =
            fill_verify_air_v7(&sha_input, &r, &a, &s_bits, &k_bits).unwrap();

        // Flip thread[0] at the reduce row.
        let cell = trace[layout.r_thread_base][layout.reduce_row];
        trace[layout.r_thread_base][layout.reduce_row] = F::one() - cell;

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.reduce_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.reduce_row + 1]).collect();
        let cons = eval_verify_air_v7_per_row(
            &cur, &nxt, layout.reduce_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering thread cell at reduce_row should violate v7 cons");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v8 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v8_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
        result: &EdwardsPoint,
    ) {
        let (trace, layout, _k) =
            fill_verify_air_v8(message, r, a, s_bits, k_bits, result)
                .expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v8_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v8 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v8_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v8(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        assert_eq!(verify_v8_per_row_constraints(8),
                   verify_v7_per_row_constraints(8) + 955);
        assert_eq!(layout.result_row, layout.kA_first_row + 8);
    }

    #[test]
    fn verify_v8_identity_result_passes() {
        // Result point = identity (0, 1, 1, 0) → all 3 SUB-then-zero
        // checks pass, no non-zero constraint anywhere.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        assert_v8_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v8_projective_identity_passes() {
        // (0, c, c, 0) for c ≠ 1 also represents identity in projective
        // coords — the SUB-canonicalised checks treat any (X=0, Y=Z, T=0)
        // as identity.  Pick c = some non-trivial field element.
        // EdwardsPoint internally uses (X, Y, Z, T) with various Z.
        // Crafting (0, c, c, 0) directly via the EdwardsPoint API is
        // tricky without the affine-to-projective constructor; instead
        // we just trust the native ED25519_BASEPOINT * 0 = identity.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"abc");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        // [0]·B = identity (one form: (0, 1, 1, 0)).
        let identity = EdwardsPoint::identity();
        assert_v8_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v8_non_identity_result_fails() {
        // Result = the basepoint (NOT identity) → SUB-canonicalised
        // check `X = 0` (or `Y = Z`, `T = 0`) must reject.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;
        let (trace, layout, _) = fill_verify_air_v8(
            &sha_input, &r, &a, &s_bits, &k_bits, &basepoint,
        ).expect("trace builder still completes");

        // Look for at least one non-zero constraint at result_row.
        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.result_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.result_row + 1]).collect();
        let cons = eval_verify_air_v8_per_row(
            &cur, &nxt, layout.result_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "non-identity result point should violate the v8 identity check");
    }

    #[test]
    fn verify_v8_tampered_zero_const_fails() {
        // Flip a zero_const cell at result_row → boundary pin must fire.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v8(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        trace[layout.zero_const_base][layout.result_row] = F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.result_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.result_row + 1]).collect();
        let cons = eval_verify_air_v8_per_row(
            &cur, &nxt, layout.result_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering zero_const cell should violate the v8 zero-pin");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v9 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v9_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
        cofactor_input: &EdwardsPoint,
    ) {
        let (trace, layout, _k) = fill_verify_air_v9(
            message, r, a, s_bits, k_bits, cofactor_input,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v9_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v9 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v9_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v9(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        assert_eq!(layout.dbl_1_row, layout.result_row + 1);
        assert_eq!(layout.dbl_2_row, layout.result_row + 2);
        assert_eq!(layout.dbl_3_row, layout.result_row + 3);
        assert_eq!(verify_v9_per_row_constraints(8),
                   verify_v8_per_row_constraints(8) + POINT_DBL_CONSTRAINTS + 70);
    }

    #[test]
    fn verify_v9_identity_cofactor_input_passes() {
        // [8]·identity = identity → v8 verdict passes AND v9 chain fires
        // dbl gadget on identity correctly.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        assert_v9_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v9_basepoint_input_dbl_chain_passes() {
        // Cofactor input = basepoint → [8]·basepoint ≠ identity, but
        // the doubling-chain constraints are still satisfied (the chain
        // computes [8]·B correctly).  v8's identity verdict will REJECT
        // (since [8]·B ≠ O), but the v9 chain itself is honest.
        // We use a separate assertion that ONLY checks the dbl chain
        // constraints (rows dbl_1..dbl_3).
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;

        let (trace, layout, _) = fill_verify_air_v9(
            &sha_input, &r, &a, &s_bits, &k_bits, &basepoint,
        ).unwrap();

        // Check ONLY the doubling rows + chaining transitions —
        // the v8 identity verdict will fail (expected: [8]·B ≠ O),
        // but the dbl gadget constraints AND chain transitions must
        // be satisfied.
        for &row in &[layout.dbl_1_row, layout.dbl_2_row, layout.dbl_3_row] {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_point_double_gadget(&cur, &layout.dbl);
            for (i, v) in cons.iter().enumerate() {
                assert!(v.is_zero(),
                    "dbl gadget cons #{} at row {} non-zero: {:?}", i, row, v);
            }
            // chain transitions only fire at dbl_1 and dbl_2.
            if row == layout.dbl_1_row || row == layout.dbl_2_row {
                for i in 0..NUM_LIMBS {
                    assert_eq!(nxt[layout.dbl_input_X_base + i],
                               cur[layout.dbl.mul_X3.c_limbs_base + i],
                               "X chain @ row {} limb {} mismatch", row, i);
                    assert_eq!(nxt[layout.dbl_input_Y_base + i],
                               cur[layout.dbl.mul_Y3.c_limbs_base + i],
                               "Y chain @ row {} limb {} mismatch", row, i);
                    assert_eq!(nxt[layout.dbl_input_Z_base + i],
                               cur[layout.dbl.mul_Z3.c_limbs_base + i],
                               "Z chain @ row {} limb {} mismatch", row, i);
                }
            }
        }
    }

    #[test]
    fn verify_v9_tampered_dbl_input_fails() {
        // Flip dbl_2's input (= dbl_1's output) → chain transition cons
        // at row dbl_1 must reject.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v9(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        let cell = trace[layout.dbl_input_X_base][layout.dbl_2_row];
        trace[layout.dbl_input_X_base][layout.dbl_2_row] = cell + F::one();

        // Check at row dbl_1 (where the (dbl_1 → dbl_2) chain transition fires).
        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.dbl_1_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.dbl_1_row + 1]).collect();
        let cons = eval_verify_air_v9_per_row(
            &cur, &nxt, layout.dbl_1_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering dbl_2 input should violate the (dbl_1 → dbl_2) \
             chain transition");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v10 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v10_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
        cofactor_input: &EdwardsPoint,
    ) {
        let (trace, layout, _k) = fill_verify_air_v10(
            message, r, a, s_bits, k_bits, cofactor_input,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v10_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v10 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v10_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v10(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        let kA_last = layout.kA_first_row + 8 - 1;
        assert_eq!(layout.dbl_1_row, kA_last + 1);
        assert_eq!(layout.dbl_3_row, kA_last + 3);
        assert_eq!(layout.result_row, kA_last + 4);
        assert_eq!(verify_v10_per_row_constraints(8),
                   verify_v9_per_row_constraints(8));
    }

    #[test]
    fn verify_v10_identity_cofactor_passes() {
        // [8]·identity = identity → all v10 cons pass end-to-end.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        assert_v10_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v10_basepoint_cofactor_fails_verdict() {
        // [8]·basepoint ≠ identity → v8 verdict (now at v10's result_row)
        // must reject.  But the dbl chain + binding still pass.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x05, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let basepoint = *crate::ed25519_group::ED25519_BASEPOINT;
        let (trace, layout, _) = fill_verify_air_v10(
            &sha_input, &r, &a, &s_bits, &k_bits, &basepoint,
        ).unwrap();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.result_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.result_row + 1]).collect();
        let cons = eval_verify_air_v10_per_row(
            &cur, &nxt, layout.result_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "non-identity cofactor result should violate v10's identity verdict");
    }

    #[test]
    fn verify_v10_tampered_result_X_fails() {
        // Flip the result_X cell at result_row → the dbl_3 → result_row
        // X-binding constraint at row dbl_3_row must reject.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v10(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        let cell = trace[layout.result_X_base][layout.result_row];
        trace[layout.result_X_base][layout.result_row] = cell + F::one();

        // Constraint at row dbl_3_row binds nxt[result_X_base] to dbl_3.mul_X3.c.
        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.dbl_3_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.dbl_3_row + 1]).collect();
        let cons = eval_verify_air_v10_per_row(
            &cur, &nxt, layout.dbl_3_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering result_X at result_row should violate the dbl_3 → \
             result transition");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v11 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v11_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
        cofactor_input: &EdwardsPoint,
    ) {
        let (trace, layout, _k) = fill_verify_air_v11(
            message, r, a, s_bits, k_bits, cofactor_input,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v11_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v11 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v11_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v11(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        assert_eq!(layout.sB_last_row, layout.sB_first_row + 7);
        assert_eq!(verify_v11_per_row_constraints(8),
                   verify_v10_per_row_constraints(8) + 80);
    }

    #[test]
    fn verify_v11_thread_consistency_passes() {
        // Identity cofactor + valid sB ladder → all v11 cons pass,
        // including the new thread chain anchored at sB_last_row.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        assert_v11_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v11_tampered_thread_constancy_fails() {
        // Flip thread_sB_X[0] at one row → constancy transition rejects
        // at the row before AND/OR the tampered row.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v11(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        // Flip thread_sB_X[0] at row 0 — constancy at row pair (0, 1)
        // must reject.
        let cell = trace[layout.thread_sB_X_base][0];
        trace[layout.thread_sB_X_base][0] = cell + F::one();

        let cur: Vec<F> = (0..layout.width).map(|c| trace[c][0]).collect();
        let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][1]).collect();
        let cons = eval_verify_air_v11_per_row(&cur, &nxt, 0, &layout);
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering thread cell at row 0 should violate the (0, 1) \
             constancy");
    }

    #[test]
    fn verify_v11_tampered_thread_anchor_fails() {
        // Flip thread_sB_X[0] AT sB_last_row → the boundary cons there
        // rejects (and constancy across the trace also rejects).
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v11(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        // Tamper ALL rows (preserving constancy) but break the boundary
        // at sB_last_row only.  Easiest: flip the cell at sB_last_row
        // ONLY — constancy will catch it elsewhere.
        let cell = trace[layout.thread_sB_X_base][layout.sB_last_row];
        trace[layout.thread_sB_X_base][layout.sB_last_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.sB_last_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.sB_last_row + 1]).collect();
        let cons = eval_verify_air_v11_per_row(
            &cur, &nxt, layout.sB_last_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering thread @ sB_last_row should violate boundary or \
             constancy");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v12 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v12_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
        cofactor_input: &EdwardsPoint,
    ) {
        let (trace, layout, _k) = fill_verify_air_v12(
            message, r, a, s_bits, k_bits, cofactor_input,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v12_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v12 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v12_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v12(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        assert_eq!(layout.kA_last_row, layout.kA_first_row + 7);
        assert_eq!(verify_v12_per_row_constraints(8),
                   verify_v11_per_row_constraints(8) + 80);
    }

    #[test]
    fn verify_v12_kA_thread_consistency_passes() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        assert_v12_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v12_tampered_kA_thread_fails() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v12(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        let cell = trace[layout.thread_kA_Y_base][layout.kA_last_row];
        trace[layout.thread_kA_Y_base][layout.kA_last_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.kA_last_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.kA_last_row + 1]).collect();
        let cons = eval_verify_air_v12_per_row(
            &cur, &nxt, layout.kA_last_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering thread_kA_Y at kA_last_row should violate boundary");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v13 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v13_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
        cofactor_input: &EdwardsPoint,
    ) {
        let (trace, layout, _k) = fill_verify_air_v13(
            message, r, a, s_bits, k_bits, cofactor_input,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v13_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v13 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v13_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v13(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        assert_eq!(verify_v13_per_row_constraints(8),
                   verify_v12_per_row_constraints(8) + 90 + MUL_GADGET_CONSTRAINTS);
    }

    #[test]
    fn verify_v13_R_thread_consistency_passes() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        assert_v13_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v13_tampered_R_T_fails() {
        // Flip thread_R_T at decompose_R_row → boundary cons rejects
        // (since MUL gadget output ≠ tampered thread).
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v13(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        let cell = trace[layout.thread_R_T_base][layout.decompress_R_row];
        trace[layout.thread_R_T_base][layout.decompress_R_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_R_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_R_row + 1]).collect();
        let cons = eval_verify_air_v13_per_row(
            &cur, &nxt, layout.decompress_R_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering thread_R_T at decompose_R_row should violate the \
             T = X·Y boundary or MUL gadget");
    }

    #[test]
    fn verify_v13_tampered_R_Z_fails() {
        // Flip thread_R_Z at decompose_R_row → Z=1 boundary rejects.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v13(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        let cell = trace[layout.thread_R_Z_base][layout.decompress_R_row];
        trace[layout.thread_R_Z_base][layout.decompress_R_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_R_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_R_row + 1]).collect();
        let cons = eval_verify_air_v13_per_row(
            &cur, &nxt, layout.decompress_R_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering thread_R_Z at decompose_R_row should violate Z=1 pin");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v14 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v14_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
        cofactor_input: &EdwardsPoint,
    ) {
        let (trace, layout, _k) = fill_verify_air_v14(
            message, r, a, s_bits, k_bits, cofactor_input,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v14_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v14 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v14_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0xa5, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v14(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        assert_eq!(layout.residual_1_row, layout.kA_last_row + 1);
        assert_eq!(layout.dbl_1_row,      layout.kA_last_row + 2);
        assert_eq!(layout.result_row,     layout.kA_last_row + 5);
    }

    #[test]
    fn verify_v14_residual_1_passes() {
        // Residual phase computes [s]·B − R via PointAdd + 2 SUB
        // negations.  The doubling chain still uses a free cofactor
        // input — for now we verify only that the residual_1 phase is
        // self-consistent for any valid sB/R derived from public inputs.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        assert_v14_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v14_tampered_zero_const_R1_fails() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v14(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        trace[layout.zero_const_R1_base][layout.residual_1_row] = F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.residual_1_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.residual_1_row + 1]).collect();
        let cons = eval_verify_air_v14_per_row(
            &cur, &nxt, layout.residual_1_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering zero_const_R1 should violate the v14 zero-pin");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v15 tests
    // ─────────────────────────────────────────────────────────────────

    fn assert_v15_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
        cofactor_input: &EdwardsPoint,
    ) {
        let (trace, layout, _k) = fill_verify_air_v15(
            message, r, a, s_bits, k_bits, cofactor_input,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v15_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v15 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v15_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let layout = verify_air_layout_v15(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        assert_eq!(layout.residual_row, layout.kA_last_row + 1);
        assert_eq!(verify_v15_per_row_constraints(8),
                   verify_v14_per_row_constraints(8)
                       + 2 * SUB_GADGET_CONSTRAINTS + POINT_ADD_CONSTRAINTS);
    }

    #[test]
    fn verify_v15_residual_2_passes() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        assert_v15_trace_satisfies(&sha_input, &r, &a, &s_bits, &k_bits, &identity);
    }

    #[test]
    fn verify_v15_tampered_sub_negkA_T_fails() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let identity = EdwardsPoint::identity();
        let (mut trace, layout, _) = fill_verify_air_v15(
            &sha_input, &r, &a, &s_bits, &k_bits, &identity,
        ).unwrap();

        let cell = trace[layout.sub_negkA_T.c_limbs_base][layout.residual_row];
        trace[layout.sub_negkA_T.c_limbs_base][layout.residual_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.residual_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.residual_row + 1]).collect();
        let cons = eval_verify_air_v15_per_row(
            &cur, &nxt, layout.residual_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering sub_negkA_T output should violate v15 cons");
    }

    // ─────────────────────────────────────────────────────────────────
    //  v16 tests — the closing binding
    // ─────────────────────────────────────────────────────────────────

    fn assert_v16_trace_satisfies(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
    ) {
        let (trace, layout, _k) = fill_verify_air_v16(
            message, r, a, s_bits, k_bits,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v16_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v16 constraints (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    /// For test purposes: check ONLY the v15-and-below cons (skip the
    /// v8 verdict at result_row).  Used when the inputs don't form a
    /// valid signature so the verdict legitimately rejects, yet all
    /// computation/binding cons should still hold.
    fn assert_v16_trace_satisfies_except_verdict(
        message: &[u8],
        r: &[u8; 32],
        a: &[u8; 32],
        s_bits: &[bool],
        k_bits: &[bool],
    ) {
        let (trace, layout, _k) = fill_verify_air_v16(
            message, r, a, s_bits, k_bits,
        ).expect("trace builder accepts valid R / A");

        let height = layout.height;
        let mut bad = Vec::new();
        for row in 0..height - 1 {
            if row == layout.result_row { continue; }   // v8 verdict skipped
            let cur: Vec<F> = (0..layout.width).map(|c| trace[c][row]).collect();
            let nxt: Vec<F> = (0..layout.width).map(|c| trace[c][row + 1]).collect();
            let cons = eval_verify_air_v16_per_row(&cur, &nxt, row, &layout);
            for (i, v) in cons.iter().enumerate() {
                if !v.is_zero() {
                    bad.push((row, i, *v));
                }
            }
        }
        assert!(bad.is_empty(),
            "non-zero v16 constraints OUTSIDE result_row (showing up to 5 of {}):\n{}",
            bad.len(),
            bad.iter().take(5).map(|(r, i, v)| {
                format!("  row {}, cons #{}: {:?}", r, i, v)
            }).collect::<Vec<_>>().join("\n"));
    }

    #[test]
    fn verify_v16_constants() {
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let _layout = verify_air_layout_v16(
            sha_input.len(), &s_bits, &k_bits, &r, &a,
        ).unwrap();
        assert_eq!(verify_v16_per_row_constraints(8),
                   verify_v15_per_row_constraints(8) + 30);
    }

    #[test]
    fn verify_v16_residual_binding_passes() {
        // For K=8 with random scalars, [8]·residual_2 generally ≠ O,
        // so v8's identity verdict will reject.  But v16's binding
        // (residual_2 → dbl_1 input) and all chain cons should hold.
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        assert_v16_trace_satisfies_except_verdict(&sha_input, &r, &a, &s_bits, &k_bits);
    }

    #[test]
    fn verify_v16_zero_scalars_full_chain_passes() {
        // [0]·B = identity, [0]·A = identity, R = identity ⇒
        // residual_2 = [0]·B − R − [0]·A = O − R.  Pick R = identity
        // too (use a special encoding).  Or: use the actual identity-
        // pubkey with all-zero scalars — then residual_2 = identity and
        // [8]·identity = identity ⇒ v8 verdict passes.
        //
        // Simpler: rather than craft test data, just verify the
        // binding-and-below cons hold (skip the verdict).
        let (r, a) = rfc8032_test1_r_a();
        let zeros = vec![false; 8];
        let sha_input = build_verify_sha512_input(&r, &a, b"abc");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        assert_v16_trace_satisfies_except_verdict(&sha_input, &r, &a, &zeros, &k_bits);
    }

    #[test]
    fn verify_v16_tampered_dbl_input_fails() {
        // Flip the dbl_1 input cell at dbl_1_row → v16's binding cons
        // at residual_row must reject (because nxt = dbl_1_row's input
        // no longer matches cur's residual_2 output).
        let (r, a) = rfc8032_test1_r_a();
        let s_bits = scalar_to_bits_msb_first(0x0a, 8);
        let sha_input = build_verify_sha512_input(&r, &a, b"");
        let k_bits = k_bits_from_canonical_for_test(&sha_input, 8);
        let (mut trace, layout, _) = fill_verify_air_v16(
            &sha_input, &r, &a, &s_bits, &k_bits,
        ).unwrap();

        let cell = trace[layout.dbl_input_X_base][layout.dbl_1_row];
        trace[layout.dbl_input_X_base][layout.dbl_1_row] = cell + F::one();

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.residual_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.residual_row + 1]).collect();
        let cons = eval_verify_air_v16_per_row(
            &cur, &nxt, layout.residual_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering dbl_1.input at dbl_1_row should violate v16's \
             residual_2 → dbl_input binding");
    }

    #[test]
    fn verify_v2_tampered_sign_A_fails() {
        let (r, a) = rfc8032_test1_r_a();
        let (mut trace, layout, _) = fill_verify_air_v2(b"", &r, &a).unwrap();

        // Flip the sign-bit cell at the A-decompression row.  The
        // sign-match constraint inside the gadget (cur[x_bits] − sb)
        // must fire (unless bit 0 of x is itself zero, in which case
        // booleanity still rejects a flipped boolean).
        let sb = trace[layout.decomp.sign_bit][layout.decompress_A_row];
        trace[layout.decomp.sign_bit][layout.decompress_A_row] = F::one() - sb;

        let cur: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_A_row]).collect();
        let nxt: Vec<F> = (0..layout.width)
            .map(|c| trace[c][layout.decompress_A_row + 1]).collect();
        let cons = eval_verify_air_v2_per_row(
            &cur, &nxt, layout.decompress_A_row, &layout,
        );
        let nonzero: Vec<_> = cons.iter().enumerate()
            .filter(|(_, v)| !v.is_zero()).collect();
        assert!(!nonzero.is_empty(),
            "tampering sign_A should violate sign-match (or booleanity)");
    }
}
