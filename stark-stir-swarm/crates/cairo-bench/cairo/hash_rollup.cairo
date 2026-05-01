// hash_rollup.cairo
//
// Cairo 0 program that mirrors the HashRollup AIR (w=4):
//   state' = state² + leaf
//
// Used for the recursion / rollup demo: two inner STARK proofs each
// produce a 32-byte SHA3-256 commitment over their public inputs.
// Those two commitments (8 felts total, 4 per hash) are streamed as
// `leaf` values into this hash chain; the final `state` is the rolled-up
// commitment that the outer rollup STARK proves.
//
// Compile:  cairo-compile hash_rollup.cairo --output hash_rollup.json
// Run:      cairo-run --program hash_rollup.json --print_output \
//               --trace_file hash_rollup.trace --memory_file hash_rollup.memory
//
// In our pipeline, the rollup leaves are usually built host-side from the
// inner-proof commitments via `pack_hash_to_leaves` and submitted via the
// REST API as `air_type: "hash_rollup"` with explicit trace columns.

%builtins output

from starkware.cairo.common.serialize import serialize_word

// One absorption step: state' = state² + leaf
func absorb(state: felt, leaf: felt) -> (felt) {
    return (state * state + leaf,);
}

// Run `n` absorption steps starting from `state`, reading leaves[i] for i in [0, n).
// In Cairo 0 we model the leaves as a function of the row index for compactness;
// in the host pipeline the leaves are SHA3-256 bytes packed 8 bytes per felt.
func run_rollup(state: felt, idx: felt, n: felt, leaves: felt*) -> (felt) {
    if idx == n {
        return (state,);
    }
    let leaf = leaves[idx];
    let (next_state) = absorb(state, leaf);
    return run_rollup(next_state, idx + 1, n, leaves);
}

func main{output_ptr: felt*}() {
    // 16 leaves: 4 felts for each of two inner-proof commitments + 8 zero-padding.
    // Replace these with the actual packed SHA3-256 hashes when running on a
    // real rollup; the constants below are placeholders to make the program
    // self-contained for cairo-compile/cairo-run inspection.
    tempvar leaves = new (
        // pi_hash_A packed as 4 little-endian u64 felts
        0x4275f21b5f4ce037, 0xf566375a7c7d267f, 0x41c922e9f63e2876, 0x593d937171986430,
        // pi_hash_B packed as 4 little-endian u64 felts
        0x68cfac9d09c030fb, 0xa7f0bdfe0490e081, 0x9ae26b0a0f1da41f, 0x54147aa1fd6b7218,
        // zero-padding to power-of-2 trace length
        0, 0, 0, 0, 0, 0, 0, 0,
    );

    const N = 16;
    let (rolled_up) = run_rollup(0, 0, N, leaves);
    serialize_word(rolled_up);
    return ();
}
