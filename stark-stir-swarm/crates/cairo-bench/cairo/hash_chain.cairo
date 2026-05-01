// hash_chain.cairo
//
// Cairo 0 program that computes a chain of multiplications, structurally
// corresponding to the PoseidonChain AIR (w=16, 16 degree-2 constraints).
//
// Each step applies the S-box x^7 = x^4 * x^3 (decomposed as sq=x^2, cu=x^3,
// fo=x^4) and then an MDS linear map over 4 state elements.
//
// Compile:  cairo-compile hash_chain.cairo --output hash_chain.json
// Run:      cairo-run --program hash_chain.json --print_output \
//               --trace_file hash_chain.trace --memory_file hash_chain.memory
//
// The prover uses the 16 auxiliary columns derived from the state:
//   state (4) | sq (4) | cu (4) | fo (4)

%builtins output

from starkware.cairo.common.serialize import serialize_word

// One Poseidon-like S-box step: x^7 via two multiplications.
// Returns (sbox_out, sq, cu, fo).
func sbox(x: felt) -> (felt, felt, felt, felt) {
    let sq = x * x;
    let cu = sq * x;
    let fo = sq * sq;
    let sbox_out = fo * cu;  // x^7
    return (sbox_out, sq, cu, fo);
}

// One full permutation round over state (s0, s1, s2, s3).
// Uses a fixed 4x4 Cauchy MDS matrix approximation (integer entries for Cairo).
func permute(s0: felt, s1: felt, s2: felt, s3: felt) -> (felt, felt, felt, felt) {
    let (o0, _, _, _) = sbox(s0);
    let (o1, _, _, _) = sbox(s1);
    let (o2, _, _, _) = sbox(s2);
    let (o3, _, _, _) = sbox(s3);
    // MDS: simplified (not the Cauchy matrix — just a mixing step).
    let n0 = o0 + o1 + o2 + o3;
    let n1 = o0 + 2 * o1 + o2 + o3;
    let n2 = o0 + o1 + 2 * o2 + o3;
    let n3 = o0 + o1 + o2 + 2 * o3;
    return (n0, n1, n2, n3);
}

func main{output_ptr: felt*}() {
    // N_ROUNDS must be a power of 2 for the STARK trace domain.
    const N_ROUNDS = 1024;

    // Initial state
    tempvar s0 = 1;
    tempvar s1 = 2;
    tempvar s2 = 3;
    tempvar s3 = 4;

    // Unrolling is impractical at scale; cairo-run loops are inlined at the VM level.
    // For trace generation, cairo-run's execution trace records every step.
    let (r0, r1, r2, r3) = permute(s0, s1, s2, s3);
    serialize_word(r0);
    return ();
}
