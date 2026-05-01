// fibonacci.cairo
//
// Cairo 0 program that computes the Fibonacci sequence.
// This program generates a trace that matches the Fibonacci AIR (w=2):
//   C0: c1' - c0 - c1 = 0
//
// Compile:  cairo-compile fibonacci.cairo --output fibonacci.json
// Run:      cairo-run --program fibonacci.json --print_output \
//               --trace_file fibonacci.trace --memory_file fibonacci.memory
//
// The resulting trace has 2 columns (c0, c1) of n_steps rows.
// Import into the prover via import_starkware_json or trace_inputs_from_air.

%builtins output

from starkware.cairo.common.serialize import serialize_word

// Iterative Fibonacci to keep the trace linear (no recursion overhead).
// Returns (fib_n, fib_n_plus_1) after n_steps iterations.
func fib_iter(c0: felt, c1: felt, n: felt) -> (felt, felt) {
    if n == 0 {
        return (c0, c1);
    }
    return fib_iter(c1, c0 + c1, n - 1);
}

func main{output_ptr: felt*}() {
    // N_STEPS must be a power of 2 for the STARK trace domain.
    // Change this constant to bench different trace sizes (256, 1024, 4096, 16384).
    const N_STEPS = 1024;

    let (result, _) = fib_iter(1, 1, N_STEPS - 1);
    serialize_word(result);
    return ();
}
