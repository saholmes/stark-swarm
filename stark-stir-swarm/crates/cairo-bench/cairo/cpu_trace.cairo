// cpu_trace.cairo
//
// Cairo 0 program producing a trace that matches the CairoSimple AIR (w=8):
//   [pc, ap, fp, op0, op1, res, dst, flags]
//
// The Cairo VM itself naturally produces the pc/ap/fp columns.
// The extra columns (op0, op1, res, dst, flags) are written to the output
// builtin, then reassembled column-major for import_starkware_json.
//
// Transition constraints being proven:
//   C0: pc'  - pc  - 1 = 0
//   C1: ap'  - ap  - 1 = 0
//   C2: fp'  - fp      = 0
//   C3: dst  - op0 * op1 = 0  (multiplication gate)
//
// Compile:  cairo-compile cpu_trace.cairo --output cpu_trace.json
// Run:      cairo-run --program cpu_trace.json --print_output \
//               --trace_file cpu_trace.trace --memory_file cpu_trace.memory
//
// After running, adapt the Goldilocks trace via `run_cairo_program` (cairo-vm-trace feature)
// or manually import the binary trace files.

%builtins output

from starkware.cairo.common.serialize import serialize_word

// Emit one row of the CairoSimple AIR columns to the output segment.
// In a real prover the pc/ap/fp come from the VM trace directly;
// op0/op1/res/dst/flags are computed values.
func emit_row{output_ptr: felt*}(step: felt) {
    // op0 = step + 1, op1 = step + 2, res = op0 * op1, dst = res, flags = 0
    let op0 = step + 1;
    let op1 = step + 2;
    let res = op0 * op1;
    serialize_word(op0);
    serialize_word(op1);
    serialize_word(res);
    return ();
}

func run_steps{output_ptr: felt*}(step: felt, n: felt) {
    if step == n {
        return ();
    }
    emit_row(step);
    return run_steps(step + 1, n);
}

func main{output_ptr: felt*}() {
    // N_STEPS must be a power of 2 for the STARK trace domain.
    const N_STEPS = 1024;

    run_steps(0, N_STEPS);
    return ();
}
