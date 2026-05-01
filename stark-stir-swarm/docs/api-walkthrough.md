# STARK API Walkthrough — Cairo AIR → Prove → Store → Verify

End-to-end usage example for `stark-server` covering:

1. A Cairo 0 source program
2. Compiling it to a trace
3. Converting the trace into StarkWare column-major JSON
4. `POST /v1/prove` with the trace, public inputs, and a NIST PQ security profile, written to disk in ethSTARK-split format
5. `POST /v1/verify` against the stored files
6. Standalone CLI verification
7. Tamper detection
8. Discovering supported security profiles

The example uses the **CairoSimple AIR** (`width = 8`, columns: `pc, ap, fp, op0, op1, res, dst, flags`) — its public inputs (initial/final `pc`, `ap`, `fp`, memory segments) are the same shape Cairo programs export.

---

## 0. Start the server

The hash variant is selected at compile time. Pick the one matching the NIST profile you want to serve (`SHA3-256` for L1/q=2⁴⁰, `SHA3-384` for L1/q=2⁶⁵ or L3/q=2⁴⁰, `SHA3-512` for everything else):

```bash
# Default build: SHA3-256 (covers Level 1, q=2^40)
cargo run --release -p stark-server

# Build for Level 5 / q=2^65 (Fp^8, SHA3-512, r=105)
cargo run --release -p stark-server --no-default-features --features sha3-512

# Environment knobs
STARK_PORT=3000 STARK_STORE_DIR=./stark-proofs \
    cargo run --release -p stark-server --no-default-features --features sha3-512
```

> **Hash architecture.** SHA-3-only is the canonical default for all
> Merkle commitments **and** the Fiat-Shamir transcript.  The optional
> `poseidon-accel` feature wires the paper's dual-hash leaf-compression
> path, but empirical measurement showed it is **81–84× slower** in
> software and is preserved only for recursive-AIR use cases.  See
> [`docs/cryptographic-architecture.md`](./cryptographic-architecture.md).

Health check:

```bash
curl http://localhost:3000/v1/health
```

List the security profiles this binary can serve:

```bash
curl http://localhost:3000/v1/security/profiles | jq .
```

```jsonc
{
  "build_hash": "SHA3-512",
  "profiles": [
    { "level": 1, "lambda_bits": 128, "quantum_budget_log2": 40,
      "ext_field": "Fp^6", "hash_alg": "SHA3-256", "r": 54,
      "supported_by_build": false, ... },
    { "level": 5, "lambda_bits": 256, "quantum_budget_log2": 65,
      "ext_field": "Fp^8", "hash_alg": "SHA3-512", "r": 105,
      "supported_by_build": true, ... },
    ...
  ]
}
```

`supported_by_build = false` rows require rebuilding with a different `--features sha3-…`.

---

## 1. Sample Cairo program

`crates/cairo-bench/cairo/cpu_trace.cairo` produces a trace whose 8 columns satisfy the CairoSimple AIR transition constraints:

```cairo
%builtins output

from starkware.cairo.common.serialize import serialize_word

func emit_row{output_ptr: felt*}(step: felt) {
    let op0 = step + 1;
    let op1 = step + 2;
    let res = op0 * op1;
    serialize_word(op0);
    serialize_word(op1);
    serialize_word(res);
    return ();
}

func run_steps{output_ptr: felt*}(step: felt, n: felt) {
    if step == n { return (); }
    emit_row(step);
    return run_steps(step + 1, n);
}

func main{output_ptr: felt*}() {
    const N_STEPS = 256;          // power of 2 — STARK trace domain
    run_steps(0, N_STEPS);
    return ();
}
```

## 2. Compile and run with cairo-vm

```bash
# Compile
cairo-compile crates/cairo-bench/cairo/cpu_trace.cairo \
    --output cpu_trace.json --proof_mode

# Run, emit raw trace + memory
cairo-run --program=cpu_trace.json \
    --trace_file=cpu_trace.trace \
    --memory_file=cpu_trace.memory \
    --print_output --proof_mode
```

The Cairo VM emits the `pc`, `ap`, `fp` columns directly; `op0`, `op1`, `res`, `dst`, `flags` are reconstructed from the memory segment.  Cairo 0 felts are reduced from the StarkNet prime to Goldilocks via:

```rust
use cairo_bench::felt_u64_to_goldilocks;
```

## 3. Convert to StarkWare column-major JSON

The API accepts `format: "starkware-v1"` traces.  After running cairo-vm, write:

```jsonc
// trace.json
{
  "format": "starkware-v1",
  "width": 8,
  "length": 256,
  "columns": {
    "pc":    [0, 1, 2, ..., 255],
    "ap":    [100, 101, ..., 355],
    "fp":    [100, 100, ..., 100],
    "op0":   [1, 2, ..., 256],
    "op1":   [2, 3, ..., 257],
    "res":   [2, 6, ..., 256*257],
    "dst":   [2, 6, ..., 256*257],
    "flags": [0, 0, ..., 0]
  }
}
```

> **Tip.** For a quick smoke test you can omit `columns` (set it to `{}`) and the server will build a synthetic trace from the AIR inferred by `width`. This is what the integration tests use.

The helper `cairo_bench::trace_to_starkware_json(&trace, &col_names)` produces this exactly.

## 4. Build the public inputs from the AIR

`CairoPublicInputs` mirrors ethSTARK's `public_input.json`:

```jsonc
// public_input.json (sent inline in the prove request)
{
  "program_hash": "0x0000…0001",
  "initial_pc": 0,
  "initial_ap": 100,
  "initial_fp": 100,
  "final_pc":   255,
  "final_ap":   355,
  "memory_segments": [
    { "start": 0,   "stop": 256 },
    { "start": 100, "stop": 356 }
  ],
  "public_memory": [
    { "address": 0, "value": 1 },
    { "address": 1, "value": 2 }
  ],
  "range_check_min": 0,
  "range_check_max": 65535
}
```

For the CairoSimple sample, use the helper:

```rust
use public_inputs::CairoPublicInputs;
use deep_ali::air_workloads::{CAIRO_SIMPLE_INITIAL_PC, CAIRO_SIMPLE_INITIAL_AP};
let pi = CairoPublicInputs::for_cairo_simple_air(
    CAIRO_SIMPLE_INITIAL_PC, CAIRO_SIMPLE_INITIAL_AP, /*n_trace=*/ 256,
);
```

## 5. POST /v1/prove

```bash
curl -X POST http://localhost:3000/v1/prove \
     -H 'Content-Type: application/json' \
     -d @- <<'JSON'
{
  "trace": {
    "format": "starkware-v1",
    "width":  8,
    "length": 256,
    "columns": {}        ← empty: server builds CairoSimple synthetic trace
  },
  "public_inputs": {
    "program_hash":     "0x0000000000000000000000000000000000000000000000000000000000000001",
    "initial_pc":       0,
    "initial_ap":       100,
    "initial_fp":       100,
    "final_pc":         255,
    "final_ap":         355,
    "memory_segments":  [{"start":0,"stop":256},{"start":100,"stop":356}],
    "public_memory":    [{"address":0,"value":1},{"address":1,"value":2}],
    "range_check_min":  0,
    "range_check_max":  65535
  },
  "config": {
    "nist_level":           5,
    "quantum_budget_log2":  65,
    "blowup":               4,
    "output_format":        "ethstark-split",
    "output_path":          "/proofs/sampleoutput"
  }
}
JSON
```

**Response**

```jsonc
{
  "proof_id":         "cf445b02-7930-4c5a-a111-fef29701d492",
  "prove_time_ms":    25,
  "proof_size_bytes": 2874568,
  "output_paths": {
    "params":       "/proofs/sampleoutput.params.json",
    "public_input": "/proofs/sampleoutput.public_input.json",
    "proof":        "/proofs/sampleoutput.proof.json"
  },
  "bundle":           { ... full bundle echoed inline ... }
}
```

The prover writes three files matching ethSTARK convention.  Their contents:

### `sampleoutput.params.json` (810 B)

```jsonc
{
  "format": "stark-stir-fips/params-v1",
  "proof_id": "cf445b02-…",
  "params": {
    "schedule":   [2,2,2,2,2,2,2,2,2,2],
    "r":          105,
    "blowup":     4,
    "n0":         1024,
    "air_type":   "cairo_simple_w8_d2",
    "security_level":      256,
    "nist_level":          5,
    "quantum_budget_log2": 65,
    "ext_degree":          8,
    "hash_alg":            "SHA3-512",
    "public_inputs_hash":  "8108e6253c…"
  },
  "metadata": { "prove_time_ms": 25, "proof_size_bytes": 2874568,
                "trace_width": 8, "trace_length": 256 }
}
```

### `sampleoutput.public_input.json` (≈ 800 B)

The Cairo public inputs verbatim, plus the SHA3-256 commitment that binds them to the proof.

### `sampleoutput.proof.json` (3.7 MB)

The FRI proof tree: Merkle roots, layer openings, query payloads, final low-degree polynomial.  All extension-field elements are arrays of `0x...` hex u64s; hashes are 64-hex (SHA3-256), 96-hex (SHA3-384), or 128-hex (SHA3-512) strings.

**Bundled (single-file) format.**  Drop the `output_format`/`output_path` fields and the server stores a single combined JSON under `${STARK_STORE_DIR}/{proof_id}.json`.

## 6. POST /v1/verify

Four input modes — pass exactly one:

### 6a. By split-file paths (matches step 5)

```bash
curl -X POST http://localhost:3000/v1/verify \
     -H 'Content-Type: application/json' \
     -d '{
       "split_paths": {
         "params":       "/proofs/sampleoutput.params.json",
         "public_input": "/proofs/sampleoutput.public_input.json",
         "proof":        "/proofs/sampleoutput.proof.json"
       }
     }'
```

### 6b. By stored proof_id

```bash
curl -X POST http://localhost:3000/v1/verify \
     -H 'Content-Type: application/json' \
     -d "{
       \"proof_id\": \"cf445b02-…\",
       \"public_inputs\": $(cat public_input.json)
     }"
```

### 6c. By bundle path (single-file)

```bash
curl -X POST http://localhost:3000/v1/verify \
     -d '{ "bundle_path": "/proofs/cf445b02.json",
           "public_inputs": { ... } }'
```

### 6d. Inline bundle

```bash
curl -X POST http://localhost:3000/v1/verify \
     -d '{ "bundle": { ...full bundle JSON... },
           "public_inputs": { ... } }'
```

**Response**

```jsonc
{
  "valid":          true,
  "proof_id":       "cf445b02-7930-4c5a-a111-fef29701d492",
  "verify_time_ms": 15,
  "message":        "proof is valid"
}
```

## 7. Standalone CLI verification

For air-gapped or CI-driven verification, the `verify_split` example takes the three file paths and runs verification with no server:

```bash
cargo run --release -p api --no-default-features --features sha3-512 \
    --example verify_split -- \
    /proofs/sampleoutput.params.json \
    /proofs/sampleoutput.public_input.json \
    /proofs/sampleoutput.proof.json
```

Exit code: `0` on `valid = true`, `1` on invalid or error. The verifier does **not** require the trace, witness, or any prover state — only the three public artifacts.

## 8. Tamper detection

Every layer of the protocol is independently checked:

| Tamper site | Caught by |
|-------------|-----------|
| `proof.root_f0` | Merkle authentication mismatch — recomputed root ≠ stored root |
| `queries[*].f_val[*]` | Merkle path walks back to a different root |
| `final_poly_coeffs[*]` | Batched degree check fails |
| Public-input file (any field) | SHA3-256 commitment hash mismatch — rejected before any FRI work |
| Hash-feature mismatch (proof made with SHA3-512, verifier built with SHA3-256) | Verifier returns `valid:false` with explicit error |

A single-nibble flip anywhere in the 3.7 MB proof flips at least one of these checks. Demonstrated in `crates/api/tests/level5_q65_e2e.rs` and reproducible with the corruption recipe in `examples/verify_split.rs`.

## 9. Discovering profiles

`GET /v1/security/profiles` returns all nine canonical (Level, q) combinations from Table III of the STIR-FIPS paper:

| Level | λ | q | Ext | Hash | r |
|-------|---|---|-----|------|---|
| 1 | 128 | 2⁴⁰ | Fp⁶ | SHA3-256 | 54 |
| 1 | 128 | 2⁶⁵ | Fp⁶ | SHA3-384 | 54 |
| 1 | 128 | 2⁹⁰ | Fp⁶ | SHA3-512 | 54 |
| 3 | 192 | 2⁴⁰ | Fp⁶ | SHA3-384 | 79 |
| 3 | 192 | 2⁶⁵ | Fp⁶ | SHA3-512 | 79 |
| 3 | 192 | 2⁹⁰ | Fp⁶ | SHA3-512 | 79 |
| 5 | 256 | 2⁴⁰ | Fp⁸ | SHA3-512 | 105 |
| 5 | 256 | 2⁶⁵ | Fp⁸ | SHA3-512 | 105 |
| 5 | 256 | 2⁹⁰ | Fp⁸ | SHA3-512 | 105 ⚠ binding wall |

The L5/q=2⁹⁰ row violates the FIPS-202 binding wall (κ_bind = 239 < λ = 256). The API rejects requests for it unless `allow_binding_wall_violation: true` is set explicitly — and even then the proof is **not FIPS-compliant**.

---

## Reference: full request / response schemas

### `POST /v1/prove`

```jsonc
{
  "trace": {
    "format":  "starkware-v1",     // optional label
    "width":   number,              // 2 | 8 | 16 (auto-selects AIR)
    "length":  number,              // power-of-2 ≥ 4
    "columns": {                    // {} → server builds synthetic trace
      "<col_name>": [u64, u64, ...]
    }
  },
  "public_inputs": CairoPublicInputs,
  "config": {
    "nist_level":          1 | 3 | 5,                       // optional
    "quantum_budget_log2": 40 | 65 | 90,                    // required if nist_level set
    "allow_binding_wall_violation": false,                  // L5/q=2^90 only
    "security_level":      number,                          // legacy bits, ignored when nist_level set
    "fri_mode":            "fri" | "stir",                  // default "fri"
    "blowup":              number,                          // default 4
    "output_format":       "bundle" | "ethstark-split",     // default "bundle"
    "output_path":         "/path/to/file_or_stem"          // optional
  }
}
```

Response:

```jsonc
{
  "proof_id":         "uuid",
  "prove_time_ms":    number,
  "proof_size_bytes": number,
  "bundle":           { full_bundle_json },
  "output_paths": {
    "bundle":       "/path.json"        // if format=bundle
    // — or —
    "params":       "/stem.params.json",      // if format=ethstark-split
    "public_input": "/stem.public_input.json",
    "proof":        "/stem.proof.json"
  }
}
```

### `POST /v1/verify`

```jsonc
{
  "proof_id":      "uuid",                       // mode 1
  "bundle":        { bundle_json },              // mode 2
  "bundle_path":   "/path.json",                 // mode 3
  "split_paths": {                                // mode 4
    "params":       "/...params.json",
    "public_input": "/...public_input.json",
    "proof":        "/...proof.json"
  },
  "public_inputs": CairoPublicInputs            // optional for mode 4
}
```

Provide **exactly one** of `proof_id`, `bundle`, `bundle_path`, `split_paths`. For mode 4 the `public_inputs` field is read from the file; if also provided inline it must match (SHA3-256 commitment).

Response:

```jsonc
{
  "valid":          true | false,
  "proof_id":       "uuid",
  "verify_time_ms": number,
  "message":        "proof is valid" | "<failure reason>"
}
```

### `GET /v1/security/profiles`

Returns `{ build_hash, profiles: [...] }` where each entry contains `level, lambda_bits, quantum_budget_log2, ext_field, hash_alg, r, kappa_{it,bind,fs,sys}, binding_wall_violated, supported_by_build`.

### `GET /v1/proofs` / `GET /v1/proofs/:id`

List stored proof IDs / fetch a stored bundle by ID.

### `GET /v1/health`

Liveness probe. Returns `{"status":"ok"}`.

---

## See also

- `crates/api/tests/level5_q65_e2e.rs` — full prove → verify integration test at Level 5 / q=2⁶⁵
- `crates/api/examples/verify_split.rs` — standalone CLI verifier
- `crates/cairo-bench/` — Criterion benchmarks across all four AIRs
- `crates/cairo-bench/cairo/*.cairo` — Cairo 0 source samples
