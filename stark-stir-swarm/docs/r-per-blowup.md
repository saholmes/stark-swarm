# Query count `r` recalibrated per blowup factor

## The Johnson-regime relationship

In the Johnson regime (the conjecture-free soundness mode used by the
ESORICS paper for FIPS-140-3 alignment), per-FRI/STIR-query rejection
error is

$$
  \varepsilon_{\text{per-query}} = 1 - \delta_{\text{Johnson}}(\rho)
                                  = \sqrt{\rho_0}
$$

where $\rho_0 = 1/\text{blowup}$ is the initial Reed-Solomon rate.
Per-query bits-of-soundness is therefore

$$
  \frac{\text{bits}}{\text{query}} = -\log_2\!\sqrt{\rho_0} = \tfrac{1}{2}\,\log_2(\text{blowup}).
$$

To meet a target information-theoretic soundness $\kappa_{\text{IT}}$ in
bits, the prover must perform

$$
  r(\text{blowup}) = \left\lceil \frac{\kappa_{\text{IT}}}{\tfrac{1}{2}\,\log_2(\text{blowup})} \right\rceil
                   = \left\lceil \frac{2\,\kappa_{\text{IT}}}{\log_2(\text{blowup})} \right\rceil.
$$

The paper Table III $r$ values (54 / 79 / 105 for L1 / L3 / L5) are the
specialisation of this formula at $\text{blowup} = 32$, where bits/query = 2.5.

## Code

```rust
impl SecurityProfile {
    pub fn r_for_blowup(&self, blowup: usize) -> Result<usize, ProfileError> {
        if blowup < 2 || !blowup.is_power_of_two() {
            return Err(ProfileError::InvalidBlowup(blowup));
        }
        let log_b = blowup.trailing_zeros() as f64;
        let bits_per_query = 0.5 * log_b;
        Ok((self.kappa_it as f64 / bits_per_query).ceil() as usize)
    }
}
```

The API's prove route now calls this for every request:

```rust
let r = profile.r_for_blowup(blowup)
    .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
```

## Recalibrated `r` for every (Level, q-budget, blowup) ∈ paper × {2,4,8,16,32,64,128}

The table below is computed by the new `kappa_it_at_blowup` method;
verify with `cargo test --release -p api --lib security`.

### NIST L1 (λ=128), κ_IT = 135

| blowup | bits / query | **r** | Realised κ_IT |
|-------:|-------------:|------:|--------------:|
| **2** | 0.5 | **270** | 135 |
| **4** | 1.0 | **135** | 135 |
| **8** | 1.5 | **90** | 135 |
| **16** | 2.0 | **68** | 136 |
| **32** | 2.5 | **54** | 135 (paper Table III ✓) |
| **64** | 3.0 | **45** | 135 |
| **128** | 3.5 | **39** | 136 |

### NIST L1 (λ=128), κ_IT = 197 (q ≥ 2⁶⁵)

(Unused — Level 1 only requires κ_IT = 135 at all q-budgets per Table III.
Listed for completeness with the q=2⁹⁰ row's κ_IT.)

### NIST L3 (λ=192), κ_IT = 197

| blowup | bits / query | **r** | Realised κ_IT |
|-------:|-------------:|------:|--------------:|
| **2** | 0.5 | **394** | 197 |
| **4** | 1.0 | **197** | 197 |
| **8** | 1.5 | **132** | 198 |
| **16** | 2.0 | **99** | 198 |
| **32** | 2.5 | **79** | 197 (paper Table III ✓) |
| **64** | 3.0 | **66** | 198 |
| **128** | 3.5 | **57** | 199 |

### NIST L5 (λ=256), κ_IT = 262

| blowup | bits / query | **r** | Realised κ_IT |
|-------:|-------------:|------:|--------------:|
| **2** | 0.5 | **524** | 262 |
| **4** | 1.0 | **262** | 262 |
| **8** | 1.5 | **175** | 262 |
| **16** | 2.0 | **131** | 262 |
| **32** | 2.5 | **105** | 262 (paper Table III ✓) |
| **64** | 3.0 | **88** | 264 |
| **128** | 3.5 | **75** | 262 |

## Practical implications

| Choosing… | Effect on prove cost | Effect on proof size | Effect on verify | Memory |
|-----------|--------------------:|--------------------:|-----------------:|-------:|
| **Larger blowup (e.g. 64, 128)** | LDE FFT cost ∝ blowup ⇒ slower per round | More layers but fewer queries ⇒ ~similar | ~constant | Higher (LDE arrays larger) |
| **Smaller blowup (e.g. 2, 4)** | LDE FFT smaller ⇒ faster per round | Many more queries ⇒ paths blow up | ~scales with `r` | Lower |
| **Paper sweet spot blowup = 32** | Optimal balance per paper §6 | 1–2 MB at d₀ ~ 2²⁰ | ~5 ms | Highest practical |

## How to use

The API auto-recalculates `r` for the requested blowup:

```bash
curl -X POST http://localhost:3000/v1/prove \
  -d '{
    "trace": { ... },
    "public_inputs": { ... },
    "config": {
      "nist_level": 1,
      "quantum_budget_log2": 40,
      "blowup": 8       ← server picks r=90 for L1/q=2⁴⁰ at blowup=8
    }
  }'
```

`GET /v1/security/profiles` now returns a `r_per_blowup` array per profile:

```jsonc
{
  "profiles": [
    {
      "level": 1, "lambda_bits": 128, "quantum_budget_log2": 40,
      "ext_field": "Fp^6", "hash_alg": "SHA3-256",
      "r": 54,                                       // baseline (blowup=32)
      "kappa_it": 135, "kappa_bind": 133, "kappa_fs": 296, "kappa_sys": 132,
      "r_per_blowup": [
        { "blowup":   2, "r": 270, "kappa_it_realised": 135 },
        { "blowup":   4, "r": 135, "kappa_it_realised": 135 },
        { "blowup":   8, "r":  90, "kappa_it_realised": 135 },
        { "blowup":  16, "r":  68, "kappa_it_realised": 136 },
        { "blowup":  32, "r":  54, "kappa_it_realised": 135 },
        { "blowup":  64, "r":  45, "kappa_it_realised": 135 },
        { "blowup": 128, "r":  39, "kappa_it_realised": 136 }
      ]
    },
    ...
  ]
}
```

## Tests

`crates/api/src/security.rs` mod tests:

* `r_at_blowup_32_matches_table_iii_baseline` — sanity: every paper row's r matches `r_for_blowup(32)` exactly
* `r_grows_inversely_with_log2_blowup` — checks the L1 row across all 5 blowups
* `r_for_blowup_rejects_non_power_of_two` — rejects 0, 1, 3, 7, 48
* `kappa_it_at_blowup_meets_target` — for every (profile, blowup) the realised κ_IT ≥ paper baseline (we ceil `r`, never underprovide)
* `level3_l5_recalibration_per_blowup` — L3 and L5 specific values

All pass:

```
cargo test --release -p api --lib security
test result: ok. 10 passed
```
