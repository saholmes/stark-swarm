# STIR-DNS Swarm Protocol — documentation

This directory holds the formal specification of the swarm proving
protocol implemented in `crates/swarm-{ctrl,worker,verify,bench}` plus
a Tamarin model for symbolic verification of its core security claims.

## Layout

```
docs/protocol/
├─ swarm-protocol.tex            # main paper (LaTeX)
├─ figures/
│  ├─ architecture.tex           # TikZ system topology
│  ├─ sequence-happy.tex         # TikZ sequence (happy path)
│  └─ sequence-byzantine.tex     # TikZ sequence (k=3 byzantine)
├─ security/
│  └─ swarm.spthy                # Tamarin theory
├─ Makefile
└─ README.md                     # this file
```

## Build the PDF

Requires a recent TeX Live (`latexmk`, `pdflatex`, `tikz`,
`amsmath`, `cleveref`, `listings`, `microtype`).

```
make pdf            # produces swarm-protocol.pdf
make clean          # removes build artifacts
```

## Run Tamarin

The Tamarin theory captures the protocol's application-layer crypto
semantics (TLS treated as a black-box authenticated channel; ML-DSA
modelled via Tamarin's `signing` builtin; STIR proving treated as a
deterministic one-way function).

### Install Tamarin

The reference is at <https://tamarin-prover.com/>. Pick whichever fits
your environment:

```
# macOS
brew install tamarin-prover/tap/tamarin-prover

# Nix / NixOS
nix-shell -p tamarin-prover

# From source (requires GHC + cabal)
git clone https://github.com/tamarin-prover/tamarin-prover.git
cd tamarin-prover && make default
```

### Batch-prove all lemmas

```
make prove
```

This runs `tamarin-prover --prove security/swarm.spthy`.  Verified
result on tamarin-prover 1.10.0 + maude 2.7.1 (total wall-clock
< 1 second):

| Lemma                       | Status     | Steps | Paper §                |
|-----------------------------|------------|------:|------------------------|
| `proved_origin` *[sources]* | verified   | 7     | (auxiliary source lem.) |
| `protocol_executable`       | verified   | 9     | sanity / liveness       |
| `allowlist_enforced`        | verified   | 5     | Property 6 (E1)         |
| `authority_binding`         | verified   | 3     | Property 1              |
| `shard_inclusion`           | verified   | 12    | Property 2              |
| `replay_freshness`          | verified   | 2     | Property 3              |
| `deterministic_proving`     | verified   | 2     | Property 4              |
| `receipt_provenance`        | verified   | 2     | (auxiliary)             |
| `witness_quorum_2`          | verified   | 8     | Property 5 (M=2)        |
| `witness_quorum_3`          | verified   | 13    | Property 5 (M=3)        |

Heuristic guidance: a `[sources, reuse]` source lemma plus `[reuse]`
chains on intermediate lemmas (`allowlist_enforced`, `authority_binding`,
`shard_inclusion`, `replay_freshness`, `witness_quorum_2`).  No oracle
script needed for this scope.

Lemmas that would still need additional work for a fully-stated
proof:

* M-of-N witness quorum for *arbitrary* M.  We prove M=2 and M=3
  explicitly; the general statement requires multiset induction on
  the witness set, which is awkward to express directly in
  Tamarin.  In practice, a deployment with 5+ witnesses can chain
  the M=2 and M=3 lemmas to bound the corruption frontier.
* Fairness / liveness in adversarially-scheduled networks — this
  needs probabilistic process algebra rather than Tamarin's
  reachability semantics.
* STIR's quantitative soundness error bound — the `h/1` symbol
  here gives unconditional collision resistance, while the real
  STARK has a `2^-λ` soundness error.  A quantitative argument
  would need to descend into the LDT proof.

The history of the model build-up is preserved alongside the
canonical version:

* `swarm-simple.spthy`       — initial 6-lemma simplified theory
                                (proved 0.60 s).
* `swarm-progressive.spthy`  — adds `shard_inclusion`,
                                `deterministic_proving`,
                                `receipt_provenance`,
                                `witness_quorum_3` (proved 0.57 s).
* `swarm.spthy`              — current canonical model.
* `swarm-original.spthy`     — original first-pass model with
                                `senc` channels and multi-arg digest
                                functions; parses but proof search
                                does not converge in default
                                heuristic.  Kept for reference.

### Open interactively

```
make tamarin
```

Opens the theory in your default browser at the Tamarin GUI for
step-by-step proof construction.

## Implementation cross-reference

| Protocol element (`.tex`)        | Code (`crates/`)                                       |
|----------------------------------|--------------------------------------------------------|
| Phase 1 — registration / E1      | `swarm-ctrl/src/main.rs::handle_session`               |
| Phase 2 — assignment / A + B     | `swarm-ctrl/src/main.rs::zone_job::Phase 2/3`          |
| Phase 3 — proving                | `swarm-dns/src/prover.rs::prove_inner_shard`           |
| Phase 4 — ensemble (F)           | `swarm-ctrl/src/main.rs::evaluate_ensemble`            |
| Phase 5 — receipts (G + H)       | `swarm-ctrl/src/main.rs` ShardDone handler;            |
|                                  | witness branch in `handle_session`                     |
| Phase 6 — outer rollup + sign    | `swarm-ctrl/src/main.rs::zone_job::Phase 5/6`          |
| Phase 7 — verification           | `swarm-verify/src/main.rs`                             |
| E3 connection-limiter            | `swarm-ctrl/src/main.rs::ConnLimiter`                  |
| §10 NSEC3 completeness AIR       | `deep_ali/src/air_workloads.rs::Nsec3Chain` family;    |
|                                  | `swarm-dns/src/prover.rs::prove_nsec3_completeness`    |
| §10 NSEC3 benchmark              | `swarm-dns/examples/nsec3_completeness_bench.rs`       |
| §10 DS→KSK SHA-256 AIR           | `deep_ali/src/sha256_air.rs` (756 cols, 766 cons);     |
|                                  | `deep_ali::deep_ali_merge_sha256` (n_blocks-aware);    |
|                                  | `swarm-dns/src/prover.rs::prove_ds_ksk_binding`        |
| §10 DS→KSK benchmark             | `swarm-dns/examples/ds_ksk_bench.rs`                   |
| §10 DS→KSK verifier path         | `swarm-verify/src/main.rs` Phase 3b (STARK preferred,  |
|                                  | runtime SHA-256 fallback)                              |

Smoke tests demonstrating each property in operation are noted in the
top-level repository README and the per-property checkpoint runs.
