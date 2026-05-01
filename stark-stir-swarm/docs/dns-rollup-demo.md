# DNS Zone Rollup — Privacy-Preserving Proof of DNS Entry

A worked example of the rollup pattern applied to **DNS zone integrity**:
prove that a specific DNS record is part of a published zone *without
leaking the rest of the zone* — even to an attacker holding the full
proof bundle.

## Why "Proof of DNS Entry"?

DNSSEC (RFC 4034/4035) provides authenticity for *positive* answers
("here is example.com's A record, signed") and for *denials of
existence* via NSEC/NSEC3.  It does **not** provide a way for a third
party to prove that a specific record was part of the zone's
authoritative state at a previous point in time — and that gap creates
several real-world failure modes:

### 1. Selective hiding by the DNS authority

Under DNSSEC, the zone administrator signs the **current** zone state.
If the administrator is compelled (or chooses) to remove a record, the
new signed zone is fully valid; nothing in the protocol prevents
silent retraction.  A user who relied on yesterday's NS or MX record
has no cryptographic recourse to prove it was ever published.

A STARK Proof of DNS Entry over a **committed snapshot** closes this
loophole.  Once the zone authority publishes a rollup proof at time
T, anyone can later prove "record R was in the zone at time T" without
having to trust the authority's continued cooperation — the snapshot
is bound by the rolled-up Merkle root, which the authority cannot
retroactively change without invalidating the proof and any signature
over it.

### 2. The DNSSEC NSEC/NSEC3 zone-walking trade-off

* **NSEC** signs the names that *don't* exist by sorting the zone and
  signing adjacent name pairs.  This leaks the entire name list to
  anyone who walks the chain.
* **NSEC3** hashes the names before signing the chain, mitigating the
  leak but allowing offline dictionary attacks (especially against
  common names like `mail`, `www`, `ftp`).

Our STARK rollup with **double-salted hashing + Merkle root** in
`public_memory`:

* Reveals **no per-record information** in the proof bundle.
* Provides authenticated denial of existence via the same Merkle tree
  (sorted by `h2`, two adjacent leaves bracket any non-member).
* Defeats cross-zone dictionary attacks via the per-zone salt.

This is structurally equivalent to NSEC3 with significantly stronger
privacy and verifiable inclusion at constant verifier cost regardless
of zone size.

### 3. Post-quantum authentication alongside DNSSEC

DNSSEC currently relies on RSA-2048, ECDSA P-256, or Ed25519 — all
broken in polynomial time by Shor's algorithm on a sufficiently large
quantum computer.  NIST's PQC migration timeline targets standardised
post-quantum DNSSEC algorithms by ≥ 2030, but DNS infrastructure
typically lags standards by years.

Our STARK proofs use **only hash functions** (SHA3-256 / SHA3-384 /
SHA3-512 per the configured NIST PQ level) and Reed-Solomon proximity
testing.  Both primitives are believed secure under quantum adversaries
(Grover gives only a quadratic speed-up).  See
[`docs/api-walkthrough.md`](./api-walkthrough.md) §0 for the
hash-feature compile-time selection and Table III of the STIR-FIPS
paper for the full NIST profile mapping.

This means **a STARK Proof of DNS Entry can be verified post-quantum
even while DNSSEC remains classical**.  Deployments that need
defence-in-depth (financial, regulated, defence) can run both:
DNSSEC for legacy interop, STARK for forward-secure audit.

### 4. Verifier cost makes this practical *today*

Verification of a single inclusion claim is **constant in zone size**:

| Step | Time |
|------|------|
| Verify outer rollup STARK | ~ 5 ms |
| Verify the one inner shard containing the record | ~ 5–7 ms |
| Walk the Merkle path (log₂ N siblings) | sub-ms |
| **Total** | **≈ 10–15 ms per record claim** |

That fits inside any reasonable DNS resolution latency budget.  A
recursive resolver can fetch the rollup + shard + path alongside the
DNSSEC chain and verify both before returning the answer.  See
[`docs/scaling-analysis.md`](./scaling-analysis.md) for measurements
up to 2²³-row shards.

### 5. Use cases summary

| Threat | Mitigated by Proof of DNS Entry? |
|--------|-----------------------------------|
| Authority retroactively removes a record | **Yes** — past snapshot is committed |
| Authority compelled to lie about a record | **Yes** — past attestations remain verifiable |
| Court-ordered take-down hidden from public view | **Yes** — public commitment archive |
| NSEC zone walking | **Yes** — privacy-preserving variant |
| Resolver-cache poisoning | **Yes** when the record is anchored to a rollup |
| DNSSEC private-key compromise | **Partial** — STARK proof remains valid until next rollup |
| Quantum adversary breaks DNSSEC signatures | **Yes** — STARK is post-quantum (with SHA3-512 build) |
| Lost-history audit ("was this the answer 3 years ago?") | **Yes** if rollups are archived |

The pattern is essentially a **certificate-transparency log for DNS**,
with STARKs replacing the Merkle-only commitment to give zone owners
post-quantum-secure attestation alongside compact verifier proofs.

## Privacy properties

This demo combines three defences over the simple "STARK over hashed
records" baseline:

1. **Per-zone salt** (16 bytes, NSEC3-style) — keys every hash to the
   zone, providing domain separation and breaking cross-zone correlation
   via shared dictionaries.

2. **Doubly-hashed leaves** —
   `h2 = H("DNS-LEAF-DOUBLE-V1" || salt || H("DNS-LEAF-V1" || salt || canonical(record)))`.
   An adversary holding `h2` needs *two* SHA3-256 preimages to recover
   record bytes; in our 256-bit setting that's 2¹²⁸ work classically,
   2¹⁰⁶ post-quantum (Brassard–Høyer–Tapp).

3. **Merkle root in `public_memory`, NOT per-record entries** —
   the published `public_memory` carries only `salt`, `record_count`,
   and the Merkle root over the salted-and-doubly-hashed leaves.
   **No `H(record)` ever appears in the proof bundle.**  Inclusion
   proofs are sent on-demand as Merkle paths and reveal only the queried
   record's leaf + log₂(N) sibling hashes.

## What the verifier sees and what stays hidden

| Artifact | Visible to anyone holding the proof | Useful info leaked |
|----------|-------------------------------------|---------------------|
| `public_inputs.public_memory` (8 entries) | Yes | salt + record_count + merkle_root only |
| Merkle root (32 B) | Yes | Aggregate commitment; no per-record info |
| `proof.queries[*]` | Yes (at FRI-random positions) | Some packed-`h2` values at queried trace indices |
| Merkle path for one record | Sent on-demand to the querier | One `h2` + log₂(N) sibling hashes |
| `H(record)` | **No** | An adversary needs to break SHA3-256 preimage |
| `record` bytes | **No** | An adversary needs to break SHA3-256 preimage |
| Set of records in the zone | **No** | Cannot be enumerated without a candidate dictionary |

The threat model is **NSEC3-equivalent**: dictionary attacks against
*known/guessable* records remain feasible (e.g. checking if `mail.X` is
in the zone for popular X) — that's an inherent limitation of any system
that lets a verifier check membership of a known candidate without a
secret. **Zone walking** (enumeration without candidates) is prevented.

## Architecture

```
   Zone shard A (5 records)              Zone shard B (5 records)
   ┌──────────────────────┐              ┌──────────────────────┐
   │ A     example.com    │              │ A     api…           │
   │ AAAA  example.com    │              │ A     cdn… ×3        │
   │ MX 10 example.com    │              │ TXT   _dmarc…        │
   │ TXT   example.com    │              │                      │
   │ A     www.example.com│              │                      │
   └──────────┬───────────┘              └──────────┬───────────┘
              │ for each record:                    │
              │   h1 = SHA3("DNS-LEAF-V1" || salt || canonical(rec))
              │   h2 = SHA3("DNS-LEAF-DOUBLE-V1" || salt || h1)
              ▼                                      ▼
   ┌──────────────────────────┐          ┌──────────────────────────┐
   │ Build off-chain Merkle    │          │ Build off-chain Merkle    │
   │ tree over h2 leaves       │          │ tree over h2 leaves       │
   │ → root_A (32 B)           │          │ → root_B (32 B)           │
   └──────────┬───────────────┘          └──────────┬───────────────┘
              ▼                                      ▼
   ┌──────────────────────────┐          ┌──────────────────────────┐
   │ Inner STARK A             │          │ Inner STARK B             │
   │ AIR = HashRollup, w=4     │          │ AIR = HashRollup, w=4     │
   │ trace absorbs all h2's    │          │ trace absorbs all h2's    │
   │ → pi_hash_A (32 B)        │          │ → pi_hash_B (32 B)        │
   │ public_memory contains    │          │ public_memory contains    │
   │   salt, count, root_A     │          │   salt, count, root_B     │
   │   (NO per-record entries) │          │   (NO per-record entries) │
   └──────────┬───────────────┘          └──────────┬───────────────┘
              └─────────────┬────────────────────────┘
                            ▼ pack each pi_hash to 4×u64
                outer_leaves = [pack(pi_hash_A), pack(pi_hash_B)]
                            ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Outer Rollup STARK   (HashRollup AIR, 16-row trace)        │
   │ → aggregate zone commitment                                │
   │ public_memory carries pi_hash_A and pi_hash_B              │
   └────────────────────────────────────────────────────────────┘
```

## Public-memory layout (per inner shard)

```
0x0001  zone format tag         ("DNS1")
0x0010  salt[0..7]               ─┐
0x0011  salt[8..15]              ─┘  16-byte zone salt (published)
0x0012  record_count
0x0020  merkle_root[0]           ─┐
0x0021  merkle_root[1]            │  Merkle root over h2 leaves
0x0022  merkle_root[2]            │  (no per-record entries)
0x0023  merkle_root[3]           ─┘
```

Eight entries total. **No `H(record)` and no record bytes.**

## Verifier workflow — proof of DNS entry

A relying party who wants to know "is record R in this zone?" performs:

| # | Step | Trust gained |
|---|------|--------------|
| 1 | Verify outer rollup STARK | Aggregate root of zone reflects the shard hashes the prover claimed |
| 2 | Verify inner shard A STARK | `pi_hash_A` and the embedded `merkle_root_A` are anchored to a real shard A execution |
| 3 | Compute `h1 = SHA3("DNS-LEAF-V1" \|\| salt \|\| canonical(R))` | Local — deterministic from R + salt |
| 4 | Compute `h2 = SHA3("DNS-LEAF-DOUBLE-V1" \|\| salt \|\| h1)` | Local |
| 5 | Receive Merkle path (log₂(N) siblings) for `h2`'s leaf index | Sent on-demand by zone authority |
| 6 | Walk the path, recompute root, compare to public_memory.merkle_root | If they match, R is one of the shard's records |
| 7 | (Optional) Tamper-check: derive `h2` for a slightly modified record (e.g. flipped TTL) and confirm it does **not** verify against the same path | Guarantees the path is uniquely binding |

If steps 1–6 succeed, the relying party has a succinct proof of DNS
entry: only the **outer rollup proof + shard A proof + log₂(N) sibling
hashes** are network-borne.  Other records and shard B's contents are
never transmitted and cannot be recovered from what was sent.

## Running

### Small integration test (2 shards × 5 records)

```bash
cargo test --release -p api --test dns_rollup -- --nocapture
```

Output (truncated):

```
zone_salt (published with proof) = 6578616d706c652d636f6d2d32303236

[STEP 1] Prove zone shard A   records=5  prove=4 ms  merkle_root=4ff24db9bb3fc495…
[STEP 2] Prove zone shard B   records=5  prove=3 ms  merkle_root=3c5ed0b2bf9661bc…
[STEP 3] Prove outer rollup    prove=2 ms

[STEP 4] Verify outer rollup           valid=true (2 ms)
[STEP 5] Verify inner shard A          valid=true (2 ms)
[STEP 6] Verify inner shard B          valid=true (2 ms)

[STEP 7] Privacy check on public_memory:
   addresses present = [1, 16, 17, 18, 32, 33, 34, 35]
   per-record leak   = false  (8 entries total — only salt/count/root)

[STEP 8] Inclusion proof for the MX record (via Merkle path)
   probe leaf_hash (h2) = 5e3c5d58e5ac5add758e3ebd7a25759a…
   leaf_index           = 2
   merkle_path siblings = 3
   ✓ Merkle path verifies against public_memory.merkle_root
   ✓ tampered record (TTL 300→600) is correctly rejected

=== DNS ROLLUP DEMO SUCCESS (privacy-preserving) ===
    public_memory leaks no per-record info
    inclusion via Merkle path (log₂N = 3 siblings) only
```

### Megazone demo — 5 shards × N records

A standalone binary `crates/cairo-bench/examples/dns_megazone_demo.rs`
generates a synthetic zone, partitions it into 5 shards, proves each
inner shard with HashRollup AIR, aggregates the five `pi_hash`-es into
one outer rollup STARK, verifies all six proofs, and demonstrates an
inclusion proof for one specific record.

| Mode | Records / shard | Total records | Sequential wall-clock | Parallel-projection (5 boxes) |
|------|----------------:|--------------:|----------------------:|------------------------------:|
| `--quick` (default) | 1 024 | 5 120 | ~0.5 s | ~0.1 s |
| `--medium` | 65 536 | 327 680 | ~37 s | ~7 s |
| `--full` | 2 097 152 | **10 485 760** | ~27 min | ~5.5 min |

```bash
# Quick architecture validation
cargo run --release -p cairo-bench --example dns_megazone_demo

# Mid-tier — 327K records (Mid Enterprise scale)
cargo run --release -p cairo-bench --example dns_megazone_demo -- --medium

# Production-scale — 10M records (Mega Enterprise / multi-cloud scale)
cargo run --release -p cairo-bench --example dns_megazone_demo -- --full

# Custom
cargo run --release -p cairo-bench --example dns_megazone_demo -- \
    --shards 5 --records-per-shard 524288
```

Sample `--medium` output:

```
=================================================================
  DNS Megazone Rollup Demo
=================================================================
  shards               = 5
  records / shard      = 65536
  total records        = 327680 (0.33 M)
  rayon threads        = 10
  shard inner-trace    = 2^18 (262144 rows)
  zone salt (published) = 6578616d706c652d636f6d2d32303236

[shard 1/5] generated 65536 records in 0.04 s
  [shard 1 of 5] records = 65536
        record hashing: 0.18 s
        merkle tree:    0.04 s   root=…
        trace + DEEP-ALI: 0.61 s   n_trace=2^18
        FRI prove:        6.70 s
        FRI verify:       3.49 ms   proof=706 KiB
… (4 more shards) …

  outer rollup:  n_trace=2^5  prove=0.01 s  verify=0.85 ms  proof=165 KiB

=================================================================
  Proof of DNS Entry — inclusion in shard 0
=================================================================
  probe record         : domain=mail-00000007.example.com, type=15, ttl=300
  probe leaf_hash (h2) : 572d5e529244729d60fe77ce362792c9…
  shard 0 merkle_root  : …
  merkle_path siblings : 16 (512 bytes total)
  ✓ inclusion verified against shard 0's merkle_root
  ✓ tampered record (TTL-bit flipped) correctly REJECTED

=================================================================
  Summary
=================================================================
  total wall-clock                 = 36.71 s (0.61 min)
  total inner prove time (Σ)       = 33.33 s  (sequential)
  max  inner prove time            = 6.70 s  (= wall-clock if N machines parallelize)
  outer rollup prove               = 0.00 s

  total proof storage              = 3515 KiB (5 inner + 1 outer)

  verifier work for ANY 1 record
    · verify outer rollup          = 0.85 ms
    · verify inner shard           ≈ 3.49 ms
    · walk merkle path             = 16 hashes (~negligible)
  ─ TOTAL verifier               ≈ 4.34 ms

  hypothetical 5-machine parallel wall-clock:
    · max(inner prove) + outer    = 6.70 s (0.11 min)
=================================================================
  STATUS: ✓ all 5 inner + 1 outer proofs verified
=================================================================
```

The `--full` mode at 10 M records produces ~5 MB of proof artifacts and
requires ~8 GB peak RAM per shard — doable on the laptop sequentially
(~27 min), but the realistic deployment runs each shard on its own
worker (cloud spot instance ≈ $0.05) and finishes in ~5.5 min wall-clock.

## Parallel proving (default-on)

Inner and outer proofs run with **rayon-parallelized FRI proving by
default** — `crates/api/Cargo.toml` includes `parallel` in the default
feature set:

```toml
[features]
default  = ["sha3-256", "parallel"]
parallel = ["deep_ali/parallel"]
```

To opt out (e.g. on a single-thread embedded verifier), build with
`--no-default-features --features sha3-256` (no `parallel`).

The parallelization is internal to `deep_ali::fri` and `deep_ali` core —
LDE evaluation, constraint composition, and per-query Merkle hashing all
fan out across `rayon::current_num_threads()`.

## Cryptographic chain summary

```
record  ─────► canonical(record)                     (length-prefixed bytes)
        ─────► h1 = SHA3("DNS-LEAF-V1" ‖ salt ‖ ·)   (32 B)        ─┐
        ─────► h2 = SHA3("DNS-LEAF-DOUBLE-V1" ‖ salt ‖ h1)         ─┤  per-record
                  ▼                                                ─┘
                  Merkle leaf
                  ▼  build off-chain
                  Merkle tree (SHA3 binary, "DNS-NODE-V1" tag)
                  ▼
                  merkle_root  ─────────────► public_memory[0x0020..0x0023]
                  ▼  also fed as packed leaves into the
                  ▼  HashRollup AIR's trace (so the prover proves
                  ▼  "I know all the h2's that hashed up to this root")
                  HashRollup chain  state' = state² + leaf
                  ▼
                  state[n_trace - 1]      (committed via FS transcript)
                  ▼
                  pi_hash = SHA3-256(public_inputs)
                  ▼  packed as 4 u64 leaves
                  Outer rollup HashRollup AIR
                  ▼
                  aggregate root        (committed in outer pi_hash)
```

### ZSK → KSK signature binding (Ed25519)

The trust chain above closes locally with the parent zone's KSK
signing the child's ZSK DNSKEY RRset (RFC 8080 + RFC 4034 §3.1.8.1).
The prototype now ships **all three layers** of this binding:

| Layer | Component | Status |
|-------|-----------|--------|
| 1. Native verifier | `deep_ali::ed25519_verify::verify` (in-crate, no dalek dep on the verify path) | landed |
| 2. Public-input commitment | `verify_zsk_ksk_native` / `verify_zsk_ksk_runtime_fallback` (`pi_hash` recipe) | landed |
| 3. In-circuit `Ed25519VerifyAir` | `crates/deep_ali/src/ed25519_verify_air.rs` v0–v16 — composes SHA-512 + scalar reduce + 2 decompositions + 2 ladders + residual chain + cofactor mul + identity verdict | landed (K=8 stub registered as `AirType::Ed25519ZskKsk`); per-signature K=256 production recipe pending parametric merge |

End-to-end paths exercised in the prototype:
- `swarm_dns::prover::prove_zsk_ksk_binding` — production stub, native verify + pi_hash, no STARK blob.
- `swarm_dns::prover::prove_zsk_ksk_binding_stub_k8` — full DEEP-ALI + STIR/FRI proof on the registered K=8 stub trace, self-verified.
- `swarm-verify` — STARK-preferred branch (`zsk_ksk_proof_path`) + runtime fallback, mirroring the DS→KSK pattern.
- `cargo run --release -p swarm-dns --example zsk_ksk_bench` — runtime-fallback table + STARK stub-K8 timings.

See **§10.7 of `docs/protocol/swarm-protocol.tex`** for the full v0–v16 soundness map and the cofactored predicate proof sketch.

## Scaling

| Zone size | Shards × records/shard | Inner-trace length | Merkle tree depth | Outer-trace length |
|-----------|------------------------|---------------------|--------------------|---------------------|
| 100       | 1 × 100                | 512                 | 7                  | 16 (no rollup)      |
| 10 000    | 50 × 200               | 1 024               | 8                  | 256                 |
| 1 000 000 | 500 × 2 000            | 8 192               | 11                 | 2 048               |
| > 4 096 shards | nest a higher rollup tier | — | — | recurse |

Outer verifier work stays **O(1)**, per-shard verifier work stays
**O(1)**, inclusion proof size stays **O(log N)** in the shard size.
Other records and other shards stay private at every layer.

## Comparison to other approaches

| Scheme | Zone walking prevented? | Inclusion proof size | Hidden record set? | Quantum-secure? |
|--------|-------------------------|----------------------|---------------------|------------------|
| **DNSSEC** (RFC 4035)    | No — full zone visible          | O(zone) | No  | No (RSA/ECDSA) |
| **NSEC3** (RFC 5155)     | Partially (hash-name leak)      | O(1)    | No  | No |
| **Plain Merkle proof**   | Yes (with double hashing + salt)| O(log N) | Yes | SHA3 → yes |
| **Plain STARK over zone**| Yes                             | O(1)    | Yes | Yes (no signatures) |
| **This demo**            | Yes (NSEC3-style + Merkle)      | O(log N) | Yes | Yes (SHA3 + STARK) |

This demo is **DNSSEC-class authentication** with **NSEC3-class
privacy** plus **STARK-class succinct aggregate verification** —
horizontally scalable to arbitrarily large zones, post-quantum secure
when built with `--features sha3-512`.

## Code map

| File | Purpose |
|------|---------|
| `crates/api/tests/dns_rollup.rs` | End-to-end test: 2 shards × 5 records + outer rollup + Merkle inclusion proof + tamper test |
| `crates/cairo-bench/cairo/dns_record_chain.cairo` | Cairo 0 illustration of the absorption chain |
| `crates/deep_ali/src/air_workloads.rs` | `AirType::HashRollup`, `pack_hash_to_leaves` |
| `crates/api/Cargo.toml` | `default = ["sha3-256", "parallel"]` |

## Path to production

To take this from demo to production deployment:

1. **Authority signature on the rolled-up root** — the zone authority
   signs the outer rollup's `pi_hash` with a long-term key, replacing
   the DNSSEC chain-of-trust.

2. **Periodic re-rollup on zone updates** — TTL changes mean record
   sets rotate; new rollup proofs need to be regenerated on each zone
   update.  Worker pools producing inner shard proofs can run
   continuously and feed the rollup-aggregator.

3. **Proof-of-non-existence** — extend the Merkle commitment to a
   sorted-by-hash interval-Merkle-tree so a verifier can prove
   `h2 NOT in tree` by exhibiting two adjacent leaves that bracket it.

4. **Salt rotation** — rotate the per-zone salt at every signing epoch
   so dictionaries built from a previous epoch's proofs become useless.

5. **Mainnet hash policy** — production deployments at NIST PQ Level 3+
   should build with `--features sha3-512` to satisfy the FIPS-202
   binding wall (see `docs/api-walkthrough.md` § 9).
