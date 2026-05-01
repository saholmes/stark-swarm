//! Wire messages exchanged between worker and controller.
//!
//! Step-3 scope: registration + heartbeat only.
//! Step-4 adds: `AssignShard` / `ShardDone`.
//! Step-5 will add: `RollupDone` and proof-bytes transport.

use serde::{Deserialize, Serialize};
use swarm_dns::dns::DnsRecord;
use swarm_dns::prover::LdtMode;

/// Numeric ID assigned to a worker by the controller after a successful
/// registration. Stable for the lifetime of the worker's connection.
pub type WorkerId = u32;

/// Self-reported capabilities of a worker, taken into account when the
/// controller decides which shards to assign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    /// NIST PQ level the worker is willing to prove at (1, 3, or 5).
    pub nist_level: u8,
    /// Maximum records-per-shard the worker can hold in memory.
    pub max_records_per_shard: usize,
    /// Logical CPU cores the worker can dedicate to proving.
    pub cores: u32,
    /// Free human-readable label (e.g. hostname or container id).
    pub label: String,
}

/// Self-contained shard work-item. Carries everything the worker needs to
/// prove its inner shard with no out-of-band setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardSpec {
    /// Controller-assigned shard id (used as the response correlator).
    pub shard_id:  u32,
    /// 16-byte zone salt used in the doubly-hashed leaves.
    pub zone_salt: [u8; 16],
    /// 32-byte SHA3-256 hash of the authority public key.
    pub authority_pk_hash: [u8; 32],
    /// 32-byte controller-chosen job identifier — the same value goes into
    /// every shard of the same job. Defends against cross-job replay.
    pub job_id: [u8; 32],
    /// 32-byte per-shard fresh nonce. Defends against same-job replay
    /// (e.g. worker A returning worker B's cached result for slot 3).
    pub shard_nonce: [u8; 32],
    /// LDT mode (STIR or FRI arity-2) — must match for the outer rollup.
    pub ldt: LdtMode,
    /// Records to commit. Step-4 ships them inline; step-5 may switch to a
    /// content-addressed pull model for very large shards.
    pub records: Vec<DnsRecord>,
}

/// Result of a successful inner-shard prove + worker self-verify.
/// All hashes are 32 bytes regardless of NIST level (FS-binding tags use
/// SHA3-256; the level-matched hash applies only to the *signed* digest
/// produced by the controller for the outer rollup).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardResult {
    pub shard_id:        u32,
    pub pi_hash:         [u8; 32],
    pub merkle_root:     [u8; 32],
    pub root_f0:         [u8; 32],
    pub record_count:    u64,
    pub n_trace:         u64,
    pub proof_bytes_len: u64,
    pub prove_ms:        f64,
    pub local_verify_ms: f64,
    /// ML-DSA signature by the worker's identity key over a domain-separated
    /// digest of (shard_id || pi_hash || merkle_root || root_f0). Lets the
    /// controller attribute work to a specific worker for the audit trail.
    pub worker_sig: Vec<u8>,
    /// Compressed `ark-serialize` encoding of the full `DeepFriProof<E>`.
    /// Shipped inline so the controller can persist a self-contained
    /// bundle that an offline verifier can walk end-to-end.
    pub proof_blob: Vec<u8>,
}

/// Worker → controller messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMsg {
    /// Sent immediately after the TLS handshake completes.
    /// `node_id` is the worker-chosen identifier (typically derived from its
    /// ML-DSA public key); `ml_dsa_pk` is the worker's authority key bytes.
    Register {
        node_id: String,
        ml_dsa_pk: Vec<u8>,
        capabilities: Capabilities,
    },
    /// Periodic liveness ping. Required at least every `heartbeat_secs`
    /// reported in `RegisterAck`, otherwise the controller drops the worker.
    Heartbeat {
        worker_id: WorkerId,
    },
    /// Inner-shard proving complete and locally verified.
    ShardDone {
        worker_id: WorkerId,
        result: ShardResult,
    },
    /// Independent evidence sent to witness controllers (H — witness mode).
    /// Carries the same audit-relevant fields as `ShardDone` but no proof
    /// bytes — witnesses don't run `deep_fri_verify`, they just sign+
    /// archive an attested receipt over the worker-signed digest.
    WorkerEvidence {
        worker_id:   WorkerId,
        job_id:      [u8; 32],
        shard_id:    u32,
        pi_hash:     [u8; 32],
        merkle_root: [u8; 32],
        root_f0:     [u8; 32],
        worker_sig:  Vec<u8>,
    },
    /// Worker hit an unrecoverable error processing a shard.
    ShardFailed {
        worker_id: WorkerId,
        shard_id: u32,
        reason: String,
    },
    /// Graceful shutdown announcement.
    Goodbye {
        worker_id: WorkerId,
    },
}

/// Controller → worker messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMsg {
    /// Successful registration. The controller's response binds a numeric
    /// `worker_id` for use in subsequent messages.
    RegisterAck {
        worker_id: WorkerId,
        heartbeat_secs: u32,
        controller_label: String,
    },
    /// Registration rejected (e.g. NIST-level mismatch, roster full).
    RegisterDenied {
        reason: String,
    },
    /// Heartbeat acknowledgement.
    HeartbeatAck,
    /// Inner-shard work assignment.
    AssignShard {
        spec: ShardSpec,
    },
    /// Signed acknowledgement that a worker's ShardDone passed validation
    /// (sig + merkle pinning). Sent before the ensemble decision is made,
    /// so even minority dissenters get one — the receipt only proves
    /// transmission, not bundle inclusion.
    Receipt {
        receipt: ShardReceipt,
    },
    /// Controller-initiated shutdown notification.
    Shutdown {
        reason: String,
    },
}

/// 32-byte composite that goes into `DeepFriParams.public_inputs_hash`
/// (and, transitively, into the `pi_hash` recipe).  Binds the inner
/// proof's Fiat-Shamir transcript to (a) the authority pk, (b) the
/// controller-chosen job id, (c) the shard slot, (d) a per-shard nonce.
/// Two workers cannot produce the same `pi_hash` from different inputs
/// without recomputing the proof.
pub fn shard_fs_binding(
    authority_pk_hash: &[u8; 32],
    job_id:            &[u8; 32],
    shard_id:          u32,
    shard_nonce:       &[u8; 32],
) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, b"DNS-SWARM-SHARD-FS-V1");
    Digest::update(&mut h, authority_pk_hash);
    Digest::update(&mut h, job_id);
    Digest::update(&mut h, &shard_id.to_le_bytes());
    Digest::update(&mut h, shard_nonce);
    Digest::finalize(h).into()
}

/// Domain-separated digest the worker signs to attest a `ShardResult`.
/// Recompute on the verifier side from the trusted fields and check
/// against `ShardResult.worker_sig` under the worker's registered pk.
pub fn worker_attestation_digest(
    shard_id:    u32,
    pi_hash:     &[u8; 32],
    merkle_root: &[u8; 32],
    root_f0:     &[u8; 32],
) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, b"DNS-SWARM-WORKER-ATTEST-V1");
    Digest::update(&mut h, &shard_id.to_le_bytes());
    Digest::update(&mut h, pi_hash);
    Digest::update(&mut h, merkle_root);
    Digest::update(&mut h, root_f0);
    Digest::finalize(h).into()
}

/// Signed receipt the controller hands back to a worker once that worker's
/// ShardDone has passed signature + merkle-root validation. The worker
/// persists this to disk; if the published bundle later omits the worker's
/// contribution or substitutes a different `pi_hash` for the same
/// (job_id, shard_id), the receipt is detached evidence of controller-side
/// misbehaviour (G — censorship / substitution detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardReceipt {
    pub job_id:               [u8; 32],
    pub shard_id:             u32,
    pub worker_id:            WorkerId,
    pub pi_hash:              [u8; 32],
    pub merkle_root:          [u8; 32],
    pub accepted_at_unix_ms:  u64,
    /// Controller's ML-DSA public key. Self-contained — verifier doesn't
    /// need the bundle to validate the receipt's signature.
    pub ctrl_authority_pk:    Vec<u8>,
    /// ML-DSA over `ctrl_receipt_digest(...)`.
    pub ctrl_sig:             Vec<u8>,
}

/// Domain-separated digest the controller signs to mint a `ShardReceipt`.
pub fn ctrl_receipt_digest(
    job_id:              &[u8; 32],
    shard_id:            u32,
    worker_id:           WorkerId,
    pi_hash:             &[u8; 32],
    merkle_root:         &[u8; 32],
    accepted_at_unix_ms: u64,
) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, b"DNS-SWARM-CTRL-RECEIPT-V1");
    Digest::update(&mut h, job_id);
    Digest::update(&mut h, &shard_id.to_le_bytes());
    Digest::update(&mut h, &worker_id.to_le_bytes());
    Digest::update(&mut h, pi_hash);
    Digest::update(&mut h, merkle_root);
    Digest::update(&mut h, &accepted_at_unix_ms.to_le_bytes());
    Digest::finalize(h).into()
}
