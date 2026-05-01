//! STIR DNS swarm — controller entry point.
//!
//! Step-5 scope: full zone-proving orchestration.
//!
//! On startup the controller binds a TLS 1.3 listener (X25519+ML-KEM-768
//! hybrid KEX), waits until `--wait-workers W` workers register, splits the
//! synthetic zone into `W` shards, assigns one shard per worker, collects
//! the attested `pi_hash`-es as workers finish, builds the outer-rollup
//! STARK locally over the collected `pi_hash`-es, ML-DSA-signs the zone
//! digest with the controller's authority key, and writes a final
//! `ZoneBundle` JSON to `--state-dir`.
//!
//! Run with:
//!     cargo run --release -p swarm-ctrl -- \
//!         --bind 127.0.0.1:7878 \
//!         --wait-workers 4 --zone-records 4096 --zone-ldt stir
//!
//! The cert and its SHA3-256 fingerprint are persisted under `--state-dir`
//! (default `./swarm-ctrl-state`). Workers consume the fingerprint via
//! `--ctrl-fingerprint <hex>` or by reading `<state-dir>/fingerprint.hex`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use swarm_dns::dns::{merkle_build, merkle_root as merkle_top, DnsRecord};
use swarm_dns::dns_authority::{level_hash, pk_binding_hash, AuthorityKeypair, NistLevel};
use swarm_dns::prover::{prove_outer_rollup, LdtMode, OuterRollupOutput};
use swarm_proto::cert::{load_or_generate, ServerIdentity};
use swarm_proto::frame::{read_frame, write_frame};
use swarm_proto::messages::{
    ctrl_receipt_digest, worker_attestation_digest,
    Capabilities, ClientMsg, ServerMsg, ShardReceipt, ShardResult, ShardSpec, WorkerId,
};
use swarm_proto::tls::server_config;

#[derive(Parser, Debug)]
#[command(name = "swarm-ctrl", about = "STIR DNS swarm controller")]
struct Args {
    /// Listen address (host:port).
    #[arg(long, default_value = "127.0.0.1:7878")]
    bind: String,

    /// State directory for cert, fingerprint, and the final ZoneBundle.
    #[arg(long, default_value = "./swarm-ctrl-state")]
    state_dir: PathBuf,

    /// Subject hostnames for the self-signed cert.
    #[arg(long, default_values_t = ["localhost".to_string(), "127.0.0.1".to_string()])]
    subject: Vec<String>,

    /// Heartbeat interval (seconds) returned to workers in `RegisterAck`.
    #[arg(long, default_value_t = 5)]
    heartbeat_secs: u32,

    /// Free human-readable label.
    #[arg(long, default_value = "stir-swarm-ctrl")]
    label: String,

    // ─── Zone job parameters ────────────────────────────────────────────────
    /// Total records in the synthetic zone. Split evenly across workers.
    #[arg(long, default_value_t = 0)]
    zone_records: usize,

    /// Number of registered workers required before the zone job kicks off.
    /// 0 disables the job (controller stays in registration-only mode).
    #[arg(long, default_value_t = 0)]
    wait_workers: usize,

    /// LDT mode for both inner shards and the outer rollup.
    #[arg(long, default_value = "stir", value_parser = parse_ldt)]
    zone_ldt: LdtMode,

    /// NIST PQ level for the controller's authority key (1, 3, or 5).
    /// Drives ML-DSA parameter set + matching SHA3 digest variant.
    #[arg(long, default_value_t = 1)]
    nist_level: u8,

    /// Hex-encoded zone salt (16 bytes). Defaults to `swarm-test-zone1`.
    #[arg(long)]
    zone_salt_hex: Option<String>,

    /// Stop the controller after the zone job completes (useful for benches).
    #[arg(long, default_value_t = false)]
    exit_on_complete: bool,

    /// Per-shard deadline (seconds). If a shard is not returned within this
    /// window the assigned worker is suspected and the shard is reassigned
    /// to another idle worker.
    #[arg(long, default_value_t = 120)]
    shard_deadline_secs: u64,

    /// Path to a JSON file listing acceptable worker pk fingerprints
    /// (SHA3-256 hex strings of the worker's ML-DSA public key).  When set,
    /// any registration whose pk_fp is not in the list is rejected with
    /// `RegisterDenied`.  When unset, the controller accepts any worker
    /// (legacy / lab mode).
    ///
    /// File format:
    ///     [
    ///         "abcd1234...64chars",
    ///         "ef567890...64chars"
    ///     ]
    #[arg(long)]
    worker_allowlist: Option<PathBuf>,

    /// Operating mode (H — distributed audit):
    ///   * `primary` — orchestrates a zone job, signs the final bundle.
    ///                 (default; matches the historical single-ctrl behaviour)
    ///   * `witness` — runs alongside a primary; accepts worker
    ///                 registrations + `WorkerEvidence` messages and
    ///                 archives independently-signed receipts. Does not
    ///                 orchestrate, does not run a zone job.
    #[arg(long, default_value = "primary", value_parser = parse_mode)]
    mode: CtrlMode,

    /// Maximum simultaneous connections from a single peer IP (E3).
    /// Prevents file-descriptor exhaustion via slowloris-style attacks.
    #[arg(long, default_value_t = 8)]
    max_conns_per_ip: usize,

    /// Token-bucket refill rate (new connections per second per IP).
    #[arg(long, default_value_t = 4.0)]
    connect_rate_per_ip: f64,

    /// Token-bucket burst capacity per IP (steady-state buffer).
    #[arg(long, default_value_t = 8.0)]
    connect_burst_per_ip: f64,

    /// Hard cap on simultaneous connections across ALL peers.
    #[arg(long, default_value_t = 1024)]
    max_active_conns: usize,

    /// Drop a connection if its TLS handshake doesn't complete within
    /// this many seconds (E3 — slow-handshake DoS).
    #[arg(long, default_value_t = 5)]
    tls_handshake_timeout_secs: u64,

    /// Shard replication factor (Byzantine collusion defence — F).
    /// Each shard is assigned to this many distinct workers; ctrl accepts
    /// the result only if all replicas return byte-identical
    /// `(merkle_root, pi_hash, root_f0)`. With k ≥ 3, the majority vote
    /// wins on disagreement and the minority is blacklisted. With k = 2,
    /// any disagreement aborts the job. Default 1 (no replication).
    /// Requires roster ≥ k × n_shards for full parallelism.
    #[arg(long, default_value_t = 1)]
    shard_replication: usize,

    /// Hex-encoded DNSKEY public-key bytes (the canonical DNSKEY RDATA
    /// encoding).  When set together with --parent-ds-hash, the verifier
    /// will check SHA-256(DNSKEY) == parent_ds_hash and reject the
    /// bundle on mismatch.  See §8.2 of the protocol paper.
    #[arg(long)]
    dnskey_pk_hex: Option<String>,

    /// Hex-encoded SHA-256 digest from the parent zone's DS record (32
    /// bytes / 64 hex chars).  Paired with --dnskey-pk-hex.
    #[arg(long)]
    parent_ds_hash_hex: Option<String>,
}

fn parse_ldt(s: &str) -> std::result::Result<LdtMode, String> {
    match s.to_ascii_lowercase().as_str() {
        "stir" => Ok(LdtMode::Stir),
        "fri"  => Ok(LdtMode::Fri),
        other  => Err(format!("invalid LDT '{other}' (expected stir or fri)")),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CtrlMode { Primary, Witness }

fn parse_mode(s: &str) -> std::result::Result<CtrlMode, String> {
    match s.to_ascii_lowercase().as_str() {
        "primary" => Ok(CtrlMode::Primary),
        "witness" => Ok(CtrlMode::Witness),
        other     => Err(format!("invalid --mode '{other}' (expected primary or witness)")),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Roster / per-session push channel
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct WorkerSession {
    info: WorkerEntry,
    /// Channel used by the zone-job task to push `AssignShard` (or future
    /// `Shutdown`) messages into the worker's session loop.
    tx_to_session: mpsc::Sender<ServerMsg>,
}

#[derive(Debug, Clone)]
struct WorkerEntry {
    id:           WorkerId,
    node_id:      String,
    capabilities: Capabilities,
    pk_fp:        [u8; 32],
    ml_dsa_pk:    Vec<u8>,
    last_seen:    Instant,
}

#[derive(Default)]
struct Roster {
    next_id: WorkerId,
    workers: HashMap<WorkerId, WorkerSession>,
}

impl Roster {
    fn allocate(&mut self) -> WorkerId {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
    fn insert(&mut self, ws: WorkerSession) {
        self.workers.insert(ws.info.id, ws);
    }
    fn touch(&mut self, id: WorkerId) -> bool {
        if let Some(ws) = self.workers.get_mut(&id) {
            ws.info.last_seen = Instant::now();
            true
        } else { false }
    }
    fn remove(&mut self, id: WorkerId) -> Option<WorkerSession> {
        self.workers.remove(&id)
    }
    fn count(&self) -> usize { self.workers.len() }
    fn ids(&self) -> Vec<WorkerId> {
        let mut v: Vec<WorkerId> = self.workers.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Session→Job event channel
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum SessionEvent {
    Registered    { worker_id: WorkerId },
    ShardDone     { worker_id: WorkerId, result: ShardResult },
    ShardFailed   { worker_id: WorkerId, shard_id: u32, reason: String },
    Disconnected  { worker_id: WorkerId },
}

// ─────────────────────────────────────────────────────────────────────────────
//  Final on-disk bundle
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct ZoneBundle {
    /// Bundle format version. v1 had a single attestation per shard
    /// (`worker_pk_hex` + `worker_sig_hex`); v2 has a list of attestations
    /// (`attestations: Vec<Attestation>`) so k-replicated proofs are
    /// represented faithfully.
    bundle_format: u32,
    nist_level:        u8,
    ml_dsa_scheme:     String,
    signed_digest_hash: String,
    zone_salt_hex:     String,
    record_count:      usize,
    shard_count:       usize,
    /// Replication factor used by the controller for every shard.
    shard_replication: usize,
    ldt:               String,
    authority_pk_hex:  String,
    authority_pk_hash_hex: String,
    /// Per-job 32-byte random tag, included in every shard's FS binding.
    job_id_hex:        String,
    /// Optional DNSSEC DS->KSK verifier-side binding (§8.2 of the paper).
    /// If both fields are present, the verifier recomputes
    /// SHA-256(dnskey_pk) and compares to parent_ds_hash; mismatch is a
    /// hard fail.  Bound into the proof's FS transcript via
    /// authority_pk_hash, so substitution after the fact is detected.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    dnskey_pk_hex:     Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    parent_ds_hash_hex: Option<String>,
    inner_pi_hashes_hex: Vec<String>,
    outer_root_f0_hex: String,
    outer_n_trace:     usize,
    outer_n0:          usize,
    outer_proof_bytes: usize,
    /// Path (relative to the bundle's directory) of the outer rollup proof.
    outer_proof_path:  String,
    zone_digest_hex:   String,
    authority_sig_hex: String,
    inner_workers:     Vec<InnerWorkerRecord>,
    timings_ms:        Timings,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InnerWorkerRecord {
    shard_id:        u32,
    /// 32-byte per-shard nonce used in this shard's FS binding.
    shard_nonce_hex: String,
    pi_hash_hex:     String,
    merkle_root_hex: String,
    record_count:    u64,
    n_trace:         u64,
    /// Length of the (canonical, identical) proof blob in bytes.
    proof_bytes_len: u64,
    /// Path (relative to the bundle's directory) of the canonical inner proof.
    proof_path:      String,
    /// One entry per ratifying replica.  Length equals
    /// `bundle.shard_replication` (or less if some replicas were a
    /// dissenting minority that got blacklisted under majority-rule).
    attestations:    Vec<Attestation>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Attestation {
    worker_id:      WorkerId,
    worker_pk_hex:  String,
    worker_sig_hex: String,
    /// This replica's individual prove time (ms). Differs across replicas
    /// even though the proof bytes are identical (different machines).
    prove_ms:       f64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Timings {
    wait_workers_ms:        f64,
    assign_to_last_done_ms: f64,
    outer_rollup_ms:        f64,
    sign_ms:                f64,
    total_ms:               f64,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let level = parse_nist(args.nist_level)?;

    let id = setup_identity(&args)?;
    let fp = id.fingerprint_sha3_256()?;
    let fp_hex = hex::encode(fp);
    let fp_path = args.state_dir.join("fingerprint.hex");
    std::fs::write(&fp_path, &fp_hex).with_context(|| format!("write {}", fp_path.display()))?;

    // Load worker allowlist (E1: anti-Sybil / anti-eclipse on the ctrl side).
    let allowlist: Option<HashSet<[u8; 32]>> = match &args.worker_allowlist {
        None => None,
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("read worker allowlist {}", path.display()))?;
            let entries: Vec<String> = serde_json::from_str(&raw)
                .with_context(|| format!("parse worker allowlist {}", path.display()))?;
            let mut set: HashSet<[u8; 32]> = HashSet::new();
            for s in entries {
                let bytes = hex::decode(s.trim())
                    .with_context(|| format!("decode allowlist hex entry"))?;
                if bytes.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "allowlist entry must be 32-byte SHA3-256 hex (64 chars), got {} bytes",
                        bytes.len()
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                set.insert(arr);
            }
            info!(count = set.len(), "worker allowlist loaded — only listed pk fingerprints will register");
            Some(set)
        }
    };
    let allowlist = Arc::new(allowlist);

    // Authority keypair — primary uses it to sign zone digests + receipts;
    // witness uses it only for receipts.  Each ctrl instance must have a
    // *distinct* key, otherwise N witnesses signing under the same pk
    // collapse to a single attestor for audit purposes.  Strategy:
    //   * primary  — fixed seed (the canonical primary, identified across
    //                deployments by its self-signed TLS cert)
    //   * witness  — seed = SHA3-256("DNS-SWARM-CTRL-WITNESS-V1" ||
    //                                canonical(state_dir)).  Different
    //                state-dirs → different witness keys.  Operators can
    //                also baseline by capturing the printed pk
    //                fingerprint and pinning it.
    let authority_seed = match args.mode {
        CtrlMode::Primary => *b"DNS-SWARM-CTRL-AUTHORITY-V1\0\0\0\0\0",
        CtrlMode::Witness => {
            use sha3::Digest;
            let mut h = sha3::Sha3_256::new();
            Digest::update(&mut h, b"DNS-SWARM-CTRL-WITNESS-V1");
            let canonical_state_dir = args.state_dir.canonicalize()
                .unwrap_or_else(|_| args.state_dir.clone());
            Digest::update(&mut h, canonical_state_dir.to_string_lossy().as_bytes());
            Digest::finalize(h).into()
        }
    };
    let authority = Arc::new(AuthorityKeypair::keygen(level, authority_seed));
    let authority_pk_bytes = Arc::new(authority.pk_bytes());

    info!(
        mode = ?args.mode, scheme = level.ml_dsa_name(),
        authority_pk_fp = %hex::encode(pk_binding_hash(&authority_pk_bytes))[..32].to_string(),
        "controller authority key ready"
    );

    let witness_archive = Arc::new(args.state_dir.join("witness-receipts"));
    if matches!(args.mode, CtrlMode::Witness) {
        std::fs::create_dir_all(witness_archive.as_path())
            .with_context(|| format!("create_dir_all {}", witness_archive.display()))?;
    }

    // E3: per-IP rate limit + caps + handshake timeout.
    let conn_limiter = Arc::new(ConnLimiter::new(
        args.max_conns_per_ip,
        args.connect_rate_per_ip,
        args.connect_burst_per_ip,
        args.max_active_conns,
    ));
    let handshake_timeout = Duration::from_secs(args.tls_handshake_timeout_secs.max(1));
    info!(
        max_per_ip = args.max_conns_per_ip,
        rate_per_ip = args.connect_rate_per_ip,
        burst_per_ip = args.connect_burst_per_ip,
        max_active = args.max_active_conns,
        tls_timeout_s = args.tls_handshake_timeout_secs,
        "connection-limiter armed"
    );

    let acceptor = TlsAcceptor::from(server_config(&id)?);
    let listener = TcpListener::bind(&args.bind).await
        .with_context(|| format!("bind {}", &args.bind))?;
    let local = listener.local_addr()?;

    info!("listening on {local}");
    info!("certificate fingerprint (SHA3-256) = {fp_hex}");
    info!("workers should connect with: --ctrl {} --ctrl-fingerprint {}", local, fp_hex);

    let roster = Arc::new(Mutex::new(Roster::default()));
    let (tx_evt, rx_evt) = mpsc::channel::<SessionEvent>(256);

    // Spawn the zone-job task only in primary mode and when configured.
    let job_handle = if matches!(args.mode, CtrlMode::Primary) && args.wait_workers > 0 && args.zone_records > 0 {
        let roster = roster.clone();
        let job_args = JobArgs {
            wait_workers:  args.wait_workers,
            zone_records:  args.zone_records,
            zone_ldt:      args.zone_ldt,
            zone_salt:     parse_zone_salt(&args.zone_salt_hex)?,
            level,
            state_dir:     args.state_dir.clone(),
            exit_on_complete: args.exit_on_complete,
            shard_deadline: Duration::from_secs(args.shard_deadline_secs),
            heartbeat_secs: args.heartbeat_secs,
            shard_replication: args.shard_replication.max(1),
            dnskey_pk_hex: args.dnskey_pk_hex.clone(),
            parent_ds_hash_hex: args.parent_ds_hash_hex.clone(),
        };
        Some(tokio::spawn(zone_job(job_args, roster, rx_evt)))
    } else {
        if matches!(args.mode, CtrlMode::Witness) {
            info!(
                archive = %witness_archive.display(),
                "running in WITNESS mode — registrations + WorkerEvidence only"
            );
        } else {
            info!("primary mode but no zone job configured — registration-only");
        }
        None
    };

    // Periodic roster-snapshot logger.
    {
        let roster = roster.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                let r = roster.lock().await;
                if r.count() == 0 {
                    info!("roster: 0 workers");
                } else {
                    info!("roster: {} worker(s) registered", r.count());
                }
            }
        });
    }

    // Accept loop.
    loop {
        let (sock, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let roster   = roster.clone();
        let tx_evt   = tx_evt.clone();
        let heartbeat_secs = args.heartbeat_secs;
        let ctrl_label = args.label.clone();
        let allowlist = allowlist.clone();
        let authority = authority.clone();
        let authority_pk_bytes = authority_pk_bytes.clone();
        let witness_archive = witness_archive.clone();
        let mode = args.mode;
        let conn_limiter = conn_limiter.clone();
        let hs_timeout = handshake_timeout;

        // E3: rate-limit / cap check happens BEFORE we spawn the handshake task,
        // so a flooder can't even cost us a tokio task allocation.
        let peer_ip = peer.ip();
        if let Err(reason) = conn_limiter.try_acquire(peer_ip) {
            warn!(%peer, ?reason, "connection denied — rate limit or cap");
            drop(sock); // explicit close
            continue;
        }

        tokio::spawn(async move {
            // Bound the TLS handshake — slowloris defence.
            let handshake = tokio::time::timeout(hs_timeout, acceptor.accept(sock)).await;
            match handshake {
                Ok(Ok(stream)) => {
                    if let Err(e) = handle_session(
                        stream, peer, roster, tx_evt, heartbeat_secs, ctrl_label,
                        allowlist, mode, authority, authority_pk_bytes, witness_archive,
                    ).await {
                        warn!(%peer, error = ?e, "session ended with error");
                    }
                }
                Ok(Err(e))  => error!(%peer, error = ?e, "TLS handshake failed"),
                Err(_)      => warn!(%peer, "TLS handshake timed out — slowloris defence"),
            }
            // Always release the limiter slot when the connection's task ends.
            conn_limiter.release(peer_ip);
        });

        // Cooperative exit: if the zone job has completed and we were asked to
        // exit, break out of the accept loop.
        if let Some(handle) = &job_handle {
            if handle.is_finished() {
                info!("zone job finished — accept loop exiting");
                break;
            }
        }
    }

    if let Some(handle) = job_handle {
        let _ = handle.await;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Per-session task
// ─────────────────────────────────────────────────────────────────────────────

async fn handle_session(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer: std::net::SocketAddr,
    roster: Arc<Mutex<Roster>>,
    tx_evt: mpsc::Sender<SessionEvent>,
    heartbeat_secs: u32,
    ctrl_label: String,
    allowlist: Arc<Option<HashSet<[u8; 32]>>>,
    mode: CtrlMode,
    authority: Arc<AuthorityKeypair>,
    authority_pk_bytes: Arc<Vec<u8>>,
    witness_archive: Arc<PathBuf>,
) -> Result<()> {
    // First message: Register.
    let first: ClientMsg = read_frame(&mut stream).await?;
    let (worker_id, node_id, mut rx_to_session) = match first {
        ClientMsg::Register { node_id, ml_dsa_pk, capabilities } => {
            let pk_fp = sha3_256(&ml_dsa_pk);

            // Allowlist check (E1).  Reject before allocating a worker_id.
            if let Some(set) = allowlist.as_ref() {
                if !set.contains(&pk_fp) {
                    warn!(
                        %peer, node = %node_id,
                        pk_fp = %hex::encode(pk_fp),
                        allowlist_size = set.len(),
                        "worker registration DENIED — pk fingerprint not in allowlist"
                    );
                    write_frame(&mut stream, &ServerMsg::RegisterDenied {
                        reason: "worker pk fingerprint not in controller allowlist".to_string(),
                    }).await?;
                    return Ok(());
                }
            }

            let (tx_to_session, rx_to_session) = mpsc::channel::<ServerMsg>(8);

            let mut r = roster.lock().await;
            let id = r.allocate();
            info!(
                worker_id = id, %peer, node = %node_id,
                pk_fp = %hex::encode(pk_fp),
                level = capabilities.nist_level, cores = capabilities.cores,
                allowlisted = allowlist.is_some(),
                "worker registered"
            );
            r.insert(WorkerSession {
                info: WorkerEntry {
                    id, node_id: node_id.clone(),
                    capabilities, pk_fp,
                    ml_dsa_pk,
                    last_seen: Instant::now(),
                },
                tx_to_session,
            });
            drop(r);

            write_frame(&mut stream, &ServerMsg::RegisterAck {
                worker_id: id,
                heartbeat_secs,
                controller_label: ctrl_label,
            }).await?;
            let _ = tx_evt.send(SessionEvent::Registered { worker_id: id }).await;
            (id, node_id, rx_to_session)
        }
        other => {
            write_frame(&mut stream, &ServerMsg::RegisterDenied {
                reason: format!("expected Register, got {:?}", std::mem::discriminant(&other)),
            }).await?;
            anyhow::bail!("first message was not Register");
        }
    };

    // Main session loop.
    loop {
        tokio::select! {
            biased;
            // Job-coordinator pushes (AssignShard / Shutdown ...).
            push = rx_to_session.recv() => {
                let Some(msg) = push else { break; };
                write_frame(&mut stream, &msg).await?;
            }
            // Worker-initiated messages.
            msg = read_frame::<_, ClientMsg>(&mut stream) => {
                match msg {
                    Ok(ClientMsg::Heartbeat { worker_id: hb_id }) => {
                        let _ = roster.lock().await.touch(hb_id);
                        write_frame(&mut stream, &ServerMsg::HeartbeatAck).await?;
                    }
                    Ok(ClientMsg::ShardDone { worker_id: w, result }) => {
                        if matches!(mode, CtrlMode::Witness) {
                            warn!(worker_id = w, "ShardDone received in witness mode — ignored");
                            continue;
                        }
                        let _ = tx_evt.send(SessionEvent::ShardDone { worker_id: w, result }).await;
                    }
                    Ok(ClientMsg::ShardFailed { worker_id: w, shard_id, reason }) => {
                        let _ = tx_evt.send(SessionEvent::ShardFailed { worker_id: w, shard_id, reason }).await;
                    }
                    Ok(ClientMsg::WorkerEvidence {
                        worker_id: w, job_id, shard_id, pi_hash,
                        merkle_root, root_f0, worker_sig,
                    }) => {
                        // Witness role: validate worker's attestation signature
                        // against the worker's registered ML-DSA pk; sign + archive
                        // an independent receipt; send a Receipt back to the worker.
                        if !matches!(mode, CtrlMode::Witness) {
                            warn!(worker_id = w, "WorkerEvidence received but not in witness mode — ignored");
                            continue;
                        }
                        let pk = match roster.lock().await.workers.get(&w) {
                            Some(ws) => ws.info.ml_dsa_pk.clone(),
                            None => { warn!(worker_id = w, "evidence from unregistered worker"); continue; }
                        };
                        let attest_dig = worker_attestation_digest(shard_id, &pi_hash, &merkle_root, &root_f0);
                        if !verify_worker_sig(&pk, &attest_dig, &worker_sig) {
                            warn!(worker_id = w, shard_id, "evidence sig verify FAILED — ignored");
                            continue;
                        }
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64).unwrap_or(0);
                        let r_dig = ctrl_receipt_digest(&job_id, shard_id, w, &pi_hash, &merkle_root, now_ms);
                        let receipt = ShardReceipt {
                            job_id, shard_id, worker_id: w,
                            pi_hash, merkle_root,
                            accepted_at_unix_ms: now_ms,
                            ctrl_authority_pk: (*authority_pk_bytes).clone(),
                            ctrl_sig: authority.sign(&r_dig),
                        };
                        // Archive locally
                        let job_dir = witness_archive.join(format!("job-{}", hex::encode(job_id)));
                        if let Err(e) = std::fs::create_dir_all(&job_dir) {
                            warn!(error = ?e, "failed to create witness archive dir");
                        } else {
                            let path = job_dir.join(format!("shard-{:04}.cbor", shard_id));
                            let mut buf = Vec::new();
                            if ciborium::ser::into_writer(&receipt, &mut buf).is_ok() {
                                if let Err(e) = std::fs::write(&path, &buf) {
                                    warn!(error = ?e, path = %path.display(), "failed to write witness receipt");
                                } else {
                                    info!(worker_id = w, shard_id,
                                          pi_hash = %hex::encode(pi_hash)[..16].to_string(),
                                          path = %path.display(),
                                          "witness receipt archived");
                                }
                            }
                        }
                        // Echo the receipt back to the worker over the same session.
                        write_frame(&mut stream, &ServerMsg::Receipt { receipt }).await?;
                    }
                    Ok(ClientMsg::Goodbye { worker_id: bye_id }) => {
                        info!(worker_id = bye_id, node = %node_id, "worker said goodbye");
                        break;
                    }
                    Ok(ClientMsg::Register { .. }) => {
                        warn!(worker_id, "duplicate Register on live session — ignoring");
                    }
                    Err(swarm_proto::frame::FrameError::Io(e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        info!(worker_id, node = %node_id, "connection closed by peer");
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }

    roster.lock().await.remove(worker_id);
    let _ = tx_evt.send(SessionEvent::Disconnected { worker_id }).await;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Zone-job orchestrator
// ─────────────────────────────────────────────────────────────────────────────

struct JobArgs {
    wait_workers:    usize,
    zone_records:    usize,
    zone_ldt:        LdtMode,
    zone_salt:       [u8; 16],
    level:           NistLevel,
    state_dir:       PathBuf,
    exit_on_complete: bool,
    shard_deadline:  Duration,
    heartbeat_secs:  u32,
    shard_replication: usize,
    dnskey_pk_hex:     Option<String>,
    parent_ds_hash_hex: Option<String>,
}

async fn zone_job(
    args: JobArgs,
    roster: Arc<Mutex<Roster>>,
    mut rx_evt: mpsc::Receiver<SessionEvent>,
) {
    let job_started = Instant::now();
    info!(
        wait_workers = args.wait_workers,
        zone_records = args.zone_records,
        ldt = args.zone_ldt.label(),
        nist_level = match args.level { NistLevel::L1 => 1, NistLevel::L3 => 3, NistLevel::L5 => 5 },
        "zone job ready, waiting for workers"
    );

    // Phase 1: wait for enough registrations.
    let waited_until = loop {
        let count = roster.lock().await.count();
        if count >= args.wait_workers {
            break Instant::now();
        }
        match tokio::time::timeout(Duration::from_secs(60), rx_evt.recv()).await {
            Ok(Some(SessionEvent::Registered { .. })) => continue,
            Ok(Some(SessionEvent::Disconnected { .. })) => continue,
            Ok(Some(_)) => continue, // Shard events shouldn't happen yet
            Ok(None)    => { error!("event channel closed before workers ready"); return; }
            Err(_)      => { warn!("still waiting for workers, count={count}"); }
        }
    };
    let wait_workers_ms = waited_until.duration_since(job_started).as_secs_f64() * 1e3;
    info!(wait_workers_ms, "worker quorum reached");

    // Phase 2: compose authority key, derive pk_hash, build records, split.
    //          Generate fresh per-job randomness for replay defence.
    const AUTHORITY_SEED: [u8; 32] = *b"DNS-SWARM-CTRL-AUTHORITY-V1\0\0\0\0\0";
    let authority = AuthorityKeypair::keygen(args.level, AUTHORITY_SEED);
    let pk_bytes  = authority.pk_bytes();
    let pk_hash32 = pk_binding_hash(&pk_bytes);

    let mut job_id_seed = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut job_id_seed);
    let job_id = job_id_seed;

    let records = build_synthetic_zone(args.zone_records);
    let initial_worker_ids = roster.lock().await.ids();
    let k = args.shard_replication.max(1);
    // With replication k, divide workers among shards so every shard gets k
    // distinct provers in parallel.  At least one shard always.
    let n_shards = std::cmp::max(1, initial_worker_ids.len() / k);
    let shards = split_evenly(&records, n_shards);
    info!(
        n_shards, replication = k, total_records = records.len(),
        job_id = %hex::encode(job_id),
        "zone composed and split"
    );

    // Build the ensemble for every shard up front:
    //   * deterministic shard_id 1..=n_shards
    //   * unique random nonce per shard (B)
    //   * pre-computed expected merkle_root per shard (A)
    //   * target replication factor k (F)
    let mut ensembles: HashMap<u32, ShardEnsemble> = HashMap::new();
    let mut shard_queue: VecDeque<u32> = VecDeque::new();
    let mut expected_merkle_roots: HashMap<u32, [u8; 32]> = HashMap::new();
    let mut shard_nonces: HashMap<u32, [u8; 32]> = HashMap::new();
    for (i, shard_records) in shards.iter().enumerate() {
        let shard_id = (i as u32) + 1;
        let mut nonce = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
        let expected_root = compute_merkle_root(&args.zone_salt, shard_records);
        let spec = ShardSpec {
            shard_id,
            zone_salt: args.zone_salt,
            authority_pk_hash: pk_hash32,
            job_id,
            shard_nonce: nonce,
            ldt: args.zone_ldt,
            records: shard_records.clone(),
        };
        ensembles.insert(shard_id, ShardEnsemble {
            spec,
            expected_merkle_root: expected_root,
            target_k: k,
            assigned: HashSet::new(),
            pending_workers: HashMap::new(),
            responses: HashMap::new(),
            attempts: 0,
        });
        shard_queue.push_back(shard_id);
        expected_merkle_roots.insert(shard_id, expected_root);
        shard_nonces.insert(shard_id, nonce);
    }
    let expected_total = ensembles.len();

    // Phase 3+4: assign + collect with reaper.
    let assign_started = Instant::now();
    let mut busy: HashSet<WorkerId> = HashSet::new();
    let mut blacklisted: HashSet<WorkerId> = HashSet::new();
    let mut results: HashMap<u32, ShardResult> = HashMap::new();
    /// Per-shard list of (worker_id, worker_pk_bytes, ShardResult.worker_sig)
    /// for every replica that ratified the canonical result.
    let mut shard_attestations: HashMap<u32, Vec<(WorkerId, Vec<u8>, Vec<u8>, f64)>> = HashMap::new();

    let heartbeat_grace = Duration::from_secs((args.heartbeat_secs as u64).saturating_mul(2).max(2));
    let mut reaper_tick = tokio::time::interval(Duration::from_millis(500));
    reaper_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Initial drain: try to fill every available worker.
    drain_assignments(&mut shard_queue, &mut ensembles, &mut busy, &blacklisted, &roster).await;

    loop {
        if results.len() == expected_total {
            break;
        }
        // Stuck check: nothing in flight, queue empty, no acceptable workers.
        if shard_queue.is_empty()
            && ensembles.values().all(|e| e.pending_workers.is_empty())
            && results.len() < expected_total
        {
            error!(
                pending = ensembles.len() - results.len(),
                blacklisted = blacklisted.len(),
                "no assignable workers and no replicas in flight — job stuck"
            );
            return;
        }

        tokio::select! {
            biased;
            _ = reaper_tick.tick() => {
                // Heartbeat reaper (D): drop workers whose last_seen is too old.
                let now = Instant::now();
                let stale: Vec<WorkerId> = {
                    let r = roster.lock().await;
                    r.workers.iter()
                        .filter(|(_, ws)| now.duration_since(ws.info.last_seen) > heartbeat_grace)
                        .map(|(id, _)| *id)
                        .collect()
                };
                for id in stale {
                    warn!(worker_id = id, "heartbeat lost (>{}s) — dropping worker", heartbeat_grace.as_secs());
                    roster.lock().await.remove(id);
                    drop_worker_from_ensembles(id, &mut ensembles, &mut busy, &mut shard_queue);
                }

                // Per-shard-replica deadline reaper (C).
                let mut to_blacklist: Vec<(WorkerId, u32)> = Vec::new();
                for (sid, ens) in ensembles.iter() {
                    for (w, t0) in &ens.pending_workers {
                        if now.duration_since(*t0) > args.shard_deadline {
                            to_blacklist.push((*w, *sid));
                        }
                    }
                }
                for (w, sid) in to_blacklist {
                    warn!(
                        shard_id = sid, worker_id = w,
                        deadline_s = args.shard_deadline.as_secs(),
                        "replica deadline expired — blacklisting worker"
                    );
                    blacklisted.insert(w);
                    if let Some(ens) = ensembles.get_mut(&sid) {
                        ens.pending_workers.remove(&w);
                    }
                    busy.remove(&w);
                    let _ = roster.lock().await.remove(w);
                    shard_queue.push_back(sid);
                }

                drain_assignments(&mut shard_queue, &mut ensembles, &mut busy, &blacklisted, &roster).await;
            }
            evt = rx_evt.recv() => {
                let evt = match evt {
                    Some(e) => e,
                    None    => { error!("event channel closed mid-job"); return; }
                };
                match evt {
                    SessionEvent::ShardDone { worker_id: w, result } => {
                        let sid = result.shard_id;
                        // (1) Was this worker assigned to this shard's ensemble?
                        let in_pending = ensembles.get(&sid)
                            .map(|e| e.pending_workers.contains_key(&w))
                            .unwrap_or(false);
                        if !in_pending {
                            warn!(worker_id = w, shard_id = sid,
                                  "ShardDone from worker not pending on this shard — ignored");
                            continue;
                        }
                        // (2) Worker attestation signature must verify.
                        let pk = match roster.lock().await.workers.get(&w) {
                            Some(ws) => ws.info.ml_dsa_pk.clone(),
                            None => { warn!(worker_id = w, "ShardDone from unregistered worker"); continue; }
                        };
                        let digest = worker_attestation_digest(
                            result.shard_id, &result.pi_hash, &result.merkle_root, &result.root_f0,
                        );
                        if !verify_worker_sig(&pk, &digest, &result.worker_sig) {
                            error!(worker_id = w, shard_id = sid, "attestation sig FAILED — blacklisting");
                            blacklisted.insert(w);
                            if let Some(ens) = ensembles.get_mut(&sid) {
                                ens.pending_workers.remove(&w);
                            }
                            busy.remove(&w);
                            let _ = roster.lock().await.remove(w);
                            shard_queue.push_back(sid);
                            drain_assignments(&mut shard_queue, &mut ensembles, &mut busy, &blacklisted, &roster).await;
                            continue;
                        }
                        // (3) MERKLE-ROOT PINNING (A).
                        let expected = expected_merkle_roots[&sid];
                        if result.merkle_root != expected {
                            error!(
                                worker_id = w, shard_id = sid,
                                got = %hex::encode(result.merkle_root),
                                expected = %hex::encode(expected),
                                "MERKLE ROOT MISMATCH — substitution attack — blacklisting"
                            );
                            blacklisted.insert(w);
                            if let Some(ens) = ensembles.get_mut(&sid) {
                                ens.pending_workers.remove(&w);
                            }
                            busy.remove(&w);
                            let _ = roster.lock().await.remove(w);
                            shard_queue.push_back(sid);
                            drain_assignments(&mut shard_queue, &mut ensembles, &mut busy, &blacklisted, &roster).await;
                            continue;
                        }

                        // Sign + send a receipt acknowledging this submission
                        // (G — censorship/substitution audit trail).  Receipts
                        // are sent on validation pass, BEFORE the ensemble
                        // decision, so even minority dissenters get one.
                        let accepted_at_unix_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        let receipt_digest = ctrl_receipt_digest(
                            &job_id, sid, w,
                            &result.pi_hash, &result.merkle_root, accepted_at_unix_ms,
                        );
                        let receipt = ShardReceipt {
                            job_id: job_id,
                            shard_id: sid,
                            worker_id: w,
                            pi_hash: result.pi_hash,
                            merkle_root: result.merkle_root,
                            accepted_at_unix_ms,
                            ctrl_authority_pk: pk_bytes.clone(),
                            ctrl_sig: authority.sign(&receipt_digest),
                        };
                        // Push the receipt down the worker's session channel.
                        if let Some(ws) = roster.lock().await.workers.get(&w) {
                            let _ = ws.tx_to_session.send(ServerMsg::Receipt { receipt }).await;
                        }

                        // Move worker from pending → responses.
                        let ens = ensembles.get_mut(&sid).expect("checked above");
                        ens.pending_workers.remove(&w);
                        ens.responses.insert(w, ResponseEntry { result: result.clone(), worker_pk: pk.clone() });
                        busy.remove(&w);

                        info!(
                            worker_id = w, shard_id = sid,
                            replica = ens.responses.len(), of_k = ens.target_k,
                            records = result.record_count, prove_ms = result.prove_ms,
                            pi_hash = %hex::encode(result.pi_hash),
                            "replica response received"
                        );

                        // Evaluate ensemble verdict.
                        let verdict = evaluate_ensemble(ens);
                        match verdict {
                            EnsembleVerdict::Pending => {
                                // need more replicas
                            }
                            EnsembleVerdict::Accepted { canonical_worker } => {
                                let canonical = ens.responses[&canonical_worker].clone();
                                let attestations: Vec<(WorkerId, Vec<u8>, Vec<u8>, f64)> = ens.responses.iter()
                                    .map(|(wid, e)| (*wid, e.worker_pk.clone(),
                                                     e.result.worker_sig.clone(),
                                                     e.result.prove_ms))
                                    .collect();
                                info!(
                                    shard_id = sid,
                                    replicas = attestations.len(),
                                    pi_hash = %hex::encode(canonical.result.pi_hash),
                                    "ensemble UNANIMOUS — shard accepted"
                                );
                                shard_attestations.insert(sid, attestations);
                                results.insert(sid, canonical.result);
                                ensembles.remove(&sid);
                            }
                            EnsembleVerdict::MajorityWin { canonical_worker, dissenters } => {
                                let canonical = ens.responses[&canonical_worker].clone();
                                let attestations: Vec<(WorkerId, Vec<u8>, Vec<u8>, f64)> = ens.responses.iter()
                                    .filter(|(wid, _)| !dissenters.contains(wid))
                                    .map(|(wid, e)| (*wid, e.worker_pk.clone(),
                                                     e.result.worker_sig.clone(),
                                                     e.result.prove_ms))
                                    .collect();
                                error!(
                                    shard_id = sid,
                                    majority = attestations.len(),
                                    dissenters = ?dissenters,
                                    "ensemble MAJORITY-WIN — dissenters blacklisted, shard accepted"
                                );
                                for d in &dissenters {
                                    blacklisted.insert(*d);
                                    let _ = roster.lock().await.remove(*d);
                                }
                                shard_attestations.insert(sid, attestations);
                                results.insert(sid, canonical.result);
                                ensembles.remove(&sid);
                            }
                            EnsembleVerdict::AllConflict => {
                                let bad: Vec<WorkerId> = ens.responses.keys().copied().collect();
                                error!(
                                    shard_id = sid, replicas = ens.responses.len(),
                                    workers = ?bad,
                                    "ensemble ALL-CONFLICT — no decisive majority. Aborting job."
                                );
                                for d in bad {
                                    blacklisted.insert(d);
                                    let _ = roster.lock().await.remove(d);
                                }
                                return; // per agreed policy: abort on undecidable disagreement
                            }
                        }
                        drain_assignments(&mut shard_queue, &mut ensembles, &mut busy, &blacklisted, &roster).await;
                    }
                    SessionEvent::ShardFailed { worker_id: w, shard_id, reason } => {
                        warn!(worker_id = w, shard_id, reason = %reason, "worker reported shard failure — slot reopened");
                        if let Some(ens) = ensembles.get_mut(&shard_id) {
                            ens.pending_workers.remove(&w);
                        }
                        busy.remove(&w);
                        shard_queue.push_back(shard_id);
                        drain_assignments(&mut shard_queue, &mut ensembles, &mut busy, &blacklisted, &roster).await;
                    }
                    SessionEvent::Disconnected { worker_id: w } => {
                        if busy.contains(&w) {
                            warn!(worker_id = w, "worker disconnected with replica outstanding — slot reopened");
                        }
                        drop_worker_from_ensembles(w, &mut ensembles, &mut busy, &mut shard_queue);
                        drain_assignments(&mut shard_queue, &mut ensembles, &mut busy, &blacklisted, &roster).await;
                    }
                    SessionEvent::Registered { worker_id: _w } => {
                        drain_assignments(&mut shard_queue, &mut ensembles, &mut busy, &blacklisted, &roster).await;
                    }
                }
            }
        }
    }
    let assign_to_last_done_ms = assign_started.elapsed().as_secs_f64() * 1e3;
    info!(
        assign_to_last_done_ms,
        blacklisted = blacklisted.len(),
        replication = k,
        "all inner shards collected"
    );

    // Persist each inner-shard proof blob to disk.
    let proofs_dir = args.state_dir.join("proofs");
    if let Err(e) = std::fs::create_dir_all(&proofs_dir) {
        error!(error = ?e, path = %proofs_dir.display(), "failed to create proofs dir");
        return;
    }
    let mut inner_proof_paths: HashMap<u32, String> = HashMap::new();
    for r in results.values() {
        let fname = format!("inner-shard-{:04}.bin", r.shard_id);
        let p = proofs_dir.join(&fname);
        if let Err(e) = std::fs::write(&p, &r.proof_blob) {
            error!(shard_id = r.shard_id, error = ?e, "failed to write inner proof");
            return;
        }
        inner_proof_paths.insert(r.shard_id, format!("proofs/{fname}"));
    }
    info!(count = results.len(), dir = %proofs_dir.display(), "inner proofs persisted");

    // Phase 5: outer rollup over collected pi_hashes (in shard-id order).
    let mut sorted: Vec<&ShardResult> = results.values().collect();
    sorted.sort_by_key(|r| r.shard_id);
    let pi_hashes: Vec<[u8; 32]> = sorted.iter().map(|r| r.pi_hash).collect();

    let outer_started = Instant::now();
    let outer = tokio::task::spawn_blocking({
        let pi = pi_hashes.clone();
        let pk = pk_hash32;
        let ldt = args.zone_ldt;
        move || prove_outer_rollup(&pi, &pk, ldt)
    }).await.expect("outer rollup task");
    let outer_rollup_ms = outer_started.elapsed().as_secs_f64() * 1e3;
    info!(
        outer_n_trace = outer.n_trace,
        outer_prove_ms = outer.prove_ms,
        outer_self_verify_ms = outer.local_verify_ms,
        outer_proof_bytes = outer.proof_bytes,
        "outer rollup proved + self-verified"
    );

    // Persist outer rollup proof blob.
    let outer_proof_filename = "proofs/outer-rollup.bin";
    let outer_proof_path = args.state_dir.join(outer_proof_filename);
    if let Err(e) = std::fs::write(&outer_proof_path, &outer.proof_blob) {
        error!(error = ?e, path = %outer_proof_path.display(), "failed to write outer proof");
        return;
    }

    // Phase 6: ML-DSA sign the level-matched zone digest.
    let nist_byte = match args.level { NistLevel::L1 => 1u8, NistLevel::L3 => 3, NistLevel::L5 => 5 };
    // DS-binding bytes: hex-decoded DNSKEY + DS hash (or empty marker if
    // not set).  Including them in the zone_digest ties the authority's
    // signature to the claimed DS context, so any post-hoc tampering on
    // those fields invalidates sig verification.
    let dnskey_bytes: Vec<u8> = match &args.dnskey_pk_hex {
        Some(h) => match hex::decode(h) {
            Ok(b)  => b,
            Err(e) => { error!(error = ?e, "bad --dnskey-pk-hex; aborting"); return; }
        },
        None    => Vec::new(),
    };
    let ds_hash_bytes: Vec<u8> = match &args.parent_ds_hash_hex {
        Some(h) => match hex::decode(h) {
            Ok(b)  => b,
            Err(e) => { error!(error = ?e, "bad --parent-ds-hash-hex; aborting"); return; }
        },
        None    => Vec::new(),
    };
    if !ds_hash_bytes.is_empty() && ds_hash_bytes.len() != 32 {
        error!(got = ds_hash_bytes.len(), "DS hash must be 32 bytes; aborting"); return;
    }
    let zone_digest = level_hash(args.level, &[
        b"DNS-ZONE-AUTHORITY-V1",
        &[nist_byte],
        &args.zone_salt,
        &(records.len() as u64).to_le_bytes(),
        &outer.root_f0,
        &pk_hash32,
        b"DS-BIND-V1",
        &(dnskey_bytes.len() as u32).to_le_bytes(),
        &dnskey_bytes,
        &(ds_hash_bytes.len() as u32).to_le_bytes(),
        &ds_hash_bytes,
    ]);
    let sign_started = Instant::now();
    let sig = authority.sign(&zone_digest);
    let sign_ms = sign_started.elapsed().as_secs_f64() * 1e3;
    let sig_ok = authority.verify(&zone_digest, &sig);
    info!(sig_ok, "authority signature produced + self-verified");
    assert!(sig_ok, "controller authority self-verify failed");

    // Phase 7: write bundle.
    let total_ms = job_started.elapsed().as_secs_f64() * 1e3;
    let bundle = ZoneBundle {
        bundle_format:     2,
        nist_level:        nist_byte,
        ml_dsa_scheme:     args.level.ml_dsa_name().to_string(),
        signed_digest_hash: args.level.hash_name().to_string(),
        zone_salt_hex:     hex::encode(args.zone_salt),
        record_count:      records.len(),
        shard_count:       n_shards,
        shard_replication: k,
        ldt:               args.zone_ldt.label().to_string(),
        authority_pk_hex:  hex::encode(&pk_bytes),
        authority_pk_hash_hex: hex::encode(pk_hash32),
        job_id_hex:        hex::encode(job_id),
        dnskey_pk_hex:     args.dnskey_pk_hex.clone(),
        parent_ds_hash_hex: args.parent_ds_hash_hex.clone(),
        inner_pi_hashes_hex: pi_hashes.iter().map(hex::encode).collect(),
        outer_root_f0_hex: hex::encode(outer.root_f0),
        outer_n_trace:     outer.n_trace,
        outer_n0:          outer.n0,
        // True transport size = serialised blob length (matches what the
        // verifier reads from disk); the prover's logical-byte heuristic
        // (`outer.proof_bytes`) is for back-of-envelope only.
        outer_proof_bytes: outer.proof_blob.len(),
        outer_proof_path:  outer_proof_filename.to_string(),
        zone_digest_hex:   hex::encode(&zone_digest),
        authority_sig_hex: hex::encode(&sig),
        inner_workers:     sorted.iter().map(|r| {
            let proof_path = inner_proof_paths.get(&r.shard_id).cloned().unwrap_or_default();
            let nonce = shard_nonces.get(&r.shard_id).copied().unwrap_or([0u8; 32]);
            let attestations = shard_attestations.get(&r.shard_id).cloned().unwrap_or_default()
                .into_iter()
                .map(|(wid, pk, sig, prove_ms)| Attestation {
                    worker_id:      wid,
                    worker_pk_hex:  hex::encode(&pk),
                    worker_sig_hex: hex::encode(&sig),
                    prove_ms,
                })
                .collect();
            InnerWorkerRecord {
                shard_id:        r.shard_id,
                shard_nonce_hex: hex::encode(nonce),
                pi_hash_hex:     hex::encode(r.pi_hash),
                merkle_root_hex: hex::encode(r.merkle_root),
                record_count:    r.record_count,
                n_trace:         r.n_trace,
                proof_bytes_len: r.proof_bytes_len,
                proof_path,
                attestations,
            }
        }).collect(),
        timings_ms: Timings {
            wait_workers_ms,
            assign_to_last_done_ms,
            outer_rollup_ms,
            sign_ms,
            total_ms,
        },
    };

    let bundle_path = args.state_dir.join("zone_bundle.json");
    let json = serde_json::to_string_pretty(&bundle).expect("serialize bundle");
    if let Err(e) = std::fs::write(&bundle_path, json) {
        error!(error = ?e, path = %bundle_path.display(), "failed to write zone bundle");
    } else {
        info!(path = %bundle_path.display(), "zone bundle written");
    }

    info!(
        total_ms,
        wait_ms = wait_workers_ms,
        prove_inner_ms = assign_to_last_done_ms,
        prove_outer_ms = outer_rollup_ms,
        sign_ms,
        "ZONE JOB COMPLETE"
    );

    if args.exit_on_complete {
        // Give the accept loop a moment to notice we're done.
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::process::exit(0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_nist(n: u8) -> Result<NistLevel> {
    Ok(match n {
        1 => NistLevel::L1,
        3 => NistLevel::L3,
        5 => NistLevel::L5,
        other => anyhow::bail!("invalid --nist-level {other} (1, 3, or 5)"),
    })
}

fn parse_zone_salt(opt: &Option<String>) -> Result<[u8; 16]> {
    let mut out = [0u8; 16];
    if let Some(hex_s) = opt {
        let bytes = hex::decode(hex_s).context("decode --zone-salt-hex")?;
        if bytes.len() != 16 {
            anyhow::bail!("zone salt must be 16 bytes, got {}", bytes.len());
        }
        out.copy_from_slice(&bytes);
    } else {
        out.copy_from_slice(b"swarm-test-zone1");
    }
    Ok(out)
}

fn split_evenly(records: &[DnsRecord], n_shards: usize) -> Vec<Vec<DnsRecord>> {
    if n_shards == 0 { return Vec::new(); }
    let base   = records.len() / n_shards;
    let remain = records.len() % n_shards;
    let mut out = Vec::with_capacity(n_shards);
    let mut i = 0;
    for s in 0..n_shards {
        let len = base + if s < remain { 1 } else { 0 };
        out.push(records[i..i + len].to_vec());
        i += len;
    }
    out
}

fn build_synthetic_zone(n: usize) -> Vec<DnsRecord> {
    (0..n as u64).map(|i| match i % 4 {
        0 => DnsRecord::a(
            &format!("host-{i:08x}.example.com"), 300,
            [10, ((i >> 16) & 0xff) as u8, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8],
        ),
        1 => DnsRecord::aaaa(
            &format!("v6-{i:08x}.example.com"), 300, {
                let mut b = [0u8; 16];
                b[0..8].copy_from_slice(&i.to_be_bytes());
                b[8..16].copy_from_slice(&(i ^ 0xCAFE_BABE_DEAD_BEEF).to_be_bytes());
                b
            },
        ),
        2 => DnsRecord::txt(
            &format!("txt-{i:08x}.example.com"), 60,
            &format!("v=auth1;rec={i}"),
        ),
        _ => DnsRecord::mx(
            &format!("mail-{i:08x}.example.com"), 300, (i % 1000) as u16,
            &format!("mx{}.example.com", i & 0xff),
        ),
    }).collect()
}

// ─── E3: per-IP rate limiter + cap (anti-DoS at the TLS-accept boundary) ───

#[derive(Debug)]
struct IpBucket {
    /// Currently in-flight connections from this IP.
    active:      usize,
    /// Token-bucket reservoir; refilled at `rate_per_sec`, capped at `burst`.
    tokens:      f64,
    last_refill: Instant,
}

#[derive(Debug)]
struct ConnLimiter {
    max_per_ip:        usize,
    rate_per_sec:      f64,
    burst:             f64,
    max_active_total:  usize,
    state:             std::sync::Mutex<HashMap<std::net::IpAddr, IpBucket>>,
    active_total:      std::sync::atomic::AtomicUsize,
}

#[derive(Debug, PartialEq, Eq)]
enum DenyReason {
    /// Concurrent-connection cap for this IP exhausted.
    MaxPerIp,
    /// Token bucket empty — too many connection attempts too fast.
    RateLimit,
    /// Global cap on simultaneous connections hit.
    MaxActiveTotal,
}

impl ConnLimiter {
    fn new(max_per_ip: usize, rate_per_sec: f64, burst: f64, max_active_total: usize) -> Self {
        Self {
            max_per_ip, rate_per_sec, burst, max_active_total,
            state: std::sync::Mutex::new(HashMap::new()),
            active_total: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    /// Try to admit a new connection from `ip`.  On success, returns Ok;
    /// caller must call `release(ip)` when the session ends.
    fn try_acquire(&self, ip: std::net::IpAddr) -> std::result::Result<(), DenyReason> {
        // Global cap first (cheap, lock-free).
        let cur = self.active_total.load(std::sync::atomic::Ordering::Relaxed);
        if cur >= self.max_active_total {
            return Err(DenyReason::MaxActiveTotal);
        }
        let mut state = self.state.lock().expect("ConnLimiter mutex poisoned");
        let now = Instant::now();
        let entry = state.entry(ip).or_insert(IpBucket {
            active: 0, tokens: self.burst, last_refill: now,
        });
        // Refill.
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * self.rate_per_sec).min(self.burst);
        entry.last_refill = now;
        // Concurrent cap.
        if entry.active >= self.max_per_ip {
            return Err(DenyReason::MaxPerIp);
        }
        // Rate limit.
        if entry.tokens < 1.0 {
            return Err(DenyReason::RateLimit);
        }
        entry.tokens -= 1.0;
        entry.active += 1;
        self.active_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn release(&self, ip: std::net::IpAddr) {
        let mut state = self.state.lock().expect("ConnLimiter mutex poisoned");
        if let Some(e) = state.get_mut(&ip) {
            e.active = e.active.saturating_sub(1);
            // Drop the entry if it's idle and full-tokened (cheap GC).
            if e.active == 0 && e.tokens >= self.burst {
                state.remove(&ip);
            }
        }
        self.active_total.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

// ─── Job-state helpers (orchestration, reaping, reassignment) ──────────────

/// Per-shard k-replicated assignment state.
///
/// A shard is "complete" when the ensemble has gathered exactly `target_k`
/// responses and they all agree on `(merkle_root, pi_hash, root_f0)`.
/// (deep_fri_prove is deterministic, so honest replicas produce
/// byte-identical proofs.)
struct ShardEnsemble {
    spec:                  ShardSpec,
    expected_merkle_root:  [u8; 32],
    target_k:              usize,
    /// Workers that have ever been assigned this shard (so we don't re-pick
    /// the same worker for two replica slots of the same shard).
    assigned:              HashSet<WorkerId>,
    /// Workers currently holding this shard (sub-set of `assigned`).
    pending_workers:       HashMap<WorkerId, Instant>,
    /// Validated responses gathered so far.
    responses:             HashMap<WorkerId, ResponseEntry>,
    attempts:              u32,
}

impl ShardEnsemble {
    fn slots_remaining(&self) -> usize {
        self.target_k.saturating_sub(self.pending_workers.len() + self.responses.len())
    }
    fn shard_id(&self) -> u32 { self.spec.shard_id }
}

#[derive(Clone)]
struct ResponseEntry {
    result:        ShardResult,
    worker_pk:     Vec<u8>,
}

#[derive(Debug)]
enum EnsembleVerdict {
    Pending,
    Accepted    { canonical_worker: WorkerId },
    MajorityWin { canonical_worker: WorkerId, dissenters: Vec<WorkerId> },
    AllConflict,
}

fn evaluate_ensemble(ens: &ShardEnsemble) -> EnsembleVerdict {
    if ens.responses.len() < ens.target_k { return EnsembleVerdict::Pending; }

    // Bucket responses by (pi_hash, merkle_root, root_f0). Honest responses
    // are byte-identical; one bucket per distinct claim.
    let mut buckets: HashMap<([u8;32],[u8;32],[u8;32]), Vec<WorkerId>> = HashMap::new();
    for (wid, e) in &ens.responses {
        buckets.entry((e.result.pi_hash, e.result.merkle_root, e.result.root_f0))
            .or_default().push(*wid);
    }

    if buckets.len() == 1 {
        // Unanimous.
        let canonical = ens.responses.keys().next().copied().expect("non-empty");
        return EnsembleVerdict::Accepted { canonical_worker: canonical };
    }

    // Disagreement. Find the largest bucket.
    let largest = buckets.values().map(|v| v.len()).max().unwrap_or(0);
    let largest_count = buckets.values().filter(|v| v.len() == largest).count();

    // Strict majority required: largest > total/2 AND only one largest bucket.
    let total = ens.target_k;
    if largest * 2 > total && largest_count == 1 {
        let majority_workers = buckets.values()
            .find(|v| v.len() == largest).cloned().unwrap_or_default();
        let canonical = majority_workers[0];
        let dissenters: Vec<WorkerId> = buckets.iter()
            .filter(|(_, v)| v.len() != largest)
            .flat_map(|(_, v)| v.iter().copied())
            .collect();
        EnsembleVerdict::MajorityWin { canonical_worker: canonical, dissenters }
    } else {
        EnsembleVerdict::AllConflict
    }
}

/// Top up every ensemble that still needs replicas with assignments to idle,
/// non-blacklisted, non-already-assigned-to-this-shard workers.
async fn drain_assignments(
    queue:       &mut VecDeque<u32>, // shard_ids needing more replicas
    ensembles:   &mut HashMap<u32, ShardEnsemble>,
    busy:        &mut HashSet<WorkerId>,
    blacklisted: &HashSet<WorkerId>,
    roster:      &Arc<Mutex<Roster>>,
) {
    let mut still_pending: VecDeque<u32> = VecDeque::new();
    while let Some(sid) = queue.pop_front() {
        let Some(ens) = ensembles.get(&sid) else { continue; };
        if ens.slots_remaining() == 0 { continue; }
        // Find an idle, non-blacklisted worker not already assigned to this shard.
        let candidate = {
            let r = roster.lock().await;
            r.workers.keys()
                .find(|id|
                    !busy.contains(id)
                    && !blacklisted.contains(id)
                    && !ens.assigned.contains(id))
                .copied()
        };
        let Some(worker_id) = candidate else {
            still_pending.push_back(sid);
            continue;
        };

        let r = roster.lock().await;
        let tx = match r.workers.get(&worker_id) {
            Some(ws) => ws.tx_to_session.clone(),
            None    => { drop(r); still_pending.push_back(sid); continue; }
        };
        drop(r);

        let spec = ens.spec.clone();
        if let Err(e) = tx.send(ServerMsg::AssignShard { spec: spec.clone() }).await {
            warn!(worker_id, shard_id = sid, error = ?e, "AssignShard push failed — will retry");
            still_pending.push_back(sid);
            continue;
        }
        info!(
            worker_id, shard_id = sid, replica_index = ens.assigned.len() + 1,
            of_k = ens.target_k,
            attempts = ens.attempts + 1,
            records = spec.records.len(), ldt = spec.ldt.label(),
            "shard replica assigned"
        );
        let ens_mut = ensembles.get_mut(&sid).expect("just got it above");
        ens_mut.assigned.insert(worker_id);
        ens_mut.pending_workers.insert(worker_id, Instant::now());
        busy.insert(worker_id);
        // Same shard might still need more replicas.
        if ens_mut.slots_remaining() > 0 {
            still_pending.push_back(sid);
        }
    }
    *queue = still_pending;
}

/// Drop a worker from any ensembles where it had outstanding work; that
/// shard's slot count goes down and the shard is requeued for top-up.
fn drop_worker_from_ensembles(
    worker_id: WorkerId,
    ensembles: &mut HashMap<u32, ShardEnsemble>,
    busy:      &mut HashSet<WorkerId>,
    queue:     &mut VecDeque<u32>,
) {
    busy.remove(&worker_id);
    for (sid, ens) in ensembles.iter_mut() {
        if ens.pending_workers.remove(&worker_id).is_some() {
            // Worker was holding this shard mid-prove; the slot reopens.
            // Note: leave them in `assigned` so we don't pick them again
            // for the same shard if they reconnect.
            queue.push_back(*sid);
        }
    }
}

/// SHA3-256 root of the per-record h2 leaf hashes — same recipe the worker
/// uses, so an honest worker always reports a matching value.
fn compute_merkle_root(salt: &[u8; 16], records: &[DnsRecord]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = records.iter().map(|r| r.leaf_hash(salt)).collect();
    let levels = merkle_build(&leaves);
    merkle_top(&levels)
}

fn verify_worker_sig(pk_bytes: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
    use fips204::traits::{SerDes, Verifier};
    use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};

    match pk_bytes.len() {
        n if n == ml_dsa_44::PK_LEN => {
            let Ok(pk_arr): Result<[u8; ml_dsa_44::PK_LEN], _> = pk_bytes.to_vec().try_into() else { return false };
            let Ok(pk) = ml_dsa_44::PublicKey::try_from_bytes(pk_arr) else { return false };
            if sig.len() != ml_dsa_44::SIG_LEN { return false; }
            let sig_arr: &[u8; ml_dsa_44::SIG_LEN] = sig.try_into().unwrap();
            pk.verify(digest, sig_arr, b"")
        }
        n if n == ml_dsa_65::PK_LEN => {
            let Ok(pk_arr): Result<[u8; ml_dsa_65::PK_LEN], _> = pk_bytes.to_vec().try_into() else { return false };
            let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_arr) else { return false };
            if sig.len() != ml_dsa_65::SIG_LEN { return false; }
            let sig_arr: &[u8; ml_dsa_65::SIG_LEN] = sig.try_into().unwrap();
            pk.verify(digest, sig_arr, b"")
        }
        n if n == ml_dsa_87::PK_LEN => {
            let Ok(pk_arr): Result<[u8; ml_dsa_87::PK_LEN], _> = pk_bytes.to_vec().try_into() else { return false };
            let Ok(pk) = ml_dsa_87::PublicKey::try_from_bytes(pk_arr) else { return false };
            if sig.len() != ml_dsa_87::SIG_LEN { return false; }
            let sig_arr: &[u8; ml_dsa_87::SIG_LEN] = sig.try_into().unwrap();
            pk.verify(digest, sig_arr, b"")
        }
        _ => false,
    }
}

fn setup_identity(args: &Args) -> Result<ServerIdentity> {
    let hosts: Vec<&str> = args.subject.iter().map(|s| s.as_str()).collect();
    load_or_generate(&args.state_dir, &hosts)
}

fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, bytes);
    Digest::finalize(h).into()
}

fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry().with(filter).with(fmt::layer().compact()).init();
}
