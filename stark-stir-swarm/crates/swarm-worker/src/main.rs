//! STIR DNS swarm — worker entry point.
//!
//! Step-3 scope: generate (or load) an ML-DSA keypair, connect to the
//! controller over TLS 1.3 with X25519+ML-KEM-768 hybrid KEX, send a
//! `Register` message, then send heartbeats at the cadence the controller
//! advertised. Subsequent steps add shard-proving handlers.
//!
//! Run with:
//!     cargo run --release -p swarm-worker -- \
//!         --ctrl 127.0.0.1:7878 \
//!         --ctrl-fingerprint <hex from ctrl logs> \
//!         --label  edge-rpi-001 \
//!         --nist-level 1
//!
//! Convenience: `--ctrl-fingerprint-file <path>` reads the fingerprint hex
//! out of the controller's `state-dir/fingerprint.hex`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use swarm_dns::dns_authority::{AuthorityKeypair, NistLevel};
use swarm_dns::prover::{prove_inner_shard, InnerShardOutput};
use swarm_proto::frame::{read_frame, write_frame};
use swarm_proto::messages::{
    shard_fs_binding, worker_attestation_digest,
    Capabilities, ClientMsg, ServerMsg, ShardResult, ShardSpec,
};
use swarm_proto::tls::client_config_with_pinned_fp;

#[derive(Parser, Debug)]
#[command(name = "swarm-worker", about = "STIR DNS swarm worker")]
struct Args {
    /// Controller address (host:port). Required unless --print-identity is set.
    #[arg(long)]
    ctrl: Option<String>,

    /// Controller cert fingerprint (SHA3-256 hex). Mutually exclusive with --ctrl-fingerprint-file.
    #[arg(long, conflicts_with = "ctrl_fingerprint_file")]
    ctrl_fingerprint: Option<String>,

    /// Read fingerprint hex from this file.
    #[arg(long)]
    ctrl_fingerprint_file: Option<PathBuf>,

    /// SNI hostname for the TLS handshake. Defaults to "localhost".
    #[arg(long, default_value = "localhost")]
    sni: String,

    /// Free human-readable label sent to the controller (e.g. hostname).
    #[arg(long, default_value = "worker")]
    label: String,

    /// NIST PQ level: 1, 3, or 5. Drives ML-DSA parameter selection.
    #[arg(long, default_value_t = 1)]
    nist_level: u8,

    /// Maximum records-per-shard this worker is willing to prove.
    #[arg(long, default_value_t = 65_536)]
    max_records: usize,

    /// Persistent identity-seed file. If it exists, the 32-byte seed is
    /// loaded; otherwise a fresh random seed is generated and written
    /// (mode 0600). Stable identity across runs is required for the
    /// controller's `--worker-allowlist` to work.
    #[arg(long)]
    identity_file: Option<PathBuf>,

    /// Print the worker's ML-DSA pk fingerprint and exit. Used by operators
    /// to populate the controller's allowlist. Requires --identity-file.
    #[arg(long, default_value_t = false)]
    print_identity: bool,

    /// Directory to persist `ShardReceipt`s received from the controller
    /// (G — censorship audit trail). One file per (job_id, shard_id);
    /// previous-job receipts are preserved across runs.
    #[arg(long)]
    receipts_dir: Option<PathBuf>,

    /// Witness controller (H), formatted `<label>=<host:port>:<fingerprint_hex>`.
    /// Repeatable.  After every successful ShardDone to the primary, the
    /// worker also sends a `WorkerEvidence` to each witness; their receipts
    /// are persisted under `receipts-dir/witness-<label>/`.
    #[arg(long = "witness")]
    witnesses: Vec<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let level = match args.nist_level {
        1 => NistLevel::L1,
        3 => NistLevel::L3,
        5 => NistLevel::L5,
        other => return Err(anyhow!("invalid --nist-level {other} (expected 1, 3, or 5)")),
    };

    // Identity seed: load from file if present, else generate + persist
    // (so the worker's pk_fingerprint is stable across runs).
    let seed = load_or_create_identity(args.identity_file.as_deref())?;
    let authority = AuthorityKeypair::keygen(level, seed);
    let pk_bytes  = authority.pk_bytes();
    let pk_fp     = sha3_256(&pk_bytes);
    let node_id   = format!("{}-{}", args.label, &hex::encode(pk_fp)[..8]);

    if args.print_identity {
        // Operator-facing: print identity + exit. Output is plain so it can
        // be piped or captured into an allowlist generator.
        println!("nist_level: L{}", args.nist_level);
        println!("ml_dsa_scheme: {}", level.ml_dsa_name());
        println!("pk_fingerprint_sha3_256_hex: {}", hex::encode(pk_fp));
        println!("node_id: {}", node_id);
        if let Some(p) = &args.identity_file {
            println!("identity_file: {}", p.display());
        }
        return Ok(());
    }

    let ctrl_addr = args.ctrl.clone()
        .ok_or_else(|| anyhow!("--ctrl <host:port> is required (unless --print-identity is set)"))?;

    let fp_hex = read_fingerprint(&args)?;
    let fp = parse_fp_hex(&fp_hex).context("parse --ctrl-fingerprint")?;
    let cfg = client_config_with_pinned_fp(fp)?;
    let connector = TlsConnector::from(cfg);

    info!(
        node = %node_id,
        scheme = level.ml_dsa_name(),
        pk_fp = %hex::encode(pk_fp),
        "worker identity ready"
    );

    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as u32;
    let caps = Capabilities {
        nist_level: args.nist_level,
        max_records_per_shard: args.max_records,
        cores,
        label: args.label.clone(),
    };

    info!(ctrl = %ctrl_addr, sni = %args.sni, "connecting to controller");
    let tcp = TcpStream::connect(&ctrl_addr).await
        .with_context(|| format!("tcp connect to {ctrl_addr}"))?;
    let server_name = ServerName::try_from(args.sni.clone())
        .map_err(|e| anyhow!("invalid SNI {:?}: {e}", args.sni))?;
    let mut stream = connector.connect(server_name, tcp).await.context("TLS handshake")?;

    // Register.
    write_frame(&mut stream, &ClientMsg::Register {
        node_id: node_id.clone(),
        ml_dsa_pk: pk_bytes,
        capabilities: caps,
    }).await?;

    let ack: ServerMsg = read_frame(&mut stream).await?;
    let (worker_id, hb_secs, ctrl_label) = match ack {
        ServerMsg::RegisterAck { worker_id, heartbeat_secs, controller_label } => {
            info!(worker_id, controller_label = %controller_label, "registered with controller");
            (worker_id, heartbeat_secs, controller_label)
        }
        ServerMsg::RegisterDenied { reason } => {
            return Err(anyhow!("registration denied: {reason}"));
        }
        other => return Err(anyhow!("unexpected first server msg: {other:?}")),
    };

    // Spawn one persistent task per witness controller (H).
    let mut witness_txs: Vec<(String, tokio::sync::mpsc::Sender<EvidenceJob>)> = Vec::new();
    for w_str in &args.witnesses {
        let spec = parse_witness_spec(w_str)
            .with_context(|| format!("parse --witness {w_str:?}"))?;
        let (tx, rx) = tokio::sync::mpsc::channel::<EvidenceJob>(16);
        let label = spec.label.clone();
        let pk_clone = authority.pk_bytes();
        let nid_clone = node_id.clone();
        let caps_clone = Capabilities {
            nist_level: args.nist_level,
            max_records_per_shard: args.max_records,
            cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as u32,
            label: format!("{}-witness-{}", args.label, label),
        };
        let recvdir = args.receipts_dir.clone();
        let sni = args.sni.clone();
        tokio::spawn(async move {
            if let Err(e) = witness_session(
                spec, sni, pk_clone, nid_clone, caps_clone, recvdir, rx,
            ).await {
                warn!(error = ?e, "witness session ended with error");
            }
        });
        witness_txs.push((label, tx));
    }
    if !witness_txs.is_empty() {
        info!(witnesses = witness_txs.len(),
              "witness fan-out enabled — every shard's evidence will be broadcast");
    }

    // Main event loop. Push heartbeats on a timer; in between, pump messages
    // arriving from the controller (AssignShard, Shutdown, ...) without
    // blocking the heartbeat cadence.
    let interval = Duration::from_secs(hb_secs.max(1) as u64);
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sent  = 0u64;
    let started   = Instant::now();

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut shards_done = 0u64;

    loop {
        tokio::select! {
            biased;
            _ = sigint.recv() => {
                info!("SIGINT — sending Goodbye and exiting");
                let _ = write_frame(&mut stream, &ClientMsg::Goodbye { worker_id }).await;
                break;
            }
            _ = tick.tick() => {
                write_frame(&mut stream, &ClientMsg::Heartbeat { worker_id }).await?;
                sent += 1;
                if sent.is_power_of_two() {
                    info!(
                        worker_id, controller_label = %ctrl_label,
                        uptime_s = started.elapsed().as_secs(),
                        sent, shards_done, "heartbeat checkpoint"
                    );
                }
            }
            msg = read_frame::<_, ServerMsg>(&mut stream) => {
                match msg {
                    Ok(ServerMsg::HeartbeatAck) => {/* matches our ping */}
                    Ok(ServerMsg::AssignShard { spec }) => {
                        // Move proving to the blocking pool so heartbeats keep
                        // flowing on the async runtime during long proves.
                        let auth_clone = authority.clone();
                        let shard_id   = spec.shard_id;
                        let job_id     = spec.job_id;
                        let join = tokio::task::spawn_blocking(move ||
                            handle_assign(&auth_clone, &spec)
                        );
                        match join.await {
                            Ok(Ok(result)) => {
                                shards_done += 1;
                                info!(
                                    worker_id,
                                    shard_id,
                                    records  = result.record_count,
                                    n_trace  = result.n_trace,
                                    prove_ms = result.prove_ms,
                                    proof_bytes = result.proof_bytes_len,
                                    "shard proved + self-verified, returning result"
                                );

                                // Fan out independent evidence to every witness ctrl
                                // (H — distributed audit). Each witness gets its own
                                // copy and writes its own signed receipt.
                                if !witness_txs.is_empty() {
                                    let evidence = EvidenceJob {
                                        job_id,
                                        shard_id,
                                        pi_hash:     result.pi_hash,
                                        merkle_root: result.merkle_root,
                                        root_f0:     result.root_f0,
                                        worker_sig:  result.worker_sig.clone(),
                                    };
                                    for (label, tx) in &witness_txs {
                                        if let Err(e) = tx.send(evidence.clone()).await {
                                            warn!(witness = %label, error = ?e,
                                                  "failed to push evidence to witness");
                                        }
                                    }
                                }

                                write_frame(&mut stream,
                                    &ClientMsg::ShardDone { worker_id, result }).await?;
                            }
                            Ok(Err(e)) => {
                                let reason = format!("{e:?}");
                                warn!(worker_id, shard_id, reason = %reason, "shard prove failed");
                                write_frame(&mut stream,
                                    &ClientMsg::ShardFailed { worker_id, shard_id, reason }).await?;
                            }
                            Err(join_err) => {
                                let reason = format!("prover task panicked: {join_err}");
                                warn!(worker_id, shard_id, reason = %reason, "shard prove panicked");
                                write_frame(&mut stream,
                                    &ClientMsg::ShardFailed { worker_id, shard_id, reason }).await?;
                            }
                        }
                    }
                    Ok(ServerMsg::Receipt { receipt }) => {
                        match persist_receipt(args.receipts_dir.as_deref(), &receipt) {
                            Ok(Some(path)) => {
                                info!(
                                    shard_id = receipt.shard_id,
                                    pi_hash  = %hex::encode(receipt.pi_hash)[..16].to_string(),
                                    path = %path.display(),
                                    "ctrl receipt persisted"
                                );
                            }
                            Ok(None) => {
                                info!(
                                    shard_id = receipt.shard_id,
                                    "ctrl receipt received (not persisted — no --receipts-dir)"
                                );
                            }
                            Err(e) => warn!(?e, "failed to persist ctrl receipt"),
                        }
                    }
                    Ok(ServerMsg::Shutdown { reason }) => {
                        info!(reason = %reason, "controller requested shutdown");
                        break;
                    }
                    Ok(other) => warn!(?other, "unexpected server msg"),
                    Err(swarm_proto::frame::FrameError::Io(e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        info!("controller closed the connection");
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(())
}

/// Run the inner-shard prover for the assigned spec, attest the result with
/// the worker's ML-DSA key, and return the wire-shaped [`ShardResult`].
fn handle_assign(
    authority: &AuthorityKeypair,
    spec:      &ShardSpec,
) -> anyhow::Result<ShardResult> {
    // Bind the proof's FS transcript to (pk_hash, job_id, shard_id, nonce).
    // Same recipe used by ctrl when computing the expected pi_hash and by
    // the standalone verifier when reconstructing.
    let fs_binding = shard_fs_binding(
        &spec.authority_pk_hash, &spec.job_id, spec.shard_id, &spec.shard_nonce,
    );
    let InnerShardOutput {
        pi_hash, merkle_root, record_count, n_trace,
        proof_bytes: _logical_bytes, prove_ms, local_verify_ms, root_f0,
        proof_blob,
    } = prove_inner_shard(&spec.zone_salt, &spec.records, &fs_binding, spec.ldt);

    let digest    = worker_attestation_digest(spec.shard_id, &pi_hash, &merkle_root, &root_f0);
    let worker_sig = authority.sign(&digest);

    // `proof_bytes_len` reports the wire-shipped transport size, i.e. the
    // length of the ark-serialize compressed encoding. The verifier
    // compares against this exactly; reporting the on-disk blob length here
    // (instead of the prover's logical-byte heuristic) keeps both honest.
    let proof_bytes_len = proof_blob.len() as u64;

    Ok(ShardResult {
        shard_id:        spec.shard_id,
        pi_hash,
        merkle_root,
        root_f0,
        record_count:    record_count as u64,
        n_trace:         n_trace as u64,
        proof_bytes_len,
        prove_ms,
        local_verify_ms,
        worker_sig,
        proof_blob,
    })
}

fn read_fingerprint(args: &Args) -> Result<String> {
    if let Some(s) = &args.ctrl_fingerprint {
        return Ok(s.trim().to_owned());
    }
    if let Some(p) = &args.ctrl_fingerprint_file {
        let s = std::fs::read_to_string(p)
            .with_context(|| format!("read {}", p.display()))?;
        return Ok(s.trim().to_owned());
    }
    Err(anyhow!("either --ctrl-fingerprint or --ctrl-fingerprint-file is required"))
}

fn parse_fp_hex(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).with_context(|| "hex decode")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32-byte fingerprint, got {} bytes", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Persist a controller-signed receipt to disk under
///   `receipts_dir/[subdir/]job-<hex>/shard-<NNNN>.cbor`
/// (CBOR for forward-compatibility with the wire format).  Returns the
/// path written, or None if no `receipts_dir` was configured.
fn persist_receipt_in(
    receipts_dir: Option<&std::path::Path>,
    subdir: Option<&str>,
    receipt: &swarm_proto::messages::ShardReceipt,
) -> Result<Option<std::path::PathBuf>> {
    let Some(base) = receipts_dir else { return Ok(None); };
    let mut dir = base.to_path_buf();
    if let Some(s) = subdir { dir.push(s); }
    dir.push(format!("job-{}", hex::encode(receipt.job_id)));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create_dir_all {}", dir.display()))?;
    let path = dir.join(format!("shard-{:04}.cbor", receipt.shard_id));
    let mut buf = Vec::with_capacity(2_500 + receipt.ctrl_authority_pk.len() + receipt.ctrl_sig.len());
    ciborium::ser::into_writer(receipt, &mut buf)
        .map_err(|e| anyhow!("cbor encode receipt: {e}"))?;
    std::fs::write(&path, &buf)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(Some(path))
}

/// Backwards-compatible: persists primary-ctrl receipt at the root of
/// `receipts_dir`.
fn persist_receipt(
    receipts_dir: Option<&std::path::Path>,
    receipt: &swarm_proto::messages::ShardReceipt,
) -> Result<Option<std::path::PathBuf>> {
    persist_receipt_in(receipts_dir, None, receipt)
}

#[derive(Clone, Debug)]
struct WitnessSpec {
    label:       String,
    addr:        String,
    fingerprint: [u8; 32],
}

fn parse_witness_spec(s: &str) -> Result<WitnessSpec> {
    // Form: "<label>=<host:port>:<fp_hex>"
    let (label, rest) = s.split_once('=')
        .ok_or_else(|| anyhow!("--witness: expected '<label>=<host:port>:<fp_hex>', got {s:?}"))?;
    // Split on the FINAL colon to separate fingerprint.
    let last_colon = rest.rfind(':')
        .ok_or_else(|| anyhow!("--witness: missing ':<fp_hex>' suffix in {s:?}"))?;
    let addr   = &rest[..last_colon];
    let fp_hex = &rest[last_colon + 1..];
    let fp = parse_fp_hex(fp_hex.trim())?;
    Ok(WitnessSpec { label: label.to_string(), addr: addr.to_string(), fingerprint: fp })
}

/// Item pushed from the main worker loop to each witness's channel.
#[derive(Clone, Debug)]
struct EvidenceJob {
    job_id:      [u8; 32],
    shard_id:    u32,
    pi_hash:     [u8; 32],
    merkle_root: [u8; 32],
    root_f0:     [u8; 32],
    worker_sig:  Vec<u8>,
}

/// Long-lived task that maintains a TLS session to one witness ctrl,
/// pushes WorkerEvidence on demand, and persists the witness's receipts.
async fn witness_session(
    spec:           WitnessSpec,
    sni:            String,
    pk_bytes:       Vec<u8>,
    node_id:        String,
    capabilities:   Capabilities,
    receipts_dir:   Option<std::path::PathBuf>,
    mut rx_evidence: tokio::sync::mpsc::Receiver<EvidenceJob>,
) -> Result<()> {
    use rustls::pki_types::ServerName;
    use swarm_proto::tls::client_config_with_pinned_fp;

    let cfg = client_config_with_pinned_fp(spec.fingerprint)?;
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let tcp = tokio::net::TcpStream::connect(&spec.addr).await
        .with_context(|| format!("witness {}: tcp connect to {}", spec.label, spec.addr))?;
    let server_name = ServerName::try_from(sni.clone())
        .map_err(|e| anyhow!("invalid SNI {:?}: {e}", sni))?;
    let mut stream = connector.connect(server_name, tcp).await
        .with_context(|| format!("witness {}: TLS handshake", spec.label))?;

    write_frame(&mut stream, &ClientMsg::Register {
        node_id, ml_dsa_pk: pk_bytes, capabilities,
    }).await?;
    let ack: ServerMsg = read_frame(&mut stream).await?;
    let (worker_id, hb_secs) = match ack {
        ServerMsg::RegisterAck { worker_id, heartbeat_secs, .. } => (worker_id, heartbeat_secs),
        ServerMsg::RegisterDenied { reason } => {
            return Err(anyhow!("witness {} denied registration: {reason}", spec.label));
        }
        other => return Err(anyhow!("witness {} unexpected ack: {other:?}", spec.label)),
    };
    info!(
        witness = %spec.label, witness_addr = %spec.addr, worker_id,
        "registered with witness controller"
    );

    let mut tick = tokio::time::interval(std::time::Duration::from_secs(hb_secs.max(1) as u64));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            ev = rx_evidence.recv() => {
                let Some(ev) = ev else {
                    let _ = write_frame(&mut stream, &ClientMsg::Goodbye { worker_id }).await;
                    break Ok(());
                };
                write_frame(&mut stream, &ClientMsg::WorkerEvidence {
                    worker_id,
                    job_id: ev.job_id,
                    shard_id: ev.shard_id,
                    pi_hash: ev.pi_hash,
                    merkle_root: ev.merkle_root,
                    root_f0: ev.root_f0,
                    worker_sig: ev.worker_sig,
                }).await?;
            }
            _ = tick.tick() => {
                write_frame(&mut stream, &ClientMsg::Heartbeat { worker_id }).await?;
            }
            msg = read_frame::<_, ServerMsg>(&mut stream) => {
                match msg {
                    Ok(ServerMsg::HeartbeatAck) => {/* normal */}
                    Ok(ServerMsg::Receipt { receipt }) => {
                        let subdir = format!("witness-{}", spec.label);
                        match persist_receipt_in(receipts_dir.as_deref(), Some(&subdir), &receipt) {
                            Ok(Some(path)) => info!(
                                witness = %spec.label,
                                shard_id = receipt.shard_id,
                                pi_hash = %hex::encode(receipt.pi_hash)[..16].to_string(),
                                path = %path.display(),
                                "witness receipt persisted"
                            ),
                            Ok(None) => info!(witness = %spec.label, shard_id = receipt.shard_id,
                                              "witness receipt received (not persisted — no --receipts-dir)"),
                            Err(e) => warn!(witness = %spec.label, ?e, "failed to persist witness receipt"),
                        }
                    }
                    Ok(ServerMsg::Shutdown { reason }) => {
                        info!(witness = %spec.label, %reason, "witness requested shutdown");
                        break Ok(());
                    }
                    Ok(other) => warn!(witness = %spec.label, ?other, "unexpected server msg from witness"),
                    Err(swarm_proto::frame::FrameError::Io(e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        info!(witness = %spec.label, "witness closed connection");
                        break Ok(());
                    }
                    Err(e) => break Err(e.into()),
                }
            }
        }
    }
}

/// Load the worker's 32-byte identity seed from `path`, or generate a fresh
/// random one and write it (mode 0600) if the file doesn't exist. If `path`
/// is None, returns a fresh ephemeral seed (legacy non-persistent behaviour).
fn load_or_create_identity(path: Option<&std::path::Path>) -> Result<[u8; 32]> {
    let Some(path) = path else {
        let mut seed = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut seed);
        return Ok(seed);
    };
    if path.exists() {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read identity seed {}", path.display()))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "{} must be exactly 32 bytes (got {})", path.display(), bytes.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(seed)
    } else {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir -p {}", parent.display()))?;
            }
        }
        let mut seed = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut seed);
        std::fs::write(path, &seed)
            .with_context(|| format!("write identity seed {}", path.display()))?;
        // Tighten permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        info!(path = %path.display(), "generated and persisted new worker identity seed");
        Ok(seed)
    }
}

fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, bytes);
    Digest::finalize(h).into()
}

fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry().with(filter).with(fmt::layer().compact()).init();
}
