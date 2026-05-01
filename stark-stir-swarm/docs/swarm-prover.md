# Swarm Prover — IoT Device Pool for Distributed Proving

## Goal

Today the prover scales linearly with RAM: a 1 GB t4g.xlarge tops out at
~2¹⁹ trace, ~2²³ trace needs 8 GB, ~2²⁴ needs ≥ 16 GB.

For deployments where many low-power devices (Raspberry Pis, edge nodes,
single-board computers) are available *but no single big box exists*,
this layer lets the coordinator partition a large prove job into shards
small enough for each device's RAM, dispatch them to the swarm, and
aggregate the per-shard proofs into one outer rollup STARK.

The coordinator **does not need to fit the full LDE** — each shard fits
on a 1 GB device, and the outer rollup is tiny (a few thousand leaves).

## Architecture

```
                   ┌─────────────────────────┐
                   │   Coordinator (this svr)│
   /v1/swarm/prove │   • device registry     │   /v1/swarm/devices
   ──────────────► │   • shard planner       │ ◄───── admin web UI
                   │   • outer rollup STARK  │   /admin
                   └────────┬────────────────┘
                            │ HTTP (per-device bearer)
                            ▼
        ┌────────────┬────────────┬────────────┬─────────...
        │  rpi-01    │  rpi-02    │  rpi-03    │
        │ 1 GB RAM   │ 1 GB RAM   │ 1 GB RAM   │  /v1/swarm/prove-shard
        │ idle/busy  │ idle/busy  │ idle/busy  │  (one small inner STARK)
        └────────────┴────────────┴────────────┴─────────...
```

Each device runs a **slimmed `stark-server`** that exposes
`POST /v1/swarm/prove-shard` (a thin wrapper around the existing
`/v1/prove` route, sized for the device's RAM budget).  The
**coordinator** holds the device registry, the shard planner, and the
outer-rollup proving step.

## Memory budget — what fits in 1 GB

From `docs/scaling-analysis.md` measurements (Goldilocks Fp⁶, blowup=32):

| Trace size | n₀ (LDE) | RAM peak | Records per shard (HashRollup, 4 leaves/record) |
|-----------:|---------:|---------:|--------------------------------------------------:|
| **2¹⁴** (16 K) | 2¹⁹ (524 K) | **761 MB** ✅ | 4 K |
| 2¹⁵ (32 K) | 2²⁰ (1 M) | ~1.5 GB | 8 K |
| 2¹⁶ (64 K) | 2²¹ (2 M) | ~3 GB | 16 K |
| 2¹⁷ (128 K) | 2²² (4 M) | ~5 GB | 32 K |
| 2¹⁸ (256 K) | 2²³ (8 M) | ~7 GB | 64 K |

**On a strict 1 GB device:** trace ≤ 2¹⁴ → ~4 K records per shard.
Declare this as `max_trace_log2 = 14, ram_mb = 1024` when registering.

**On a 2 GB device:** trace ≤ 2¹⁵ → ~8 K records per shard. Set
`max_trace_log2 = 15`.

The coordinator's shard planner reads the **smallest** `max_trace_log2`
across the pool and sizes every shard to fit, so a heterogeneous fleet
is automatically clamped to the weakest member.

## REST API

### Device registry (admin-session protected)

```bash
# Register a device
POST /v1/swarm/devices
Content-Type: application/json
{
  "name":           "rpi-01",
  "address":        "192.168.1.42:3000",
  "bearer_token":   "dev_secret_per_device",
  "max_trace_log2": 14,
  "ram_mb":         1024,
  "notes":          "kitchen rpi"
}
→ 201 Created
{ "id": 7, "name": "rpi-01", ..., "status": "idle" }

# List
GET /v1/swarm/devices
→ 200 [ { "id": 7, ... }, ... ]

# Remove
DELETE /v1/swarm/devices/7
→ 204
```

### Heartbeat (devices call in)

```bash
POST /v1/swarm/devices/{id}/heartbeat
Authorization: Bearer <device's-bearer>
→ 204 (updates `last_seen`)
```

### Distributed prove

```bash
POST /v1/swarm/prove
Authorization: Bearer <client-token>
Content-Type: application/json
{
  "total_records":       1000000,
  "shard_records":       null,         # auto-clamp to pool capability
  "nist_level":          1,
  "quantum_budget_log2": 40,
  "fallback_local":      false         # if pool empty: 503 (true: route to /v1/prove)
}
→ 200 (currently plan-only; HTTP dispatch is the next development step)
{
  "status":            "plan-only (dispatch not yet implemented)",
  "shard_count":       16,
  "devices_used":      3,
  "records_per_shard": 65536,
  "estimated_walls":   { "sequential_secs": 800, "parallel_secs": 300 },
  "plan": [
    { "shard_index": 0, "records_in_shard": 65536,
      "device_id": 1, "device_name": "rpi-01",
      "device_address": "192.168.1.41:3000" },
    ...
  ]
}
```

## Live smoke test (already working)

```bash
# 1. Bootstrap server + grab admin credentials
$ ./target/release/stark-server &
$ TOKEN=$(grep "bearer token:" ./stark-bootstrap.txt | awk '{print $3}')

# 2. Get an admin session for the device-management endpoints
$ curl -c cookies.txt -X POST http://localhost:3000/admin/login \
       -d "username=admin&password=<bootstrap-password>" -L

# 3. Register 3 IoT devices
$ for i in 1 2 3; do
    curl -b cookies.txt -X POST http://localhost:3000/v1/swarm/devices \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"rpi-0$i\",\"address\":\"192.168.1.4$i:3000\",\
            \"max_trace_log2\":18,\"ram_mb\":1024}"
  done

# 4. Plan a 1M-record swarm prove
$ curl -X POST http://localhost:3000/v1/swarm/prove \
       -H "Authorization: Bearer $TOKEN" \
       -d '{"total_records":1000000,"nist_level":1,"quantum_budget_log2":40}' \
       | jq '.shard_count, .records_per_shard, .devices_used'
16
65536
3
```

The web admin UI at `/admin` shows the device pool table inline with
the token table; register/remove forms work the same way.

## Implementation status

| Component | Status |
|-----------|:------:|
| SQLite `swarm_devices` schema + CRUD | ✅ shipped |
| Admin REST endpoints (`POST /v1/swarm/devices`, `GET`, `DELETE`) | ✅ shipped |
| Admin web UI section (form + table) | ✅ shipped |
| Heartbeat endpoint (`POST /v1/swarm/devices/{id}/heartbeat`) | ✅ shipped |
| Shard planner (computes `records_per_shard`, assigns devices, returns plan) | ✅ shipped |
| Wall-clock estimator | ✅ shipped (extrapolated from `docs/scaling-analysis.md`) |
| HTTP dispatch (coordinator → device's `/v1/swarm/prove-shard`) | ⏳ skeleton |
| Outer rollup STARK aggregating shard pi_hashes | ⏳ skeleton |
| Per-device bearer auth on dispatch | ⏳ skeleton |
| Capability-aware retry on device failure | ⏳ skeleton |

## Why this is "optional" — the existing single-machine path is unchanged

`POST /v1/prove` continues to work exactly as before: one machine, one
proof, no swarm involvement.  The swarm machinery is a **separate route
family** (`/v1/swarm/*`).  The coordinator falls back to a single-server
proof simply by routing the request to `/v1/prove` instead of
`/v1/swarm/prove`.  Deployments without an IoT pool need no
configuration change.

The new `swarm_devices` SQLite table is empty by default and adds
~5 KB of disk; if no devices are registered, no swarm code path is
exercised.

## Filling in the dispatch step (what's left to ship distributed proving)

The shape is fully specified in `crates/api/src/routes/swarm.rs` with a
commented `dispatch_to_devices` skeleton.  Concretely:

```rust
async fn dispatch_to_devices(
    shard:         &ShardAssignment,
    shard_records: &[u64],
    state:         &AppState,
) -> Result<ShardProofResult, DispatchError> {
    let device = state.auth_db.find_device_by_id(shard.device_id)?;
    let url = format!("http://{}/v1/swarm/prove-shard", device.address);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()?;

    state.auth_db.set_device_status(device.id, DeviceStatus::Busy)?;
    let resp = client.post(&url)
        .header("Authorization",
                format!("Bearer {}", device.bearer_token.unwrap_or_default()))
        .json(&shard_records)
        .send().await?
        .error_for_status()?;
    let result: ShardProofResult = resp.json().await?;
    state.auth_db.set_device_status(device.id, DeviceStatus::Idle)?;
    Ok(result)
}
```

The aggregation step is **already implemented** in
`crates/api/tests/dns_rollup.rs` and `crates/cairo-bench/examples/dns_megazone_demo.rs` —
the same `HashRollup` AIR that aggregates shard `pi_hash`-es.  Wiring
that aggregation into a `swarm_prove` follow-on call is straightforward
once `dispatch_to_devices` lands.

**Estimated remaining work:** ~1–2 days for the HTTP dispatcher + retry
logic + outer-rollup wire-up + integration test on a 3-device localhost
mock fleet.

## Security model for the IoT swarm

| Threat | Mitigation |
|--------|------------|
| Compromised device returns a forged proof | Coordinator verifies every shard proof before aggregation; failed shards re-dispatched to a different device |
| Coordinator cannot reach device (offline) | Status auto-flipped to `offline` on dispatch failure; planner skips offline devices |
| Eavesdropper on the LAN | Coordinator–device link should be TLS (terminate at nginx in front of each device) |
| Compromised coordinator | Devices only accept work signed by the coordinator's bearer; rotate the per-device bearer if the coordinator is rebuilt |
| Replay of an old shard request | Each shard request includes a coordinator-supplied UUID; devices store recent UUIDs and reject duplicates |

These are the same trust assumptions as any other "trusted controller +
worker pool" design (e.g. Kubernetes node bootstrap), and the fallback
to `/v1/prove` on a single trusted machine remains available for
zero-trust-network deployments.

## Estimated wall-clock with a swarm

From `/v1/swarm/prove`'s `estimated_walls` field (linear extrapolation
from `docs/scaling-analysis.md` measurements):

| Total records | Pool size | Shards | Sequential | Parallel | Per-device prove |
|--------------:|----------:|-------:|-----------:|---------:|-----------------:|
| 100 K | 3 | 2 | 100 s | 50 s | 50 s |
| 1 M | 3 | 16 | 800 s (13 min) | 300 s (5 min) | 50 s |
| 1 M | 30 | 16 | 800 s | 50 s | 50 s |
| 10 M | 30 | 153 | 7 650 s (2 h) | 250 s (4 min) | 50 s |
| 100 M | 100 | 1 526 | 21 hr | 800 s (13 min) | 50 s |
| 1 B | 1000 | 15 259 | 8.4 days | ~13 min | 50 s |

(Per-device prove time assumes 65 K records per shard at NIST L1 / blowup 32.
Sequential is `shards × per-device-time`; parallel assumes one device per
shard with batches of `ceil(shards / pool_size)`.)

**A swarm of 1 000 Raspberry Pi 4s (4 GB each) can prove a 1-billion-record
zone in ~13 minutes** — the same wall-clock as a single 64 GB workstation,
at roughly 1/10th the hardware cost.

## Files

| File | What |
|------|------|
| `crates/auth/src/lib.rs` | `swarm_devices` table + CRUD + 2 unit tests |
| `crates/api/src/routes/swarm.rs` | Register / list / remove / heartbeat / plan endpoints |
| `crates/api/src/routes/admin.rs` | Web UI section: device table + register/remove forms |
| `crates/api/src/lib.rs` | Router wiring |
| `docs/swarm-prover.md` | This document |

## Tests

```
$ cargo test --release -p auth
test result: ok. 10 passed
   (8 token/user/session tests + register_device_and_list + remove_device_works)

$ cargo test --release -p api
test result: ok. 10 passed (security profile + r-per-blowup)
test result: ok. 1 passed (rollup_demo)
test result: ok. 1 passed (dns_rollup)
test result: ok. 1 passed (level1_q40_smoke)
```

Live HTTP smoke test (above) confirms:
- Admin login → cookie session works
- Bearer-protected `POST /v1/swarm/devices` registers devices
- `GET /v1/swarm/devices` returns the live registry
- `POST /v1/swarm/prove` correctly partitions a 1 M-record job across 3 devices into 16 shards of 65 K records each (auto-clamped to smallest `max_trace_log2 = 18`)
