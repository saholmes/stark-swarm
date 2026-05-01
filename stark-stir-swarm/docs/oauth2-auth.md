# OAuth2 + Bearer Token Authentication

The `stark-server` ships a SQLite-backed token store, a bearer-token
middleware on every `/v1/*` route, an OAuth2 `client_credentials` token
endpoint, an admin web UI for token lifecycle management, and a
first-run bootstrap that creates an admin user + initial token.

## Architecture

```
                 ┌────────────────────────────────────────────┐
                 │                stark-server                 │
                 │                                              │
   ┌──────────┐  │   /v1/* (bearer required)                   │
   │  Client  ├──┼─►  POST /v1/prove, /v1/verify                │
   │  (curl,  │  │   GET  /v1/security/profiles, …             │
   │   API    │  │                                              │
   │   user)  │  │   /admin/* (cookie session for web UI)      │
   │          ├──┼─►  Login form + token-management dashboard  │
   └──────────┘  │                                              │
                 │   /oauth2/* (RFC 6749 / 7662)                │
                 │   POST /oauth2/token (client_credentials)    │
                 │   POST /oauth2/introspect                    │
                 │                                              │
                 │   bootstrap_admin() ─► auth::AuthDb (SQLite)│
                 │     • users (Argon2 passwords)               │
                 │     • api_tokens (SHA3-256 hashed bearers)   │
                 │     • sessions (cookie-keyed)                │
                 └────────────────────────────────────────────┘
```

## Token model

* Plaintext bearer string format: `stark_` + 64 lowercase hex chars
  (32 random bytes from OS RNG). Shown to the user **once** at creation.
* Database stores only `SHA3-256("STARK-API-BEARER-V1" || bearer)` —
  never the plaintext.
* Tokens may have:
  * a free-form `name` (e.g. `"ci-pipeline"`)
  * a space-separated `scope` (e.g. `"stark:prove stark:verify"`)
  * an optional `expires_at` (absolute timestamp)
  * a `revoked` flag (set by admin; immediately invalidates the token)

## Bootstrap (first run)

On first server start, if no users exist the `bootstrap_admin` routine
creates an admin user and mints a single bootstrap token, writing both
to a file (mode 0600 on Unix) and to STDERR.

```
$ ./target/release/stark-server
INFO Auth database at: ./stark-auth.sqlite
INFO Admin user: admin (id=1, is_admin=true)

=================================================================
STARK API bootstrap credentials
===============================
admin username:   admin
admin password:   131602d73eee3413810242aa4c75f2fc
bearer token:     stark_2554bc44cfb97412bc6b993d3f005637f3e53f6596689acceb135d97ae82052b
token id:         1
scope:            stark:prove stark:verify stark:read

USE the bearer token in API requests:
  curl -H 'Authorization: Bearer stark_…' http://<host>:3000/v1/security/profiles

LOG IN to the admin web UI:
  http://<host>:3000/admin/login

Bootstrap details also written to: ./stark-bootstrap.txt
=================================================================

INFO Listening on http://0.0.0.0:3000
INFO Admin UI:  http://0.0.0.0:3000/admin/login
```

Subsequent starts **reuse** the existing user and tokens.  The bootstrap
file is only created when there are zero live tokens.

### Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `STARK_AUTH_DB` | `./stark-auth.sqlite` | Path to the SQLite users + tokens database |
| `STARK_ADMIN_USER` | `admin` | Bootstrap admin username (only used at first run) |
| `STARK_ADMIN_PASSWORD` | random hex | Bootstrap admin password (printed + saved to file if random) |
| `STARK_BOOTSTRAP_FILE` | `./stark-bootstrap.txt` | Where to write the first-run credentials |
| `STARK_PORT` | 3000 | TCP listen port |
| `STARK_STORE_DIR` | `./stark-proofs` | Proof store directory |

Set `STARK_ADMIN_PASSWORD` to a known value if you want a stable
password for unattended deployment; otherwise a random 16-byte hex
string is generated, written to the bootstrap file, and printed once.

## Endpoints

### Open (no auth)

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/v1/health` | Liveness probe |
| GET    | `/admin/login` | Admin login form |
| POST   | `/admin/login` | Submit credentials, set session cookie |
| POST   | `/oauth2/token` | Mint a fresh access token (caller bearer-authenticates) |
| POST   | `/oauth2/introspect` | RFC 7662 token introspection |

### Bearer-protected (`/v1/*`)

Every `/v1/*` route requires `Authorization: Bearer <token>`.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/prove` | Run the prover, store proof |
| POST | `/v1/verify` | Verify a proof |
| GET  | `/v1/proofs` | List stored proofs |
| GET  | `/v1/proofs/:id` | Fetch a stored bundle |
| GET  | `/v1/security/profiles` | NIST profile catalogue (incl. r-per-blowup) |
| POST | `/v1/admin/tokens` | (admin session) Issue a bearer |
| GET  | `/v1/admin/tokens` | (admin session) List bearers |
| POST | `/v1/admin/tokens/revoke` | (admin session) Revoke a bearer |

### Admin web UI (cookie session)

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/admin` | Token-management dashboard |
| POST | `/admin/logout` | Clear session cookie |
| POST | `/admin/create-token` | Issue long-lived bearer (form) |
| POST | `/admin/revoke` | Revoke bearer (form) |

## Live smoke test (real run)

```bash
$ STARK_PORT=33877 ./target/release/stark-server &

$ curl http://localhost:33877/v1/security/profiles
{"error":"missing or malformed Authorization header",
 "details":"expected: Authorization: Bearer <token>"}     ← 401

$ TOKEN=$(grep "bearer token:" ./stark-bootstrap.txt | awk '{print $3}')

$ curl -H "Authorization: Bearer $TOKEN" \
       http://localhost:33877/v1/security/profiles | jq '.profiles[0]'
{
  "level": 1, "lambda_bits": 128, "quantum_budget_log2": 40,
  "ext_field": "Fp^6", "hash_alg": "SHA3-256",
  "r": 54, "kappa_it": 135, ...,
  "r_per_blowup": [
    {"blowup":2,"r":270,...}, {"blowup":4,"r":135,...},
    {"blowup":32,"r":54,...}
  ]
}

$ curl -X POST http://localhost:33877/oauth2/token \
       -H "Authorization: Bearer $TOKEN" \
       -d "grant_type=client_credentials&scope=stark:verify&expires_in=300"
{"access_token":"stark_5ebb…","token_type":"Bearer",
 "expires_in":300,"scope":"stark:verify"}                  ← short-lived child token
```

## Web admin walkthrough

```
1.  Visit http://localhost:3000/admin/login
2.  Enter the bootstrap credentials (username `admin`, password from
    bootstrap file).
3.  Dashboard shows all issued tokens with: id, name, scope, created,
    expires, last-used, status, revoke button.
4.  "Issue a new API token" form mints a new bearer.  The plaintext is
    displayed exactly once — copy it now.
5.  "Revoke" button on any row immediately invalidates that token.
6.  "Log out" button clears the session.
```

## Token lifecycle from clients

The recommended pattern matches OAuth2 `client_credentials`:

1. Provision the long-lived bearer once via the admin UI.
2. The client uses the bearer to **mint short-lived access tokens**
   via `POST /oauth2/token`, e.g. every 5 min.
3. The client uses the short-lived token in `/v1/*` requests.
4. If a long-lived token is compromised, revoke it via the admin UI;
   all child tokens are unaffected (they were already short-lived) and
   the long-lived token's children can no longer be minted.

## Security properties

| Property | How it's achieved |
|----------|-------------------|
| Tokens at rest | SHA3-256 hash; plaintext never persisted |
| Passwords at rest | Argon2id with random per-user salt |
| Bearer over the wire | Caller responsibility (TLS-terminate at reverse proxy or Axum-rustls) |
| Constant-time hash comparison | `argon2::verify_password` is constant-time |
| Session cookie hijacking | `HttpOnly`, `SameSite=Lax`, 12-hour max-age |
| Replay after revocation | Every bearer validate hits the `revoked` flag before use |
| Replay after expiry | `expires_at` checked on every validate |

## Limitations / not yet implemented

These are out of scope for the MVP and would be useful follow-ups:

- **TLS termination** — assume external proxy (nginx, Caddy)
- **Refresh tokens** (`grant_type=refresh_token`) — current model is mint-on-bearer
- **Authorization code flow** with PKCE — only `client_credentials` shipped
- **Per-token rate limits** — token table has no quota fields yet
- **Audit log** — no `audit_events` table; can be added by writing to
  a third SQLite table on every prove/verify call
- **2FA / TOTP for admin login** — admin can only use username + password
- **Multi-admin RBAC** — single `is_admin` flag, no roles beyond it
- **OAuth2 `scope` enforcement on /v1/*** — middleware extracts
  `validated.scope` into the request extensions but no per-route
  scope checks are wired in yet (would be a 5-line change per route)

## Files

| File | What |
|------|------|
| `crates/auth/Cargo.toml` | Crate manifest |
| `crates/auth/src/lib.rs` | `AuthDb`, schema, users / tokens / sessions, bootstrap, 8 unit tests |
| `crates/api/src/auth_middleware.rs` | `require_bearer` middleware for /v1/* |
| `crates/api/src/routes/oauth.rs` | `/oauth2/token`, `/oauth2/introspect`, admin-JSON tokens |
| `crates/api/src/routes/admin.rs` | HTML admin UI (login, dashboard, create, revoke) |
| `crates/api/src/lib.rs` | Router wiring + middleware layer |
| `crates/stark-server/src/main.rs` | Bootstrap admin + initial token, env-var config |

## Tests

```bash
$ cargo test --release -p auth -p api
test result: ok. 8 passed                  # auth: users, tokens, sessions, bootstrap
test result: ok. 10 passed                 # api::security profiles + r_for_blowup
test result: ok. 1 passed                  # rollup_demo
test result: ok. 1 passed                  # dns_rollup
test result: ok. 1 passed                  # level1_q40_smoke
```

Live server smoke test (above) confirms:
- Unauth `GET /v1/security/profiles` → 401 with structured error
- Auth `GET /v1/security/profiles` → 200 with full profile + per-blowup r table
- Open `GET /v1/health` → 200
- `POST /oauth2/token` with client_credentials grant → 200 + new short-lived token
