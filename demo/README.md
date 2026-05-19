# RBAC sync-server demo

A self-contained walkthrough that exercises the RBAC + JWT-bearer auth on a
live sync server. Spins up `tursodb`, mints JWTs for several principals
(operator/editor/user/stranger), and walks through realistic CRUD scenarios
showing what each role can and cannot do.

## What's in here

| File | Purpose |
|---|---|
| `tour.sh` | End-to-end orchestrator. Starts the server, runs every scenario, tears down. |
| `jwt.sh` | `mint_jwt <sub> <roles_csv>` — sources cleanly into other scripts. |
| `pipeline.sh` | `pipeline <token> <sql>` — wraps the `/v2/pipeline` JSON over curl. |
| `setup.env` | Env vars (JWT secret, issuer, etc.). Sourced by everything. |
| `scenarios/` | One scenario per role/attack vector. Each is runnable standalone. |

## Prerequisites

- Built `tursodb` binary. From the repo root:
  ```sh
  cargo build -p turso_cli --no-default-features --features fts,pure-rust-crypto
  ```
- `curl` and `openssl` on `PATH`. Both are bundled with Git for Windows / Git Bash.
- A free TCP port (default `8080`).
- **Optional**: `jq` for prettier ad-hoc curl exploration. The demo scripts
  don't need it — they parse JSON responses with `grep` + `sed` against the
  known protocol shape. Install if you want it:
  ```sh
  winget install jqlang.jq         # Windows 11
  choco install jq                  # Chocolatey
  scoop install jq                  # Scoop
  brew install jq                   # macOS
  apt-get install jq                # Debian/Ubuntu
  ```

## One-line tour

```sh
cd demo
./tour.sh
```

This will:

1. Kill any prior server.
2. Delete `cloud_demo.db` for a clean state.
3. Start the sync server in the background with HS256 JWT auth.
4. Walk through 7 scenarios, printing each request and the server's response.
5. Stop the server.

## What the tour demonstrates

| # | Scenario | Why it matters |
|---|---|---|
| 1 | **TOFU bootstrap** — operator's first auth promotes them to admin. | Closes the "who is admin?" chicken-and-egg. |
| 2 | **Admin creates schema + grants roles** to bob (editor) and alice (user). | Admin manages policy without restart. |
| 3 | **Editor (bob) does CRUD on products** — INSERT, UPDATE, DELETE all succeed. | Per-table grants work. |
| 4 | **Editor escalation attempts** — DDL, RBAC writes, dangerous PRAGMA, sqlite_schema writes — all denied. | Role boundaries hold. |
| 5 | **User (alice) updates her own profile** — succeeds. | Row-level USING predicate. |
| 6 | **User tries to update someone else's row** — silently filtered to zero rows. | RLS narrows the WHERE. |
| 7 | **Unauthenticated request** — 401. | Anonymous → default-deny. |
| 8 | **Can local SQL writes bypass cloud RBAC?** — alice edits her local replica, then tries 4 different attack paths to get the change into the cloud. | All paths converge on `/v2/pipeline` and are denied. The security property holds: every channel from local→cloud is gated. |
| 9 | **Can a client manipulate policy via sync?** — alice pulls the cloud policy down, forges admin rows in her local replica, attempts six different push shapes (INSERT/UPDATE/DELETE/DROP/ALTER on the policy tables) to escalate. | Every push is denied. Local forgery is harmless; the cloud's authoritative policy is unchanged. |

## Where the databases live

The demo runs everything on one machine, so all files end up in the
`demo/` directory side-by-side. That's purely for visibility — in a
real deployment the cloud DB and any client replicas would live on
different machines.

> **Demo simplification:** the `client_*.db` files in this demo only
> contain a single `products` table with one row. They're set up that
> way by direct `tursodb` invocations, NOT by a real sync pull. In a
> real deployment the sync engine pulls **all pages** from the cloud
> (the sync protocol is page-level, not table-level), so a real client
> replica would contain everything the cloud has: user tables, RBAC
> policy tables, sync bookkeeping, the sqlite_schema catalog — all of
> it. See "What syncs to clients?" below for what this means for
> confidentiality.

| File | What it represents | Lives where (production) | Lives where (this demo) |
|---|---|---|---|
| `cloud_demo.db` | **Cloud canonical state** — the sync server's authoritative copy | Sync server host, in a private directory | `demo/cloud_demo.db` |
| `cloud_demo.db-wal`, `cloud_demo.db-shm` | Cloud WAL + shared-memory index | Alongside the cloud DB | `demo/` |
| `client_alice.db` | **Alice's local replica** — what the sync engine would maintain on her device. Alice has only the `user` role, so her bypass-attempt row sits unsynced here forever. | Alice's device (laptop, phone, etc.) | `demo/` (only after scenario 8 runs) |
| `client_bob.db` | **Bob's local replica** — what the sync engine would maintain on his device. Bob has the `editor` role, so his local edits DO propagate to the cloud. | Bob's device | `demo/` (only after scenario 8 runs) |
| `server.log` | tursodb sync-server stderr | `/var/log/...` or wherever the sync server's stderr is collected | `demo/server.log` |

After running `./tour.sh`, `demo/` contains the cloud DB plus alice's
and bob's local replicas from scenario 8. Inspect all three to see the
authorization asymmetry on disk:

```sh
# Cloud DB — row 555 (bob's push) IS here; row 777 (alice's bypass) IS NOT
../target/debug/tursodb cloud_demo.db "SELECT id, name, owner_id FROM products"

# Alice's local replica — row 777 IS here (she edited her own file,
# which is fine; it just couldn't propagate)
../target/debug/tursodb client_alice.db "SELECT id, name, owner_id FROM products"

# Bob's local replica — row 555 IS here AND made it to the cloud
# (his grant authorized the push)
../target/debug/tursodb client_bob.db "SELECT id, name, owner_id FROM products"
```

## What RBAC actually protects

Turso's sync architecture has two distinct databases per principal:

```
┌──────────────────────────────┐         ┌──────────────────────────────┐
│  Local replica (client.db)   │         │  Cloud DB (server.db)        │
│                              │         │                              │
│  - Owned by the user         │  push   │  - Source of truth           │
│  - Full read+write access    │ ──────► │  - Shared by all clients     │
│  - Cannot be locked down     │  pull   │  - Writes gated by RBAC      │
│    (user's own device)       │ ◄────── │  - Reads currently open      │
└──────────────────────────────┘         └──────────────────────────────┘
```

**The single security property RBAC enforces:**

> *Unauthorized local writes cannot reach the canonical cloud state.*

This is what scenario 8 tests directly. The threat is a holder of valid
credentials (a real user with a JWT) who tries to write rows their grant
wouldn't permit. The defense is that every path from "local change" to
"cloud state" goes through `/v2/pipeline`, which runs the authorizer.

Scenario 8 walks every realistic attack path and shows each is blocked:

| Path | What it tries | Result |
|---|---|---|
| **A** | Local SQL edit, then sync engine auto-push | `/v2/pipeline` denies via RBAC |
| **B** | Malicious client crafts a direct `/v2/pipeline` POST | Same gate fires; same denial |
| **C** | Forge a `/pull-updates` upload | Endpoint is read-only — no write side effect possible |
| **D** | Probe for hidden write endpoints | Only `/v2/pipeline` and `/pull-updates` exist; everything else returns 404 |

All paths converge on `/v2/pipeline`. That's the chokepoint. There are
no side channels.

### What syncs to clients?

Short answer: **everything in the cloud DB**, because the sync protocol
copies pages, not rows.

Long answer:

| Table | Synced to clients? | Implication |
|---|---|---|
| User tables (`products`, `user_profile`, ...) | Yes | Every client sees every row of every user table. Per-row hiding would require partial replication, which isn't implemented in MVP. |
| `_turso_rbac_grants` | Yes | Every client can read the full grant list — they know who has what permission on what. |
| `_turso_rbac_role_assignments` | Yes | Every client can see every role assignment for every principal. |
| `sqlite_schema` | Yes | Same DDL schema everywhere. |
| `turso_sync_*` | Yes | Sync engine bookkeeping. Visible but rarely interesting. |
| Last-admin protection triggers | Yes | Triggers travel with their tables. The protection fires on the cloud writer (only place that matters); local clients can't bypass it via push (admin gate runs first) and can't damage anything via local edits (those don't propagate). |

**This is by design** for an MVP focused on write integrity. It has
real consequences worth being honest about:

- **Policy is not confidential.** Any authenticated client can `SELECT
  * FROM _turso_rbac_grants` and see the full policy. If you need to
  hide who has what role, you'd add a filter at the pull endpoint or
  switch to row-level replication — neither is implemented today.
- **User data is not isolated per-user.** Alice's client replica
  contains bob's `user_profile` row. The RLS USING predicate prevents
  alice from *modifying* bob's row, but it doesn't prevent her client
  from *reading* it.
- **The deployment model that makes sense for this MVP is "one cloud DB
  per tenant"**, where all users within a tenant are co-trusted to see
  each other's data, and the tenant boundary is the database boundary.
  RBAC then governs what each user can write within the shared tenant
  state. This is the same model Notion, Linear, and similar SaaS apps
  use at the database layer.
- **What about local writes to policy tables?** They succeed (it's the
  user's file), but they cannot propagate via push — the cloud's
  authorizer denies any non-admin write to `_turso_rbac_*`. So a
  malicious client can forge a "fake admin role" row in their local
  replica and… nothing happens. The forged row sits unsynced; the
  cloud ignores any push attempt to propagate it; the next pull will
  overwrite their local state with the cloud's truth.

If you need stronger confidentiality (hide policy from clients, hide
other users' rows), that's a meaningful extension on top of this MVP.
It's a different problem from "unauthorized writes" and would need a
different mechanism (per-table replication filters, or per-row
encryption with key-based access, depending on how strict you need it).

### What about gating local writes too?

That's a useful **consistency** feature, not a **security** feature. A
deployment might want to prevent local apps from making writes the cloud
would later reject (avoiding the "worked offline, rolled back on sync"
UX trap). Implementing it would mean running the same RBAC check on the
client connection. That's possible and reasonable — but it's about
keeping local state in sync with cloud-accepted state, not about
preventing the user from editing files they own. The user can always
edit their own file no matter what gating exists; the question is
whether those edits *reach the cloud*. RBAC at `/v2/pipeline` settles
that question. Local gating is on top, for app UX.

### A separate concern: filesystem access on the cloud host

If you also need to protect the cloud server's `.db` file from local
sysadmin shells on the server host (a separate threat from network
attackers), that's standard OS-level access control:

```sh
chown sync-server:sync-server cloud.db
chmod 600 cloud.db
# Run the sync server under a dedicated unprivileged user.
```

Same posture as Postgres data dirs or SQLite files anywhere. This is
filesystem ACLs doing their job; RBAC is the SQL-layer control. Both
layers serve different threats.

## Running individual scenarios

Each script is standalone after the server is up:

```sh
source setup.env
source jwt.sh
source pipeline.sh

./start_server.sh &        # background
sleep 1                    # give it a moment to bind

# Now run any scenario:
./scenarios/01_bootstrap.sh
./scenarios/04_editor_blocked.sh

./stop_server.sh
```

## Environment variables (set in `setup.env`)

| Var | Value | Why |
|---|---|---|
| `TURSO_SYNC_JWT_HS_SECRET` | `demo-shared-secret-do-not-use-in-prod` | The HS256 signing key. JWT verifier and `mint_jwt` both read this. |
| `TURSO_SYNC_JWT_KID` | `hs1` | Key ID embedded in every minted JWT. |
| `TURSO_SYNC_JWT_ISSUERS` | `https://idp.demo.local` | Allow-listed iss. JWTs from any other issuer are rejected. |
| `TURSO_SYNC_JWT_ROLE_SOURCE` | `table` | Mode A — roles come from `_turso_rbac_role_assignments`. The JWT only carries identity. |
| `TURSO_SYNC_SERVER_ADDR` | `127.0.0.1:8080` | What the server binds to. |
| `TURSO_DEMO_DB` | `cloud_demo.db` | DB file (relative to `demo/`). Deleted at start of `tour.sh`. |

## Reading the output

Each scenario prints three lines per request:

```
─── editor INSERT product
→ POST /v2/pipeline  Authorization: Bearer eyJhbGciOiJIUz...truncated
← 200 OK  result.affected_row_count=1
```

Failures look like:

```
─── editor tries CREATE TABLE
→ POST /v2/pipeline  Authorization: Bearer eyJhbGciOiJIUz...truncated
← 200 OK  error.code=AUTHORIZATION_DENIED  message="ddl-requires-admin for Ddl..."
```

(HTTP is 200; the denial surfaces inside the JSON envelope under
`results[].error` because libsql/turso wraps per-statement errors that way.
The bash scripts extract the `code` and `message` fields with `grep` + `sed`
against the known protocol shape — no JSON parser required.)

## Troubleshooting

- **`bind: address already in use`**: another server is still running. `./stop_server.sh` or change `TURSO_SYNC_SERVER_ADDR` in `setup.env`.
- **`openssl: not found`** on Windows: install Git for Windows (bundles `openssl`) or use WSL.
- **`401 Unauthorized`** when you expected success: check that `mint_jwt` and the server are sharing `TURSO_SYNC_JWT_HS_SECRET` — both must be the same value, and the server must have been started AFTER `source setup.env`.
- **`jq` not found**: the demo doesn't need `jq` — its absence is a soft warning, not an error. Install it for ad-hoc curl work (see Prerequisites).
- **`429` or hangs**: the demo runs synchronously on a single connection; concurrent requests queue. Not a bug.

## Cleaning up

```sh
./stop_server.sh
rm -f cloud_demo.db cloud_demo.db-wal cloud_demo.db-shm
```
