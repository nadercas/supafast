# Multi-Project Supabase Self-Hosting Platform

## Context

The current project (SupaFast) deploys a single Supabase instance per Hetzner server via browser-generated cloud-init scripts. The goal is to transform it into a **multi-project platform**: one master server runs shared infrastructure (Kong, Caddy, Studio, Management Dashboard), and separate worker servers each run a complete per-project Supabase stack (Postgres, GoTrue, PostgREST, Realtime, Storage, Edge Functions). Workers connect to master via WireGuard VPN. No changes to the Supabase codebase are needed — all services are configured via environment variables.

---

## Architecture Overview

```
                    *.project.domain.com
                           |
                    [Master Server - 16GB/8vCPU]
                    ├── Caddy (wildcard TLS)
                    ├── Kong (API gateway, routes by subdomain)
                    ├── Studio (Supabase dashboard)
                    ├── Management API + Dashboard (new)
                    ├── WireGuard Server (10.100.0.1)
                    ├── Kong Postgres (routing config DB)
                    ├── Analytics/Logflare (centralized, all projects)
                    ├── Vector (centralized log collection)
                    ├── Supavisor (shared connection pooler)
                    ├── Authelia + Redis (optional 2FA)
                    └── Docker Socket Proxy
                           |
              WireGuard VPN (10.100.0.0/24)
                    /              \
    [Worker 1 - 10.100.0.2]    [Worker 2 - 10.100.0.3]
    ├── Postgres               ├── Postgres
    ├── GoTrue (auth)          ├── GoTrue
    ├── PostgREST              ├── PostgREST
    ├── Realtime               ├── Realtime
    ├── Storage + ImgProxy     ├── Storage + ImgProxy
    ├── Edge Functions         ├── Edge Functions
    ├── Postgres-Meta          ├── Postgres-Meta
    ├── Worker Agent (new)     ├── Worker Agent
    └── WireGuard Client       └── WireGuard Client
```

**Routing**: `project1.domain.com/rest/v1/*` → Caddy → Kong → `10.100.0.2:3000` (worker1 PostgREST)

---

## Implementation Phases

### Phase 1: Refactor cloudInitGenerator.js into Modules

Split the monolithic 2,462-line file into a clean module structure:

```
components/cloudInit/
  index.js                     -- exports generateMasterCloudInit, generateWorkerCloudInit
  shared/tarUtils.js           -- extract tar/gzip utils (lines 10-78)
  shared/hardeningScript.js    -- extract Phase 1 hardening (lines 1936-2177)
  shared/backupScript.js       -- extract Phase 3 backup (lines 2272-2412)
  configs/sqlFiles.js          -- all SQL init files
  configs/vectorYml.js         -- vector config
  configs/functionsIndex.js    -- edge function templates
```

Keep `cloudInitGenerator.js` as a backward-compatible re-export.

**Files to modify**: `components/cloudInitGenerator.js`
**Files to create**: ~8 files in `components/cloudInit/`

**Key line boundaries in cloudInitGenerator.js:**
- Lines 10-78: `tarHeader`, `writeOctal`, `createTar`, `gzipAndBase64` (tar utils)
- Lines 85-1021: Static config generators (`getKongYml`, `getVectorYml`, `getPoolerExs`, SQL files, etc.)
- Lines 1023-1709: Dynamic config builders (`generateEnvFile`, `generateDockerCompose`)
- Lines 1710-1862: `generateAutheliaConfig`, `generateCaddyfile`, `generateCorsConf`
- Lines 1865-2461: `generateCloudInit` (main function + hardening + backup scripts)

---

### Phase 2: Master Server Deployment

Create master-specific cloud-init and docker-compose generation:

```
components/cloudInit/master/
  masterCompose.js      -- Caddy, Kong (DB-backed), Studio, Management API, WireGuard, Analytics/Logflare, Vector, Supavisor, Authelia/Redis
  masterEnv.js          -- Master .env file
  masterCaddyfile.js    -- Wildcard cert: *.domain.com
  masterKongYml.js      -- Base Kong config (Admin API enabled on 127.0.0.1:8001)
  wireguardServer.js    -- WireGuard server config (10.100.0.1/24)
  masterCloudInit.js    -- Assembles master cloud-init script
```

**Key decisions**:
- Kong runs in **DB-backed mode** (small Postgres on master) for dynamic route management via Admin API
- Caddy uses **wildcard TLS** (`*.domain.com` + `domain.com`)
- WireGuard server listens on UDP 51820
- Firewall: ports 22, 80, 443, 51820 open

**Files to create**: ~6 files in `components/cloudInit/master/`

---

### Phase 3: Management API + Dashboard

A Node.js service running on the master (extends `management/server.js` pattern):

```
management-api/
  server.js               -- HTTP server with API routes
  routes/projects.js      -- CRUD for projects
  routes/kong.js          -- Kong Admin API integration (add/remove routes per project)
  routes/wireguard.js     -- WireGuard peer management (add/remove workers)
  db/registry.js          -- Project registry (Postgres on master)
  db/schema.sql           -- projects table, master_config table
  services/hetzner.js     -- Hetzner API client for provisioning
  services/provisioner.js -- Orchestrates: create server → WireGuard peer → Kong routes → register
  Dockerfile
  package.json
```

**Project registry schema** (in master's Kong Postgres):
```sql
-- projects table
id, name, subdomain, worker_server_id, worker_ip, wireguard_ip,
jwt_secret, anon_key, service_role_key, postgres_password,
status, created_at

-- master_config table
key, value  -- stores WireGuard state, Hetzner token (encrypted)
```

**Project creation flow**:
1. Generate project secrets (client-side)
2. Allocate next WireGuard IP (10.100.0.N)
3. Generate WireGuard keypair for worker
4. Call Hetzner API to create worker server with worker cloud-init
5. Add WireGuard peer on master
6. Wait for worker to connect via WireGuard
7. Register Kong routes via Admin API
8. Store project metadata in registry

**Files to create**: ~10 files in `management-api/`

---

### Phase 4: Worker Server Deployment

Create worker-specific cloud-init and docker-compose:

```
components/cloudInit/worker/
  workerCompose.js     -- Postgres, GoTrue, PostgREST, Realtime, Storage, ImgProxy, Edge Functions, Meta, Worker Agent
  workerEnv.js         -- Per-project .env with project-specific secrets
  workerCloudInit.js   -- Worker cloud-init script
  wireguardClient.js   -- WireGuard client config (connects to master)
```

```
worker-agent/
  server.js            -- Health reporting, accepts commands from master (restart, backup trigger)
  Dockerfile
  package.json
```

**Key decisions**:
- Services bind to `0.0.0.0` on worker, but UFW only allows traffic from WireGuard subnet (10.100.0.0/24) and SSH (port 22)
- Worker agent reports health to master's management API every 30s
- Per-worker backup to Storage Box (same approach as current, subfolder per project)

**Files to create**: ~4 files in `components/cloudInit/worker/`, ~3 files in `worker-agent/`

---

### Phase 5: UI Changes

Modify the deployment wizard to support master vs project modes.

**Landing page**: Two paths — "Deploy Master Server" (first time) or "Add Project" (subsequent)

**Master wizard** (new `MasterWizard.jsx`):
> Welcome → API Key → Master Config (domain, server type, location, 2FA) → Review → Deploy → Complete

**Project wizard** (new `ProjectWizard.jsx`):
> Project Config (name, subdomain, server type) → Review → Deploy Worker → Complete (shows credentials)

**Project dashboard** (new `ProjectDashboard.jsx`):
> Project list with health indicators, "Open in Studio" links, restart/delete actions, backup status

**Files to modify**: `components/SupabaseDeployer.jsx` (add mode selection)
**Files to create**: `MasterWizard.jsx`, `ProjectWizard.jsx`, `ProjectDashboard.jsx`

---

### Phase 6: Studio Multi-Project Support

Run one Studio on master. For each project, the management dashboard provides an "Open in Studio" link that:
1. Configures Studio to connect to the selected project's pg-meta (via WireGuard IP)
2. Uses a lightweight reverse proxy on master that routes Studio's pg-meta requests based on a session cookie

For Phase 1 simplicity: restart Studio container with updated env vars when switching projects. Automate with the proxy approach later.

---

### Phase 7: Production Hardening

- Encrypt secrets at rest in the project registry
- Management API authentication (JWT or API key)
- Worker auto-recovery (detect dead workers, alert)
- WireGuard connection monitoring
- Rollback on failed provisioning (clean up Hetzner resources)
- Rate limiting on management API

---

## Networking: WireGuard VPN

**Why WireGuard**: Kernel-level performance, static config, no external dependencies (vs Tailscale), persistent connections (vs SSH tunnels), simpler than managing firewall rules for every service port across every worker.

```
Master:   10.100.0.1/24 (WireGuard hub, UDP 51820)
Worker 1: 10.100.0.2/24
Worker 2: 10.100.0.3/24
...
Worker N: 10.100.0.(N+1)/24
```

Worker firewall: only ports 22 (SSH) and 51820 (WireGuard) are public. All Supabase service ports are accessible only via WireGuard.

---

## Backup Strategy

Same restic + Hetzner Storage Box approach as current, extended for multi-project.

**Workers (per-project backups):**
- Each worker runs the same backup script from the current codebase
- Postgres dump + storage volumes + edge functions staged to `/tmp/backup-staging/`
- restic encrypts and sends to Storage Box subfolder: `/backups/{project-name}/`
- Daily 3 AM cron with retention: 7 daily, 4 weekly, 6 monthly
- Worker agent reports backup status (last success, last failure) to master's management API

**Master (platform backups):**
- Backs up: Kong Postgres (project registry + routing config), WireGuard configs, Caddy config, Authelia config
- Same restic approach, subfolder: `/backups/master/`
- Daily 3 AM cron (offset by 1 hour from workers to avoid Storage Box contention)

**Storage Box layout:**
```
/backups/
  master/       -- Kong DB, WireGuard, Caddy, Authelia configs
  project1/     -- project1's Postgres dump + storage files
  project2/     -- project2's Postgres dump + storage files
  ...
```

**Management dashboard** shows per-project backup status and allows manual backup triggers via worker agent.

**Reused from current codebase:** `shared/backupScript.js` (extracted from `cloudInitGenerator.js` lines 2272-2412) — parameterized with project name for subfolder isolation.

---

## Capacity Estimate

With per-project stack (no analytics/vector on workers) and low-traffic indie apps:
- **10 projects**: comfortable on master (16GB) + 10 small workers (2GB each)
- **20 projects**: possible with 2GB workers if traffic is minimal
- Per-worker idle RAM: ~600-800MB (Postgres + GoTrue + PostgREST + Realtime + Storage + Edge Functions + Meta)
- Master handles centralized logging for all projects via Analytics/Logflare + Vector
- Workers ship logs to master's Vector endpoint over WireGuard

---

## Verification Plan

1. **Phase 1-2**: Deploy master on Hetzner, verify Caddy wildcard cert, Kong responds, WireGuard server is up
2. **Phase 3-4**: Create a project via management API, verify worker boots, WireGuard connects, services start
3. **Phase 3**: Verify Kong routes `project1.domain.com/rest/v1/` to worker1's PostgREST
4. **End-to-end**: From browser, create a Supabase project, insert data via REST API, query via PostgREST, authenticate via GoTrue, upload file via Storage — all through `project1.domain.com`
5. **Studio**: Open Studio on master, verify it can browse the worker's database tables

---

## Critical Files (existing, to modify/reference)

| File | Purpose |
|------|---------|
| `components/cloudInitGenerator.js` | Refactor into modules (2,461 lines) |
| `components/SupabaseDeployer.jsx` | Add mode selection UI (1,281 lines) |
| `management/server.js` | Pattern for management-api (618 lines) |
| `management/Dockerfile` | Pattern for new container images |

## Files to Create

### Phase 1
- `components/cloudInit/index.js`
- `components/cloudInit/shared/tarUtils.js`
- `components/cloudInit/shared/hardeningScript.js`
- `components/cloudInit/shared/backupScript.js`
- `components/cloudInit/configs/sqlFiles.js`
- `components/cloudInit/configs/vectorYml.js`
- `components/cloudInit/configs/kongYml.js`
- `components/cloudInit/configs/functionsIndex.js`

### Phase 2
- `components/cloudInit/master/masterCompose.js`
- `components/cloudInit/master/masterEnv.js`
- `components/cloudInit/master/masterCaddyfile.js`
- `components/cloudInit/master/masterKongYml.js`
- `components/cloudInit/master/wireguardServer.js`
- `components/cloudInit/master/masterCloudInit.js`

### Phase 3
- `management-api/server.js`
- `management-api/routes/projects.js`
- `management-api/routes/kong.js`
- `management-api/routes/wireguard.js`
- `management-api/db/registry.js`
- `management-api/db/schema.sql`
- `management-api/services/hetzner.js`
- `management-api/services/provisioner.js`
- `management-api/Dockerfile`
- `management-api/package.json`

### Phase 4
- `components/cloudInit/worker/workerCompose.js`
- `components/cloudInit/worker/workerEnv.js`
- `components/cloudInit/worker/workerCloudInit.js`
- `components/cloudInit/worker/wireguardClient.js`
- `worker-agent/server.js`
- `worker-agent/Dockerfile`
- `worker-agent/package.json`

### Phase 5
- `components/MasterWizard.jsx`
- `components/ProjectWizard.jsx`
- `components/ProjectDashboard.jsx`

---

## What Does NOT Need to Change

- Supabase service source code (GoTrue, PostgREST, Realtime, etc.) — all configured via env vars
- Secret generation approach (client-side Web Crypto API)
- Server hardening script (reused as-is for both master and workers)
- Backup approach (per-server restic to Storage Box)
