# SupaFast

**Zero-knowledge deployment tool for self-hosted Supabase on Hetzner Cloud.**

Deploy a production-hardened Supabase instance in ~10 minutes. All secrets are generated in your browser using Web Crypto API and never transmitted to any server.

<img width="1366" height="768" alt="supafast" src="https://github.com/user-attachments/assets/7a42f980-8cbd-405c-90c6-1b82ae2aadb1" />


---

## Why I Built This

I spent weeks trying to self-host Supabase securely. The official docs are great for getting started, but they don't cover production hardening: SSH lockdown, automated backups, fail2ban, swap configuration, kernel tuning, SSL certificates, 2FA... the list goes on.

Every tutorial I found was either too basic (just `docker compose up`) or assumed I already knew how to secure a production server. I wanted something that **just worked** — a tool that would provision a hardened, production-ready Supabase instance with one click, without me having to SSH in and manually configure 50 different things.

So I built SupaFast. It's the tool I wish existed when I started.

Now you can deploy a **fully secured, managed Supabase instance** on Hetzner Cloud with:
- Zero manual server configuration
- All secrets generated client-side (zero-knowledge architecture)
- Automatic security hardening (SSH lockdown, UFW, fail2ban, kernel tuning)
- Built-in 2FA with Authelia (optional)
- Encrypted daily backups to AWS S3
- Web-based management panel (restart containers, update images, view logs)
- Auto-HTTPS with Let's Encrypt via Caddy
- Full Claude MCP integration (37 tools for managing your Supabase via AI)

It's basically a **managed Supabase solution**, but you own the infrastructure.

---

## What Gets Deployed

**Server (Ubuntu 24.04 LTS)**
- Non-root deploy user, root login fully disabled
- SSH key-only access (ed25519 keypair generated in browser)
- UFW firewall (ports 22, 80, 443 only)
- fail2ban brute-force protection
- Kernel hardening via sysctl
- Unattended security updates
- Swap configured for server type
- Docker with hardening flags
- A management panel at /admin/ to perform basic docker operations for all containers (start/stop/restart), and also to display critical logs / banned IP's on Fail2ban / and backup data.

**Supabase Stack**
- PostgreSQL 15
- Auth (GoTrue)
- Storage
- Realtime
- Edge Functions (Deno runtime)
- Supabase Studio
- Kong API Gateway
- Supavisor connection pooler
- Caddy reverse proxy (auto-HTTPS via Let's Encrypt)
- Authelia 2FA with TOTP (optional)
- Redis session store (optional)

**Backups**
- Restic AES-256 encrypted backups to AWS S3
- Daily cron at 3 AM
- Retention: 7 daily, 4 weekly, 6 monthly
- Postgres dump + config files + storage volumes

**MCP Server (Claude / Cursor / Windsurf integration)**
- Full Supabase MCP server deployed on the server
- 37 tools across database, auth, storage, edge functions, migrations, RLS, realtime, logs, and admin
- Accessible via SSH stdio — no extra ports, no new attack surface
- Edge function create/update/delete implemented via direct filesystem writes (self-hosted native)

---

## Quick Start

### Prerequisites

- Hetzner Cloud account + API token (Read & Write)
- Domain with DNS access
- AWS S3 bucket for backups (see [S3 Setup](#s3-setup))
- SMTP Credentials to setup Supabase Auth (use resend or similar)

### Deploy

1. Visit the deployer UI
2. Enter your Hetzner Cloud API token
3. Configure:
   - Server name, location, and type (CX33 recommended — 4 vCPU, 8 GB RAM, ~€4.99/mo) - Also optimized to work flawlessly on cheapest instance CX23 (~€2.99/mo)
   - Domain (e.g. `https://supabase.yourdomain.com`)
   - Supabase credentials and display name
   - AWS S3 bucket, region, access key, secret key
   - Optional: enable Authelia 2FA, Redis (While I made this optional, it is highly recommended you turn it on for 2FA as self hosting Supabase with Basic Auth is not recommended.
4. Review and deploy
5. **Save your credentials immediately** — they exist only in browser memory

### After Deployment

1. Save the SSH private key to `~/.ssh/your-server-name` and `chmod 600` it
2. Point your DNS A record to the server IP
3. Wait 2–5 min for Caddy to provision the TLS certificate
4. Visit your domain and log in
5. Add the MCP config to your Claude/Cursor settings (shown in completion screen)

---

## Claude MCP Integration

The deployer automatically installs a full Supabase MCP server on your server. At the end of deployment you'll see a ready-to-paste config block:

```json
{
  "mcpServers": {
    "supabase-your-server": {
      "command": "ssh",
      "args": [
        "-i", "~/.ssh/your-server-name",
        "-o", "StrictHostKeyChecking=accept-new",
        "username@YOUR_SERVER_IP",
        "/home/username/bin/supabase-mcp"
      ]
    }
  }
}
```

Add this to `~/.claude/mcp.json` (Claude Code), Cursor MCP settings, or Windsurf.

### How It Works

The MCP server uses SSH stdio transport — no HTTP server, no new open ports. When your MCP client starts:

1. Your local machine spawns an SSH process authenticated with your private key
2. SSH connects to your server as the deploy user
3. The server runs `/home/deploy/bin/supabase-mcp` — a wrapper that sources credentials and launches the MCP server
4. All MCP communication flows through the SSH stdio pipe
5. The MCP server connects to Supabase (service role key) and PostgreSQL directly on the server

```
Claude Code (local) ──── SSH stdio ──── MCP server (on your server)
                                              │
                                     ┌────────┴────────┐
                                     │                 │
                              Supabase SDK          pg client
                            (REST + Realtime)    (direct postgres)
```

**Security model:**
- Authentication = your SSH private key. No key = no access, period.
- Server has `PasswordAuthentication no` — brute force impossible
- Supabase credentials (service role key, JWT secret, DB password) live in `/home/deploy/.mcp.env` (chmod 600, deploy user only)
- They never appear in your local MCP config
- `StrictHostKeyChecking=accept-new` — accepts on first connect, rejects if host key ever changes (MITM protection)

### Available Tools (37 total)

| Category | Tools |
|---|---|
| **Database** | query, insert, update, delete, describe table, list tables |
| **Auth** | list users, create user, delete user, update user, get user, list sessions |
| **Storage** | list buckets, create bucket, delete bucket, list files, upload file, delete file |
| **Edge Functions** | create/update, list, delete, invoke |
| **Migrations** | create, list, apply, rollback, status |
| **RLS** | list policies, create policy, delete policy, enable RLS, disable RLS |
| **Realtime** | list channels, list publications, manage subscriptions |
| **Logs** | query postgres logs, query auth logs, query edge function logs |
| **Admin** | health check, get config, restart services, get stats, get version |

### Edge Functions via MCP

Unlike the hosted Supabase platform (which requires the CLI), our MCP server deploys edge functions directly to the filesystem. The Supabase Edge Runtime hot-reloads on file changes — functions are live immediately:

```
Claude → MCP create_edge_function → writes to /opt/supabase/docker/volumes/functions/name/index.ts
                                                                    ↓
                                              Edge Runtime detects change → function is live
```

### MCP Server Fork

The MCP server is based on [mcp-supabase-self-hosted](https://github.com/ninedotdev/mcp-supabase-self-hosted) by **ninedotdev** — full credit for the original 37-tool implementation. Our fork ([nadercas/supafast-mcp](https://github.com/nadercas/supafast-mcp)) adds:

- Filesystem-based edge function CRUD (replaces "not supported" errors)
- Dependency overrides to patch all known vulnerabilities in transitive deps
- Updated `@modelcontextprotocol/sdk` to `^1.0.0`
- `npm prune --omit=dev` baked in — clean production install

---

## S3 Setup

1. Create an S3 bucket in AWS (any region)
   - Block all public access: ON
   - Versioning: disabled (restic manages its own)
   - Server-side encryption: SSE-S3
2. Create an IAM user with programmatic access and attach this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ],
    "Resource": [
      "arn:aws:s3:::YOUR-BUCKET-NAME",
      "arn:aws:s3:::YOUR-BUCKET-NAME/*"
    ]
  }]
}
```

3. Save the Access Key ID and Secret Access Key for the deployer

Backups are stored at `s3://YOUR-BUCKET/SERVER-NAME/` with restic's content-addressed, AES-256 encrypted format.

---

## Security Architecture

| Layer | Implementation |
|---|---|
| SSH access | ed25519 key only, password auth disabled, root login disabled |
| Firewall | UFW: ports 22, 80, 443 only |
| Brute force | fail2ban on SSH |
| Kernel | sysctl hardening (IP spoofing, SYN cookies, ICMP, etc.) |
| Passwords | bcrypt cost 12 via Authelia |
| 2FA | TOTP pre-registered at deploy time (no setup required post-deploy) |
| HTTPS | Caddy auto-HTTPS via Let's Encrypt |
| Backups | restic AES-256, unique key per server, stored in S3 |
| MCP creds | chmod 600, deploy user only, never in local config |
| Secrets | Generated in browser via Web Crypto API, never sent to any server |

---

## Project Structure

```
.
├── components/
│   ├── SupabaseDeployer.jsx      # Main deployment wizard UI
│   └── cloudInitGenerator.js    # Generates the cloud-init bash script
├── management/
│   ├── server.js                 # Management panel backend (Node.js)
│   ├── public/index.html         # Management panel UI
│   └── Dockerfile                # Management container (includes restic)
├── app/
│   ├── layout.jsx
│   └── page.jsx
└── README.md
```

**The cloud-init script (generated at deploy time) handles:**
- Phase 1: OS hardening (packages, user, SSH, kernel, swap, firewall, Docker)
- Phase 2: Supabase stack (config files, docker-compose, Caddy, Authelia, pull + start)
- Phase 3: S3 backup (restic install, repo init, backup script, cron)
- Phase 4: MCP server (Node.js, clone fork, build, env file, wrapper script)

---

## Self-Hosted Supabase Notes

Some Supabase Studio features call the Supabase Cloud Management API and will not work on self-hosted:

- **Publishable keys** — use your anon key instead
- **API key management UI** — manage keys directly in `/opt/supabase/docker/.env`
- **JWT secret rotation UI** — update `JWT_SECRET` in `.env` and restart containers

Everything else — Studio, SQL editor, Auth, Storage, Edge Functions, Realtime — works fully.

---

## Credits

- **[supabase-automated-self-host](https://github.com/singh-inder/supabase-automated-self-host)** by singh-inder — foundation for the Supabase docker-compose configuration
- **[mcp-supabase-self-hosted](https://github.com/ninedotdev/mcp-supabase-self-hosted)** by ninedotdev — original 37-tool MCP server implementation that made full Supabase MCP integration possible
- **[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)** by Tecnativa — Docker API proxy that restricts socket access to only the operations the management panel needs
- **[restic](https://restic.net/)** — encrypted backup engine
- **[Caddy](https://caddyserver.com/)** — automatic HTTPS
- **[Authelia](https://www.authelia.com/)** — 2FA / SSO

---

MIT License
