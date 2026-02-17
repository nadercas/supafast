# 🚀 Supabase Deploy

**Zero-knowledge deployment tool for self-hosted Supabase on Hetzner Cloud.**

Deploy production-ready Supabase in ~10 minutes with automated server hardening, 2FA, and encrypted backups. All secrets are generated in your browser and never leave your machine.

## ✨ Features

- **🔐 Zero-Knowledge Architecture** — API tokens and secrets exist only in browser memory (React state). Never stored, never transmitted to our servers.
- **🛡️ Hardened by Default** — SSH key-only, UFW firewall, fail2ban, kernel sysctl tuning, auto-updates, bcrypt-12, security headers.
- **🔄 Encrypted Backups** — Daily AES-256 encrypted backups via restic to Hetzner Storage Box. One Storage Box supports unlimited servers.
- **⚡ One-Click Deploy** — Server provisioning → OS hardening → Supabase + Caddy + Authelia + Redis → backup cron. All automated via cloud-init.
- **🔑 Browser SSH Key Generation** — Ed25519 keypairs generated client-side using Web Crypto API. No pre-existing SSH keys required.
- **👤 Deploy User** — Creates a dedicated non-root user with sudo access. Root login is fully disabled.

## 🏗️ What Gets Deployed

**Server Hardening:**
- Ubuntu 24.04 LTS
- Non-root deploy user with SSH key-only access
- UFW firewall (22, 80, 443) with rate limiting
- fail2ban protection
- Kernel hardening (sysctl)
- Automatic security updates
- Swap and performance tuning
- Docker with security hardening

**Supabase Stack:**
- PostgreSQL 15
- Auth (GoTrue)
- Storage (with MinIO)
- Realtime
- Edge Functions
- Studio
- Kong API Gateway
- Caddy reverse proxy (auto-HTTPS via Let's Encrypt)
- Authelia 2FA (optional)
- Redis session store (optional)

**Backups:**
- Restic encrypted backups
- Hetzner Storage Box via SFTP
- Daily automated backups (3 AM)
- Retention: 7 daily, 4 weekly, 6 monthly
- Health-check notifications (healthchecks.io, ntfy.sh, etc.)

## 🚀 Quick Start

### Prerequisites

1. **Hetzner Cloud Account** — Sign up at [hetzner.com/cloud](https://www.hetzner.com/cloud)
2. **Hetzner Cloud API Token** — Get one at console.hetzner.cloud → Security → API Tokens (Read & Write permissions)
3. **Domain Name** — For HTTPS/TLS (point A record to server IP after deployment)
4. **Hetzner Storage Box** (optional but recommended) — Order at [hetzner.com/storage/storage-box](https://www.hetzner.com/storage/storage-box)

### Deploy

1. Visit [your-deployed-url.vercel.app](#)
2. Enter your Hetzner Cloud API token
3. Configure your deployment:
   - Server name (e.g., `supabase-prod`)
   - Deploy user name (SSH login username)
   - Location (Falkenstein, Nuremberg, Helsinki, Ashburn, Hillsboro)
   - Server type (CX33 recommended — 4 vCPU, 8 GB RAM)
   - Domain (must start with `https://`)
   - Supabase credentials (username, password, email)
   - Storage Box credentials (for encrypted backups)
4. Review and deploy
5. Wait ~10 minutes for deployment to complete
6. **Save your credentials** — they only exist in browser memory!

### After Deployment

1. **Save SSH private key** to `~/.ssh/your-server-name`
2. **Point DNS A record** from your domain to the server IP
3. Wait 2-5 minutes for Caddy to provision TLS certificate
4. Visit your domain and log in
5. SSH access: `ssh -i ~/.ssh/your-server-name deploy-user@server-ip`

## 🔒 Security

### Zero-Knowledge Architecture

- **All secrets generated client-side** using Web Crypto API
- **No backend server** — all API calls go directly from your browser to api.hetzner.cloud
- **No analytics, no tracking** — open source, auditable code
- **Secrets never stored** in localStorage, cookies, or databases
- **Ed25519 SSH keys** generated in browser and never leave your machine (except public key uploaded to Hetzner)

### Server Hardening

- **Non-root deploy user** with SSH key-only access, root login fully disabled
- **UFW firewall** with rate limiting on SSH
- **fail2ban** protection against brute-force attacks
- **Kernel hardening** via sysctl (IP spoofing protection, SYN cookies, etc.)
- **Automatic security updates** via unattended-upgrades
- **Docker security** (no-new-privileges, user namespaces)
- **Bcrypt-12** password hashing for Authelia
- **Security headers** (X-Content-Type-Options, X-Frame-Options, CSP)

### Backup Security

- **AES-256 encryption** via restic
- **Unique encryption key per server** — generated in browser, stored in server's backup.env
- **SSH key authentication** for Storage Box (password used once during setup, then wiped from logs)
- **Isolated backup folders** — `/backups/server-name` per deployment

## 🛠️ Development

```bash
# Clone the repo
git clone <your-repo-url>
cd supabase-selfhost

# Install dependencies
npm install

# Run dev server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## 📁 Project Structure

```
.
├── app/
│   ├── layout.jsx          # Next.js app layout with metadata
│   └── page.jsx            # Main page (renders SupabaseDeployer)
├── components/
│   └── SupabaseDeployer.jsx # Main deployment component
├── public/                 # Static assets
├── package.json
├── next.config.js
└── README.md
```

## 🌐 Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/your-username/your-repo)

Or manually:

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel
```

## 📚 Documentation

### Storage Box Setup

1. Order a Storage Box at [hetzner.com/storage/storage-box](https://www.hetzner.com/storage/storage-box)
2. Go to Hetzner Robot panel → Storage Box → Enable SSH
3. Note your username (e.g., `u123456`), hostname (e.g., `u123456.your-storagebox.de`), and password
4. Enter these credentials during deployment

**For 2nd+ deployments:** Reuse the same Storage Box credentials. Each server creates its own `/backups/server-name` folder with a unique encryption key and SSH key.

### Manual Backup Operations

SSH into your server and run:

```bash
cd /root/supabase-automated-self-host/docker

# Manual backup
./supabase-backup.sh

# List snapshots
restic -r sftp:u123456@storagebox-server-name:/backups/server-name snapshots

# Restore latest backup
# (stop Supabase first: docker compose down)
restic -r sftp:u123456@storagebox-server-name:/backups/server-name restore latest --target /restore
# Then copy files back manually

# Check repo stats
restic -r sftp:u123456@storagebox-server-name:/backups/server-name stats
```

### Environment Variables

The deployed server's `.env` file contains:

- `JWT_SECRET` — Supabase JWT secret
- `ANON_KEY` — Public anonymous key for client SDKs
- `SERVICE_ROLE_KEY` — Admin key (keep secret!)
- `POSTGRES_PASSWORD` — PostgreSQL superuser password
- `SECRET_KEY_BASE` — Auth secret key base
- `VAULT_ENC_KEY` — Vault encryption key
- `S3_PROTOCOL_ACCESS_KEY_ID/SECRET` — MinIO credentials
- `AUTHELIA_SESSION_SECRET` — Authelia session encryption
- `AUTHELIA_STORAGE_ENCRYPTION_KEY` — Authelia DB encryption
- `AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET` — Authelia JWT

All of these are generated in your browser and included in the credentials you save at the end.

## 🤝 Contributing

Contributions welcome! Please open an issue or PR.

## 📄 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This tool is provided as-is. Always review the generated cloud-init script and verify the security of your deployment. Keep your credentials safe and never commit them to version control.

## 🙏 Credits

- Built with [Next.js](https://nextjs.org/)
- Supabase deployment based on [supabase-automated-self-host](https://github.com/singh-inder/supabase-automated-self-host)
- Server hardening inspired by best practices from the community
- Encrypted backups via [restic](https://restic.net/)

---

Made with ❤️ for the self-hosting community
