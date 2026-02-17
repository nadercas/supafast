# Deployment Guide

## Deploy to Vercel (Recommended)

### Option 1: Deploy via Vercel Dashboard

1. Push your code to GitHub:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/your-username/supabase-deploy.git
   git push -u origin main
   ```

2. Go to [vercel.com/new](https://vercel.com/new)
3. Import your GitHub repository
4. Vercel will auto-detect Next.js — no configuration needed
5. Click "Deploy"
6. Your app will be live at `your-project.vercel.app`

### Option 2: Deploy via Vercel CLI

```bash
# Install Vercel CLI
npm i -g vercel

# Login to Vercel
vercel login

# Deploy (run from project root)
vercel

# Deploy to production
vercel --prod
```

## Deploy to Other Platforms

### Netlify

1. Push code to GitHub
2. Go to [app.netlify.com](https://app.netlify.com)
3. "Add new site" → Import from Git
4. Build settings:
   - Build command: `npm run build`
   - Publish directory: `.next`
5. Deploy

### Self-Hosted (Node.js)

```bash
# Build the app
npm run build

# Start production server
npm start

# Or use PM2 for process management
npm i -g pm2
pm2 start npm --name "supabase-deploy" -- start
pm2 save
pm2 startup
```

### Docker

Create `Dockerfile`:

```dockerfile
FROM node:20-alpine AS base

FROM base AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV production
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV PORT 3000
CMD ["node", "server.js"]
```

Build and run:
```bash
docker build -t supabase-deploy .
docker run -p 3000:3000 supabase-deploy
```

## Environment Variables

No environment variables are required for this app since it's a zero-knowledge architecture — everything runs client-side.

## Custom Domain

### Vercel
1. Go to your project settings
2. Domains → Add domain
3. Follow DNS configuration instructions

### Other platforms
Follow your platform's custom domain setup guide.

## Security Headers

Security headers are configured in `vercel.json` for Vercel deployments. For other platforms, ensure these headers are set:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

## Performance Optimization

The app is already optimized for production:
- Next.js 15 with App Router
- SWC minification
- React 19 server components
- Automatic code splitting
- Font optimization via `next/font`

## Monitoring

Since this is a zero-knowledge tool with no backend:
- No server-side analytics needed
- No error tracking required (everything runs client-side)
- Monitor Vercel deployment status in dashboard

## Updates

To deploy updates:

```bash
# Make your changes
git add .
git commit -m "Your update message"
git push

# Vercel will auto-deploy from main branch
# Or use CLI: vercel --prod
```

## Troubleshooting

### Build fails on Vercel
- Check Node.js version (should be 18+ or 20+)
- Verify all dependencies are in `package.json`
- Check build logs for specific errors

### App doesn't load
- Clear browser cache
- Check browser console for errors
- Ensure CORS isn't blocking Hetzner API calls

### Performance issues
- Run `npm run build` locally to check bundle size
- Use Vercel Analytics to identify bottlenecks
- Consider lazy-loading heavy components

## Server Operations Guide

After a successful deployment, use this guide to manage your self-hosted Supabase instance.

### SSH Access

```bash
# During deployment (root access available for debugging)
ssh -i ~/.ssh/<server-name> root@<server-ip>

# After deployment completes (root is locked, use deploy user)
ssh -i ~/.ssh/<server-name> <deploy-user>@<server-ip>

# Check deployment logs
sudo cat /var/log/supabase-deploy.log
```

### Backups

Backups are managed by [restic](https://restic.net/) and run daily at 3:00 AM via cron.

**Check backup status:**

```bash
cd /root/supabase-automated-self-host/docker
source backup.env
restic snapshots
```

**List contents of the latest backup:**

```bash
source backup.env
restic ls latest
```

**Run a manual backup:**

```bash
sudo /root/supabase-automated-self-host/docker/supabase-backup.sh
```

**Check backup logs:**

```bash
sudo cat /var/log/supabase-backup-<server-name>.log
```

**Check cron schedule:**

```bash
sudo crontab -l | grep supabase-backup
```

**What gets backed up:**
- Full PostgreSQL dump (`postgres_dump.sql.gz`)
- Supabase config files (`.env`, `docker-compose.yml`, `Caddyfile`, Authelia config)
- Uploaded files (`volumes/storage/`)
- Backup metadata (server name, timestamp, IP)

**Backup retention policy:**
- 7 daily snapshots
- 4 weekly snapshots
- 6 monthly snapshots

### Restore from Backup

**1. Restore to a temporary directory:**

```bash
source /root/supabase-automated-self-host/docker/backup.env
mkdir -p /tmp/restore
restic restore latest --target /tmp/restore
```

**2. Restore the database:**

```bash
cd /tmp/restore/tmp/supabase-backup.*
gunzip postgres_dump.sql.gz
docker exec -i supabase-db psql -U postgres < postgres_dump.sql
```

**3. Restore uploaded files:**

```bash
cp -r /tmp/restore/root/supabase-automated-self-host/docker/volumes/storage/* \
  /root/supabase-automated-self-host/docker/volumes/storage/
```

**4. Restore config files (if needed):**

```bash
cp /tmp/restore/tmp/supabase-backup.*/config/.env \
  /root/supabase-automated-self-host/docker/.env
cp /tmp/restore/tmp/supabase-backup.*/config/docker-compose.yml \
  /root/supabase-automated-self-host/docker/docker-compose.yml
```

**5. Restart Supabase:**

```bash
cd /root/supabase-automated-self-host/docker
docker compose down && docker compose up -d
```

**6. Clean up:**

```bash
rm -rf /tmp/restore
```

**Full disaster recovery (new server):**
1. Deploy a fresh server using the deployer tool
2. SSH in and stop containers: `docker compose down`
3. Restore database, files, and configs as above
4. Restart: `docker compose up -d`

### Storage Box

Backups are sent to a Hetzner Storage Box via SFTP. If the Storage Box connection failed during deployment, backups fall back to local disk at `/root/backups/<server-name>`.

**Check where backups are stored:**

```bash
grep RESTIC_REPOSITORY /root/supabase-automated-self-host/docker/backup.env
```

- If it starts with `sftp:` — backups go to the remote Storage Box
- If it starts with `/root/backups/` — backups are local only (no off-site protection)

**Test Storage Box connection:**

```bash
ssh storagebox-<server-name>
```

**Manually set up Storage Box (if it failed during deployment):**

```bash
# Generate SSH key
ssh-keygen -t ed25519 -f /root/.ssh/storagebox_key -N ""

# Show the public key — add this in Hetzner Robot > Storage Box > SSH tab
cat /root/.ssh/storagebox_key.pub

# Add SSH config
cat >> /root/.ssh/config <<EOF

Host storagebox-<server-name>
    HostName <host>.your-storagebox.de
    User <user>
    Port 23
    IdentityFile /root/.ssh/storagebox_key
    StrictHostKeyChecking accept-new
EOF

# Test connection
ssh storagebox-<server-name>

# Update backup.env
nano /root/supabase-automated-self-host/docker/backup.env
# Change: RESTIC_REPOSITORY="sftp:<user>@storagebox-<server-name>:/backups/<server-name>"

# Initialize remote repo
source /root/supabase-automated-self-host/docker/backup.env
restic init

# Run first backup
/root/supabase-automated-self-host/docker/supabase-backup.sh
```

### Docker & Supabase Management

**Check running containers:**

```bash
docker ps
```

**Restart all services:**

```bash
cd /root/supabase-automated-self-host/docker
docker compose restart
```

**Stop all services:**

```bash
docker compose down
```

**Start all services:**

```bash
docker compose up -d
```

**View logs for a specific service:**

```bash
docker logs supabase-db --tail 50
docker logs supabase-kong --tail 50
docker logs supabase-auth --tail 50
docker logs supabase-storage --tail 50
docker logs supabase-studio --tail 50
docker logs authelia --tail 50
docker logs caddy-container --tail 50
```

**Update Supabase images:**

```bash
cd /root/supabase-automated-self-host/docker
docker compose pull
docker compose up -d
```

### Authelia (Authentication)

Authelia protects the Supabase Studio dashboard with username/password authentication.

**Brute-force protection:**
- 3 failed attempts within 30 minutes = banned for 60 minutes
- Only applies to valid usernames (non-existent usernames are not rate-limited)

**View Authelia logs:**

```bash
docker logs authelia --tail 50
```

**Authelia config files:**

```
/root/supabase-automated-self-host/docker/volumes/authelia/configuration.yml  # Main config
/root/supabase-automated-self-host/docker/volumes/authelia/users_database.yml # Users
/root/supabase-automated-self-host/docker/volumes/authelia/notification.txt   # OTP codes (filesystem notifier)
```

### Server Security

**Firewall (UFW):**

```bash
sudo ufw status
```

**Fail2ban (SSH brute-force protection):**

```bash
sudo fail2ban-client status sshd
```

**Check banned IPs:**

```bash
sudo fail2ban-client status sshd | grep "Banned IP"
```

**Unban an IP:**

```bash
sudo fail2ban-client set sshd unbanip <ip-address>
```

### Swap Management

Swap is configured during deployment based on server RAM. To resize after scaling:

```bash
sudo swapoff /swapfile
sudo rm /swapfile
sudo dd if=/dev/zero of=/swapfile bs=1M count=<size-in-mb>
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

Recommended swap sizes:
- 2GB RAM: 4GB swap
- 4GB RAM: 4GB swap
- 8GB RAM: 8GB swap
- 16GB RAM: 8GB swap
- 32GB RAM: 16GB swap

## Support

For deployment issues:
- Check [Next.js deployment docs](https://nextjs.org/docs/deployment)
- Check [Vercel docs](https://vercel.com/docs)
- Open an issue in the GitHub repository
