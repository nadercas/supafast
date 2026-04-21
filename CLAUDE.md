# SupaFast — Claude project notes

SupaFast is a self-hosted Supabase distribution deployed on Hetzner VPS via
cloud-init. This file documents the parts a future Claude session is most
likely to get wrong if it reads the code cold.

## Repo layout (high level)

- `components/cloudInitGenerator.js` — browser-side generator that produces the
  one-shot Hetzner user-data script. Contains the VM bootstrap and the
  embedded host scripts `supabase-upgrade.sh` + `supabase-rotate-keys.sh`
  (installed by cloud-init because the management container needs them on
  first boot).
- `management/` — the management container (`ghcr.io/nadercas/supafast`). Runs
  inside the VM; drives rotation, upgrades, pin, and migrations via systemd
  path-unit triggers.
  - `management/server.js` — HTTP API.
  - `management/public/index.html` — single-page admin UI.
  - `management/migrations/NNN_*.sh` (+ sibling asset dirs) — numbered
    migrations bundled into the image.
  - `management/hostbin/` — frozen copies of host scripts shipped *inside* the
    image and installed to `/usr/local/bin/` by the bootstrap endpoint
    (`supafast-migrate.sh`, `supabase-pin-digests.sh`).
  - `management/scripts/extract-runner.js` — regenerates everything in
    `management/hostbin/` from the `get*Sh()` generators. Run this after
    editing any of those generators so the frozen copies stay in sync.

## Shipping a management-image change to production

Whenever `management/` changes (server.js, public/, migrations/, hostbin/,
Dockerfile) and needs to reach running servers:

1. If any `get*Sh()` generator in `cloudInitGenerator.js` was edited, run
   `node management/scripts/extract-runner.js` to refresh frozen copies in
   `management/hostbin/`.
2. `docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/nadercas/supafast:latest --push ./management`
3. Commit the repo changes (generator + hostbin copies together).
4. On each target server, pull the new image and recreate mgmt:
   `cd /opt/supabase/docker && sudo docker compose pull management && sudo docker compose up -d management`
5. If a host runner (`supafast-migrate.sh`, `supabase-pin-digests.sh`) changed,
   re-run the bootstrap endpoint so `/usr/local/bin/*.sh` and its systemd path
   unit get rewritten from the new image. Via docker bridge:
   `MGMT_IP=$(sudo docker inspect $(sudo docker compose ps -q management) -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' | head -1) && curl -fsSL http://$MGMT_IP:3001/api/migrations/bootstrap.sh | sudo bash`
6. Open the panel → Upgrades tab → Apply pending if a new migration shipped.

End-to-end sanity check after non-trivial changes: add a throwaway
`003_noop.sh` migration with just `echo noop`, bump `LATEST_MIGRATION_VERSION`,
build+push, pull on a server, confirm it shows as pending and applies.

**Known gap:** pulling a new image does not auto-re-run bootstrap. Runner
changes therefore require step 5 on existing servers. If this becomes painful,
add an entrypoint hook in the mgmt container that calls its own
`/api/migrations/bootstrap.sh` on startup — idempotent, safe.

## Cloud-init size budget

Hetzner caps `user_data` at 32 KiB. `minifyBashOutsideHeredocs` strips comments
from generated bash to stay under. When adding to the generator, check the
output size — keep 500+ bytes headroom.

## Migration system

SupaFast has two code-delivery channels. Knowing which one reaches which
servers is the thing to get right.

| Channel | What it ships | Reaches |
|---|---|---|
| `cloudInitGenerator.js` (GitHub) | VM bootstrap | **Fresh deploys only** — existing VMs never re-run cloud-init |
| `ghcr.io/nadercas/supafast` (management image) | Admin UI + migrations bundle + runner | **All servers** — pulled via the existing Upgrades tab |

So: new features that need to reach existing servers go through the management
image as a numbered migration. The generator is only touched when a fresh
deploy needs the feature built in from day one.

### Persistent artifacts on the VM

| Path | Purpose |
|---|---|
| `/opt/supabase/docker/.supafast-version` | Integer. Highest applied migration number. Fresh deploys seed this to `LATEST_MIGRATION_VERSION` so bundled migrations are not re-run. |
| `/opt/supabase/docker/upgrade/migrate-request.json` | Trigger file written by the mgmt container. |
| `/opt/supabase/docker/upgrade/migrate-result.json` | Status file written by the host runner. |
| `/opt/supabase/docker/upgrade/migrations/` | Staging dir — mgmt container copies bundled `NNN_*.sh` + sibling asset dirs here before triggering. |
| `/opt/supabase/docker/upgrade/migrations-backup/` | Pre-apply tarball snapshots of `.env`, `kong.yml`, `docker-compose.yml`. Used by revert. |
| `/usr/local/bin/supafast-migrate.sh` | Host runner. Installed by cloud-init (fresh) or bootstrap (pre-6ed886c). |
| `/etc/systemd/system/supafast-migrate.{path,service}` | Path unit watches `migrate-request.json`, fires the oneshot runner. |

### Apply flow

1. User clicks "Apply pending" in the Upgrades tab.
2. `POST /api/migrations/apply` copies each pending `NNN_*.sh` (and its asset
   dir if present) from `/app/migrations/` into
   `/opt/supabase/docker/upgrade/migrations/`, then writes
   `migrate-request.json` atomically.
3. Systemd path unit fires `supafast-migrate.sh` on the host.
4. Runner, per migration in order:
   - Snapshots `.env`, `volumes/api/kong.yml`, `docker-compose.yml` to
     `migrations-backup/NNN-<ts>.tar`.
   - Executes the script. Scripts are idempotent and must exit non-zero on
     failure (`set -uo pipefail`).
   - On success: bumps `.supafast-version` to `NNN`.
   - On failure: restores the snapshot, recreates touched services
     (`auth rest realtime storage meta kong`), stops, reports in result file.
5. UI polls `migrate-result.json` and renders status.

### Revert flow

"Revert last" posts a trigger with `mode: "revert"`. The runner finds the
most recent backup tar, restores those three files, recreates the services
listed in the migration's `@restarts:` header, and decrements the version.

### Migration header format

Each `NNN_*.sh` must begin with this comment block (parsed by
`parseMigrationHeader` in `server.js` and displayed in the UI):

```
#!/bin/bash
# @summary: One line describing what this migration does
# @touches: .env, volumes/api/kong.yml, docker-compose.yml, /usr/local/bin/foo.sh
# @restarts: auth, rest, realtime, storage, meta, kong
```

The UI shows `@summary` plus per-migration **View source** (served by
`/api/migrations/source/:name`) so users can audit before applying.

### Adding a new migration

1. Create `management/migrations/NNN_description.sh` with the header block.
2. Keep it idempotent — re-running must be a no-op.
3. If it ships host files or compose-fragment assets, put them in
   `management/migrations/NNN_description/` next to the script.
4. Update the Dockerfile `COPY migrations ./migrations` line still covers it
   (already does — no change needed).
5. Bump `LATEST_MIGRATION_VERSION` in `components/cloudInitGenerator.js` so
   fresh deploys seed to include the new migration (cloud-init's inline
   bootstrap of the feature is what makes it unnecessary on fresh installs).
6. Build + push a new management image tag. Existing users pull it via the
   Upgrades tab; the UI will then show the new migration as pending.

### Updating the runner itself

`components/cloudInitGenerator.js :: getSupafastMigrateSh()` is the source of
truth. `management/hostbin/supafast-migrate.sh` is a frozen copy shipped in
the image and embedded base64 in `/api/migrations/bootstrap.sh`. After
editing the generator, regenerate the frozen copy:

```
node management/scripts/extract-runner.js
```

Then commit both files together.

## Two scenarios

### A. Fresh deploy (post-6ed886c)

Cloud-init installs `/usr/local/bin/supafast-migrate.sh`, creates the systemd
path unit, and seeds `.supafast-version=LATEST_MIGRATION_VERSION`. Bundled
migrations up to that version are treated as already applied. Future migrations
arrive via `docker compose pull` of the management image.

### B. Pre-6ed886c server

These VMs were bootstrapped before the runner existed and have two structural
gaps that must be patched **one time via SSH** before the Upgrades tab works:

1. Management container mounts `/supabase` read-only, with no rw override for
   `upgrade/`. The API can't write trigger files.
2. No `/usr/local/bin/supafast-migrate.sh`, no systemd path unit.

Full one-time fix (run on the server as a sudoer):

```bash
cd /opt/supabase/docker

# 1. Pull the new management image.
sudo docker compose pull management

# 2. Add the rw mount for upgrade/ to docker-compose.yml.
sudo sed -i '/- \.\/volumes\/functions\/\.env:\/supabase\/volumes\/functions\/\.env/a\      - ./upgrade:/supabase/upgrade' docker-compose.yml
sudo mkdir -p ./upgrade

# 3. Recreate management with the new mount + new image.
sudo docker compose up -d management

# 4. Install the host runner via the container's docker bridge IP
#    (port 3001 is container-internal; /api/migrations/bootstrap.sh sits
#    behind authelia on the caddy edge, so we bypass caddy here).
MGMT_IP=$(sudo docker inspect $(sudo docker compose ps -q management) \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{"\n"}}{{end}}' | head -1)
curl -fsSL http://$MGMT_IP:3001/api/migrations/bootstrap.sh | sudo bash
```

From then on the server is in the same state as a fresh deploy. Open the
management panel → **Upgrades** tab → **Apply pending**. Migrations run in
order:

- **001_es256_and_new_keys** — ES256 JWT keypair, `sb_publishable_*`/
  `sb_secret_*` API keys, kong consumers, rotation/upgrade/pin host scripts,
  systemd path units.
- **002_image_env_vars** — extracts hardcoded image tags from compose into
  `IMAGE_*` env vars in `.env` and rewrites the compose `image:` lines to
  `${IMAGE_*}` so the per-service Upgrade buttons in the panel work.

After that, every future update is `docker compose pull management` → new
migrations appear pending → click Apply. No more SSH.

## Security model

The management container can execute arbitrary root code on the host through
the path-unit triggers. This is by design — it replaces the "SSH in and run
scripts" workflow. The trust boundary is the management image itself; anyone
who can push to `ghcr.io/nadercas/supafast` can root every SupaFast VM. Treat
that registry credential accordingly.

Migration scripts run as root with no sandbox. `View source` in the UI is the
user's primary audit tool before clicking Apply.

## Known footguns

- `kong.yml` must be world-readable (0644). Kong runs as non-root; if a
  migration writes it via `tempfile` (which defaults to 0600), Kong enters a
  crash loop. `getSupabaseRotateKeysSh()` already `chmod 644`s it — any new
  migration touching kong.yml must do the same.
- Adding XSS-unsafe `innerHTML` writes in `management/public/index.html` is
  blocked by a project hook. Build DOM with `createElement` + `textContent`.
- Cloud-init size. See budget note above.
