#!/bin/bash
# @summary: Raise fs.nr_open / fs.file-max so services can set their default NOFILE on reboot
# @touches: /etc/sysctl.d/99-performance.conf
# @restarts: none
#
# Migration 004 — fixes a time bomb in earlier cloud-init where fs.nr_open
# was set as low as 131072 on <8GB RAM servers. systemd's default
# LimitNOFILE=524288 then exceeds the kernel cap, so on the next reboot
# containerd (and sysstat, and others) fail with status=205/LIMITS and the
# server looks crashed even though the OS is fine. Raising these limits at
# runtime is safe — they are ceilings, not allocations. No service restart.

set -uo pipefail

CONF=/etc/sysctl.d/99-performance.conf
TARGET_FILE_MAX=2097152
TARGET_NR_OPEN=1048576

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(ts)] [mig-004] $*"; }

if [ ! -f "$CONF" ]; then
  log "$CONF not found — nothing to do"
  exit 0
fi

cur_file_max=$(grep -E "^fs\.file-max\s*=" "$CONF" | tail -n1 | cut -d= -f2- | tr -d ' ')
cur_nr_open=$(grep -E "^fs\.nr_open\s*=" "$CONF" | tail -n1 | cut -d= -f2- | tr -d ' ')

changed=0

# Only rewrite when the current value is below our floor. Users who
# deliberately set higher values get left alone.
if [ -n "$cur_file_max" ] && [ "$cur_file_max" -lt "$TARGET_FILE_MAX" ] 2>/dev/null; then
  log "fs.file-max: $cur_file_max → $TARGET_FILE_MAX"
  sed -i.tmp "s|^fs\.file-max\s*=.*|fs.file-max = $TARGET_FILE_MAX|" "$CONF" && rm -f "$CONF.tmp"
  changed=1
fi

if [ -n "$cur_nr_open" ] && [ "$cur_nr_open" -lt "$TARGET_NR_OPEN" ] 2>/dev/null; then
  log "fs.nr_open: $cur_nr_open → $TARGET_NR_OPEN"
  sed -i.tmp "s|^fs\.nr_open\s*=.*|fs.nr_open = $TARGET_NR_OPEN|" "$CONF" && rm -f "$CONF.tmp"
  changed=1
fi

if [ "$changed" -eq 0 ]; then
  log "fs.file-max=$cur_file_max fs.nr_open=$cur_nr_open already safe"
  exit 0
fi

log "applying sysctl --system"
sysctl --system >/dev/null 2>&1 || log "WARN: sysctl --system exited non-zero"

log "live values: $(sysctl -n fs.file-max) / $(sysctl -n fs.nr_open)"
log "migration 004 complete"
