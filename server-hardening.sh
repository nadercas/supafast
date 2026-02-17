#!/bin/bash
###############################################################################
# server-hardening.sh
# ---------------------------------------------------------------------------
# Run ONCE on a fresh Hetzner (Ubuntu 22.04 / 24.04) as root BEFORE Supabase.
#
# Usage:
#   ./server-hardening.sh --user deploy --ssh-key "ssh-ed25519 AAAA...your-key"
###############################################################################

set -euo pipefail

NO_COLOR='' RED='' CYAN='' GREEN='' YELLOW=''
if [ -t 1 ]; then
    nc=$(tput colors 2>/dev/null || echo 0)
    if [ "$nc" -ge 8 ]; then
        NO_COLOR='\033[0m'; RED='\033[0;31m'; CYAN='\033[0;36m'
        GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    fi
fi

info()  { echo -e "${CYAN}[INFO]${NO_COLOR}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NO_COLOR}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NO_COLOR}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NO_COLOR}  $*"; exit 1; }

[ "$EUID" -eq 0 ] || fail "Run this script as root"

# ── Parse args ──────────────────────────────────────────────────────────────
DEPLOY_USER="" SSH_PUB_KEY="" SSH_PORT=22 SKIP_DOCKER=false

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]
  --user NAME        Deploy account username (required)
  --ssh-key KEY      Public SSH key for that user (required)
  --ssh-port PORT    SSH port (default: 22)
  --skip-docker      Don't install Docker
  -h, --help         Help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user)        DEPLOY_USER="$2"; shift 2 ;;
        --ssh-key)     SSH_PUB_KEY="$2"; shift 2 ;;
        --ssh-port)    SSH_PORT="$2"; shift 2 ;;
        --skip-docker) SKIP_DOCKER=true; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             fail "Unknown option: $1" ;;
    esac
done

[ -n "$DEPLOY_USER" ] || fail "--user is required"
[ -n "$SSH_PUB_KEY" ] || fail "--ssh-key is required"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ] \
    || fail "Invalid SSH port: $SSH_PORT"

# ── Detect resources ────────────────────────────────────────────────────────
TOTAL_RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
CPU_CORES=$(nproc)
TOTAL_DISK_GB=$(df / --output=size -BG | tail -1 | tr -d ' G')
info "System: ${CPU_CORES} cores · ${TOTAL_RAM_MB} MB RAM · ${TOTAL_DISK_GB} GB disk"

###############################################################################
# 1. SYSTEM UPDATE
###############################################################################
info "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    curl wget git jq openssl ufw fail2ban \
    unattended-upgrades apt-listchanges \
    net-tools htop iotop sysstat \
    apparmor apparmor-utils libpam-pwquality \
    apt-transport-https ca-certificates gnupg lsb-release
ok "System packages updated"

###############################################################################
# 2. CREATE DEPLOY USER
###############################################################################
if id "$DEPLOY_USER" &>/dev/null; then
    warn "User '$DEPLOY_USER' exists — skipping"
else
    adduser --disabled-password --gecos "" "$DEPLOY_USER"
    usermod -aG sudo "$DEPLOY_USER"
    ok "User '$DEPLOY_USER' created"
fi

DEPLOY_HOME=$(eval echo "~$DEPLOY_USER")
SSH_DIR="$DEPLOY_HOME/.ssh"
mkdir -p "$SSH_DIR"
echo "$SSH_PUB_KEY" > "$SSH_DIR/authorized_keys"
chmod 700 "$SSH_DIR"; chmod 600 "$SSH_DIR/authorized_keys"
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$SSH_DIR"
echo "$DEPLOY_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$DEPLOY_USER"
chmod 440 "/etc/sudoers.d/$DEPLOY_USER"
ok "SSH key configured for '$DEPLOY_USER'"

###############################################################################
# 3. HARDEN SSH
###############################################################################
info "Hardening SSH..."
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)"
mkdir -p /etc/ssh/sshd_config.d

cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
AllowUsers $DEPLOY_USER
EOF

sshd -t || fail "Invalid sshd config — aborting (backup saved)"
systemctl restart sshd
ok "SSH hardened (port $SSH_PORT, key-only, root disabled)"

###############################################################################
# 4. FIREWALL
###############################################################################
info "Configuring UFW..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp comment "SSH"
ufw allow 80/tcp  comment "HTTP"
ufw allow 443/tcp comment "HTTPS"
ufw allow 443/udp comment "HTTPS-QUIC"
ufw limit "$SSH_PORT"/tcp
ufw --force enable
ok "UFW enabled — ports $SSH_PORT, 80, 443"

###############################################################################
# 5. FAIL2BAN
###############################################################################
info "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
banaction = ufw

[sshd]
enabled = true
port = $SSH_PORT
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban && systemctl restart fail2ban
ok "fail2ban configured"

###############################################################################
# 6. AUTO SECURITY UPDATES
###############################################################################
info "Enabling auto security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

systemctl enable unattended-upgrades
ok "Auto security updates enabled"

###############################################################################
# 7. KERNEL HARDENING
###############################################################################
info "Hardening kernel..."
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

sysctl --system >/dev/null 2>&1
ok "Kernel hardened"

###############################################################################
# 8. SWAP (sized to RAM)
###############################################################################
info "Configuring swap..."

calculate_swap_mb() {
    local ram=$1
    if   [ "$ram" -le 2048  ]; then echo $((ram * 2))
    elif [ "$ram" -le 8192  ]; then echo "$ram"
    elif [ "$ram" -le 65536 ]; then
        local s=$((ram / 2)); [ "$s" -lt 4096 ] && s=4096; echo "$s"
    else echo 4096; fi
}

SWAP_MB=$(calculate_swap_mb "$TOTAL_RAM_MB")
SWAP_FILE="/swapfile"

if swapon --show | grep -q "$SWAP_FILE"; then
    warn "Swap already active — skipping"
else
    [ -f "$SWAP_FILE" ] && rm -f "$SWAP_FILE"
    info "Creating ${SWAP_MB} MB swap..."
    dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$SWAP_MB" status=progress
    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE" && swapon "$SWAP_FILE"
    grep -q "$SWAP_FILE" /etc/fstab || echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
    ok "Swap: ${SWAP_MB} MB"
fi

###############################################################################
# 9. PERFORMANCE TUNING
###############################################################################
info "Tuning performance..."

if   [ "$TOTAL_RAM_MB" -ge 16384 ]; then FD_LIMIT=524288
elif [ "$TOTAL_RAM_MB" -ge 8192  ]; then FD_LIMIT=262144
elif [ "$TOTAL_RAM_MB" -ge 4096  ]; then FD_LIMIT=131072
else                                      FD_LIMIT=65536; fi

cat > /etc/security/limits.d/99-supabase.conf <<EOF
* soft nofile $FD_LIMIT
* hard nofile $FD_LIMIT
root soft nofile $FD_LIMIT
root hard nofile $FD_LIMIT
EOF

if [ "$TOTAL_RAM_MB" -ge 8192 ]; then
    TCP_RMEM="4096 87380 16777216"; TCP_WMEM="4096 65536 16777216"
    NETDEV_BUDGET=600; SOMAXCONN=4096
else
    TCP_RMEM="4096 87380 6291456"; TCP_WMEM="4096 65536 6291456"
    NETDEV_BUDGET=300; SOMAXCONN=2048
fi

cat > /etc/sysctl.d/99-performance.conf <<EOF
fs.file-max = $FD_LIMIT
fs.nr_open  = $FD_LIMIT

net.core.somaxconn            = $SOMAXCONN
net.core.netdev_max_backlog   = 5000
net.core.netdev_budget        = $NETDEV_BUDGET
net.ipv4.tcp_max_syn_backlog  = 4096
net.ipv4.tcp_tw_reuse         = 1
net.ipv4.tcp_fin_timeout      = 15
net.ipv4.tcp_keepalive_time   = 300
net.ipv4.tcp_keepalive_intvl  = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_rmem = $TCP_RMEM
net.ipv4.tcp_wmem = $TCP_WMEM
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing     = 1
net.ipv4.ip_local_port_range  = 1024 65535

vm.swappiness            = 10
vm.dirty_ratio           = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure    = 50
vm.overcommit_memory     = 0
EOF

sysctl --system >/dev/null 2>&1
ok "Performance tuned (fd=$FD_LIMIT, somaxconn=$SOMAXCONN)"

# I/O scheduler — 'none' for SSD/NVMe
for disk in /sys/block/sd* /sys/block/vd* /sys/block/nvme*; do
    [ -d "$disk" ] || continue
    devname=$(basename "$disk")
    rot=$(cat "$disk/queue/rotational" 2>/dev/null || echo 1)
    if [ "$rot" -eq 0 ] && [ -f "$disk/queue/scheduler" ]; then
        echo "none" > "$disk/queue/scheduler" 2>/dev/null || true
        info "I/O scheduler → none for $devname"
    fi
done

###############################################################################
# 10. DOCKER
###############################################################################
if [ "$SKIP_DOCKER" = true ]; then
    warn "Skipping Docker (--skip-docker)"
elif command -v docker &>/dev/null; then
    warn "Docker already installed"
    usermod -aG docker "$DEPLOY_USER" 2>/dev/null || true
else
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker "$DEPLOY_USER"

    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<EOF
{
    "log-driver": "json-file",
    "log-opts": { "max-size": "10m", "max-file": "3" },
    "storage-driver": "overlay2",
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true,
    "default-ulimits": {
        "nofile": { "Name": "nofile", "Hard": $FD_LIMIT, "Soft": $FD_LIMIT }
    }
}
EOF
    systemctl enable docker && systemctl restart docker
    ok "Docker installed & hardened"
fi

###############################################################################
# 11. MISC HARDENING
###############################################################################
# Secure shared memory
if ! grep -q "tmpfs.*/run/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    ok "Shared memory secured"
fi

# Tighter umask for deploy user
echo "umask 027" >> "$DEPLOY_HOME/.bashrc"
ok "Default umask 027 for $DEPLOY_USER"

###############################################################################
# SUMMARY
###############################################################################
echo ""
echo -e "${GREEN}=======================================================${NO_COLOR}"
echo -e "${GREEN}  Server hardening complete!${NO_COLOR}"
echo -e "${GREEN}=======================================================${NO_COLOR}"
echo ""
echo "  CPU:      ${CPU_CORES} cores"
echo "  RAM:      ${TOTAL_RAM_MB} MB"
echo "  Swap:     ${SWAP_MB} MB"
echo "  FD limit: ${FD_LIMIT}"
echo "  SSH port: ${SSH_PORT}"
echo "  User:     ${DEPLOY_USER}"
echo ""
echo -e "  ${YELLOW}CRITICAL — before closing this session:${NO_COLOR}"
echo ""
echo "  1. Open a NEW terminal and test:"
echo -e "     ${CYAN}ssh -p $SSH_PORT $DEPLOY_USER@<server-ip>${NO_COLOR}"
echo ""
echo "  2. Then deploy Supabase:"
echo -e "     ${CYAN}sudo ./setup-supabase.sh --proxy caddy --with-authelia${NO_COLOR}"
echo ""
echo -e "  ${RED}Do NOT close this session until you confirm SSH works!${NO_COLOR}"
echo ""