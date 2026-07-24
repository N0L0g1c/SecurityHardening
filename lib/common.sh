#!/bin/bash
# Shared helpers for Debian/Ubuntu security hardening
# shellcheck disable=SC2034

# Prevent double-sourcing
[[ -n "${_SECURITY_COMMON_LOADED:-}" ]] && return 0
_SECURITY_COMMON_LOADED=1

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE="${NEEDRESTART_MODE:-a}"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Paths ---
_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITE_ROOT="$(cd "${_COMMON_DIR}/.." && pwd)"
CONFIG_DIR="${SUITE_ROOT}/security_configs"
LOG_FILE="${LOG_FILE:-/var/log/security-hardening.log}"
BACKUP_DIR="${BACKUP_DIR:-/etc/security/backups}"

# --- Logging ---
_ensure_log() {
  mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR" 2>/dev/null || true
  touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/security-hardening.log"
}

log()     { _ensure_log; echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"; }
warn()    { _ensure_log; echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"; }
error()   { _ensure_log; echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"; }
info()    { _ensure_log; echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"; }
success() { _ensure_log; echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    error "Please run as root: sudo $0"
    exit 1
  fi
}

# --- OS detection ---
DISTRO_ID=""
DISTRO_LIKE=""
DISTRO_VERSION=""
DISTRO_CODENAME=""
IS_DEBIAN=0
IS_UBUNTU=0

detect_os() {
  if [[ ! -f /etc/os-release ]]; then
    error "Unsupported system: /etc/os-release not found"
    exit 1
  fi
  # shellcheck source=/dev/null
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
  DISTRO_VERSION="${VERSION_ID:-}"
  DISTRO_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"

  case "$DISTRO_ID" in
    debian) IS_DEBIAN=1 ;;
    ubuntu) IS_UBUNTU=1 ;;
    *)
      if [[ "$DISTRO_LIKE" == *debian* ]] || [[ "$DISTRO_LIKE" == *ubuntu* ]]; then
        IS_DEBIAN=1
        [[ "$DISTRO_LIKE" == *ubuntu* || "$DISTRO_ID" == *ubuntu* ]] && IS_UBUNTU=1
      else
        error "This suite supports Debian and Ubuntu only (detected: ${DISTRO_ID})"
        exit 1
      fi
      ;;
  esac

  info "Detected: ${PRETTY_NAME:-$DISTRO_ID $DISTRO_VERSION}"
}

# --- Apt helpers ---
apt_update() {
  log "Updating package lists..."
  apt-get update -qq
}

apt_upgrade() {
  if [[ "${SKIP_APT_UPGRADE:-0}" == "1" ]]; then
    info "Skipping apt upgrade (SKIP_APT_UPGRADE=1)"
    return 0
  fi
  log "Applying available upgrades..."
  apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
}

pkg_available() {
  local pkg="$1"
  local cand
  cand="$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  [[ -n "$cand" && "$cand" != "(none)" ]]
}

# Install packages; skip missing ones instead of failing the whole run
install_packages() {
  local pkgs=("$@")
  local available=()
  local missing=()
  local p

  log "Resolving packages..."
  for p in "${pkgs[@]}"; do
    if pkg_available "$p"; then
      available+=("$p")
    else
      missing+=("$p")
    fi
  done

  if ((${#missing[@]})); then
    warn "Skipping unavailable packages: ${missing[*]}"
  fi

  if ((${#available[@]} == 0)); then
    warn "No packages to install"
    return 0
  fi

  log "Installing: ${available[*]}"
  apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "${available[@]}"
}

# --- Backup ---
backup_file() {
  local src="$1"
  local dest
  [[ -f "$src" ]] || return 0
  mkdir -p "$BACKUP_DIR"
  dest="${BACKUP_DIR}/$(basename "$src").$(date +%Y%m%d%H%M%S).bak"
  cp -a "$src" "$dest"
  info "Backed up $src -> $dest"
}

# --- SSH service helpers ---
ssh_service_name() {
  if systemctl list-unit-files ssh.service 2>/dev/null | grep -q '^ssh\.service'; then
    echo ssh
  elif systemctl list-unit-files sshd.service 2>/dev/null | grep -q '^sshd\.service'; then
    echo sshd
  elif [[ -f /usr/lib/systemd/system/ssh.service ]] || [[ -f /lib/systemd/system/ssh.service ]]; then
    echo ssh
  elif [[ -f /usr/lib/systemd/system/sshd.service ]] || [[ -f /lib/systemd/system/sshd.service ]]; then
    echo sshd
  else
    echo ssh
  fi
}

current_ssh_port() {
  local port
  port="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')" || true
  if [[ -z "$port" ]]; then
    port="$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1)" || true
  fi
  port="${port:-22}"
  [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)) || port=22
  echo "$port"
}

restart_ssh() {
  local svc
  svc="$(ssh_service_name)"
  if ! command -v sshd >/dev/null 2>&1 && ! dpkg -s openssh-server >/dev/null 2>&1; then
    warn "openssh-server not installed; skipping SSH restart"
    return 0
  fi
  if ! sshd -t 2>/dev/null; then
    error "sshd config validation failed; not restarting SSH"
    sshd -t || true
    return 1
  fi
  systemctl restart "$svc"
  systemctl enable "$svc" >/dev/null 2>&1 || true
  success "SSH service ($svc) restarted"
}

# --- Firewall ---
configure_ufw() {
  local ssh_port
  ssh_port="$(current_ssh_port)"

  log "Configuring UFW (SSH port ${ssh_port})..."
  # Allow SSH before reset completes enable — avoid lockout mid-script
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${ssh_port}/tcp" comment 'SSH-pre' >/dev/null 2>&1 || true
  fi

  if [[ -f "${CONFIG_DIR}/ufw_rules.sh" ]]; then
    SSH_PORT="$ssh_port" bash "${CONFIG_DIR}/ufw_rules.sh"
    success "UFW enabled"
    return
  fi

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw limit "${ssh_port}/tcp" comment 'SSH'
  ufw allow 80/tcp comment 'HTTP'
  ufw allow 443/tcp comment 'HTTPS'
  ufw logging on
  ufw --force enable
  success "UFW enabled"
}

# --- Fail2ban ---
configure_fail2ban() {
  log "Configuring fail2ban..."
  mkdir -p /etc/fail2ban
  if [[ -f "${CONFIG_DIR}/fail2ban_jail.local" ]]; then
    cp "${CONFIG_DIR}/fail2ban_jail.local" /etc/fail2ban/jail.local
  else
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
backend = systemd

[sshd]
enabled = true
port = ssh
maxretry = 3
EOF
  fi

  # Prefer systemd journal when auth.log is absent (some minimal images)
  if [[ ! -f /var/log/auth.log ]]; then
    sed -i '/^\[sshd\]/,/^\[/{s/^logpath/#logpath/}' /etc/fail2ban/jail.local 2>/dev/null || true
    if ! grep -q '^backend' /etc/fail2ban/jail.local; then
      sed -i '/^\[DEFAULT\]/a backend = systemd' /etc/fail2ban/jail.local
    fi
  fi

  systemctl enable fail2ban
  systemctl restart fail2ban
  success "fail2ban active"
}

# --- Unattended upgrades (Debian vs Ubuntu origins) ---
configure_unattended_upgrades() {
  log "Configuring automatic security updates..."

  if [[ "$IS_UBUNTU" -eq 1 ]]; then
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  else
    # Debian: security + optionally stable-updates labeling
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  fi

  cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  systemctl enable unattended-upgrades >/dev/null 2>&1 || true
  success "Unattended upgrades configured for ${DISTRO_ID}"
}

# --- SSH hardening via drop-in (safe; does not wipe vendor config) ---
configure_ssh_hardening() {
  local dropin="/etc/ssh/sshd_config.d/99-security-hardening.conf"

  if ! dpkg -s openssh-server >/dev/null 2>&1; then
    warn "openssh-server not installed; installing..."
    install_packages openssh-server
  fi

  log "Hardening SSH (drop-in config)..."
  mkdir -p /etc/ssh/sshd_config.d
  backup_file /etc/ssh/sshd_config

  if [[ -f "${CONFIG_DIR}/ssh_hardening.conf" ]]; then
    cp "${CONFIG_DIR}/ssh_hardening.conf" "$dropin"
  else
    cat > "$dropin" << 'EOF'
# Managed by SecurityHardening suite
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
DebianBanner no
EOF
  fi

  # Ensure Include is present (Debian/Ubuntu default)
  if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
    backup_file /etc/ssh/sshd_config
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  fi

  restart_ssh
}

# --- Password policy ---
configure_password_policy() {
  local minlen="${1:-12}"

  log "Configuring password policy (minlen=${minlen})..."
  install_packages libpam-pwquality

  backup_file /etc/security/pwquality.conf
  cat > /etc/security/pwquality.conf << EOF
# Managed by SecurityHardening suite
minlen = ${minlen}
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
minclass = 3
maxrepeat = 2
maxclassrepeat = 2
dictcheck = 1
usercheck = 1
EOF

  # Enable pam_pwquality without replacing the whole common-password stack
  if [[ -f /etc/pam.d/common-password ]]; then
    backup_file /etc/pam.d/common-password
    if ! grep -q 'pam_pwquality\.so' /etc/pam.d/common-password; then
      sed -i '/pam_unix\.so/i password\trequisite\t\t\tpam_pwquality.so retry=3' /etc/pam.d/common-password
    fi
  fi
  success "Password policy applied"
}

# --- Kernel / sysctl ---
configure_sysctl() {
  local conf="/etc/sysctl.d/99-security-hardening.conf"

  log "Applying kernel hardening (sysctl)..."
  cat > "$conf" << 'EOF'
# Managed by SecurityHardening suite
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_rfc1337 = 1

net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.core_uses_pid = 1
kernel.sysrq = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

  # Apply keys that exist; ignore unknowns (no set -e abort)
  while IFS='=' read -r key value; do
    key="$(echo "$key" | xargs)"
    value="$(echo "$value" | xargs)"
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    sysctl -w "${key}=${value}" >/dev/null 2>&1 || warn "sysctl skip: ${key}"
  done < "$conf"

  success "Kernel parameters applied via ${conf}"
}

# --- AppArmor ---
configure_apparmor() {
  log "Enabling AppArmor..."
  install_packages apparmor apparmor-utils
  systemctl enable apparmor >/dev/null 2>&1 || true
  systemctl start apparmor >/dev/null 2>&1 || true
  if command -v aa-enforce >/dev/null 2>&1 && [[ -d /etc/apparmor.d ]]; then
    # Enforce only profiles that load cleanly
    find /etc/apparmor.d -maxdepth 1 -type f ! -name '*.dpkg-*' ! -name '*~' -print0 2>/dev/null \
      | xargs -0 -r -n1 aa-enforce >/dev/null 2>&1 || warn "Some AppArmor profiles could not be enforced"
  fi
  success "AppArmor configured"
}

# --- auditd ---
configure_auditd() {
  log "Enabling auditd..."
  install_packages auditd audispd-plugins
  systemctl enable auditd
  systemctl start auditd || systemctl start audit-rules || true
  success "auditd enabled"
}

# --- AIDE ---
configure_aide() {
  log "Initializing AIDE (may take several minutes)..."
  install_packages aide aide-common

  if command -v aideinit >/dev/null 2>&1; then
    # -y yes to overwrite, -f force; noninteractive
    aideinit -y -f || aideinit || true
  elif command -v aide >/dev/null 2>&1; then
    aide --init || true
  else
    warn "AIDE not available"
    return 0
  fi

  # Normalize DB path across Debian/Ubuntu versions
  if [[ -f /var/lib/aide/aide.db.new ]]; then
    mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
    mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
  fi
  success "AIDE database ready"
}

# --- Monitoring scripts ---
install_security_check() {
  cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash
echo "=== Security Status Check ==="
echo "Date: $(date)"
echo "Host: $(hostname) | $(. /etc/os-release; echo "$PRETTY_NAME")"
echo ""
echo "=== Firewall ==="
ufw status verbose 2>/dev/null || echo "ufw not active"
echo ""
echo "=== Failed logins (recent) ==="
journalctl -u ssh -u sshd --since "24 hours ago" 2>/dev/null | grep -i "Failed password" | tail -10 \
  || grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 \
  || echo "none"
echo ""
echo "=== Services ==="
for s in ufw fail2ban apparmor auditd clamav-daemon; do
  printf "%-16s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null || echo n/a)"
done
echo ""
echo "=== Updates ==="
apt list --upgradable 2>/dev/null | grep -v "Listing..." | head -20 || true
EOF
  chmod 755 /usr/local/bin/security-check.sh

  cat > /etc/cron.daily/security-report << 'EOF'
#!/bin/bash
/usr/local/bin/security-check.sh > "/var/log/security-report-$(date +%Y%m%d).log" 2>&1
EOF
  chmod 755 /etc/cron.daily/security-report
}

install_security_monitor() {
  cat > /usr/local/bin/security-monitor.sh << 'EOF'
#!/bin/bash
echo "=== Advanced Security Monitor ==="
echo "Date: $(date)"
echo ""
echo "=== System ==="
uptime
free -h | head -2
df -h / | tail -1
echo ""
echo "=== Services ==="
systemctl is-active ufw fail2ban clamav-daemon auditd apparmor 2>/dev/null || true
echo ""
echo "=== Firewall ==="
ufw status verbose 2>/dev/null || true
echo ""
echo "=== Listening ports ==="
ss -tuln 2>/dev/null | grep -E ':(22|80|443)\s' || true
echo ""
if command -v aide >/dev/null 2>&1; then
  echo "=== AIDE (summary) ==="
  aide --check 2>/dev/null | tail -8 || true
fi
if command -v lynis >/dev/null 2>&1; then
  echo "=== Lynis hints ==="
  lynis audit system --quick 2>/dev/null | grep -E '(WARNING|SUGGESTION)' | head -10 || true
fi
EOF
  chmod 755 /usr/local/bin/security-monitor.sh

  cat > /etc/cron.daily/security-report << 'EOF'
#!/bin/bash
/usr/local/bin/security-monitor.sh > "/var/log/security-report-$(date +%Y%m%d).log" 2>&1
EOF
  chmod 755 /etc/cron.daily/security-report
}

print_next_steps() {
  local level="$1"
  echo ""
  echo "=== Hardening complete (${level}) ==="
  echo "OS: ${PRETTY_NAME:-$DISTRO_ID}"
  echo "Log: $LOG_FILE"
  echo "Backups: $BACKUP_DIR"
  echo ""
  echo "Next steps:"
  echo "  1. Keep an open console/session until you verify SSH"
  echo "  2. Test SSH from another session: ssh -p $(current_ssh_port) user@host"
  echo "  3. Review firewall: ufw status verbose"
  echo "  4. Check fail2ban: fail2ban-client status"
  if [[ "$level" == "advanced" ]]; then
    echo "  5. Run: /usr/local/bin/security-monitor.sh"
  else
    echo "  5. Run: /usr/local/bin/security-check.sh"
  fi
  echo "  6. Reboot when convenient to apply all kernel/AppArmor changes"
}
