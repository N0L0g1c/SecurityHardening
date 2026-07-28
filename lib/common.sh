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
UBUNTU_GE_24=0
UBUNTU_GE_26=0
SSH_SOCKET_ACTIVATION=0

# True if $1 is greater than or equal to $2 (26.04, 26.10, 28.04, …)
version_ge() {
  local ver="$1" min="$2"
  if command -v dpkg >/dev/null 2>&1; then
    dpkg --compare-versions "$ver" ge "$min"
    return $?
  fi
  local lowest
  lowest="$(printf '%s\n%s\n' "$min" "$ver" | sort -V | tail -n1)"
  # If ver is the highest (or equal), ge is true when lowest==min OR ver==min handled by: highest==ver
  [[ "$lowest" == "$ver" ]]
}

detect_ssh_socket_activation() {
  SSH_SOCKET_ACTIVATION=0
  if [[ -f /usr/lib/systemd/system/ssh.socket ]] \
    || [[ -f /lib/systemd/system/ssh.socket ]] \
    || systemctl list-unit-files ssh.socket 2>/dev/null | grep -q '^ssh\.socket'; then
    SSH_SOCKET_ACTIVATION=1
  fi
}

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
        if [[ "$DISTRO_LIKE" == *ubuntu* || "$DISTRO_ID" == *ubuntu* ]]; then
          IS_UBUNTU=1
        fi
      else
        error "This suite supports Debian and Ubuntu only (detected: ${DISTRO_ID})"
        exit 1
      fi
      ;;
  esac

  if [[ "$IS_UBUNTU" -eq 1 && -n "$DISTRO_VERSION" ]]; then
    if version_ge "$DISTRO_VERSION" "24.04"; then UBUNTU_GE_24=1; fi
    if version_ge "$DISTRO_VERSION" "26.04"; then UBUNTU_GE_26=1; fi
  fi

  detect_ssh_socket_activation

  info "Detected: ${PRETTY_NAME:-$DISTRO_ID $DISTRO_VERSION}"
  if [[ "$IS_UBUNTU" -eq 1 ]]; then
    if [[ "$UBUNTU_GE_26" -eq 1 ]]; then
      info "Ubuntu ${DISTRO_VERSION} (≥ 26.04): socket SSH, deb822 apt, full-upgrade path enabled"
    elif [[ "$UBUNTU_GE_24" -eq 1 ]]; then
      info "Ubuntu ${DISTRO_VERSION}: modern path (socket SSH when present)"
    fi
  fi
  if [[ "$SSH_SOCKET_ACTIVATION" -eq 1 ]]; then
    info "SSH socket activation detected (ssh.socket)"
  fi
  return 0
}

# --- Apt helpers ---
# Ensure universe/multiverse on Ubuntu 24+/26+ deb822 sources (needed for some hardening pkgs)
ensure_ubuntu_components() {
  [[ "$IS_UBUNTU" -eq 1 ]] || return 0
  local src="/etc/apt/sources.list.d/ubuntu.sources"
  [[ -f "$src" ]] || return 0

  if grep -qE '^Components:.*\buniverse\b' "$src" \
    && grep -qE '^Components:.*\bmultiverse\b' "$src"; then
    return 0
  fi

  log "Enabling universe/multiverse in ${src}..."
  backup_file "$src"
  # Append missing components on each Components: line (DEB822 / Ubuntu 24+)
  awk '
    /^Components:/ {
      line=$0
      if (line !~ /(^| )universe( |$)/) line=line " universe"
      if (line !~ /(^| )multiverse( |$)/) line=line " multiverse"
      print line
      next
    }
    { print }
  ' "$src" > "${src}.tmp" && mv "${src}.tmp" "$src"
}

apt_update() {
  ensure_ubuntu_components
  log "Updating package lists..."
  apt-get update -qq
}

apt_upgrade() {
  if [[ "${SKIP_APT_UPGRADE:-0}" == "1" ]]; then
    info "Skipping apt upgrade (SKIP_APT_UPGRADE=1)"
    return 0
  fi
  # Ubuntu 26+ (and 24+): full-upgrade handles changed dependencies cleanly
  if [[ "$UBUNTU_GE_24" -eq 1 ]]; then
    log "Applying available upgrades (full-upgrade)..."
    apt-get full-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
  else
    log "Applying available upgrades..."
    apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
  fi
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

# --- SSH service helpers (Ubuntu 24+/26+: ssh.socket + sshd-socket-generator) ---
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

# Port from systemd socket ListenStream (authoritative under socket activation)
ssh_socket_listen_port() {
  local line port
  # Live unit properties first
  while IFS= read -r line; do
    port="$(printf '%s' "$line" | sed -nE 's/.*[=:]([0-9]+)$/\1/p')"
    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
      echo "$port"
      return 0
    fi
  done < <(systemctl show ssh.socket -p Listen --value 2>/dev/null | tr ' ' '\n')

  # Unit file / drop-ins
  while IFS= read -r line; do
    port="$(printf '%s' "$line" | sed -nE 's/^ListenStream=.*:([0-9]+)$/\1/p')"
    [[ -z "$port" ]] && port="$(printf '%s' "$line" | sed -nE 's/^ListenStream=([0-9]+)$/\1/p')"
    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
      echo "$port"
      return 0
    fi
  done < <(systemctl cat ssh.socket 2>/dev/null | grep -E '^ListenStream=')
  return 1
}

current_ssh_port() {
  local port=""
  if [[ "${SSH_SOCKET_ACTIVATION:-0}" -eq 1 ]]; then
    port="$(ssh_socket_listen_port || true)"
  fi
  if [[ -z "$port" ]]; then
    port="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')" || true
  fi
  if [[ -z "$port" ]]; then
    port="$(grep -hE '^\s*Port\s+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | tail -1)" || true
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

  # Ubuntu 24.04+ / 26.04+: Port/ListenAddress are applied via sshd-socket-generator
  if [[ "${SSH_SOCKET_ACTIVATION:-0}" -eq 1 ]]; then
    systemctl daemon-reload
    systemctl enable ssh.socket >/dev/null 2>&1 || true
    systemctl restart ssh.socket
    # Reload running daemon (if any sessions hold ssh.service active)
    systemctl try-reload-or-restart "$svc" >/dev/null 2>&1 \
      || systemctl kill -s HUP "$svc" >/dev/null 2>&1 \
      || true
    success "SSH reloaded (ssh.socket + ${svc})"
    return 0
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

  # Ubuntu 26+ / journal-first installs: prefer systemd backend always on modern Ubuntu
  if [[ "$UBUNTU_GE_24" -eq 1 ]] || [[ ! -f /var/log/auth.log ]]; then
    sed -i '/^\[sshd\]/,/^\[/{s/^logpath/#logpath/}' /etc/fail2ban/jail.local 2>/dev/null || true
    if grep -qE '^backend\s*=' /etc/fail2ban/jail.local; then
      sed -i 's/^backend\s*=.*/backend = systemd/' /etc/fail2ban/jail.local
    else
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
    # Codename placeholders work for 26.04 (resolute) and any newer release
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
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

# --- Post-quantum SSH (hybrid KEM key exchange) ---
# Protects against harvest-now-decrypt-later. Requires OpenSSH 9.0+ (sntrup) or 9.9+/10 (ML-KEM).
# Set ALLOW_CLASSICAL_KEX=1 to also permit classical KEX for legacy clients.

ssh_query_algs() {
  local kind="$1"
  if command -v ssh >/dev/null 2>&1; then
    ssh -Q "$kind" 2>/dev/null || true
  fi
}

ssh_filter_supported() {
  # Usage: ssh_filter_supported kex alg1 alg2 ...
  local kind="$1"
  shift
  local supported wanted out=()
  supported="$(ssh_query_algs "$kind")"
  [[ -n "$supported" ]] || { printf '%s' "$*" | tr ' ' ','; return 0; }
  local a
  for a in "$@"; do
    if printf '%s\n' "$supported" | grep -qxF "$a"; then
      out+=("$a")
    fi
  done
  ((${#out[@]})) || return 1
  local IFS=,
  echo "${out[*]}"
}

ensure_ssh_host_keys() {
  [[ "${SKIP_SSH_HOST_KEY_GEN:-0}" == "1" ]] && return 0
  # Ed25519 is required for our HostKey preference
  if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
    log "Generating Ed25519 host key..."
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
  fi
  if [[ ! -f /etc/ssh/ssh_host_ecdsa_key ]]; then
    ssh-keygen -t ecdsa -b 256 -f /etc/ssh/ssh_host_ecdsa_key -N "" -q || true
  fi
  if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
    ssh-keygen -t rsa -b 3072 -f /etc/ssh/ssh_host_rsa_key -N "" -q || true
  fi
}

build_pq_kex_list() {
  local pq classical kex
  # Prefer NIST ML-KEM-768 hybrid, then Streamlined NTRU Prime hybrid
  pq="$(ssh_filter_supported kex \
    mlkem768x25519-sha256 \
    sntrup761x25519-sha512 \
    sntrup761x25519-sha512@openssh.com \
    || true)"

  classical="$(ssh_filter_supported kex \
    curve25519-sha256 \
    curve25519-sha256@libssh.org \
    ecdh-sha2-nistp256 \
    ecdh-sha2-nistp384 \
    ecdh-sha2-nistp521 \
    || true)"

  if [[ -n "$pq" ]]; then
    if [[ "${ALLOW_CLASSICAL_KEX:-0}" == "1" && -n "$classical" ]]; then
      kex="${pq},${classical}"
      warn "ALLOW_CLASSICAL_KEX=1: classical key exchange permitted (not fully PQ for all clients)"
    else
      kex="$pq"
    fi
    echo "$kex"
    return 0
  fi

  # No PQ algorithms in this OpenSSH build
  if [[ "${ALLOW_CLASSICAL_KEX:-0}" == "1" && -n "$classical" ]]; then
    warn "No post-quantum KEX available; using classical KEX only (ALLOW_CLASSICAL_KEX=1)"
    echo "$classical"
    return 0
  fi
  return 1
}

apply_ssh_post_quantum() {
  local dropin="$1"
  local client="${SSH_CLIENT_DROPIN:-/etc/ssh/ssh_config.d/99-security-hardening.conf}"
  local kex hostkeys pubkeys ciphers macs crypto tmp line

  ensure_ssh_host_keys

  kex="$(build_pq_kex_list)" || {
    error "This OpenSSH build has no post-quantum KEX (need OpenSSH ≥ 9.0 with sntrup/ML-KEM)"
    error "Upgrade openssh-server, or set ALLOW_CLASSICAL_KEX=1 (not PQ-secure)"
    return 1
  }

  hostkeys="$(ssh_filter_supported key-sig \
    ssh-ed25519 \
    ssh-ed25519-cert-v01@openssh.com \
    sk-ssh-ed25519@openssh.com \
    sk-ssh-ed25519-cert-v01@openssh.com \
    ecdsa-sha2-nistp256 \
    ecdsa-sha2-nistp384 \
    ecdsa-sha2-nistp521 \
    rsa-sha2-512 \
    rsa-sha2-256 \
    || echo 'ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256')"

  pubkeys="$hostkeys"

  ciphers="$(ssh_filter_supported cipher \
    chacha20-poly1305@openssh.com \
    aes256-gcm@openssh.com \
    aes128-gcm@openssh.com \
    || echo 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com')"

  macs="$(ssh_filter_supported mac \
    hmac-sha2-512-etm@openssh.com \
    hmac-sha2-256-etm@openssh.com \
    umac-128-etm@openssh.com \
    || echo 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com')"

  crypto=$(cat << EOF
# Post-quantum hybrid key exchange (ML-KEM-768 / sntrup761 + X25519)
# Classical-only KEX disabled unless ALLOW_CLASSICAL_KEX=1
KexAlgorithms ${kex}
HostKeyAlgorithms ${hostkeys}
PubkeyAcceptedAlgorithms ${pubkeys}
Ciphers ${ciphers}
MACs ${macs}
EOF
)

  tmp="$(mktemp)"
  if grep -q 'PLACEHOLDER_SSH_PQ_CRYPTO' "$dropin" 2>/dev/null; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" == *PLACEHOLDER_SSH_PQ_CRYPTO* ]]; then
        printf '%s\n' "$crypto"
      else
        printf '%s\n' "$line"
      fi
    done < "$dropin" > "$tmp"
  else
    # Refresh existing PQ / crypto lines then append
    grep -vE '^(# Post-quantum hybrid key exchange|# Classical-only KEX|KexAlgorithms |HostKeyAlgorithms |PubkeyAcceptedAlgorithms |Ciphers |MACs )' "$dropin" > "$tmp" || true
    printf '\n%s\n' "$crypto" >> "$tmp"
  fi
  mv "$tmp" "$dropin"

  mkdir -p "$(dirname "$client")"
  cat > "$client" << EOF
# Managed by SecurityHardening suite — post-quantum client defaults
Host *
    KexAlgorithms ${kex}
    HostKeyAlgorithms ${hostkeys}
    PubkeyAcceptedAlgorithms ${pubkeys}
    Ciphers ${ciphers}
    MACs ${macs}
EOF

  info "Post-quantum KEX: ${kex}"
  success "SSH post-quantum crypto applied (server + client defaults)"
}

# --- SSH hardening via drop-in (safe; does not wipe vendor config) ---
configure_ssh_hardening() {
  local dropin="/etc/ssh/sshd_config.d/99-security-hardening.conf"

  if ! dpkg -s openssh-server >/dev/null 2>&1; then
    warn "openssh-server not installed; installing..."
    install_packages openssh-server
  fi
  # Re-detect after install (Ubuntu 26 ships ssh.socket with the package)
  detect_ssh_socket_activation

  log "Hardening SSH (drop-in config + post-quantum KEX)..."
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
HostKey /etc/ssh/ssh_host_ed25519_key
# PLACEHOLDER_SSH_PQ_CRYPTO
EOF
  fi

  # Ensure Include is present (Debian/Ubuntu default; OpenSSH 9+/10 on Ubuntu 26)
  if [[ -f /etc/ssh/sshd_config ]] \
    && ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
    backup_file /etc/ssh/sshd_config
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  fi

  apply_ssh_post_quantum "$dropin" || return 1

  # Only keep HostKey lines for keys that exist
  if [[ ! -f /etc/ssh/ssh_host_ecdsa_key ]]; then
    sed -i '\|/etc/ssh/ssh_host_ecdsa_key|d' "$dropin"
  fi
  if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
    sed -i '\|/etc/ssh/ssh_host_rsa_key|d' "$dropin"
  fi

  # If a directive is rejected by this OpenSSH build, strip and re-validate
  if ! sshd -t 2>/dev/null; then
    warn "sshd rejected drop-in; removing unknown keys and retrying"
    local bad
    bad="$(sshd -t 2>&1 || true)"
    info "$bad"
    while IFS= read -r key; do
      [[ -n "$key" ]] || continue
      sed -i -E "s/^[[:space:]]*${key}[[:space:]].*/# & (disabled: unsupported on this OpenSSH)/I" "$dropin"
    done < <(printf '%s\n' "$bad" | sed -nE 's/.*[Uu]nsupported option[= ]+([A-Za-z0-9]+).*/\1/p; s/.*Bad configuration option[=: ]+([A-Za-z0-9]+).*/\1/p')
    if ! sshd -t 2>/dev/null; then
      error "SSH hardening drop-in still invalid; leaving previous SSH config active"
      rm -f "$dropin"
      return 1
    fi
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
for s in ufw fail2ban apparmor auditd clamav-daemon ssh.socket ssh sshd; do
  printf "%-16s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null || echo n/a)"
done
echo ""
echo "=== SSH KEX (post-quantum) ==="
sshd -T 2>/dev/null | grep -i kexalgorithms || echo "sshd not available"
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
systemctl is-active ufw fail2ban clamav-daemon auditd apparmor ssh.socket ssh sshd 2>/dev/null || true
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
