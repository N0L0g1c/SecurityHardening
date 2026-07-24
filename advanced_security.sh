#!/bin/bash
# Advanced Security Hardening — Debian / Ubuntu
# Standard stack plus ClamAV, optional IDS tools, Lynis, extended monitoring

set -euo pipefail

SUITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SUITE_ROOT}/lib/common.sh"

require_root
detect_os

log "Starting Advanced Security Hardening..."

apt_update
apt_upgrade

# Core + advanced; unavailable packages are skipped automatically
install_packages \
  ufw \
  fail2ban \
  unattended-upgrades \
  apt-listchanges \
  openssh-server \
  rkhunter \
  chkrootkit \
  lynis \
  aide \
  aide-common \
  auditd \
  audispd-plugins \
  apparmor \
  apparmor-utils \
  libpam-pwquality \
  clamav \
  clamav-daemon \
  clamav-freshclam \
  psad \
  portsentry \
  tiger \
  logwatch \
  nmap \
  iptables-persistent \
  rsyslog \
  logrotate \
  htop

configure_ufw
configure_fail2ban
configure_unattended_upgrades
configure_ssh_hardening
configure_password_policy 14
configure_sysctl
configure_apparmor
configure_auditd
configure_aide

# ClamAV
if pkg_available clamav-daemon || dpkg -s clamav-daemon >/dev/null 2>&1; then
  log "Configuring ClamAV..."
  systemctl enable clamav-freshclam >/dev/null 2>&1 || true
  systemctl start clamav-freshclam >/dev/null 2>&1 || true
  # freshclam can fail if another instance holds the lock — non-fatal
  freshclam || warn "freshclam failed (signatures may update later via clamav-freshclam)"
  systemctl enable clamav-daemon >/dev/null 2>&1 || true
  systemctl start clamav-daemon >/dev/null 2>&1 || warn "clamav-daemon did not start yet"
  success "ClamAV configured"
fi

# Optional host IDS — enable only if installed; leave default configs
for svc in psad portsentry; do
  if systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "${svc}.service"; then
    systemctl enable "$svc" >/dev/null 2>&1 || true
    systemctl start "$svc" >/dev/null 2>&1 || warn "${svc} installed but not started (review its config)"
  fi
done

install_security_monitor

success "Advanced security hardening completed"
print_next_steps advanced
