#!/bin/bash
# Standard Security Hardening — Debian / Ubuntu
# Firewall, fail2ban, SSH, password policy, sysctl, AppArmor, AIDE, auditd, lockdown

set -euo pipefail

SUITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SUITE_ROOT}/lib/common.sh"

require_root
detect_os
create_hardening_snapshot

log "Starting Standard Security Hardening..."

apt_update
apt_upgrade

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
  rsyslog \
  logrotate \
  iptables-persistent \
  htop

configure_ufw
configure_fail2ban
configure_unattended_upgrades
configure_ssh_hardening
configure_password_policy 12
configure_sysctl
configure_apparmor
configure_auditd
configure_privilege_lockdown
configure_aide
install_security_check

# Soft limits (append once)
if ! dry_run && ! grep -q 'SecurityHardening suite' /etc/security/limits.conf 2>/dev/null; then
  backup_file /etc/security/limits.conf
  cat >> /etc/security/limits.conf << 'EOF'

# SecurityHardening suite
* soft nproc 65536
* hard nproc 65536
* soft nofile 65536
* hard nofile 65536
EOF
fi

success "Standard security hardening completed"
print_next_steps standard
