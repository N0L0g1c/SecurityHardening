#!/bin/bash
# Quick Security Setup — Debian / Ubuntu
# Basic firewall, fail2ban, unattended upgrades, SSH hardening + snapshot

set -euo pipefail

SUITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SUITE_ROOT}/lib/common.sh"

require_root
detect_os
create_hardening_snapshot

log "Starting Quick Security Setup..."

apt_update
apt_upgrade
install_packages ufw fail2ban unattended-upgrades openssh-server

configure_ufw
configure_fail2ban
configure_unattended_upgrades
configure_ssh_hardening
configure_privilege_lockdown
install_security_check

success "Quick security setup completed"
print_next_steps quick
