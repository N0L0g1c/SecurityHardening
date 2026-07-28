#!/bin/bash
# Restore pre-hardening snapshot created by the SecurityHardening suite.
#
# Usage:
#   sudo ./restore.sh
#   sudo ./restore.sh /etc/security/backups/snapshot-YYYYMMDDHHMMSS.tar.gz
#   sudo DRY_RUN=1 ./restore.sh

set -euo pipefail

SUITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SUITE_ROOT}/lib/common.sh"

require_root
detect_os

ARCHIVE="${1:-}"

warn "This restores SSH, fail2ban, sysctl, audit, sudoers, and related configs from a snapshot."
warn "Keep a console session open."

if [[ "${ASSUME_YES:-0}" != "1" ]] && ! dry_run; then
  read -r -p "Continue restore? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
fi

restore_hardening_snapshot "${ARCHIVE}"
