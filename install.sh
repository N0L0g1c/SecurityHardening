#!/bin/bash
# SecurityHardening installer — Debian / Ubuntu
# One entry point: choose a level or pass flags for full automation.
#
# Usage:
#   sudo ./install.sh                  # interactive menu
#   sudo ./install.sh --level quick -y
#   sudo ./install.sh --dry-run --level standard
#   sudo ./install.sh --restore
#   sudo ./restore.sh [snapshot.tar.gz]

set -euo pipefail

SUITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SUITE_ROOT}/lib/common.sh"

LEVEL=""
ASSUME_YES=0
DO_RESTORE=0
RESTORE_ARCHIVE=""

usage() {
  cat << EOF
Usage: sudo $0 [options]

Options:
  -l, --level LEVEL   quick | standard | advanced
  -k, --kex MODE      compatibility | pq-preferred | pq-only
  -y, --yes           non-interactive (no confirmation prompt)
  -n, --dry-run       print planned actions; make no changes
  -r, --restore [FILE] restore latest (or given) pre-hardening snapshot
  -h, --help          show this help

Environment:
  SKIP_APT_UPGRADE=1              skip apt upgrade
  SKIP_SNAPSHOT=1                 skip pre-run snapshot
  SSH_KEX_MODE=pq-preferred       compatibility | pq-preferred | pq-only
  ALLOW_CLASSICAL_KEX=1           alias for --kex compatibility
  SSH_KEX_FORCE=1                 apply pq-only over SSH without a second-session probe
  SSH_DISABLE_PASSWORD_AUTH=auto  auto|1|0 — disable passwords when keys exist
  SSH_FORCE_DISABLE_PASSWORD=1    allow disabling passwords with no keys (dangerous)
  SSH_PORT=2222                   set SSH listen port (updates ssh.socket on Ubuntu 24+/26+)

Examples:
  sudo $0 --level quick -y
  sudo $0 --kex pq-only --level quick
  sudo $0 --dry-run --level advanced
  sudo SSH_PORT=2222 SSH_DISABLE_PASSWORD_AUTH=1 $0 --level standard -y
  sudo $0 --restore
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--level)
      LEVEL="${2:-}"
      shift 2
      ;;
    -k|--kex)
      SSH_KEX_MODE="${2:-}"
      if ! ssh_kex_mode_valid "$SSH_KEX_MODE"; then
        error "Invalid --kex: ${SSH_KEX_MODE} (use compatibility|pq-preferred|pq-only)"
        exit 1
      fi
      shift 2
      ;;
    -y|--yes)
      ASSUME_YES=1
      shift
      ;;
    -n|--dry-run)
      DRY_RUN=1
      export DRY_RUN
      shift
      ;;
    -r|--restore)
      DO_RESTORE=1
      if [[ -n "${2:-}" && "${2}" != -* ]]; then
        RESTORE_ARCHIVE="$2"
        shift 2
      else
        shift
      fi
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -n "$LEVEL" && ! "$LEVEL" =~ ^(quick|standard|advanced)$ ]]; then
  error "Invalid level: $LEVEL (use quick|standard|advanced)"
  exit 1
fi

require_root
detect_os

if [[ "$DO_RESTORE" -eq 1 ]]; then
  export ASSUME_YES
  exec bash "${SUITE_ROOT}/restore.sh" ${RESTORE_ARCHIVE:+"$RESTORE_ARCHIVE"}
fi

if [[ -z "$LEVEL" ]]; then
  echo ""
  echo "SecurityHardening — ${PRETTY_NAME:-$DISTRO_ID}"
  echo "  1) quick     — firewall, fail2ban, SSH, lockdown, auto-updates"
  echo "  2) standard  — + password policy, sysctl/BPF, AppArmor, AIDE, auditd"
  echo "  3) advanced  — + ClamAV, IDS tools, Lynis monitoring"
  echo ""
  read -r -p "Select level [1-3]: " choice
  case "$choice" in
    1) LEVEL=quick ;;
    2) LEVEL=standard ;;
    3) LEVEL=advanced ;;
    *) error "Invalid selection"; exit 1 ;;
  esac
fi

export ASSUME_YES
export SSH_KEX_MODE="${SSH_KEX_MODE:-}"
export ALLOW_CLASSICAL_KEX="${ALLOW_CLASSICAL_KEX:-0}"
export SSH_KEX_FORCE="${SSH_KEX_FORCE:-0}"
resolve_ssh_kex_mode

if dry_run; then
  warn "DRY-RUN mode: no changes will be made"
else
  warn "This will change firewall, SSH, audit, mounts, and system security settings."
  warn "A snapshot will be saved under ${BACKUP_DIR} (unless SKIP_SNAPSHOT=1)."
  warn "SSH KEX mode: ${SSH_KEX_MODE}. Keep an active session until you verify a second SSH login."
fi

if [[ "$ASSUME_YES" -ne 1 ]] && ! dry_run; then
  read -r -p "Continue with '${LEVEL}' hardening (KEX ${SSH_KEX_MODE})? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
fi

chmod +x \
  "${SUITE_ROOT}/quick_secure.sh" \
  "${SUITE_ROOT}/secure_debian.sh" \
  "${SUITE_ROOT}/advanced_security.sh" \
  "${SUITE_ROOT}/restore.sh" \
  "${SUITE_ROOT}/security_configs/ufw_rules.sh" \
  2>/dev/null || true

export DRY_RUN
export SSH_PORT="${SSH_PORT:-}"
export SSH_DISABLE_PASSWORD_AUTH="${SSH_DISABLE_PASSWORD_AUTH:-auto}"
export SSH_FORCE_DISABLE_PASSWORD="${SSH_FORCE_DISABLE_PASSWORD:-0}"
export SKIP_APT_UPGRADE="${SKIP_APT_UPGRADE:-0}"
export SKIP_SNAPSHOT="${SKIP_SNAPSHOT:-0}"
export SSH_KEX_MODE
export _SSH_KEX_RESOLVED=1

case "$LEVEL" in
  quick)    exec bash "${SUITE_ROOT}/quick_secure.sh" ;;
  standard) exec bash "${SUITE_ROOT}/secure_debian.sh" ;;
  advanced) exec bash "${SUITE_ROOT}/advanced_security.sh" ;;
esac
