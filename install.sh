#!/bin/bash
# SecurityHardening installer — Debian / Ubuntu
# One entry point: choose a level or pass flags for full automation.
#
# Usage:
#   sudo ./install.sh                  # interactive menu
#   sudo ./install.sh --level quick
#   sudo ./install.sh --level standard --yes
#   sudo ./install.sh --level advanced -y

set -euo pipefail

SUITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SUITE_ROOT}/lib/common.sh"

LEVEL=""
ASSUME_YES=0

usage() {
  cat << EOF
Usage: sudo $0 [options]

Options:
  -l, --level LEVEL   quick | standard | advanced
  -y, --yes           non-interactive (no confirmation prompt)
  -h, --help          show this help

Environment:
  SKIP_APT_UPGRADE=1     skip apt upgrade (faster re-runs; still updates indexes)
  ALLOW_CLASSICAL_KEX=1  allow non-PQ SSH key exchange for legacy clients

Examples:
  sudo $0 --level quick -y
  sudo SKIP_APT_UPGRADE=1 $0 --level standard -y
  sudo ALLOW_CLASSICAL_KEX=1 $0 --level quick -y
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--level)
      LEVEL="${2:-}"
      shift 2
      ;;
    -y|--yes)
      ASSUME_YES=1
      shift
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

if [[ -z "$LEVEL" ]]; then
  echo ""
  echo "SecurityHardening — ${PRETTY_NAME:-$DISTRO_ID}"
  echo "  1) quick     — firewall, fail2ban, SSH, auto-updates (~5-10 min)"
  echo "  2) standard  — + password policy, sysctl, AppArmor, AIDE, auditd"
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

warn "This will change firewall, SSH, and system security settings."
warn "Keep an active console session until you verify remote SSH still works."

if [[ "$ASSUME_YES" -ne 1 ]]; then
  read -r -p "Continue with '${LEVEL}' hardening? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
fi

chmod +x \
  "${SUITE_ROOT}/quick_secure.sh" \
  "${SUITE_ROOT}/secure_debian.sh" \
  "${SUITE_ROOT}/advanced_security.sh" \
  "${SUITE_ROOT}/security_configs/ufw_rules.sh" \
  2>/dev/null || true

case "$LEVEL" in
  quick)    exec bash "${SUITE_ROOT}/quick_secure.sh" ;;
  standard) exec bash "${SUITE_ROOT}/secure_debian.sh" ;;
  advanced) exec bash "${SUITE_ROOT}/advanced_security.sh" ;;
esac
