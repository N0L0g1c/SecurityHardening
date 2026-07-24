#!/bin/bash
# UFW Firewall Rules — Debian/Ubuntu
# Respects SSH_PORT env (set by suite) so custom SSH ports stay reachable.

set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]] || ((SSH_PORT < 1 || SSH_PORT > 65535)); then
  echo "Invalid SSH_PORT='$SSH_PORT'; defaulting to 22" >&2
  SSH_PORT=22
fi

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Rate-limit SSH on the active port
ufw limit "${SSH_PORT}/tcp" comment 'SSH'

ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Optional services (uncomment as needed)
# ufw allow 25/tcp comment 'SMTP'
# ufw allow 587/tcp comment 'SMTP submission'
# ufw allow from 192.168.0.0/16

ufw logging on
ufw --force enable

echo "UFW configured (SSH ${SSH_PORT}/tcp rate-limited)."
ufw status verbose
