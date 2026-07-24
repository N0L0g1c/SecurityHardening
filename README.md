# Security Hardening Suite (Debian & Ubuntu)

Automated security hardening for **Debian** and **Ubuntu**. One installer, three levels, shared helpers that skip missing packages and avoid SSH lockouts.

## Quick start

```bash
cd SecurityHardening
chmod +x install.sh
sudo ./install.sh                  # interactive menu
sudo ./install.sh --level quick -y # fully automated
sudo ./install.sh --level standard -y
sudo ./install.sh --level advanced -y
sudo SKIP_APT_UPGRADE=1 ./install.sh --level standard -y  # re-run without full upgrade
```

Or run a level script directly:

```bash
sudo ./quick_secure.sh
sudo ./secure_debian.sh
sudo ./advanced_security.sh
```

## What works on Debian vs Ubuntu

| Concern | Behavior |
|---------|----------|
| Distro check | Refuses non-Debian-family systems |
| Packages | Installs only packages available in your repos (e.g. skips `libpam-cracklib` on modern Ubuntu) |
| Unattended upgrades | Ubuntu security/ESM origins vs Debian-Security origins |
| SSH service | Restarts `ssh` or `sshd` after `sshd -t` validation |
| SSH config | Drop-in under `/etc/ssh/sshd_config.d/` (does not wipe vendor config) |
| Firewall | Detects current SSH port before enabling UFW rate-limit |
| Sysctl | Writes `/etc/sysctl.d/99-security-hardening.conf`; skips unknown keys |
| Non-interactive | `DEBIAN_FRONTEND=noninteractive` + safe `apt-get` options |

## Feature levels

| Feature | Quick | Standard | Advanced |
|---------|-------|----------|----------|
| System updates | yes | yes | yes |
| UFW + Fail2ban | yes | yes | yes |
| SSH hardening | yes | yes | yes |
| Auto security updates | yes | yes | yes |
| Password policy | — | yes | yes (stricter) |
| Kernel sysctl | — | yes | yes |
| AppArmor + auditd | — | yes | yes |
| AIDE integrity DB | — | yes | yes |
| ClamAV | — | — | yes |
| Optional IDS (psad/portsentry) | — | — | if packaged |
| Lynis / extended monitor | — | — | yes |

## Layout

```
install.sh                 # orchestrator (--level, --yes)
quick_secure.sh
secure_debian.sh           # standard level
advanced_security.sh
lib/common.sh              # shared detection & hardening helpers
security_configs/
  ssh_hardening.conf
  fail2ban_jail.local
  ufw_rules.sh
```

## Prerequisites

- Debian or Ubuntu (or close derivative with `ID_LIKE=debian`)
- Root via `sudo`
- Network for `apt`
- Console access recommended the first time you harden SSH

## After install

```bash
/usr/local/bin/security-check.sh      # quick/standard
/usr/local/bin/security-monitor.sh    # advanced
ufw status verbose
fail2ban-client status
tail -f /var/log/security-hardening.log
ls /var/log/security-report-*.log
```

Config backups land in `/etc/security/backups/`.

## Safety notes

- Keep an open session until you confirm SSH still works from another client.
- Scripts never set empty `AllowUsers` (that would lock everyone out).
- Obsolete OpenSSH keys (`UsePrivilegeSeparation`, `RSAAuthentication`, etc.) are not used.
- Always test on a non-production host first.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Permission denied | `sudo ./install.sh ...` |
| UFW blocks you | From console: `ufw allow <ssh-port>/tcp` or `ufw disable` |
| SSH won't start | `sshd -t` and check `/etc/ssh/sshd_config.d/99-security-hardening.conf` |
| Package skipped | Normal if not in your release repos; check the log warning |
| fail2ban / auth.log | Suite defaults to `backend = systemd` |

## License

Provided as-is for educational and operational security use. Use at your own risk.
