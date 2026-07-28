# Security Hardening Suite (Debian & Ubuntu)

Automated security hardening for **Debian** and **Ubuntu**, with first-class support for **Ubuntu 26.04+** (and newer releases such as 26.10 / 28.04).

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

## Ubuntu 26.04+ support

| Concern | Behavior |
|---------|----------|
| Version detection | Recognizes 26.04 and any newer `VERSION_ID` via version sort (26.10, 28.04, …) |
| SSH listener | Uses `ssh.socket` + `sshd-socket-generator` (`daemon-reload` + restart socket) |
| SSH config | Drop-in under `/etc/ssh/sshd_config.d/`; strips unknown OpenSSH 10 keys if `sshd -t` fails |
| Post-quantum SSH | Requires hybrid PQ KEX (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`) |
| APT sources | Ensures `universe`/`multiverse` in deb822 `ubuntu.sources` when present |
| Upgrades | Uses `apt-get full-upgrade` on Ubuntu 24.04+ |
| Unattended upgrades | Codename-based origins (security, updates, ESM) — future-proof for new releases |
| Fail2ban | Prefers `backend = systemd` (journal) on Ubuntu 24.04+ |

## Post-quantum OpenSSH

By default the suite **requires** post-quantum hybrid key exchange (no classical-only KEX):

1. `mlkem768x25519-sha256` — ML-KEM-768 + X25519 (OpenSSH 9.9+ / 10, Ubuntu 26)
2. `sntrup761x25519-sha512` — Streamlined NTRU Prime + X25519 (OpenSSH 9.0+)

Also sets AEAD ciphers, EtM MACs, Ed25519-first host keys, and matching **client** defaults in `/etc/ssh/ssh_config.d/`.

```bash
# Default: PQ-only KEX (recommended)
sudo ./install.sh --level quick -y

# Legacy clients that lack PQ KEX (not harvest-now-decrypt-later safe for those sessions)
sudo ALLOW_CLASSICAL_KEX=1 ./install.sh --level quick -y
```

Clients need OpenSSH ≥ 9.0 (sntrup) or ≥ 9.9 (ML-KEM). Verify after install:

```bash
sshd -T | grep -i kexalgorithms
# Expect mlkem768… and/or sntrup761… only (unless ALLOW_CLASSICAL_KEX=1)
```
## What works on Debian vs Ubuntu

| Concern | Behavior |
|---------|----------|
| Distro check | Refuses non-Debian-family systems |
| Packages | Installs only packages available in your repos (e.g. skips `libpam-cracklib` on modern Ubuntu) |
| Unattended upgrades | Ubuntu security/ESM/updates origins vs Debian-Security origins |
| SSH service | Socket activation when present; otherwise `ssh` / `sshd` |
| Firewall | Detects current SSH port (socket or config) before enabling UFW rate-limit |
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

- Debian or Ubuntu (Ubuntu **26.04+** recommended; 22.04/24.04 still work)
- Root via `sudo`
- Network for `apt`
- Console access recommended the first time you harden SSH

## After install

```bash
/usr/local/bin/security-check.sh      # quick/standard
/usr/local/bin/security-monitor.sh    # advanced
ufw status verbose
fail2ban-client status
systemctl status ssh.socket           # Ubuntu 24.04+ / 26.04+
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
| SSH won't start | `sshd -t`; check `/etc/ssh/sshd_config.d/99-security-hardening.conf` |
| SSH port unchanged (Ubuntu 26) | `systemctl daemon-reload && systemctl restart ssh.socket` |
| Package skipped | Normal if not in your release repos; check the log warning |
| fail2ban / auth.log | Suite defaults to `backend = systemd` on Ubuntu 24.04+ |

## License

Provided as-is for educational and operational security use. Use at your own risk.
