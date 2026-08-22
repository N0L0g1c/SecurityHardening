# Security Hardening Suite (Debian & Ubuntu)

Automated security hardening for **Debian** and **Ubuntu**, with first-class support for **Ubuntu 26.04+** (and newer releases such as 26.10 / 28.04).

## Quick start

```bash
cd SecurityHardening
chmod +x install.sh
sudo ./install.sh --dry-run --level standard   # preview
sudo ./install.sh --level quick -y             # pq-preferred KEX unless --kex is set
sudo ./install.sh --kex pq-only --level standard
sudo SSH_PORT=2222 SSH_DISABLE_PASSWORD_AUTH=1 ./install.sh --level standard -y
sudo ./install.sh --restore                    # rollback latest snapshot
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
| Post-quantum SSH | First run chooses KEX mode; default is **pq-preferred** (not silent pq-only) |
| APT sources | Ensures `universe`/`multiverse` in deb822 `ubuntu.sources` when present |
| Upgrades | Uses `apt-get full-upgrade` on Ubuntu 24.04+ |
| Unattended upgrades | Codename-based origins (security, updates, ESM) — future-proof for new releases |
| Fail2ban | Prefers `backend = systemd` (journal) on Ubuntu 24.04+ |

## High-value hardening (included)

| Feature | Behavior |
|---------|----------|
| SSH password policy | `auto`: disable passwords when `authorized_keys` exist; never lock out without keys unless forced |
| SSH KEX policy | First-run choice: compatibility / pq-preferred / pq-only; second-session probe before pq-only |
| SSH port | `SSH_PORT=N` updates drop-in + `ssh.socket` override on Ubuntu 24+/26+ |
| Auditd rules | CIS-style rules in `security_configs/audit-hardening.rules` → `/etc/audit/rules.d/` |
| Privilege lockdown | Remove telnet/rsh/talk; mask `ctrl-alt-del`; harden `/tmp` & `/dev/shm`; sudo `use_pty` + logfile |
| Sysctl extras | `fs.suid_dumpable=0`, BPF harden, `vm.mmap_min_addr`, protected fifos/regular |
| Snapshot / restore | Pre-run tarball under `/etc/security/backups/`; `sudo ./restore.sh` or `./install.sh --restore` |
| Dry-run | `sudo ./install.sh --dry-run --level standard` |

## SSH key exchange (availability-aware)

PQ-only KEX is still available, but it is **not** applied silently. A first run that does not set `--kex` / `SSH_KEX_MODE` chooses a policy, and `pq-only` is refused until a second SSH login proves the client you depend on can still connect.

| Mode | Server `KexAlgorithms` | When to use |
|------|------------------------|-------------|
| `compatibility` | Unchanged (vendor OpenSSH default; 9+ already prefers PQ) | Mixed/unknown clients, appliances, CI |
| `pq-preferred` | PQ hybrids first, then modern classical (`curve25519` / NIST ECDH) | Default: PQ when the client can, no lockout if it cannot |
| `pq-only` | PQ hybrids only (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`) | After you have verified every remaining client speaks PQ |

Before applying a policy the installer:

1. Detects whether it is running over SSH, current `sshd` KEX, this host’s `ssh -Q kex`, recent client versions in logs, and local `KexAlgorithms` overrides.
2. Warns if logs show OpenSSH < 9.0 (no hybrid PQ).
3. Prompts interactively: compatibility / pq-preferred / pq-only (default 2).
4. For unattended `-y` with no saved/explicit mode: uses **pq-preferred** (not pq-only).
5. For interactive `pq-only` over SSH: starts a short-lived probe `sshd` on a high port and waits for a **second** login from your real client. Failure falls back to `pq-preferred`.
6. After restart, probes a new connection to the real listener; KEX failure rolls the drop-in back.

`ALLOW_CLASSICAL_KEX=1` is kept as an alias for `compatibility`. The system SSH **client** drop-in is never PQ-only, so outbound `git`/`scp` to hosts without PQ (some GitHub/enterprise endpoints) keeps working.

```bash
# Interactive first run: detect clients, then choose a KEX mode
sudo ./install.sh --level quick

# Unattended: pq-preferred (classical fallback remains)
sudo ./install.sh --level quick -y

# PQ-only after you can complete the second-session probe (keep this SSH session open)
sudo ./install.sh --kex pq-only --level quick

# Unattended pq-only over SSH (can lock you out — requires explicit acknowledgement)
sudo SSH_KEX_FORCE=1 ./install.sh --kex pq-only --level quick -y
```

Saved under `/etc/security/hardening-ssh-kex-mode` and reused on later runs unless you pass `--kex` / `SSH_KEX_MODE`.

Verify:

```bash
cat /etc/security/hardening-ssh-kex-mode
sshd -T | grep -i kexalgorithms
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
| SSH + KEX policy + auth policy | yes | yes | yes |
| Privilege lockdown | yes | yes | yes |
| Snapshot / restore | yes | yes | yes |
| Auto security updates | yes | yes | yes |
| Password policy | — | yes | yes (stricter) |
| Kernel sysctl + BPF/coredump | — | yes | yes |
| AppArmor + auditd rules | — | yes | yes |
| AIDE integrity DB | — | yes | yes |
| ClamAV | — | — | yes |
| Optional IDS (psad/portsentry) | — | — | if packaged |
| Lynis / extended monitor | — | — | yes |

## Layout

```
install.sh                 # --level, --yes, --dry-run, --restore
restore.sh                 # restore latest (or given) snapshot
quick_secure.sh
secure_debian.sh           # standard level
advanced_security.sh
lib/common.sh
security_configs/
  ssh_hardening.conf
  fail2ban_jail.local
  ufw_rules.sh
  audit-hardening.rules
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
- `pq-only` is never the silent default; unattended installs use `pq-preferred` unless you pass `--kex` / `SSH_KEX_MODE`.
- Scripts never set empty `AllowUsers` (that would lock everyone out).
- Obsolete OpenSSH keys (`UsePrivilegeSeparation`, `RSAAuthentication`, etc.) are not used.
- Always test on a non-production host first.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Permission denied | `sudo ./install.sh ...` |
| UFW blocks you | From console: `ufw allow <ssh-port>/tcp` or `ufw disable` |
| SSH won't start | `sshd -t`; check `/etc/ssh/sshd_config.d/99-security-hardening.conf` |
| Locked out after pq-only | Console: `sudo ./restore.sh`, or set `SSH_KEX_MODE=pq-preferred` and re-run |
| KEX probe timed out | Expected if the second client never connected; installer falls back to pq-preferred |
| git/GitHub SSH fails | Client drop-in is not PQ-only; check `~/.ssh/config` Host overrides |
| SSH port unchanged (Ubuntu 26) | `systemctl daemon-reload && systemctl restart ssh.socket` |
| Package skipped | Normal if not in your release repos; check the log warning |
| fail2ban / auth.log | Suite defaults to `backend = systemd` on Ubuntu 24.04+ |

## License

[MIT](LICENSE). Copyright © 2026 [Vassbrekke AS](https://www.vassbrekke.no).

Source: https://github.com/Vassbrekke/SecurityHardening

Provided as-is for educational and operational security use. Use at your own risk.
