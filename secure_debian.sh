#!/bin/bash
# Advanced Debian Security Hardening Script
# Comprehensive security setup for fresh Debian installations
# Version: 2.0 - Enhanced with advanced security features

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/security-hardening.log"
SECURITY_DIR="/etc/security"
BACKUP_DIR="/etc/security/backups"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

# Create necessary directories
mkdir -p "$SECURITY_DIR" "$BACKUP_DIR"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (use sudo)"
    exit 1
fi

log "Starting Debian Security Hardening Process..."

# Update system packages
log "Updating system packages..."
apt update && apt upgrade -y

# Install essential security packages
log "Installing security packages..."
apt install -y \
    ufw \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    rkhunter \
    chkrootkit \
    lynis \
    aide \
    auditd \
    apparmor-utils \
    libpam-pwquality \
    libpam-cracklib \
    rsyslog \
    logrotate \
    htop \
    netstat-nat \
    iptables-persistent

# Configure UFW firewall
log "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Configure fail2ban
log "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Configure automatic updates
log "Configuring automatic security updates..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Configure password policy
log "Configuring password policy..."
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
minclass = 3
maxrepeat = 2
maxclassrepeat = 2
EOF

# Configure PAM for password complexity
cat > /etc/pam.d/common-password << 'EOF'
password        requisite                       pam_pwquality.so retry=3
password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass yescrypt
password        requisite                       pam_deny.so
password        required                        pam_permit.so
password        optional        pam_gnome_keyring.so
EOF

# Configure SSH security
log "Configuring SSH security..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config << 'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 2048
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 60
PermitRootLogin no
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
EOF

systemctl restart sshd

# Configure system limits
log "Configuring system limits..."
cat >> /etc/security/limits.conf << 'EOF'
* soft nproc 65536
* hard nproc 65536
* soft nofile 65536
* hard nofile 65536
EOF

# Configure kernel parameters
log "Configuring kernel security parameters..."
cat >> /etc/sysctl.conf << 'EOF'
# Network security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Memory protection
kernel.exec-shield = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
EOF

sysctl -p

# Configure AppArmor
log "Configuring AppArmor..."
systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/*

# Configure auditd
log "Configuring audit daemon..."
systemctl enable auditd
systemctl start auditd

# Set up log monitoring
log "Configuring log monitoring..."
cat > /etc/logrotate.d/security << 'EOF'
/var/log/auth.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
}
EOF

# Configure AIDE for file integrity monitoring
log "Configuring AIDE..."
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Create security monitoring script
log "Creating security monitoring script..."
cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash
echo "=== Security Status Check ==="
echo "Date: $(date)"
echo ""

echo "=== Firewall Status ==="
ufw status verbose
echo ""

echo "=== Failed Login Attempts ==="
grep "Failed password" /var/log/auth.log | tail -10
echo ""

echo "=== Recent SSH Connections ==="
grep "Accepted" /var/log/auth.log | tail -5
echo ""

echo "=== System Updates Available ==="
apt list --upgradable 2>/dev/null | grep -v "Listing..."
echo ""

echo "=== Running Services ==="
systemctl list-units --type=service --state=running | grep -E "(ssh|fail2ban|ufw|apparmor)"
echo ""

echo "=== Disk Usage ==="
df -h
echo ""

echo "=== Memory Usage ==="
free -h
echo ""

echo "=== Load Average ==="
uptime
EOF

chmod +x /usr/local/bin/security-check.sh

# Create daily security report
log "Setting up daily security reports..."
cat > /etc/cron.daily/security-report << 'EOF'
#!/bin/bash
/usr/local/bin/security-check.sh > /var/log/security-report-$(date +%Y%m%d).log 2>&1
EOF

chmod +x /etc/cron.daily/security-report

log "Security hardening completed successfully!"
log "Run 'security-check.sh' to view security status"
log "Check /var/log/security-report-*.log for daily reports"

echo ""
echo "=== Next Steps ==="
echo "1. Reboot the system to apply all changes"
echo "2. Test SSH connection from another machine"
echo "3. Run: /usr/local/bin/security-check.sh"
echo "4. Review firewall rules: ufw status verbose"
echo "5. Check fail2ban status: fail2ban-client status"
