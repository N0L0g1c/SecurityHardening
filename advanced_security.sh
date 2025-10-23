#!/bin/bash
# Advanced Debian Security Hardening Script v2.0
# Comprehensive security setup with advanced features

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
LOG_FILE="/var/log/security-hardening.log"
SECURITY_DIR="/etc/security"

# Logging
log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    error "Run as root: sudo $0"
    exit 1
fi

log "Starting Advanced Security Hardening..."

# System update
log "Updating system..."
apt update && apt upgrade -y

# Install advanced security packages
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
    aide-common \
    auditd \
    apparmor-utils \
    libpam-pwquality \
    libpam-cracklib \
    clamav \
    clamav-daemon \
    psad \
    portsentry \
    tiger \
    tripwire \
    logwatch \
    nmap \
    iptables-persistent \
    rsyslog \
    logrotate \
    htop

# Advanced UFW configuration
log "Configuring advanced firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 53/tcp
ufw allow 53/udp
ufw --force enable

# Advanced fail2ban configuration
log "Configuring fail2ban with advanced rules..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 7200
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Advanced SSH hardening
log "Hardening SSH..."
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
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding no
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
AllowUsers
DenyUsers
AllowGroups
DenyGroups
EOF

systemctl restart sshd

# Advanced password policy
log "Configuring advanced password policy..."
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -2
ucredit = -2
lcredit = -2
ocredit = -2
difok = 8
minclass = 4
maxrepeat = 2
maxclassrepeat = 2
dictcheck = 1
usercheck = 1
EOF

# Kernel hardening
log "Hardening kernel parameters..."
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
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0

# Memory protection
kernel.exec-shield = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
kernel.sysrq = 0
EOF

sysctl -p

# Configure ClamAV
log "Configuring ClamAV antivirus..."
systemctl enable clamav-daemon
systemctl start clamav-daemon
freshclam

# Configure AIDE
log "Configuring file integrity monitoring..."
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Advanced monitoring script
log "Creating advanced monitoring..."
cat > /usr/local/bin/security-monitor.sh << 'EOF'
#!/bin/bash
echo "=== Advanced Security Monitor ==="
echo "Date: $(date)"
echo ""

echo "=== System Status ==="
echo "Uptime: $(uptime)"
echo "Load: $(cat /proc/loadavg)"
echo "Memory: $(free -h | grep Mem)"
echo "Disk: $(df -h / | tail -1)"
echo ""

echo "=== Security Services ==="
systemctl is-active ufw fail2ban clamav-daemon auditd apparmor
echo ""

echo "=== Firewall Status ==="
ufw status verbose
echo ""

echo "=== Failed Logins (Last 24h) ==="
grep "Failed password" /var/log/auth.log | grep "$(date +%b\ %d)" | wc -l
echo ""

echo "=== Recent SSH Connections ==="
grep "Accepted" /var/log/auth.log | tail -5
echo ""

echo "=== Running Processes ==="
ps aux | grep -E "(ssh|apache|nginx|mysql)" | grep -v grep
echo ""

echo "=== Network Connections ==="
ss -tuln | grep -E ":(22|80|443|3306|5432)"
echo ""

echo "=== File Integrity Check ==="
aide --check 2>/dev/null | tail -5
echo ""

echo "=== Malware Scan Results ==="
clamscan --infected --recursive /home /var/www 2>/dev/null | tail -5
echo ""

echo "=== System Vulnerabilities ==="
lynis audit system --quick 2>/dev/null | grep -E "(WARNING|SUGGESTION)" | head -10
EOF

chmod +x /usr/local/bin/security-monitor.sh

# Create daily security report
cat > /etc/cron.daily/security-report << 'EOF'
#!/bin/bash
/usr/local/bin/security-monitor.sh > /var/log/security-report-$(date +%Y%m%d).log 2>&1
EOF

chmod +x /etc/cron.daily/security-report

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

log "Advanced security hardening completed!"
echo ""
echo "=== Security Status ==="
echo "Firewall: $(ufw status | head -1)"
echo "Fail2ban: $(systemctl is-active fail2ban)"
echo "ClamAV: $(systemctl is-active clamav-daemon)"
echo "AIDE: $(aide --version 2>/dev/null | head -1)"
echo ""
echo "Run 'security-monitor.sh' for detailed status"
echo "Check logs: tail -f $LOG_FILE"
