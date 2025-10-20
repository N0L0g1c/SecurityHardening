# Debian Security Hardening Suite

A collection of security hardening scripts and configurations for Debian-based Linux distributions.

## 🛡️ Overview

This suite provides multiple levels of security hardening for Debian systems, from quick basic setup to comprehensive enterprise-grade security configurations.

## 📁 Contents

### Scripts

- **`advanced_security.sh`** - Comprehensive security hardening with advanced features
- **`secure_debian.sh`** - Standard security hardening script
- **`quick_secure.sh`** - Quick basic security setup

### Configuration Files

- **`security_configs/ssh_hardening.conf`** - SSH security configuration
- **`security_configs/fail2ban_jail.local`** - Fail2ban intrusion prevention rules
- **`security_configs/ufw_rules.sh`** - UFW firewall configuration

## 🚀 Quick Start

### 1. Basic Security (Recommended for beginners)
```bash
cd security_hardening
chmod +x quick_secure.sh
sudo ./quick_secure.sh
```

### 2. Standard Security (Recommended for most users)
```bash
cd security_hardening
chmod +x secure_debian.sh
sudo ./secure_debian.sh
```

### 3. Advanced Security (Enterprise/Production)
```bash
cd security_hardening
chmod +x advanced_security.sh
sudo ./advanced_security.sh
```

## 🔧 Features Comparison

| Feature | Quick | Standard | Advanced |
|---------|-------|----------|----------|
| System Updates | ✅ | ✅ | ✅ |
| UFW Firewall | ✅ | ✅ | ✅ |
| Fail2ban | ✅ | ✅ | ✅ |
| SSH Hardening | ✅ | ✅ | ✅ |
| Password Policy | ❌ | ✅ | ✅ |
| Kernel Hardening | ❌ | ✅ | ✅ |
| AppArmor | ❌ | ✅ | ✅ |
| File Integrity (AIDE) | ❌ | ✅ | ✅ |
| Antivirus (ClamAV) | ❌ | ❌ | ✅ |
| Advanced Monitoring | ❌ | ❌ | ✅ |
| Vulnerability Scanning | ❌ | ❌ | ✅ |
| Log Analysis | ❌ | ❌ | ✅ |

## 📋 Prerequisites

- Debian-based Linux distribution (Ubuntu, Debian, etc.)
- Root/sudo access
- Internet connection
- At least 2GB RAM (for advanced features)

## 🔍 What Each Script Does

### Quick Security (`quick_secure.sh`)
- Updates system packages
- Installs essential security packages (UFW, Fail2ban)
- Configures basic firewall rules
- Hardens SSH configuration
- Sets up automatic security updates

**Time to complete:** ~5-10 minutes

### Standard Security (`secure_debian.sh`)
- All quick security features
- Advanced password policy enforcement
- Kernel security parameter hardening
- AppArmor configuration
- File integrity monitoring with AIDE
- Comprehensive logging and monitoring
- Security status reporting

**Time to complete:** ~15-20 minutes

### Advanced Security (`advanced_security.sh`)
- All standard security features
- ClamAV antivirus installation and configuration
- Advanced intrusion detection (PSAD, PortSentry)
- Vulnerability scanning with Lynis
- Malware scanning capabilities
- Advanced system monitoring
- Comprehensive security reporting
- Network security hardening

**Time to complete:** ~30-45 minutes

## 🛠️ Configuration Files

### SSH Hardening (`security_configs/ssh_hardening.conf`)
- Disables root login
- Enforces key-based authentication
- Limits authentication attempts
- Configures secure protocols
- Sets connection timeouts

### Fail2ban Configuration (`security_configs/fail2ban_jail.local`)
- SSH brute force protection
- Web server protection (Apache/Nginx)
- Customizable ban times and retry limits
- Email notifications (configurable)
- IP whitelist support

### UFW Rules (`security_configs/ufw_rules.sh`)
- Deny-by-default policy
- Essential service ports only
- Rate limiting for SSH
- Logging configuration
- Custom IP range support

## 📊 Monitoring and Maintenance

### Security Monitoring
After running any script, you can monitor security status:

```bash
# Run security monitor (if using advanced script)
/usr/local/bin/security-monitor.sh

# Check security logs
tail -f /var/log/security-hardening.log

# View daily security reports
ls /var/log/security-report-*.log
```

### Regular Maintenance
- **Daily**: Check security reports
- **Weekly**: Run malware scans
- **Monthly**: Review failed login attempts
- **Quarterly**: Update security policies

## 🔒 Security Features Explained

### Firewall (UFW)
- Blocks all incoming connections by default
- Allows only essential services (SSH, HTTP, HTTPS)
- Configurable port rules
- Rate limiting for SSH connections

### Intrusion Prevention (Fail2ban)
- Monitors log files for suspicious activity
- Automatically bans IPs with multiple failed attempts
- Configurable ban times and retry limits
- Supports multiple services (SSH, Apache, Nginx)

### SSH Hardening
- Disables root login
- Enforces strong authentication
- Limits connection attempts
- Configures secure protocols only
- Sets appropriate timeouts

### Password Policy
- Minimum 12-14 character passwords
- Requires multiple character types
- Prevents dictionary words
- Enforces password history

### Kernel Hardening
- Disables dangerous network features
- Enables memory protection
- Restricts kernel information access
- Configures secure networking parameters

### File Integrity Monitoring (AIDE)
- Creates database of file checksums
- Detects unauthorized file changes
- Monitors critical system files
- Generates integrity reports

### Antivirus (ClamAV)
- Real-time malware scanning
- Regular signature updates
- Scheduled system scans
- Quarantine capabilities

## 🚨 Troubleshooting

### Common Issues

1. **Script fails with permission errors**
   - Ensure you're running as root: `sudo ./script_name.sh`

2. **UFW blocks your connection**
   - Check UFW status: `ufw status`
   - Temporarily disable: `ufw disable`
   - Reconfigure and re-enable

3. **SSH connection refused after hardening**
   - Check SSH config: `sshd -T`
   - Restart SSH: `systemctl restart sshd`
   - Check logs: `journalctl -u ssh`

4. **Fail2ban bans legitimate IPs**
   - Check fail2ban status: `fail2ban-client status`
   - Unban IP: `fail2ban-client set sshd unbanip IP_ADDRESS`
   - Adjust jail configuration

### Log Locations
- Security hardening: `/var/log/security-hardening.log`
- Daily reports: `/var/log/security-report-*.log`
- System logs: `/var/log/syslog`
- Auth logs: `/var/log/auth.log`
- Fail2ban: `/var/log/fail2ban.log`

## 📚 Additional Resources

- [Debian Security Documentation](https://www.debian.org/security/)
- [UFW Documentation](https://help.ubuntu.com/community/UFW)
- [Fail2ban Documentation](https://www.fail2ban.org/wiki/)
- [SSH Hardening Guide](https://infosec.mozilla.org/guidelines/openssh)

## ⚠️ Important Notes

- **Always test in a non-production environment first**
- **Backup your system before running security scripts**
- **Ensure you have console access in case of SSH issues**
- **Review and customize configurations for your specific needs**
- **Regular updates are essential for maintaining security**

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve these security scripts.

## 📄 License

This project is provided as-is for educational and security purposes. Use at your own risk.
