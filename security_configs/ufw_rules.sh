#!/bin/bash
# UFW Firewall Rules Configuration
# This script sets up comprehensive firewall rules for a Debian server

# Reset UFW to default state
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow essential services
ufw allow ssh
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS

# Allow specific ports for common services (uncomment as needed)
# ufw allow 21/tcp    # FTP
# ufw allow 22/tcp    # SSH (already allowed above)
# ufw allow 25/tcp    # SMTP
# ufw allow 53/tcp    # DNS
# ufw allow 53/udp    # DNS
# ufw allow 110/tcp   # POP3
# ufw allow 143/tcp   # IMAP
# ufw allow 993/tcp   # IMAPS
# ufw allow 995/tcp   # POP3S
# ufw allow 587/tcp   # SMTP submission
# ufw allow 993/tcp   # IMAPS
# ufw allow 995/tcp   # POP3S

# Allow specific IP ranges (customize as needed)
# ufw allow from 192.168.1.0/24
# ufw allow from 10.0.0.0/8

# Rate limiting for SSH (optional)
# ufw limit ssh

# Enable logging
ufw logging on

# Enable UFW
ufw --force enable

echo "UFW firewall rules configured successfully!"
echo "Current status:"
ufw status verbose
