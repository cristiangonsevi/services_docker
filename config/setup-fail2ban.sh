#!/bin/bash
set -euo pipefail

# Instalar fail2ban
apt-get update
apt-get install -y fail2ban

# Copiar configuración base
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Configuración óptima para producción
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 1h
findtime  = 10m
maxretry = 5
backend = auto
destemail = tu-correo@dominio.com
sender = fail2ban@$(hostname -f)
mta = sendmail
action = %(action_mwl)s

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 4
bantime = 2h

[nginx-http-auth]
enabled = true
port    = http,https
filter  = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled = true
port    = http,https
filter  = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
bantime  = 1d
findtime = 1d
maxretry = 3
EOF

# Reiniciar fail2ban
systemctl restart fail2ban
systemctl enable fail2ban

echo "Fail2ban instalado y configurado para producción."
