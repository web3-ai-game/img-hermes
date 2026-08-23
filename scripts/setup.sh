#!/usr/bin/env bash
set -euo pipefail

echo "========================================================="
echo "   🚀 Hermes Full-Stack Agent & Dashboard One-Click Setup"
echo "========================================================="

# 1. System updates & Dependencies
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y \
    curl git htop ufw nginx sqlite3 libsqlite3-dev build-essential \
    python3 python3-pip python3-venv python3-full \
    ca-certificates gnupg openssl

# 2. Install Node.js 22.x LTS
if ! command -v node &>/dev/null; then
    echo "📦 Installing Node.js 22.x..."
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
fi
echo "✅ Node.js: $(node -v), NPM: $(npm -v)"

# 3. Create Hermes Directories
mkdir -p /opt/hermes-dashboard /root/.hermes/memories /root/.hermes/skills /root/.hermes/cron /root/.hermes/logs /etc/ssl/oece

# 4. Generate SSL Certificates (Self-signed 10-year wildcard for Cloudflare Full SSL)
if [ ! -f /etc/ssl/oece/fullchain.pem ]; then
    echo "🔒 Generating 10-year SSL Certificate for Cloudflare..."
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/oece/privkey.pem \
        -out /etc/ssl/oece/fullchain.pem \
        -subj "/C=SG/ST=Singapore/L=Singapore/O=Hermes/CN=a.oece-x.com"
    chmod 600 /etc/ssl/oece/privkey.pem
fi

# 5. Create Python Virtual Environment
if [ ! -d /opt/hermes-venv ]; then
    echo "🐍 Creating Python Virtual Environment at /opt/hermes-venv..."
    python3 -m venv /opt/hermes-venv
    /opt/hermes-venv/bin/pip install --upgrade pip setuptools wheel
    /opt/hermes-venv/bin/pip install hermes-agent fastapi uvicorn openai pyyaml pydantic httpx rich
fi

# 6. Install Dashboard Dependencies
cd /opt/hermes-dashboard
npm install better-sqlite3 cookie-parser express

# 7. Configure Nginx
cp /opt/hermes-dashboard/nginx/a.oece-x.com.conf /etc/nginx/sites-available/a.oece-x.com.conf
ln -sf /etc/nginx/sites-available/a.oece-x.com.conf /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# 8. Setup Systemd Services
cp /opt/hermes-dashboard/systemd/hermes-dashboard.service /etc/systemd/system/
cp /opt/hermes-dashboard/systemd/hermes-gateway.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable hermes-dashboard hermes-gateway
systemctl restart hermes-dashboard hermes-gateway

echo "========================================================="
echo "   🎉 Hermes Deployment Successfully Completed!"
echo "   Web Dashboard: https://a.oece-x.com/ (PIN: 684861)"
echo "========================================================="
