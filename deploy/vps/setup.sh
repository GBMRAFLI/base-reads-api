#!/usr/bin/env bash
# One-time server setup (Ubuntu/Debian). Run as root on the server. Idempotent.
set -euo pipefail
DENO_VERSION="${DENO_VERSION:-v2.9.7}"
SWAP_GB="${SWAP_GB:-2}"

apt-get update -y
apt-get install -y curl unzip ufw sqlite3 debian-keyring debian-archive-keyring apt-transport-https gnupg rsync

# swap
if ! swapon --show | grep -q /swapfile; then
  fallocate -l "${SWAP_GB}G" /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
sysctl -w vm.swappiness=10 && echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf

# firewall: only 22/80/443
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# deno (pinned)
if ! /usr/local/bin/deno --version 2>/dev/null | grep -q "${DENO_VERSION#v}"; then
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/deno.zip" "https://github.com/denoland/deno/releases/download/${DENO_VERSION}/deno-x86_64-unknown-linux-gnu.zip"
  unzip -o "$tmp/deno.zip" -d /usr/local/bin && chmod 755 /usr/local/bin/deno && rm -rf "$tmp"
fi

# caddy (official apt repo)
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi
mkdir -p /var/log/caddy && chown caddy:caddy /var/log/caddy

# service user + dirs
id basereads >/dev/null 2>&1 || useradd --system --home /opt/base-reads --shell /usr/sbin/nologin basereads
install -d -o basereads -g basereads -m 750 /opt/base-reads /opt/base-reads/deno-cache /var/lib/base-reads
install -d -o root -g root -m 700 /etc/base-reads /var/backups/base-reads
[ -f /etc/base-reads/env ] || install -o root -g root -m 600 /dev/null /etc/base-reads/env
echo "setup done; fill /etc/base-reads/env (root:600), then run deploy.sh"
