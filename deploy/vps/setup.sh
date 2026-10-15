#!/usr/bin/env bash
# One-time server setup for Ubuntu 24.04 (incl. Minimal image). Run as root on the server. Idempotent.
set -euo pipefail
API_DOMAIN="${API_DOMAIN:?set API_DOMAIN (hostname only, e.g. api.example.com)}"
DENO_VERSION="v2.9.7"
# sha256 of deno-x86_64-unknown-linux-gnu.zip for DENO_VERSION (matches the release's .sha256sum file)
DENO_SHA256="c6527f24f4b16031d3ae4fa9f658d5f11534c8d84ce7dc8502420280919c3490"
SWAP_GB="${SWAP_GB:-2}"

apt-get update -y
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends ca-certificates curl unzip ufw sqlite3 gnupg rsync debian-keyring debian-archive-keyring apt-transport-https

# swap: top up to SWAP_GB total (image ships /swap.img 512M); written to a temp file then renamed
have_mb=$(swapon --show=SIZE --bytes --noheadings | awk '{s+=$1} END {print int(s/1048576)}')
want_mb=$((SWAP_GB * 1024))
if [ ! -f /swapfile ] && [ "$have_mb" -lt "$want_mb" ]; then
  add=$((want_mb - have_mb))
  fallocate -l "${add}M" /swapfile.tmp && chmod 600 /swapfile.tmp && mkswap /swapfile.tmp >/dev/null && mv /swapfile.tmp /swapfile && swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
# optional: free ~80 MB RAM on the minimal image (set TRIM_SERVICES=1)
if [ "${TRIM_SERVICES:-0}" = 1 ]; then
  systemctl disable --now multipathd ModemManager udisks2 packagekit 2>/dev/null || true
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
  echo "$DENO_SHA256  $tmp/deno.zip" | sha256sum -c - || { echo "deno download checksum mismatch" >&2; exit 1; }
  unzip -o "$tmp/deno.zip" -d "$tmp" && install -m 755 "$tmp/deno" /usr/local/bin/deno.new && mv /usr/local/bin/deno.new /usr/local/bin/deno && rm -rf "$tmp"
fi

# caddy (official apt repo)
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list.tmp && mv /etc/apt/sources.list.d/caddy-stable.list.tmp /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi
mkdir -p /var/log/caddy && chown caddy:caddy /var/log/caddy

# service user + dirs
id basereads >/dev/null 2>&1 || useradd --system --home /opt/base-reads --shell /usr/sbin/nologin basereads
install -d -o basereads -g basereads -m 750 /opt/base-reads /opt/base-reads/deno-cache /var/lib/base-reads
install -d -o root -g root -m 700 /etc/base-reads /var/backups/base-reads
[ -f /etc/base-reads/env ] || install -o root -g root -m 600 /dev/null /etc/base-reads/env
sed "s/API_DOMAIN_PLACEHOLDER/$API_DOMAIN/" "$(dirname "$0")/Caddyfile" > /etc/caddy/Caddyfile.new
caddy validate --config /etc/caddy/Caddyfile.new --adapter caddyfile >/dev/null && mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile && systemctl restart caddy

# sshd: keys only. Only applied when root already has an authorized key, and validated before reload.
if [ -s /root/.ssh/authorized_keys ]; then
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\n' > /etc/ssh/sshd_config.d/10-key-only.conf
  if sshd -t; then systemctl reload ssh; else rm -f /etc/ssh/sshd_config.d/10-key-only.conf; echo "sshd config invalid; left unchanged" >&2; fi
else
  echo "no /root/.ssh/authorized_keys: password login left enabled" >&2
fi
echo "setup done; fill /etc/base-reads/env (root:600), then run deploy.sh"
