#!/usr/bin/env bash
# Run from a workstation: ./deploy.sh <ssh-target> [git-ref]. Ships a git ref to the server and restarts.
set -euo pipefail
TARGET="${1:?usage: deploy.sh user@host [ref]}"; REF="${2:-main}"
SSH_OPTS="${SSH_OPTS:-}"
ROOT="$(git rev-parse --show-toplevel)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git -C "$ROOT" archive --format=tar "$REF" deno deploy/vps | tar -x -C "$tmp"
SHA=$(git -C "$ROOT" rev-parse --short "$REF")
rsync -a --delete -e "ssh $SSH_OPTS" "$tmp/" "$TARGET:/opt/base-reads/release-$SHA/"
ssh $SSH_OPTS "$TARGET" bash -s -- "$SHA" <<'REMOTE'
set -euo pipefail
SHA="$1"; R=/opt/base-reads/release-$SHA
chown -R basereads:basereads "$R"
sudo -u basereads env DENO_DIR=/opt/base-reads/deno-cache /usr/local/bin/deno cache --config "$R/deno/deno.json" "$R/deno/main.ts"
install -m 644 "$R/deploy/vps/base-reads.service" /etc/systemd/system/base-reads.service
install -m 755 "$R/deploy/vps/kv-backup.sh" /usr/local/sbin/base-reads-kv-backup
install -m 644 "$R/deploy/vps/kv-backup.service" /etc/systemd/system/base-reads-kv-backup.service
install -m 644 "$R/deploy/vps/kv-backup.timer" /etc/systemd/system/base-reads-kv-backup.timer
PREV=$(readlink -f /opt/base-reads/app || true)
ln -sfn "$R" /opt/base-reads/app.new && mv -T /opt/base-reads/app.new /opt/base-reads/app
systemctl daemon-reload
systemctl enable --now base-reads-kv-backup.timer
systemctl enable base-reads && systemctl restart base-reads
for i in $(seq 1 20); do curl -fsS -o /dev/null http://127.0.0.1:8000/llms.txt && { echo "healthy: $SHA"; exit 0; }; sleep 1; done
echo "health check failed; rolling back to $PREV" >&2
[ -n "$PREV" ] && ln -sfn "$PREV" /opt/base-reads/app.new && mv -T /opt/base-reads/app.new /opt/base-reads/app && systemctl restart base-reads
exit 1
REMOTE
