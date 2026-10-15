#!/usr/bin/env bash
# Run from a checkout: deploy/vps/deploy.sh <ssh-target> [git-ref]
# Ships the ref to a fresh release dir, snapshots KV + current units, switches, checks /healthz,
# and on failure restores KV, units and the previous release.
set -euo pipefail
TARGET="${1:?usage: deploy.sh user@host [ref]}"; REF="${2:-main}"
SSH_OPTS="${SSH_OPTS:-}"; KEEP_RELEASES="${KEEP_RELEASES:-5}"
ROOT="$(git rev-parse --show-toplevel)"
SHA=$(git -C "$ROOT" rev-parse --short "$REF"); ID="$SHA-$(date -u +%Y%m%d%H%M%S)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git -C "$ROOT" archive --format=tar "$REF" deno deploy/vps | tar -x -C "$tmp"
# fresh directory per deploy (same SHA included); never sync into the live release
rsync -a -e "ssh $SSH_OPTS" "$tmp/" "$TARGET:/opt/base-reads/.incoming-$ID/"
ssh $SSH_OPTS "$TARGET" bash -s -- "$ID" "$KEEP_RELEASES" <<'REMOTE'
set -euo pipefail
ID="$1"; KEEP="$2"; B=/opt/base-reads; R="$B/release-$ID"; APP="$B/app"
UNITS="base-reads.service base-reads-kv-backup.service base-reads-kv-backup.timer"
KVF=$(sed -n 's/^KV_PATH=//p' /etc/base-reads/env | tail -1); KVF="${KVF:-/var/lib/base-reads/kv.sqlite3}"
PORT=$(sed -n 's/^PORT=//p' /etc/base-reads/env | tail -1); PORT="${PORT:-8000}"
SAVE="/var/backups/base-reads/predeploy-$ID"; install -d -m 700 "$SAVE"
mv "$B/.incoming-$ID" "$R" && chown -R basereads:basereads "$R"
sudo -u basereads env DENO_DIR="$B/deno-cache" /usr/local/bin/deno cache --config "$R/deno/deno.json" "$R/deno/main.ts"

PREV=$([ -L "$APP" ] && readlink -f "$APP" || true)
# 1) consistent KV copy before anything changes
[ -f "$KVF" ] && sqlite3 "$KVF" ".timeout 10000" ".backup '$SAVE/kv.sqlite3'"
# 2) keep current unit files
for u in $UNITS; do [ -f "/etc/systemd/system/$u" ] && cp -p "/etc/systemd/system/$u" "$SAVE/$u"; done
[ -f /usr/local/sbin/base-reads-kv-backup ] && cp -p /usr/local/sbin/base-reads-kv-backup "$SAVE/kv-backup.sh"

rollback() {
  echo "health check failed; rolling back" >&2
  systemctl stop base-reads || true
  if [ -f "$SAVE/kv.sqlite3" ]; then
    cp -p "$SAVE/kv.sqlite3" "$KVF.restore" && chown basereads:basereads "$KVF.restore"
    rm -f "$KVF-wal" "$KVF-shm"; mv "$KVF.restore" "$KVF"
  fi
  for u in $UNITS; do
    if [ -f "$SAVE/$u" ]; then cp -p "$SAVE/$u" "/etc/systemd/system/$u"; else rm -f "/etc/systemd/system/$u"; fi
  done
  [ -f "$SAVE/kv-backup.sh" ] && cp -p "$SAVE/kv-backup.sh" /usr/local/sbin/base-reads-kv-backup
  systemctl daemon-reload
  if [ -n "$PREV" ]; then ln -sfn "$PREV" "$APP.new" && mv -T "$APP.new" "$APP" && systemctl restart base-reads
  else rm -f "$APP"; fi
  exit 1
}

install -m 644 "$R/deploy/vps/base-reads.service" /etc/systemd/system/base-reads.service
install -m 644 "$R/deploy/vps/kv-backup.service" /etc/systemd/system/base-reads-kv-backup.service
install -m 644 "$R/deploy/vps/kv-backup.timer" /etc/systemd/system/base-reads-kv-backup.timer
install -m 755 "$R/deploy/vps/kv-backup.sh" /usr/local/sbin/base-reads-kv-backup.new && mv /usr/local/sbin/base-reads-kv-backup.new /usr/local/sbin/base-reads-kv-backup
ln -sfn "$R" "$APP.new" && mv -T "$APP.new" "$APP"
systemctl daemon-reload
systemctl enable base-reads >/dev/null && systemctl restart base-reads
ok=0
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" 2>/dev/null | grep -Eq '"ok": ?true'; then ok=1; break; fi; sleep 1
done
[ "$ok" = 1 ] || rollback
systemctl enable --now base-reads-kv-backup.timer >/dev/null
echo "healthy: release-$ID"
# prune: keep the newest $KEEP releases plus the live and previous ones; keep 5 predeploy snapshots
LIVE=$(readlink -f "$APP")
ls -1dt "$B"/release-* | tail -n +$((KEEP + 1)) | while read -r d; do
  [ "$d" = "$LIVE" ] || [ "$d" = "$PREV" ] || rm -rf "$d"; done
ls -1dt /var/backups/base-reads/predeploy-* | tail -n +6 | xargs -r rm -rf
REMOTE
