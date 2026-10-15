#!/usr/bin/env bash
# Consistent online copy of the KV SQLite file (sqlite3 .backup), gzip, keep 14 daily + 8 weekly.
set -euo pipefail
umask 077
trap 'rm -f "$DST"/.kv-*.sqlite3 "$DST"/.kv-*.sqlite3.gz "$DST"/.weekly.tmp' EXIT
SRC="${KV_PATH:-/var/lib/base-reads/kv.sqlite3}"; DST=/var/backups/base-reads
d=$(date -u +%F); tmp="$DST/.kv-$d.sqlite3"
sqlite3 "$SRC" ".timeout 10000" ".backup '$tmp'"
sqlite3 "$tmp" "PRAGMA integrity_check;" | grep -qx ok
gzip -f "$tmp" && chmod 600 "$tmp.gz" && mv "$tmp.gz" "$DST/kv-$d.sqlite3.gz"   # rename = atomic publish
if [ "$(date -u +%u)" = 7 ]; then cp "$DST/kv-$d.sqlite3.gz" "$DST/.weekly.tmp" && mv "$DST/.weekly.tmp" "$DST/weekly-kv-$d.sqlite3.gz"; fi
ls -1t "$DST"/kv-*.sqlite3.gz | tail -n +15 | xargs -r rm -f
ls -1t "$DST"/weekly-kv-*.sqlite3.gz 2>/dev/null | tail -n +9 | xargs -r rm -f
