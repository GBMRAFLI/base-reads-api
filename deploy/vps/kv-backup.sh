#!/usr/bin/env bash
# Consistent online copies (sqlite3 .backup) of the KV file and the payment ledger, integrity-checked, gzip,
# published by rename, keep 14 daily + 8 weekly of each. Backups are local; see README for an offsite hook.
set -euo pipefail
umask 077
DST=/var/backups/base-reads
trap 'rm -f "$DST"/.tmp-*' EXIT
KVF="${KV_PATH:-/var/lib/base-reads/kv.sqlite3}"
LGF="${LEDGER_PATH:-$(dirname "$KVF")/ledger.sqlite3}"
d=$(date -u +%F)
backup() { # name source
  local name="$1" src="$2" tmp="$DST/.tmp-$1-$d.sqlite3"
  [ -f "$src" ] || { echo "skip $name: $src missing" >&2; return 0; }
  sqlite3 "$src" ".timeout 10000" ".backup '$tmp'"
  sqlite3 "$tmp" "PRAGMA integrity_check;" | grep -qx ok
  gzip -f "$tmp" && chmod 600 "$tmp.gz" && mv "$tmp.gz" "$DST/$name-$d.sqlite3.gz"   # rename = atomic publish
  if [ "$(date -u +%u)" = 7 ]; then cp "$DST/$name-$d.sqlite3.gz" "$DST/.tmp-weekly" && mv "$DST/.tmp-weekly" "$DST/weekly-$name-$d.sqlite3.gz"; fi
  # optional offsite copy: an executable hook receives the backup path; it must encrypt before upload
  local hook=/etc/base-reads/backup-offsite.sh
  if [ -x "$hook" ]; then "$hook" "$DST/$name-$d.sqlite3.gz" || echo "offsite hook failed ($name)" >&2; fi
  ls -1t "$DST/$name"-*.sqlite3.gz | tail -n +15 | xargs -r rm -f
  ls -1t "$DST/weekly-$name"-*.sqlite3.gz 2>/dev/null | tail -n +9 | xargs -r rm -f
}
backup kv "$KVF"
backup ledger "$LGF"
