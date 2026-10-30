# Self-hosting on a VPS (Ubuntu 24.04)

1. Copy `deploy/vps/` to the server and run `API_DOMAIN=<your-hostname> ./setup.sh` as root: packages, swap top-up, ufw 22/80/443,
   Deno pinned by version and sha256, Caddy (admin API off), service user, and sshd key-only login. Key-only login is only
   enabled when root or the sudo user already has an authorized key; root must log in with a key afterwards.
2. Put secrets in `/etc/base-reads/env` (root, mode 600) using the names in `env.example`. Never commit values.
3. Hostname: to change it, edit the site line in `/etc/caddy/Caddyfile` and `PUBLIC_URL` in `/etc/base-reads/env`,
   then `systemctl restart caddy base-reads`. A wildcard-DNS name that maps to the server IP works for testing, but its
   certificates count against a shared Let's Encrypt rate limit, so use your own domain for production.
   Real values (`API_DOMAIN`, `PUBLIC_URL`) live only in `/etc/base-reads/env`; the repo keeps placeholders.
   `setup.sh` and `deploy.sh` render the Caddyfile from `API_DOMAIN`; `deploy/gen_listings.ts` reads `PUBLIC_URL`.
   `PUBLIC_URL` sets the 402 resource URLs, `llms.txt` and `openapi.json`; it is required on Base mainnet (without it paid routes return 503; free routes stay up and a startup warning is logged).
4. From a checkout: `deploy/vps/deploy.sh [--restore-kv] root@<server> <git-ref>`. Each deploy gets a fresh release dir
   and saved unit files; the switch is an atomic symlink move; `/healthz` (signing key loads + KV round-trip, booleans only,
   answered to loopback peers only; Caddy returns 404 for it) must pass within 30 s, otherwise the units and the previous
   release are restored. The newest 5 releases are kept.
   - Default rollback is code-only: the live KV is never replaced, so used nonces / tx hashes and sale records stay.
   - `--restore-kv` is for releases that migrate KV data. The service is stopped before the KV copy, so paid routes are
     down for the whole deploy. On rollback the copy is restored and `kv-merge.ts` copies every `rec`, `pending` and
     `inflight` key from the live KV into it first. Replay protection does not depend on this: it lives in the ledger.
   - `--restore-kv` copies live in `/var/backups/base-reads/predeploy-*` (root, mode 700). They are full copies of the KV,
     including sale records, so treat them as sensitive; only the newest 5 are kept.
5. Storage is split in two SQLite files:
   - `KV_PATH` (Deno KV): snapshots, caches, metadata, sale records, in-flight locks. Recoverable; may be restored.
   - `LEDGER_PATH` (default: `ledger.sqlite3` next to the KV file): spent payment authorizations (payer + nonce) and
     settlement tx hashes. Append-only (UPDATE/DELETE are rejected by triggers), WAL with `synchronous=FULL`, so an
     entry is fsync'ed before the payment is settled or served. Deploys, rollbacks and `--restore-kv` never touch it.
     On start, replay keys left in the KV by older releases are imported once.
     The ledger needs a local filesystem (node:sqlite); serverless hosts without one are not supported. The server
     refuses to start without a file ledger (`LEDGER_PATH`, or derived from `KV_PATH`); an in-memory ledger is only
     allowed on testnet with `LEDGER_MEMORY_OK=1`, never on Base mainnet. As defense in depth, spent authorizations
     and tx hashes are also written to the KV (`authused`, `txused`); a reuse is rejected if either store has it.
   `base-reads-kv-backup.timer` makes a daily consistent copy of both (14 daily + 8 weekly each).
   Backups are local to the server only and are lost with it. For an offsite copy, add an executable
   `/etc/base-reads/backup-offsite.sh`; it receives the backup path and must encrypt (e.g. age or gpg) before uploading.

## Payment ledger rules

- **Spent on submission.** An authorization is recorded as spent right before it is sent for settlement. If settlement
  then fails, or the process crashes mid-request, that authorization stays spent: the client must sign a new one with a
  new nonce. Such responses are 402 with a `hint` field saying so.
- **Trigger limits.** UPDATE/DELETE triggers stop the app and normal SQL from changing rows, not someone with file
  access: `DROP TRIGGER`, editing the file, or replacing it are still possible. Protect it with file permissions
  (service user only) and backups. Optional hardening (not built in): ship an append-only export offsite, e.g. a daily
  file of new rows where each line carries `sha256(previous_line_hash + row)`, so later tampering is detectable.
- **Never restore the ledger by replacing the file.** A replaced file can lose entries written after the backup and
  re-open spent authorizations. Only merge rows back with INSERT OR IGNORE:
  `deno run --allow-read --allow-write deploy/vps/ledger-merge.ts <live-ledger> <backup-ledger>` (adds missing rows, never
  changes existing ones; gunzip the backup first).
- **Finality.** `MIN_CONFIRMATIONS` (1..64, clamped; default 1 = receipt is enough). Consider 2-3 for higher-priced routes.
- `NETWORK=` empty is treated as Base mainnet, so the in-memory ledger is refused.

## Snapshot size and memory (measured 2026-10-20, real Bazaar data)

- Full crawl: 26,130 listings in 27 pages, ~11 s, status `complete`.
- Peak RSS by pages fetched (separate runs): 5 pages 150 MiB, 10 pages 198 MiB, 20 pages 217 MiB, 27 pages 225 MiB
  (process start ~43 MiB). Slope above 10 pages is ~1.6 MiB/page, so the 50-page default projects to roughly 260-300 MiB,
  well below systemd MemoryHigh 500M / MemoryMax 600M. Re-measure if Bazaar approaches 50k listings.
- Bounds: `SNAPSHOT_MAX_PAGES` (default 50, hard cap 100) and a 10 minute total time budget. Hitting either ends the run as
  `partial` (`coverage.stopped` = `page_cap` or `time_budget`). `complete` requires a short final page; the reported
  total alone is not trusted.
- Stored: 860,713 bytes gzip in 15 chunks of at most 60,000 bytes (below the 64 KiB Deno KV value limit; each chunk is its
  own write and the switch to the new generation is one small atomic commit). Reduced day: 81,343 bytes; aggregate: 218 bytes.
- Retention estimate: 31 full days + 334 reduced days = ~51 MiB per year of KV data.
- A loaded full index takes ~10 MiB of heap; the in-process cache keeps at most 3.

## Backup disk use

- A KV backup is roughly the KV file size: snapshot chunks are already gzip, so gzip saves little
  (measured: 925,696-byte KV file -> 865,250 bytes gzip).
- At the steady state above (~51 MiB KV) each daily copy is ~50 MiB; 14 daily + 8 weekly = 22 copies, about 1.1 GiB.
  Ledger copies are a few KB. `--restore-kv` deploys add one uncompressed KV copy each (newest 5 kept).
- The server has ~50 GB free, so this is under 3% of disk; lower the retention in `kv-backup.sh` if disk is tighter.

## Trial keys

A request to a paid route with header `X-Trial-Key: <key>` is served without payment while the key is valid, not revoked,
not expired and under its daily quota (`TRIAL_DAILY_LIMIT`, default 50 per key per UTC day, clamped to 1..10000). In every
other case (unknown, revoked, expired, over quota, malformed) the request gets exactly the same 402 as without the header.
A request that carries `PAYMENT-SIGNATURE` always takes the payment path.

- Storage: `TRIAL_KEYS_FILE` (default `/var/lib/base-reads/trial-keys.json`, mode 600, owned by `basereads`) holds only
  `{label, hash (SHA-256 hex), created, expires, revoked}`. The plaintext key (`trk_` + 32 random bytes, base64url) is never stored
  on the server. A missing or empty file turns the feature off.
- Reload: the server re-checks the file's mtime/size at most every 5 s and re-reads it on change, so generate and revoke take
  effect within about 5 s without a restart.
- Quota: counted atomically in Deno KV per key label and UTC day (entries expire after 2 days). A call is counted when it is
  accepted, before the route runs, so a trial call that fails inside the route (bad input, upstream error) still uses one unit.
  For `/x402/preflight`, the URL/SSRF checks and capacity checks run first and do not use a unit: per key+target limit (429),
  per-target budget (503), and a probe slot from the same global pool paid checks use (one in-flight check per key: 429;
  pool full: 503). Trial checks therefore can never exceed the global outbound concurrency cap; the slot is released when
  the check ends. With a valid key these input/capacity answers can appear before an exhausted quota would give the 402.
- Attestation: a trial `/x402/preflight` response is signed exactly like a paid one. The attestation describes the target
  endpoint, not the caller or any payment, so it carries no trial marker.
- Timing: rejected keys (malformed, unknown, revoked, expired, over quota) get byte-identical status, headers and body, but
  response times can differ slightly (a malformed key skips the hash lookup; an over-quota key does one KV read). This is
  only observable by someone who already holds a key and reveals nothing about other keys.
- Records: each served trial call is stored in a separate `trials` stream (`kind: "trial"`, `label`, `route`, `httpStatus`,
  `servedAt`, optional `ref`). Never the key or its hash. Trial calls are never sales: they do not appear in
  `executions`/`outcomes`/`costs`, so they never count as buyers, verified sales or revenue. `/internal/export` returns them
  in a top-level `trials` array (only when there are any); `records` is unchanged.

Operator commands (on the server, as root, from the app directory):

```sh
cd /opt/base-reads/app/deno
# create a key; the plaintext goes only into the new mode-600 file, stdout shows label and path
deno run --cached-only --allow-read=/var/lib/base-reads,/root --allow-write=/var/lib/base-reads,/root --allow-env=TRIAL_KEYS_FILE \
  scripts/trial_key.ts generate --label acme --days 30 --out /root/trial-key-acme.txt
# hand the file content over through a private channel, then delete it
shred -u /root/trial-key-acme.txt
# revoke (effective within ~5 s) and list (labels and dates only, never keys or hashes)
deno run --cached-only --allow-read=/var/lib/base-reads --allow-write=/var/lib/base-reads --allow-env=TRIAL_KEYS_FILE scripts/trial_key.ts revoke --label acme
deno run --cached-only --allow-read=/var/lib/base-reads --allow-env=TRIAL_KEYS_FILE scripts/trial_key.ts list
```

Labels are lowercase `[a-z0-9._-]`, up to 48 characters, and must be unique (a revoked label cannot be reused).
