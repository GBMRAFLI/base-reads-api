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
   `PUBLIC_URL` sets the 402 resource URLs, `llms.txt` and `openapi.json`.
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
