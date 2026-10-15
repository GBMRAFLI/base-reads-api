# Self-hosting on a VPS (Ubuntu 24.04)

1. Copy `deploy/vps/` to the server and run `API_DOMAIN=<your-hostname> ./setup.sh` as root: packages, swap top-up, ufw 22/80/443,
   Deno pinned by version and sha256, Caddy (admin API off), service user, and sshd key-only login (only if root already has an authorized key).
2. Put secrets in `/etc/base-reads/env` (root, mode 600) using the names in `env.example`. Never commit values.
3. Hostname: to change it, edit the site line in `/etc/caddy/Caddyfile` and `PUBLIC_URL` in `/etc/base-reads/env`,
   then `systemctl restart caddy base-reads`. A wildcard-IP name (`<a-b-c-d>.sslip.io`) works for testing, but its
   certificates count against a shared Let's Encrypt rate limit, so use your own domain for production.
   `PUBLIC_URL` sets the 402 resource URLs, `llms.txt` and `openapi.json`.
4. From a checkout: `deploy/vps/deploy.sh root@<server> <git-ref>`. Each deploy gets a fresh release dir, a pre-deploy KV copy and
   saved unit files; the switch is an atomic symlink move; `/healthz` (signing key loads + KV round-trip, booleans only) must
   pass within 30 s, otherwise KV, units and the previous release are restored. The newest 5 releases are kept.
5. KV lives in `KV_PATH` (SQLite); `base-reads-kv-backup.timer` makes a daily consistent copy (14 daily + 8 weekly).
   Backups are local to the server only and are lost with it. For an offsite copy, add an executable
   `/etc/base-reads/backup-offsite.sh`; it receives the backup path and must encrypt (e.g. age or gpg) before uploading.
