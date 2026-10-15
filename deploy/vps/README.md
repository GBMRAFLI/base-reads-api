# Self-hosting on a VPS (Ubuntu 24.04)

1. Copy `deploy/vps/` to the server and run `setup.sh` as root (packages, swap top-up, ufw 22/80/443, pinned Deno, Caddy, service user).
2. Put secrets in `/etc/base-reads/env` (root, mode 600) using the names in `env.example`. Never commit values.
3. Hostname: the default is the temporary `89-116-220-218.sslip.io`. To change it, edit the site line in
   `/etc/caddy/Caddyfile` and `PUBLIC_URL` in `/etc/base-reads/env`, then `systemctl reload caddy && systemctl restart base-reads`.
   `PUBLIC_URL` sets the 402 resource URLs, `llms.txt` and `openapi.json`.
4. From a checkout: `deploy/vps/deploy.sh root@<server> <git-ref>` (release dir, atomic symlink switch, health check, rollback).
5. KV lives in `KV_PATH` (SQLite); `base-reads-kv-backup.timer` makes a daily consistent copy (14 daily + 8 weekly).
