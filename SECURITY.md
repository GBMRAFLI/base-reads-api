The signing key for Pre-pay Check has never been in this repository. If you find a key that may have leaked, report it to gbmrafli@agentmail.to.

# Seller payment path: audit (2026-10-15)

Scope: the verify → handler → settle → serve path in `api/index.py` (`paid()`) and `deno/main.ts` (`paid()`), plus
`api/settle_guard.py` / `deno/lib/settle_guard.ts` and the on-chain check in `api/sales_log.py` / `deno/lib/stream.ts`.
Both implementations follow the same rules and share tests for each case.

| # | Attack class | Severity (before) | Status | Mitigation |
|---|---|---|---|---|
| 1 | **Serving on the facilitator's word alone**: a buggy, compromised or spoofed facilitator returns `success` for a payment that never landed | High | Fixed | The resource is served only when an independent Base RPC read of the settlement receipt shows status 1, a USDC `Transfer(payer → payTo, ≥ amount)` **and**, for EIP-3009 payments, USDC `AuthorizationUsed(payer, nonce)` for *this* payment's nonce in the same receipt. Failure → 402, nothing served. |
| 2 | **Replay / duplicate signature** (same authorization sent twice or concurrently; facilitators that answer idempotently for an already-used nonce) | High | Fixed | Each authorization (`from`+`nonce`, or the hash of the header for other schemes) is claimed with an atomic check-and-set **before** verify: Deno KV `atomic().check(versionstamp:null)` (shared across isolates), Python a lock-protected map. Kept until `validBefore` + 60 s (min 1 h), never released, so duplicates are rejected consistently (409). Since only EIP-3009 is accepted (#11), every accepted payment has a `from`+`nonce` key. Tested with 8 concurrent identical requests: exactly one is served and settled. |
| 3 | **Settlement tx reuse** (facilitator returns a tx hash that already paid for another request) | High | Fixed | A settlement tx can back one served sale only (Deno: append-only payment ledger file (`LEDGER_PATH`, SQLite, fsync on commit), first-use insert, never rolled back with the KV; spent authorizations (payer + nonce) are recorded there before settlement; Python: lock + sales-log check); reuse → 409 and a mismatch record. The nonce binding in #1 also ties the tx to this authorization. |
| 4 | **Freshness: `validAfter` / `validBefore`** | Medium | Fixed | Rejected locally before any facilitator call if not yet valid or valid for < 6 s more. Payee (`to`), exact `value` and the `accepted` requirements (scheme, network, asset, payTo, amount) must match ours. |
| 5 | **Settle reports failure but the tx confirms on-chain** (timeouts) | Medium | Fixed | If the failed settle response still carries a tx hash, the chain is checked; a confirmed, nonce-bound, unused transfer is honored and served (recorded with a note). |
| 6 | **Settle reports success but the chain disagrees, or the receipt is slow** | Medium | Fixed | Disagreement → 402, not served, recorded as `not_delivered`. Not visible yet → `202` and the payment is parked; repeating the same request re-checks the chain and serves exactly once (atomic take). |
| 7 | **ERC-6492 / smart-wallet (ERC-1271) signatures** | Low (seller) | Accepted, documented | Signature validity is the facilitator's job. The seller's protection does not depend on it: we serve only on a confirmed on-chain transfer to our payee, whatever wallet type signed. Counterfactual-wallet deployment gas is borne by the facilitator, not the seller. |
| 8 | **Gas / work griefing** (valid-looking payments that fail at settle after the handler ran; oversized headers) | Medium | Fixed | Payment header capped at 16 KB with strict base64/JSON parsing; payers with 3 failed settles in 10 min get 429 before verify (see A3: per-payer, per-IP and global counters); a seen signature cannot be replayed to re-run the handler. The handler (RPC reads, preflight probe) still runs before settle so that bad input is never charged — bounded by the cooldown. |
| 9 | **Response-header spoofing** | Medium | Fixed | `PAYMENT-RESPONSE` is built from the facilitator response only; client-sent `X-PAYMENT-RESPONSE` is ignored. Facilitator `transaction`/`payer` must match strict hex formats before use. The client-controlled `Host` header can no longer inject arbitrary text into the 402 challenge's `resource.url` (only `hostname[:port]`; set `PUBLIC_URL` in production; on Base mainnet `PUBLIC_URL` is required: without it the server logs a startup warning, paid routes return 503 and `resource.url` is never derived from `Host`). |
| 10 | Facilitator auth secrets | Info | OK | CDP keys are only read from env and only sent to `api.cdp.coinbase.com` (exact host match). |
| 11 | **Permit2 payments** (`payload.permit2Authorization`, or `accepted.extra.assetTransferMethod: "permit2"`) | High | Rejected | A Permit2 transfer emits no USDC `AuthorizationUsed(payer, nonce)` event, so #1 could not bind the on-chain tx to this payment. Such payloads get `402 permit2_not_supported` before any facilitator call; payloads without an EIP-3009 `authorization` get `402 eip3009_authorization_required`. Only `exact` EIP-3009 `transferWithAuthorization` is accepted. |

## External review findings (against main@7ea7267)

Fixed in both servers unless noted; each has a test in `tests/test_preflight.py` (class `T10`) and `deno/tests/contract_test.ts` (`A1`..`A11`, `SSRF`).

| # | Finding | Severity | Status | Fix |
|---|---|---|---|---|
| A1 | Non-EIP-3009 payloads accepted; replay key fell back to a hash of the raw header (re-encoding = new key) | Medium | Fixed | Only `exact` EIP-3009 `transferWithAuthorization` is accepted (Permit2 → `permit2_not_supported`, no authorization → `eip3009_authorization_required`). The replay key is `(from, nonce)` lower-cased, the on-chain uniqueness unit, so any re-encoding or re-signing of the same authorization is a replay (409). This is stricter than hashing the canonical payload; the canonical-payload sha256 is stored with the claim for audit. `accepted` must match exactly. |
| A2 | Payer for the on-chain check and records taken from the facilitator's `payer` | Medium | Fixed | The payer is always the signed authorization's `from`. A differing facilitator `payer` is recorded as a mismatch and otherwise ignored. |
| A3 | Cooldown per instance, settle failures only, payer only | Medium | Fixed (revised by N1/N3) | Deno: KV counters `["fail", scope, who, bucket]` (`Deno.KvU64`, `kv.atomic().sum()`), shared by all instances. Blocking scopes: `payer` (3 settle failures / 10 min; only after verify passed, so a forged `from` cannot lock out a real payer) and `ip` (10 verify + settle failures / 10 min, IPv6 per /64). `global` is alert-only (N1). 429 names the scope. Python: same rules, in memory (single process). |
| A4 | Nonce accepted as 1..64 hex digits | Medium | Fixed | Must match `^0x[0-9a-fA-F]{64}$` (32 bytes), lower-cased for the key → `authorization_bad_nonce`. |
| A5 | `accepted` fields only compared when present | Low | Fixed | `accepted` and all 5 fields (`scheme`, `network`, `asset`, `payTo`, `amount`) are required; addresses compare case-insensitively, the rest exactly. |
| A6 | Replay claim taken before the local precheck | Low | Fixed | Precheck runs first, so a rejected payload never consumes its nonce slot. |
| A7 | `ONCHAIN_CHECK=log` allowed on mainnet | Low | Fixed | Refused on `eip155:8453`: startup fails, runtime forces `block`. |
| A8 | Facilitator error strings and settle body echoed to clients | Low | Fixed | Error codes are allow-listed (x402 spec codes), anything else → `facilitator_error`. `PAYMENT-RESPONSE` is rebuilt from validated fields only: `{success, transaction, network, payer}` (+ `errorReason` on failure). |
| A9 | Deno signing key imported as extractable | Low | Fixed (Deno) | The public key is read once from a short-lived import; the kept signing key is non-extractable and the decrypted PKCS#8 buffer is zeroed. Python (pycryptodome) has no non-extractable key object; the key stays in process memory only. |
| A10 | `loadKey`/`publicKeyInfo` ignored the passed env; unvalidated `SIGNING_KEY_CREATED_AT` / `SIGNING_KEY_HISTORY` dates | Low | Fixed | env is threaded through `loadKey`, `publicKeyInfo`, `sign`, `keyHistory`, `snapshotMeta`, `preflight`. Dates must be strict ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SS[.fff]Z`, a real date), otherwise published as `null`. |
| A11 | Unpinned `pycryptodome` and Docker base image | Low | Fixed | `pycryptodome==3.24.1` with `--hash` for all 43 files on PyPI, installed with `pip --require-hashes` in CI and Docker; `FROM python:3.13-slim@sha256:70729b46…` (multi-arch index digest). |
| SSRF | Review of the Python preflight fetcher | Medium (found) | Fixed | See below. |
| N1 | `global` limit (200) plus counting every verify failure: junk signatures from ~20 IPs could lock out every buyer | Medium | Fixed | `global` now counts **settle failures only** and is **alert-only** (logs once per window above 1000, never blocks). Verify failures count per IP only (never per payer or globally). Per-IP limits key IPv6 on the /64, so rotating addresses within one /64 does not help. Tested: 400 junk payments from 40 IPs, then a real buyer is still served. |
| N2 | Deno preflight: resolved IPs checked, then `fetch` resolves again (DNS rebinding); no-DNS case allowed | Medium | Fixed | `checkUrl` refuses when DNS is unavailable (`dns resolution unavailable`), and when it returns nothing the result is `dns_unresolvable` with no connection attempt. The probe no longer uses `fetch`: `Deno.connect` to the **checked IP**, then `Deno.startTls(conn, {hostname})`, so SNI and certificate verification use the original hostname, plus a minimal HTTP/1.1 GET with the original `Host` header (`Connection: close`, header block and body capped at 64 KB, chunked and content-length handled, 8 s overall timeout, no redirects). `Deno.createHttpClient` cannot pin an address (only proxy and TLS options), so it was not used. There is no fallback to `fetch`. Residual: Deno Deploy runs the standard Deno runtime with outbound TCP and TLS. If a Deploy region ever disallows `Deno.connect`, probes report `reachable: false / ConnectionError` instead of fetching unpinned. |
| N3 | CAS loop dropped increments after 20 conflicts; `blocked()` raced under parallel bursts | Low | Fixed | Counters use `kv.atomic().sum(key, 1n)` (server-side add, never lost). `sum` cannot take `expireIn`, so the same atomic op deletes the bucket two windows back, and an hourly `Deno.cron` purge removes the rest. Each paid request holds a concurrency slot (atomic set-if-absent KV keys with `expireIn`, max 4 per payer and 8 per IP/64) while it checks `blocked()`, verifies and settles, so a parallel burst cannot exceed a failure limit by more than the slot count (extra requests get 429 `concurrency`). Python mirrors this with a lock-protected slot counter. |
| N5 | `PREFLIGHT_EXTRA_ALLOWED_CIDRS` (Python) bypassed every address check | Low | Fixed | The server refuses to start with it set unless `PREFLIGHT_TEST_MODE=1` is also set, and logs a warning when both are set. |
| A10b | Invalid `SIGNING_KEY_CREATED_AT` / history dates were silently nulled | Low | Fixed | Startup warning (both servers) naming the bad variable; the value is still published as `null`. |

### SSRF review (Python `api/preflight.py`; Deno mirrored)
Already sound (Python; Deno since N2): https only; DNS resolved once and the TCP connection pinned to the checked IP (SNI, certificate and Host
use the hostname; no DNS rebinding); every resolved address must pass; no redirects followed; 8 s timeouts; body read capped at 64 KB.
Found and fixed:
- **100.64.0.0/10 (shared/CGNAT) was allowed in Python**: `is_private` is false for it. Now only `is_global` addresses pass.
- IPv6 forms that embed an IPv4 address (IPv4-mapped/compatible, NAT64 `64:ff9b::/96` and `/48`, 6to4 `2002::/16`, Teredo `2001::/32`) are refused outright; Deno also allows only global unicast `2000::/3`.
- Any port was allowed: now only 443 and 8443.
- Credentials in the URL (`https://user:pass@host`) and (Python) control or whitespace characters are refused; the WHATWG URL parser on Deno strips them.
- Deno read the whole response before truncating: it now streams at most 64 KB and cancels the rest.

## Latency tradeoff (on-chain check before serving)
The check costs one `eth_getTransactionReceipt` (typically < 300 ms) because facilitators return after the tx is mined.
It retries up to 3 times, 1 s apart, then answers `202` instead of making the buyer wait. Options:
- `ONCHAIN_CHECK=block` (default): as above. Strongest; worst case about 2 s extra before `202`.
- `ONCHAIN_CHECK=log`: serve on facilitator success, record any on-chain mismatch for review. Testnets only:
  **refused on Base mainnet** (the server will not start with it, and `block` is forced at runtime).

## Python server: single process only

The Python server (`api/`) keeps its replay map, used-tx set and failed-settle cooldown (`FailLimiter`) in process memory. That is correct for one process (tests, a single container), but **it is not for production behind several workers or instances**: each would keep its own state. The production deployment is the Deno server, whose nonce claims, used tx hashes, parked payments and cooldown counts all live in Deno KV.

## Open items
- Python replay claims and pending deliveries are in process memory: a restart forgets them (the USDC contract still
  rejects a reused nonce on-chain, and the sales-log tx check survives restarts). Deno Deploy uses KV and is durable.

## Re-audit hardening (paid Pre-pay Check)

- Before settlement the service applies a per target+payer limit (default 3/min, `PER_TARGET_PAYER_PER_MIN`) and reserves both an outbound slot and one unit of the target's global budget (`OUTBOUND_PER_HOST_PER_MIN`). If either is unavailable the answer is 503 with `Retry-After` and `charged:false`; when the target is already full this happens before any facilitator call. A failed settlement returns the reserved unit, so failed settles never consume the budget; a successful settlement consumes it and the probe runs immediately. A buyer is never charged into a queue.
- An outbound slot is reserved before settlement without waiting; if none is free the request gets 503 and is not charged. At most one probe per payer is in flight.
- Rate-limit tables evict the oldest key when full instead of refusing new clients. IPv6 clients are limited per /64 and per /48 aggregate (`UNPAID_PER_48_PER_MIN`, default 600).
- A pending (settled, not yet delivered) check stores the paid URL; retries probe that URL only, at most 3 attempts, under the same limits.
- Post-delivery settlement re-checks are persisted in KV (7-day expiry) and processed by a cron sweep every 2 minutes, so they survive restarts.
- Signed snapshot metadata carries `snapshot_sha256` for the last 30 days. Limitation: the per-day hash is computed from the same KV that stores the snapshot, so it detects post-publication changes and inconsistent copies, not a compromise of the storage that wrote both.

## Python reference implementation

The Python code in `api/` is a reference implementation used for test vectors and cross-checks. It is not deployed and does not implement the paid-route abuse guards (settle-before-probe ordering, rate limits, outbound slots, pending retries, post-delivery re-checks). Only the Deno service under `deno/` serves traffic.

## Queued and expired paid checks

- Pending is used only for a settlement not yet visible on-chain and for a probe that failed after settlement; a retry probes the paid URL and does not take another budget unit.
- A pending check keeps a fixed 1-hour window from its first park. If it is not served in that window, a sweep (every 5 minutes) removes it atomically and logs a `pending_expired_unserved` incident with the settlement transaction. Refund path: the buyer contacts the issuer contact address with the transaction hash; the incident record is used to confirm the unserved payment and the amount is returned to the payer address.
- Signed snapshot metadata is cached for 60 seconds.
- Post-delivery re-check records are keyed by due time; a sweep lists only due records and removes each with a versionstamp-checked atomic delete before reporting.

## Probe slots

- Order on the paid route: result cache, then per target+payer limit, then probe slot, then target budget, then settlement, then probe.
- A slot is reserved in one synchronous step after the payment signature is verified and before settlement. It is bound to payer + payment nonce (the idempotency key) + target host, lives 15 seconds (`PROBE_SLOT_TTL_S`), and each payer may hold one (a second parallel request from the same wallet gets 429). Unpaid requests reserve nothing.
- One slot is kept for retries of already-settled checks, so new buyers cannot starve them.
- Cache hit: a cached result for the same payer and target is still a paid result. It settles without taking a slot, since no outbound probe runs.
- Settlement fails: the slot is released immediately and the answer is 402. Abandoned request: the slot expires after its TTL, nothing is charged. Slot expired during settlement: the payment is kept and the answer is 502 with `retry_free: true`; repeating the same request is served from the pending path without a second charge. All slots taken: 503 with `Retry-After`, nothing charged.
- Failed settlements are counted per network (IPv4 /24, IPv6 /48; `FAILED_SETTLE_PER_NET_PER_MIN`, default 10). While a network is over that count, only the IPs and payers in it that themselves failed a settlement in the last minute are refused (429, before verification); other buyers on the same network are never affected. This limit only slows repeat offenders: a sender that rotates IPs or payers is never refused by it, which is harmless because a failed settlement is never charged and the probe slot is released immediately.
- The slot is extended to 20 seconds when the probe starts, covering the probe timeout (5 s) and the attestation `eth_getCode` lookups (5 s timeout each, run in parallel), so it cannot lapse mid-probe.
- If a cached result expired between the pre-check and delivery, the free retry takes a target budget unit before probing; without one it is re-parked (503, no new charge).

## Signing key pin

Published signing key (second pin source; public data, the same values as `/.well-known/issuer.json`):
`key_id` `72cb9da845cc948f`, fingerprint `SHA256:csudqEXMlI/dQFGjVQ5N2hl9R3/wXZXyP551gsX7Mz0`. If the key is rotated,
this line is updated in the same release.
