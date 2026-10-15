---
title: Base Reads x402
emoji: 🔎
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# Base Reads (x402)

Pay-per-call Base mainnet reads and signed pre-payment checks for x402 endpoints, via [x402](https://x402.org) v2
(USDC on Base, `exact` scheme). Deterministic code only: no LLMs, no advice. Maintained by GBMRAFLI.

## Paid routes (GET)

| Route | Price (USDC) | Returns |
|---|---|---|
| `/base/usdc-balance?address=0x…` | $0.001 | USDC + ETH balance |
| `/base/tx-status?hash=0x…` | $0.002 | success/failed/pending, block, confirmations, gas |
| `/base/basename?name=jesse` or `?address=0x…` | $0.003 | Basename ⇄ address (reverse is forward-verified) |
| `/base/network` | $0.001 | block, block age, base fee, gas price |
| `/base/address-intel?address=0x…` | $0.005 | USDC+ETH, verified Basename, tx count, is_contract |
| `/x402/preflight?url=https://…` | $0.001 | Pre-pay Check: Ed25519-signed facts about another x402 endpoint |

Unpaid requests return `402` with a `PAYMENT-REQUIRED` header (x402 v2, with Bazaar discovery metadata).
Invalid input or upstream errors are never settled, so you are not charged for them. A paid response is returned only
after the payment is settled **and** independently confirmed on Base (see [SECURITY.md](SECURITY.md)); if the chain
has not shown the transfer yet you get `202` and the same request (same payment header) is served once it does.

Optional `?ref=<tag>` (`A-Z a-z 0-9 . _ -`, max 64; first occurrence wins) is stored with the paid call for attribution. It is self-reported and unverified, and never changes the price, the 402 challenge or the payment requirements.

## Free routes (GET)

| Route | Returns |
|---|---|
| `/` | service info, prices, facilitator in use |
| `/openapi.json` | OpenAPI 3.1 for the paid routes; prices generated from the same table as the 402 challenge |
| `/.well-known/402index-verify.txt` | 402index ownership token, exact bytes, no trailing newline |
| `/llms.txt` | plain-text summary for agents: routes, prices, payment info, discovery links (cached 1 h) |
| `/.well-known/x402-preflight` | public key, key_id, fingerprint, how to verify, facilitator, repo |
| `/.well-known/x402-preflight-key-history.json` | current and retired signing keys with dates |
| `/x402/preflight/pubkey` | `{alg, public_key_b64, key_id, fingerprint, fingerprint_short, created_at}` |
| `/bazaar/snapshots` | daily Bazaar snapshot history: counts of listings, hosts, payout wallets, 30-day calls and payers |
| `/.well-known/bazaar-snapshot.json` | signed snapshot-series metadata (version, started_at, last_updated, total_snapshots, covered_listings) |

## Pre-pay Check
Facts only: challenge validity, reachability and latency, Bazaar listing, host listing count, payout wallet reuse
across hosts, last-called time and payer trend from daily snapshots. Example response (abridged):

```json
{"facts": {"schema": "prepay-check/v1", "target": "https://x402.org/protected", "checked_at": "2026-10-15T00:00:00Z",
           "disclaimer": "Deterministic observations only. Not advice to pay, buy or sell.",
           "reachability": {"reachable": true, "http_status": 402, "latency_ms": 180},
           "challenge": {"valid": true, "problems": [], "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "10000", "payTo": "0x…"}]},
           "bazaar": {"available": true, "snapshot_date": "2026-10-15", "listed": true, "host_listing_count": 3, "payout_wallet_reuse": {}, "payer_trend": []}},
 "signature": {"alg": "Ed25519", "key_id": "72cb9da845cc948f", "public_key_b64": "…", "value_b64": "…",
               "signed_over": "canonical JSON of facts (sorted keys, no whitespace)"}}
```

### Verify the signature
```python
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
body = ...  # the JSON response above
msg = json.dumps(body["facts"], sort_keys=True, separators=(",", ":")).encode()
Ed25519PublicKey.from_public_bytes(base64.b64decode(body["signature"]["public_key_b64"])).verify(base64.b64decode(body["signature"]["value_b64"]), msg)
```
Then check `signature.key_id` against `GET /.well-known/x402-preflight` (or pin the fingerprint). `key_id` is the first
16 hex characters of SHA-256 of the raw public key; `fingerprint` is `SHA256:` + base64 of the same digest.
Hook examples for the official clients: `examples/ts/preflight-hook.ts`, `examples/python/preflight_hook.py`.

## Facilitator
Payments are verified and settled by the facilitator in `FACILITATOR` (default PayAI, `https://facilitator.payai.network`;
optionally the CDP facilitator, see below). The one in use is shown live in `/` and `/.well-known/x402-preflight`.
The seller never signs or sends funds; it only receives USDC at its payee wallet.

## Sales log
Both paid routes write to one sales log (chain_reads = `/base/*`, endpoint_check =
`/x402/preflight`). After each settled sale the seller reads the Base receipt, checks the USDC Transfer to the payee,
and writes ExecutionRecord / OutcomeRecord / CostEntry / Observation rows to `DATA_STORE`.
`verified_success` requires on-chain settlement, an external (non-self) payer, and delivery. URLs and HTTP contracts are unchanged.

## Free tier + on-chain truth
Render free plan, no disk: snapshots and the sales log live in /tmp (ephemeral). `GET /internal/export`
(Bearer `EXPORT_TOKEN`) serves the log; an external collector pulls it hourly and rebuilds buyers, calls and timestamps from USDC
Transfer logs into the payee on Base, matched to the settlement tx hashes from PAYMENT-RESPONSE. The chain is the source of truth.

## Hosting on Hugging Face Spaces (Docker)
`Dockerfile` listens on port 7860; storage is ephemeral (`/tmp`). Set Space secrets `SIGNING_KEY_PASSPHRASE`,
`SIGNING_KEY_ENC_B64`, `EXPORT_TOKEN` (and optionally the variable `PUBLIC_URL=https://<owner>-<space>.hf.space`).
## Deno Deploy port (`deno/`)
TypeScript port with the same routes, 402 challenges (byte-identical body and `PAYMENT-REQUIRED` header), Ed25519 signed
facts (same encrypted key and pubkey, byte-identical signatures), `/internal/export` with the same bearer auth, and the same
record format. Storage: Deno KV. Daily Bazaar snapshot: `Deno.cron` at 00:15 UTC only (never at startup), at most one attempt per UTC calendar day (KV key `["snapattempt", YYYY-MM-DD]` with `versionstamp: null`, so a failed attempt also consumes the day and there is no every-other-day skip), capped at `SNAPSHOT_MAX_PAGES` pages of 1000 listings (default 3, range 1–50 with clamp + warning on invalid values; 15 s per page, 1 retry), snapshots retained 60 days. On Deno the snapshot is therefore often partial.

### Optional `prepay-check/v1` bazaar fields (Deno production)
Schema stays `prepay-check/v1` (safer than a version bump: existing clients keep working; new fields are additive and optional). When the index is capped, `bazaar.coverage` is present with `pages_fetched`, `max_pages`, `items_indexed`, `bazaar_total`, `complete`. If `coverage.complete !== true` and the resource was not found in the indexed pages: `listed` is `null` and `listed_reason` is `"not_in_indexed_part"` (do not treat as "definitely unlisted"). `host_listing_count` and `payout_wallet_reuse` keep their existing shapes; when the snapshot is incomplete they are lower bounds and Deno also sets `host_listing_count_is_min: true` and `payout_wallet_reuse_is_min: true` (backward-compatible: unknown clients ignore the flags). When `complete` is true, `listed` is a boolean as before.

The Python reference (`api/`) does **not** yet apply the page cap or emit `coverage` / `listed: null` / `*_is_min` — Deno Deploy is production. Python still builds a full local snapshot for tests and the HF Docker path.

Entry point `deno/main.ts`; env: `SIGNING_KEY_PASSPHRASE`, `SIGNING_KEY_ENC_B64`, `EXPORT_TOKEN` (+ optional `PAY_TO_ADDRESS`,
`SELF_WALLETS`, `PUBLIC_URL`, `RPC`, `FACILITATOR`, `NETWORK`, `SNAPSHOT_MAX_PAGES`). Contract fixtures come from the Python reference
(`python scripts/gen_contract_fixture.py`); `tests/fixtures/py_signed.json` holds a public THROWAWAY test key only.

## Bazaar discovery and the CDP facilitator (optional)
Every 402 challenge carries `extensions.bazaar` in the `declareDiscoveryExtension` format: `info` (GET input with
query-param examples, JSON output example) plus a JSON `schema`. Descriptions and examples live in `api/discovery.json`
(mirrored at `deno/lib/discovery.json`; a test keeps them identical). Check a deployment for free, without a key:
`curl -X POST https://api.cdp.coinbase.com/platform/v2/x402/validate -H 'Content-Type: application/json' -d '{"resource":"<url>","method":"GET"}'`.

The default facilitator stays PayAI. To settle through the CDP facilitator (needed for Bazaar indexing) set
`FACILITATOR=https://api.cdp.coinbase.com/platform/v2/x402` **and** `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET`
(Ed25519 key from the CDP portal). Each verify/settle call then carries a fresh 2-minute EdDSA JWT; if either key is
missing, requests go out without auth exactly as before. CDP returns the same settle fields (`success`, `transaction`,
`payer`, `network`), so the settlement tx hash handling is unchanged.

