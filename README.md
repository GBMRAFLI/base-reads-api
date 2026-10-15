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

Pay-per-call Base mainnet reads for agents, via [x402](https://x402.org) v2 (USDC on Base, `exact` scheme). Deterministic JSON-RPC reads only; no LLMs.

| Route | Price | Returns |
|---|---|---|
| `GET /base/usdc-balance?address=0x…` | $0.001 | USDC + ETH balance |
| `GET /base/tx-status?hash=0x…` | $0.002 | success/failed/pending, block, confirmations, gas |
| `GET /base/basename?name=jesse` or `?address=0x…` | $0.003 | Basename ⇄ address (reverse is forward-verified) |
| `GET /base/network` | $0.001 | block, block age, base fee, gas price |
| `GET /base/address-intel?address=0x…` | $0.005 | USDC+ETH, verified Basename, tx count, is_contract |

Unpaid requests return `402` with a `PAYMENT-REQUIRED` header. Invalid input or RPC errors are never settled, so you are not charged for them.

Maintained by GBMRAFLI.

## Pre-pay Check (`GET /x402/preflight?url=`) — $0.001 USDC on Base
Signed (Ed25519) deterministic facts about an x402 endpoint before you pay it: challenge validity,
reachability and latency, host listing count, payout wallet reuse across hosts, last-called time and
payer trend from daily Bazaar snapshots. Facts only; no advice. Public key: `GET /x402/preflight/pubkey`.
Hook examples for the official clients: `examples/ts/preflight-hook.ts`, `examples/python/preflight_hook.py`.
Daily snapshot job: `python scripts/bazaar_snapshot.py` (see `render.yaml`).

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
record format. Storage: Deno KV. Daily Bazaar snapshot: `Deno.cron` at 00:15 UTC.
Entry point `deno/main.ts`; env: `SIGNING_KEY_PASSPHRASE`, `SIGNING_KEY_ENC_B64`, `EXPORT_TOKEN` (+ optional `PAY_TO_ADDRESS`,
`SELF_WALLETS`, `PUBLIC_URL`, `RPC`, `FACILITATOR`, `NETWORK`). Contract fixtures come from the Python reference
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

