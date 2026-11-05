# RWA Exitability Check

`GET /rwa/exitability?asset=<SYMBOL>` — **5.000 USDC** per call (x402 v2, exact scheme, USDC on Base), same payment
flow as the other paid routes. Supported assets: `JAAA`, `USYC`, `mWIN` (matched case-insensitively).

What it is: a deterministic lookup of what public sources state about exiting a position in one tokenized real-world
asset. Every value carries the URL it came from and when it was retrieved. Anything without a cited source is
returned as `"not_disclosed"`. No language model, no scoring of the asset, no predictions.

**Not a liquidity guarantee, not a redemption promise, and not investment advice.**

## Requests

| Request | Result |
|---|---|
| no payment, supported or missing `asset` | `402` with the `PAYMENT-REQUIRED` challenge (`extensions.bazaar` included) |
| no payment, unknown `asset` | `400 {"error": "unknown asset; supported: JAAA, USYC, mWIN"}`, no challenge, nothing charged |
| paid, unknown or missing `asset` | `400`, payment not settled |
| paid, supported `asset` | `200` JSON below, served after the transfer is confirmed on-chain |
| `X-Trial-Key` (valid, within quota) | `200` JSON, same as paid |

## Response (`rwa-exitability/v1`)

```json
{
  "schema": "rwa-exitability/v1",
  "asset": "JAAA",
  "checked_at": "2026-11-05T05:40:00Z",
  "dataset": { "version": "rwa-exitability-dataset/1", "revision": 1, "generated_at": "2026-11-05T05:40:00Z" },
  "fields": {
    "transfer_eligibility": "not_disclosed",
    "nav_freshness": "not_disclosed",
    "redemption_path": "not_disclosed",
    "redemption_timing": "not_disclosed",
    "instant_capacity": "not_disclosed",
    "pause_freeze": "not_disclosed"
  },
  "sources": {
    "transfer_eligibility": "not_disclosed",
    "nav_freshness": "not_disclosed",
    "redemption_path": "not_disclosed",
    "redemption_timing": "not_disclosed",
    "instant_capacity": "not_disclosed",
    "pause_freeze": "not_disclosed"
  },
  "confidence": { "level": "none", "disclosed_fields": 0, "total_fields": 6,
    "basis": "share of fields with a cited public source; not a quality or risk rating" },
  "disclaimer": "Reported facts from cited public sources at the stated retrieval times. Not a liquidity guarantee, not a redemption promise, and not investment advice. Fields marked not_disclosed had no cited source in this dataset revision."
}
```

A cited field looks like `"fields": {"redemption_path": <value>}` with
`"sources": {"redemption_path": {"url": "https://...", "retrieved_at": "2026-...Z"}}`.
A field read from a contract also carries the call that produced it, and `url` is the contract's block-explorer page:
`"sources": {"pause_freeze": {"url": "https://<explorer>/address/0x...", "retrieved_at": "2026-...Z",
"onchain": {"chain": "ethereum", "address": "0x...", "function": "paused()", "block": 12345678}}}`.
`onchain` appears only when the field is cited to that contract read (`url` is the explorer page of `onchain.address`);
values cited to a document carry no `onchain`. `function` is a signature, up to four signatures joined by `/` when a value combines several calls, or a 4-byte selector. Raw call results are not included; `fields` holds the reported value.

| Field | Meaning |
|---|---|
| `transfer_eligibility` | who may hold / receive the token (allow-list, KYC, jurisdiction) as stated by the issuer |
| `nav_freshness` | the latest published NAV and its as-of time |
| `redemption_path` | how a holder redeems (issuer redemption, on-chain facility, secondary venue) |
| `redemption_timing` | stated settlement time or cut-off for redemptions |
| `instant_capacity` | announced instant-redemption capacity, if any |
| `pause_freeze` | whether the token or redemptions are stated or observed as paused / frozen |

`confidence.level` is computed from coverage only: `none` (0 of 6 fields cited), `low` (< 3), `medium` (3-5), `high` (6).
It says how much is documented, not whether the asset is liquid. There is no per-field confidence in the response:
every served field meets the same bar (a value, a cited source and a retrieval time), and a second, subjective score
per field would read like a quality rating.

## Dataset

The data ships in the repo as `spec/rwa-exitability-dataset.json` (`rwa-exitability-dataset/1`), versioned by
`dataset_revision`. Each field entry has exactly `value`, `source_url` (https) and `retrieved_at` (ISO-8601 UTC), plus
an optional `onchain` with exactly `chain`, `address`, `function`, `block` (positive integer); a field with no cited
source is simply omitted and is served as `not_disclosed`.

```sh
cd deno
deno run -A scripts/rwa_dataset.ts validate                 # schema check (also run by the tests)
deno run -A scripts/rwa_dataset.ts build <source_dir>       # rebuild from per-asset source files, bumps the revision
```

Source files for `build` are one per asset (`<source_dir>/JAAA.json`, `USYC.json`, `mWIN.json`), each
`{"asset": "JAAA", "fields": {"<field>": {"value": ..., "source_url": "https://...", "retrieved_at": "...Z",
"confidence": ..., "refresh_method": ..., "onchain": {"chain", "address", "function" | "selector", "block", "result"}}}}`.
- `value: null` means no public source: the field is dropped and served as `not_disclosed`.
- Entries missing a value, an https source or a retrieval time are dropped and listed, never filled in.
- `onchain` is reduced to `chain`, `address`, `function` (or `selector`), `block`. If that is not a valid citation, the
  entry is dropped when `source_url` is the explorer page, otherwise it is kept on its document source without `onchain`.
- A valid `onchain` is kept only when `source_url` is the explorer page of `onchain.address`; otherwise it is omitted
  and the document source stands (also enforced by the runtime validator).
- A `source_url` that looks like an RPC endpoint, a keyed API URL, an internal address or path, or carries
  `user:pass@` userinfo drops the entry; the runtime validator rejects userinfo and internal paths too.
- The shipped dataset is validated when the server loads; an invalid file fails startup.
- Only `<SYMBOL>.json` for the supported symbols is read; other files in the directory are ignored.
- `result`, `confidence`, `refresh_method` and any other keys are ignored and never shipped.

## Known behaviour

An unknown `asset` is answered 400 (or 429) before the payment header is read and always counts against the per-client
unpaid limit. On the other routes a malformed payment header is answered 400 without counting against that limit; this
is pre-existing and costs one header parse, no network call.
