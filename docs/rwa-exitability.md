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

| Field | Meaning |
|---|---|
| `transfer_eligibility` | who may hold / receive the token (allow-list, KYC, jurisdiction) as stated by the issuer |
| `nav_freshness` | the latest published NAV and its as-of time |
| `redemption_path` | how a holder redeems (issuer redemption, on-chain facility, secondary venue) |
| `redemption_timing` | stated settlement time or cut-off for redemptions |
| `instant_capacity` | announced instant-redemption capacity, if any |
| `pause_freeze` | whether the token or redemptions are stated or observed as paused / frozen |

`confidence.level` is computed from coverage only: `none` (0 of 6 fields cited), `low` (< 3), `medium` (3-5), `high` (6).
It says how much is documented, not whether the asset is liquid.

## Dataset

The data ships in the repo as `spec/rwa-exitability-dataset.json` (`rwa-exitability-dataset/1`), versioned by
`dataset_revision`. Each field entry must have exactly `value`, `source_url` (https) and `retrieved_at` (ISO-8601 UTC);
a field with no cited source is simply omitted and is served as `not_disclosed`.

```sh
cd deno
deno run -A scripts/rwa_dataset.ts validate                 # schema check (also run by the tests)
deno run -A scripts/rwa_dataset.ts build <source_dir>       # rebuild from per-asset source files, bumps the revision
```

Source files for `build` are `<source_dir>/*.json`, each
`{"asset": "JAAA", "fields": {"<field>": {"value": ..., "source_url": "https://...", "retrieved_at": "...Z"}}}`.
Entries missing a value, an https source or a retrieval time are dropped and listed, never filled in.
