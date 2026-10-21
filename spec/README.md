# Pre-pay Check Attestation v1.0

License: this specification, the JSON Schema (`prepay-check-attestation-v1.schema.json`), the test vectors
(`test-vectors.json`) and the verifier scripts (`scripts/verify_attestation.py`, `scripts/verify_attestation.ts`)
are dedicated to the public domain under CC0 1.0 Universal.

Contact: gbmrafli@agentmail.to

## What it is

A signed, machine-verifiable record of deterministic facts observed about one x402 endpoint at one moment,
before a buyer pays it. It contains facts and per-check observations only. It has no score, no rating, no overall
verdict and no advice to pay, buy or sell. A `pass` means only that the stated observation matched the stated expectation.

The paid route `GET /x402/preflight?url=<endpoint>` (0.010 USDC, x402 v2, `PAYMENT-REQUIRED` challenge) returns:

```json
{ "facts": { ... }, "signature": { ... }, "attestation": { ...v1.0 envelope... } }
```

`facts` + `signature` is the earlier format, kept for existing verifiers for a transition period. New verifiers should use `attestation`.

## Envelope

| field | meaning |
|---|---|
| `spec` | `"prepay-check-attestation"` |
| `version` | `"1.0"` |
| `canonicalization` | `"JCS"` (RFC 8785) |
| `attestation_id` | random UUID v4 |
| `issued_at`, `expires_at` | UTC, `YYYY-MM-DDTHH:MM:SSZ`; validity window is an integer number of seconds, default 900, at most 86400 |
| `issuer` | `{name, key_id, issuer_url, contact}` |
| `subject` | `{type: "x402_endpoint", url}` |
| `claims.facts` | the Pre-pay Check facts (schema `prepay-check/v1`): reachability, 402 challenge, Bazaar snapshot facts |
| `claims.payto_code` | for each distinct payTo (at most 4): `eth_getCode` at latest Base block, `kind` = `eoa` (no code), `eip7702_delegated` (code is the EIP-7702 designator `0xef0100` + delegate address, given in `delegate`), `contract`, or `null` if the lookup failed |
| `claims.checks` | `[{id, status: pass / fail / not_applicable, observed, expected?}]` |
| `claims.checks_passed`, `claims.checks_failed` | the check ids with that status |
| `signature` | `{alg: "Ed25519", key_id, value_b64}` |

Check ids in v1.0: `endpoint_reachable`, `http_402_returned`, `challenge_well_formed`, `network_is_base` (expected `eip155:8453`),
`asset_is_base_usdc` (expected `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`), `payto_is_eoa`, `bazaar_snapshot_available`, `listed_in_bazaar`,
`responds_within_5000ms` (the probe times out at 5 s; a timeout is a `fail`), `pay_to_matches_snapshot` (payTo set in the live 402
equals the payTo set recorded for the resource in the Bazaar snapshot; also given as `claims.pay_to_matches_snapshot`, `null` when not comparable).

Snapshot binding: `claims.facts.bazaar.snapshot_sha256` is the sha256 of the stored snapshot the facts were read from. The same
hash is published per date at `/bazaar/snapshots` and for the newest date in the signed `/.well-known/bazaar-snapshot.json`.
The service re-checks the hash on every load and reports `snapshot_hash_mismatch` instead of using a modified snapshot.
Both verifiers take `--snapshots FILE|URL` (the `/bazaar/snapshots` document) and reject an attestation whose snapshot hash differs
from the published one.
`payto_is_eoa` passes only for `eoa`. It fails for `contract` and for `eip7702_delegated` (an account whose code delegates
execution to another address); `observed` then shows `kind` and `delegate`, so a reader can apply their own policy.
`network` and `asset` values are reported only when they are JSON strings; anything else is reported as `null`.
`not_applicable` means the input needed for the check was not observed (for example no 402 challenge, or an RPC lookup failed).

## Signing

Signed bytes = UTF-8 of the domain prefix `prepay-check-attestation/v1` followed by a line feed (`\n`), then the
RFC 8785 canonical form of the envelope with the `signature` member removed.

Domain separation: the free snapshot metadata (`/.well-known/bazaar-snapshot.json`) is signed over
`bazaar-snapshot-meta/v1` + `\n` + JCS(metadata) with the same key, and the legacy `{facts, signature}` form is signed over
sorted-key JSON of `facts` with no prefix. A signature from one of these can never verify as another.
The prefix bytes are `7072657061792d636865636b2d6174746573746174696f6e2f76310a` (attestation) and the UTF-8 of
`bazaar-snapshot-meta/v1\n` (snapshot metadata); `/.well-known/issuer.json` publishes both under `signing.domains`.
Signature = Ed25519 (RFC 8032), standard base64. `key_id` = first 16 hex characters of sha256(raw 32-byte public key).

Signing keys are generated and held only in the production server environment. They are never committed to this
repository, never published and never exported; tests use throwaway keys generated in memory.

## Keys and rotation

`GET /.well-known/issuer.json` lists the issuer identity and every key: the active key and retired keys with
`retired_at`. Retired keys stay listed so older attestations remain verifiable. A verifier should reject an
attestation whose `issued_at` is after its key's `retired_at`.

## Verifying

```
python3 scripts/verify_attestation.py response.json            # uses issuer.issuer_url
deno run --allow-net --allow-read scripts/verify_attestation.ts response.json --issuer issuer.json
```

Steps (both official verifiers do all of them):
1. Parse JSON strictly (duplicate object keys are rejected).
2. `signature.key_id` must equal `issuer.key_id`, must be listed exactly once in the issuer document (and equal `--key-id` if given),
   and must equal the first 16 hex chars of sha256 of that listed public key.
3. `issued_at` and `expires_at` must be valid timestamps; `0 <= expires_at - issued_at <= 86400` s; `issued_at <= now + 60` s.
4. Remove `signature`, build `prepay-check-attestation/v1\n` + JCS, verify Ed25519.
5. Reject when now is after `expires_at` (unless explicitly ignored), or when the key was retired before `issued_at`.

`test-vectors.json` holds JCS cases and one signed attestation (public key only) for cross-implementation tests.

### Snapshot hash binding

`/.well-known/bazaar-snapshot.json` signs `snapshot_sha256`, a map of date to content hash for the last 30 snapshots, so `claims.facts.bazaar.snapshot_sha256` of any recent attestation can be bound to a signed value. The hash is computed by the issuer from its own stored snapshot; it proves consistency with what the issuer published, not independent provenance of the Bazaar data.
