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
| `issued_at`, `expires_at` | UTC, second precision; validity window (default 900 s, at most 24 h) |
| `issuer` | `{name, key_id, issuer_url, contact}` |
| `subject` | `{type: "x402_endpoint", url}` |
| `claims.facts` | the Pre-pay Check facts (schema `prepay-check/v1`): reachability, 402 challenge, Bazaar snapshot facts |
| `claims.payto_code` | for each distinct payTo (at most 4): `eth_getCode` at latest Base block, `kind` = `eoa` (no code), `eip7702_delegated` (code is the EIP-7702 designator `0xef0100` + delegate address, given in `delegate`), `contract`, or `null` if the lookup failed |
| `claims.checks` | `[{id, status: pass / fail / not_applicable, observed, expected?}]` |
| `claims.checks_passed`, `claims.checks_failed` | the check ids with that status |
| `signature` | `{alg: "Ed25519", key_id, value_b64}` |

Check ids in v1.0: `endpoint_reachable`, `http_402_returned`, `challenge_well_formed`, `network_is_base` (expected `eip155:8453`),
`asset_is_base_usdc` (expected `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`), `payto_is_eoa`, `bazaar_snapshot_available`, `listed_in_bazaar`.
`payto_is_eoa` passes for `eoa` and `eip7702_delegated` (an externally owned account with delegated code; see `claims.payto_code` for the delegate) and fails for `contract`.
`not_applicable` means the input needed for the check was not observed (for example no 402 challenge, or an RPC lookup failed).

## Signing

Signed bytes = UTF-8 of the RFC 8785 canonical form of the envelope with the `signature` member removed.
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

Steps: remove `signature`; JCS-canonicalize; find the key by `key_id` in the issuer document and check its
`key_id` derivation; verify Ed25519; optionally reject when now is after `expires_at`.

`test-vectors.json` holds JCS cases and one signed attestation (public key only) for cross-implementation tests.
