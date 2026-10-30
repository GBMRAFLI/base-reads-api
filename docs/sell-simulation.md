# Sell simulation and pre-sign verdict (prototype)

Status: local prototype. **Not wired to any HTTP route**; no existing route changes. Free, no paywall.
Everything is read-only: `eth_call` with state overrides at a pinned block. Nothing is signed or broadcast on-chain.
No LLM in the path; the verdict is a pure function of simulated facts and the thresholds below.

## Input

- a Base token address, or
- an unsigned Base tx `{to, data, value, from}`.

## Pipeline

1. **Decode** (`deno/lib/presign.ts`, `deno/lib/abi.ts`):
   - ERC20 `approve`, `increaseAllowance`, EIP-2612 `permit`, DAI-style `permit`, Permit2 `approve`, UR `PERMIT2_PERMIT`
   - `transfer`, `transferFrom`
   - Uniswap v2 router swaps (all exact-in/out and fee-on-transfer variants)
   - SwapRouter02 `exactInput[Single]`, `exactOutput[Single]`, `multicall`
   - Universal Router `execute`: V2/V3 swap commands, `V4_SWAP` (`SWAP_EXACT_IN[_SINGLE]`, `SWAP_EXACT_OUT[_SINGLE]`), with pool keys and hooks
   - Direct PoolManager `unlock` and unknown selectors are reported under `unknowns`.
2. **Tx simulation:** `eth_call` of the tx itself at the pinned block. The sender's native balance is topped up by a state override only if it cannot cover `value` + 0.01 ETH; the override is recorded in the proof.
3. **Token sell simulation** (`deno/lib/sellsim.ts`) for every non-quote token involved, or for the token input:
   - Pool discovery:
     - v2 `getPair`
     - v3 `getPool`
     - v4 hookless enumeration over fee/tickSpacing × {ETH, WETH, USDC}
     - v4 `Initialize` logs after the token's creation block
   - Ranking by active-range quote depth (in ETH).
   - A helper contract (`contracts/SellSimHelper.sol`, injected by code override, never deployed) buys 0.001 ETH (or 3 USDC) worth, then sells everything it received, in the same call. It works on the v2 pair, the v3 pool callback, or the v4 PoolManager unlock/settle/take path.
   - If the deepest pool's buy leg reverts, up to 2 further pools are tried.
   - Taxes: `buy_tax = 1 - received/pool_out`; `sell_tax = 1 - (pool_in/sent)·(received/pool_out)`.
4. **Verification facts:**
   - Spender and hook source verification uses the free Sourcify API only.
   - Etherscan/Basescan need a key, so they are not used. `not_found` on Sourcify is reported as such, not as proof that a contract is unverified.
5. **Verdict + proof:** see below.

## Policy `presign-policy/0.2` (deterministic)

| condition | reason code | effect |
|---|---|---|
| tx `eth_call` reverts | `tx_reverts {data, message}` | **block** |
| sell leg reverts or returns 0 | `honeypot {token, stage, revert}` | **block** |
| buy or sell tax ≥ 30% | `buy_tax` / `sell_tax {pct}` | **block** |
| buy or sell tax > 1% and < 30% | `buy_tax` / `sell_tax {pct}` | warn |
| round-trip return < 0.80 | `low_round_trip_return {ratio}` | warn |
| approval ≥ 2^255 to an address with no code | `unlimited_approval_eoa_spender {spender}` | warn |
| approval ≥ 2^255 to a contract that is not a known spender and not Sourcify-verified | `unlimited_approval_unverified_spender {spender, verification}` | warn |
| main pool is v4 with a non-zero hook not on the allowlist (allowlist is empty) | `main_liquidity_v4_hook {pool, hook}` | warn |
| buy leg reverts in all tried pools | `buy_reverts` | warn (+ unknown) |
| no supported pool, token Sourcify-verified | `no_supported_liquidity {severity: normal}` | warn (+ unknown) |
| no supported pool, token not Sourcify-verified (or lookup failed) | `no_supported_liquidity_unverified_token {severity: high, verification}` | warn (+ unknown) |
| any other unknown (rpc error, undecoded calldata) | in `unknowns` | at least warn |

Otherwise the verdict is **allow**.

Changes in 0.2: added the `severity` field and the `no_supported_liquidity_unverified_token` code. When there is no simulatable pool, the outcome cannot be measured. A closed-source token in that state cannot be checked by either code reading or simulation, so the warning is stronger. It stays `warn`, not `block`, because block is reserved for observed failures (revert, honeypot, tax), and missing evidence is not proof of a trap.

Pool selection: pools with in-range liquidity are tried first. If none exist, pools that exist but have zero in-range liquidity (v3 `liquidity()==0`, positions out of range) are still simulated (`pool_mode: zero_active_liquidity_fallback`), because a swap can cross into out-of-range ticks. An empty factory response (`0x`) is an RPC error recorded in `discovery_notes`, never "no pool". Each v3 fee tier and quote is checked independently.

Known spenders are the canonical Uniswap v2 router, SwapRouter02, the Universal Routers, Permit2 and the v4 PoolManager on Base.

The thresholds live in `POLICY` in `deno/lib/presign.ts` and are copied into every proof.

## Proof

- Spec `sell-simulation-attestation` 0.1. The envelope is JCS-canonicalized and Ed25519-signed over `"sell-simulation-attestation/v1\n" + JCS(envelope without signature)`.
- Signing uses the same `Signer`/`keyIdOf` scheme as the existing attestation. TTL is 24 h.
- `claims` holds everything needed to replay:
  - the block number and hash
  - every `eth_call` object
  - the state overrides (helper code and its sha256/solc version, balances)
  - the raw results, decoded amounts, verdict, reasons, unknowns and policy

To replay:

```
cd deno && deno run -A tools/verify_sellsim.ts --pubkey <b64> proof.json
```

This checks the signature, re-runs each `eth_call` at the same block, and compares the raw results. It needs an RPC that serves state at that block.

## Keys

- **Local:** `tools/sellsim.ts` / `tools/presign.ts --test-key <file>` create or use a throwaway Ed25519 key. It is labeled `THROWAWAY LOCAL TEST KEY`, written with mode 0600 outside the repo, and never printed.
- **Production:** when `SIGNING_KEY_*` env vars are set, the CLIs use `envSigner()` from `lib/sign.ts` instead. No code change is needed.

## RPCs

These are environment variables with free public defaults:

- `SELLSIM_RPC`: `mainnet.base.org`, falling back to `base.drpc.org` and then `base-rpc.publicnode.com`
- `SELLSIM_LOGS_RPC`: the Tenderly public gateway, 1000-block log chunks
- `SELLSIM_ARCHIVE_RPC`: used for the creation-block search

## Rebuilding the helper

```
NODE_PATH=<dir with solc@0.8.26>/node_modules node deno/tools/compile_sellsim_helper.cjs contracts/SellSimHelper.sol deno/lib/sellsim_helper.ts
```

The output is byte-for-byte reproducible. A unit test checks the pinned source sha256.

## Limitations

- **Venues:** only Uniswap v2/v3/v4 pools against ETH, WETH or USDC are covered. Tokens whose liquidity lives on Aerodrome or other DEXes show `no_supported_liquidity`.
- **Probe:** a single small probe trade from a fresh contract address at one block. Taxes or blocks that depend on sender, size, time, cooldowns, max-tx or max-wallet, or later owner actions are not detected. Hooks are simulated, not analysed.
- **v4 log discovery:** limited to the first 3000 blocks after token creation, using free-RPC log limits. Pools initialized later are found only if they are hookless.
- **Tx simulation:** a single call; ERC20 balances and allowances of the sender are not overridden. A tx from an unfunded sender reverts and is reported as `tx_reverts`. A replay of a reverted tx compares only the revert, not the revert data.
- **Unsupported decoding:** Permit2 `permitBatch`, DAI-style permits with `allowed=false`, v4 `exact out` amounts, and other routers. These appear in `unknowns` when not decoded.
