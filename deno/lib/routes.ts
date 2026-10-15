// Generated from api/index.py ROUTES (order preserved). Keep in sync: tests compare against the Python fixture.
export const PAY_TO_DEFAULT = "0x427F423908233DbCA2C51e4c6AE36D18f821641c"; // public receive-only payee wallet (same default as Python)
export const ROUTES: Record<string, [number, string, Record<string, string>]> = {
  "/base/usdc-balance": [1000, "Base mainnet USDC + ETH balance for any address (live eth_call). Query: ?address=0x...", {"address": "0x4200000000000000000000000000000000000016"}],
  "/base/tx-status": [2000, "Base mainnet transaction status: success/failed/pending, block, confirmations, gas used, from/to. Query: ?hash=0x...", {"hash": "0x0000000000000000000000000000000000000000000000000000000000000000"}],
  "/base/basename": [3000, "Resolve a Basename (name.base.eth) to its Base address, or an address to its primary Basename. Query: ?name=jesse.base.eth or ?address=0x...", {"name": "jesse.base.eth"}],
  "/base/address-intel": [5000, "One call: Base USDC balance, ETH balance, verified primary Basename, tx count (nonce) and is_contract for an address. Query: ?address=0x...", {"address": "0x2211d1d0020daea8039e46cf1367962070d77da9"}],
  "/x402/preflight": [1000, "Pre-pay Check: Ed25519-signed deterministic facts about an x402 endpoint before you pay it: challenge validity, reachability and latency, host listing count, payout wallet reuse across hosts, last-called and payer trend from Bazaar snapshots. Facts only, no advice. Query: ?url=https://...", {"url": "https://x402.org/protected"}],
  "/base/network": [1000, "Base mainnet head: block number, block age seconds, base fee and gas price in gwei.", {}],
};
