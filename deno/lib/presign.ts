// Pre-sign check: decode an unsigned Base tx (or take a bare token), simulate it read-only
// (eth_call at a pinned block, optional state overrides), run the token sell simulation for
// every token involved, and map the facts to allow | warn | block with a fixed, documented policy.
// Never signs or sends a transaction. No network calls except the injected rpc / lookup functions.
import { decode, selector } from "./abi.ts";
import { CHAIN_ID, ETH, isAddr, POOL_MANAGER, Rpc, sellSim, signProof, USDC, WETH, decodeRevert } from "./sellsim.ts";
import { jcs, type Signer } from "./attestation.ts";
import { sha256 } from "@noble/hashes/sha2";
import { hex } from "./util.ts";

export const POLICY_VERSION = "presign-policy/0.2";
export const POLICY = {
  block_tax_at_or_above: 0.30,   // buy or sell tax >= 30% -> block
  warn_tax_above: 0.01,          // buy or sell tax > 1% -> warn (rounding noise below)
  warn_round_trip_below: 0.80,   // buy then sell of the probe amount returns < 80% -> warn (pool fees + impact + tax)
  unlimited_approval_at_or_above: (1n << 255n).toString(), // >= 2^255 treated as unlimited (covers max uint256 and common max-ish values)
  // 0.2: every approval-type grant (approve, increaseAllowance, permit, Permit2 approve) with amount > 0 to a spender
  // outside KNOWN_SPENDERS is at least warn. "large" = amount >= min(token totalSupply, 2^128); a large grant to an
  // EOA or a non-verified contract gets severity "high" (verdict stays warn: no harm has been observed yet).
  large_approval_cap: (1n << 128n).toString(),
  // 0.2: native value or ERC20 transfer/transferFrom to an address with no code and nonce 0 -> warn (transfer_to_fresh_eoa)
  verification_source: "sourcify (free public API, chain 8453)",
} as const;
const UNLIMITED = 1n << 255n;
const LARGE_CAP = 1n << 128n;
export const MAX_UINT = (1n << 256n) - 1n;

// Spenders treated as known: canonical Uniswap / Permit2 deployments on Base.
export const KNOWN_SPENDERS: Record<string, string> = {
  "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24": "uniswap_v2_router02",
  "0x2626664c2603336e57b271c5c0b26f421741e481": "uniswap_swap_router02",
  "0x6ff5693b99212da76ad316178a184ab56d299b43": "uniswap_universal_router_v4",
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "uniswap_universal_router_v1_2",
  "0x000000000022d473030f116ddee9f6b43ac78ba3": "permit2",
  [POOL_MANAGER]: "uniswap_v4_pool_manager",
};
// v4 hooks treated as known. Empty by default: any non-zero hook on the main pool warns.
export const HOOK_ALLOWLIST: Record<string, string> = {};
const QUOTES = new Set([ETH, WETH, USDC]);

export type Tx = { to: string; data?: string; value?: string | number | bigint; from?: string };
export type Approval = { kind: string; token: string; spender: string; amount: string; unlimited: boolean };
export type SwapLeg = { venue: string; token_in: string | null; token_out: string | null; pool_key?: Record<string, unknown> };
export type Decoded = { method: string; target: string; approvals: Approval[]; transfers: { token: string; to: string; amount: string }[]; swaps: SwapLeg[]; tokens: string[]; notes: string[] };

const S = (sig: string) => selector(sig);
const lc = (a: string) => a.toLowerCase();
const appr = (kind: string, token: string, spender: string, amt: bigint): Approval => ({ kind, token: lc(token), spender: lc(spender), amount: amt.toString(), unlimited: amt >= UNLIMITED });
export function v3Path(path: string): string[] {
  const h = path.replace(/^0x/, ""); const out: string[] = [];
  for (let i = 0; i + 40 <= h.length; i += 46) out.push("0x" + h.slice(i, i + 40).toLowerCase());
  return out;
}
const POOLKEY = "(address,address,uint24,int24,address)";
const keyObj = (k: any[]) => ({ currency0: lc(k[0]), currency1: lc(k[1]), fee: Number(k[2]), tick_spacing: Number(k[3]), hooks: lc(k[4]) });

const ABI: Record<string, { sig: string; f: (a: any[], d: Decoded, to: string) => void }> = {};
const reg = (sig: string, f: (a: any[], d: Decoded, to: string) => void) => { ABI[S(sig)] = { sig, f }; };
reg("approve(address,uint256)", (a, d, to) => d.approvals.push(appr("erc20_approve", to, a[0], a[1])));
reg("increaseAllowance(address,uint256)", (a, d, to) => d.approvals.push(appr("erc20_increase_allowance", to, a[0], a[1])));
reg("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", (a, d, to) => d.approvals.push(appr("eip2612_permit", to, a[1], a[2])));
reg("permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)", (a, d, to) => d.approvals.push(appr("dai_permit", to, a[1], a[4] ? MAX_UINT : 0n)));
reg("approve(address,address,uint160,uint48)", (a, d) => d.approvals.push(appr("permit2_approve", a[0], a[1], a[2] >= (1n << 159n) ? MAX_UINT : a[2])));
reg("transfer(address,uint256)", (a, d, to) => d.transfers.push({ token: lc(to), to: lc(a[0]), amount: a[1].toString() }));
reg("transferFrom(address,address,uint256)", (a, d, to) => d.transfers.push({ token: lc(to), to: lc(a[1]), amount: a[2].toString() }));
// Uniswap v2 router
const v2 = (inEth: boolean, outEth: boolean, pathIdx: number) => (a: any[], d: Decoded) => {
  const p = (a[pathIdx] as string[]).map(lc);
  d.swaps.push({ venue: "v2_router", token_in: inEth ? ETH : p[0], token_out: outEth ? ETH : p[p.length - 1] }); d.tokens.push(...p);
};
reg("swapExactETHForTokens(uint256,address[],address,uint256)", v2(true, false, 1));
reg("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)", v2(true, false, 1));
reg("swapETHForExactTokens(uint256,address[],address,uint256)", v2(true, false, 1));
reg("swapExactTokensForETH(uint256,uint256,address[],address,uint256)", v2(false, true, 2));
reg("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)", v2(false, true, 2));
reg("swapTokensForExactETH(uint256,uint256,address[],address,uint256)", v2(false, true, 2));
reg("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)", v2(false, false, 2));
reg("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)", v2(false, false, 2));
reg("swapTokensForExactTokens(uint256,uint256,address[],address,uint256)", v2(false, false, 2));
// SwapRouter02 (v3)
reg("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))", (a, d) => { const p = a[0]; d.swaps.push({ venue: "v3_router", token_in: lc(p[0]), token_out: lc(p[1]) }); d.tokens.push(lc(p[0]), lc(p[1])); });
reg("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))", (a, d) => { const p = a[0]; d.swaps.push({ venue: "v3_router", token_in: lc(p[0]), token_out: lc(p[1]) }); d.tokens.push(lc(p[0]), lc(p[1])); });
reg("exactInput((bytes,address,uint256,uint256))", (a, d) => { const p = v3Path(a[0][0]); d.swaps.push({ venue: "v3_router", token_in: p[0], token_out: p[p.length - 1] }); d.tokens.push(...p); });
reg("exactOutput((bytes,address,uint256,uint256))", (a, d) => { const p = v3Path(a[0][0]); d.swaps.push({ venue: "v3_router", token_in: p[p.length - 1], token_out: p[0] }); d.tokens.push(...p); });
const multi = (idx: number) => (a: any[], d: Decoded, to: string) => { for (const c of a[idx] as string[]) decodeInto(c, to, d, 1); };
reg("multicall(bytes[])", multi(0)); reg("multicall(uint256,bytes[])", multi(1)); reg("multicall(bytes32,bytes[])", multi(1));
// Universal Router
const ur = (a: any[], d: Decoded) => decodeUniversal(a[0], a[1], d);
reg("execute(bytes,bytes[],uint256)", ur); reg("execute(bytes,bytes[])", ur);
reg("unlock(bytes)", (_a, d) => d.notes.push("pool_manager_unlock: callback payload is caller-defined and is not decoded"));

export const UR_CMD: Record<number, string> = { 0x00: "V3_SWAP_EXACT_IN", 0x01: "V3_SWAP_EXACT_OUT", 0x02: "PERMIT2_TRANSFER_FROM", 0x04: "SWEEP", 0x05: "TRANSFER", 0x06: "PAY_PORTION",
  0x08: "V2_SWAP_EXACT_IN", 0x09: "V2_SWAP_EXACT_OUT", 0x0a: "PERMIT2_PERMIT", 0x0b: "WRAP_ETH", 0x0c: "UNWRAP_WETH", 0x10: "V4_SWAP" };
export function decodeUniversal(commands: string, inputs: string[], d: Decoded) {
  const cmds = (commands.replace(/^0x/, "").match(/../g) ?? []).map((x) => parseInt(x, 16));
  cmds.forEach((c, i) => {
    const t = c & 0x3f, name = UR_CMD[t], inp = inputs[i];
    try {
      if (t === 0x00 || t === 0x01) { const [, , , path] = decode(["address", "uint256", "uint256", "bytes", "bool"], inp); const p = v3Path(path); const inT = t === 0 ? p[0] : p[p.length - 1], outT = t === 0 ? p[p.length - 1] : p[0]; d.swaps.push({ venue: "universal_router_v3", token_in: inT, token_out: outT }); d.tokens.push(...p); }
      else if (t === 0x08 || t === 0x09) { const [, , , path] = decode(["address", "uint256", "uint256", "address[]", "bool"], inp); const p = (path as string[]).map(lc); d.swaps.push({ venue: "universal_router_v2", token_in: p[0], token_out: p[p.length - 1] }); d.tokens.push(...p); }
      else if (t === 0x0a) { const [ps] = decode(["((address,uint160,uint48,uint48),address,uint256)", "bytes"], inp); d.approvals.push(appr("permit2_permit_single", ps[0][0], ps[1], ps[0][1] >= (1n << 159n) ? MAX_UINT : ps[0][1])); }
      else if (t === 0x10) { const [actions, params] = decode(["bytes", "bytes[]"], inp); decodeV4Actions(actions, params, d); }
      else if (name) d.notes.push(`ur_command_${name}`);
      else d.notes.push(`ur_command_0x${t.toString(16)}_not_decoded`);
    } catch (e) { d.notes.push(`ur_command_${name ?? t}_decode_failed: ${(e as Error).message}`); }
  });
}
export const V4_ACTION: Record<number, string> = { 0x06: "SWAP_EXACT_IN_SINGLE", 0x07: "SWAP_EXACT_IN", 0x08: "SWAP_EXACT_OUT_SINGLE", 0x09: "SWAP_EXACT_OUT",
  0x0b: "SETTLE", 0x0c: "SETTLE_ALL", 0x0d: "SETTLE_PAIR", 0x0e: "TAKE", 0x0f: "TAKE_ALL", 0x10: "TAKE_PORTION", 0x11: "TAKE_PAIR", 0x12: "CLOSE_CURRENCY", 0x14: "SWEEP" };
export function decodeV4Actions(actions: string, params: string[], d: Decoded) {
  const acts = (actions.replace(/^0x/, "").match(/../g) ?? []).map((x) => parseInt(x, 16));
  acts.forEach((a, i) => {
    if (a === 0x06 || a === 0x08) {
      const [p] = decode([`(${POOLKEY},bool,uint128,uint128,bytes)`], params[i]); const k = keyObj(p[0]); const z = p[1];
      const tin = z ? k.currency0 : k.currency1, tout = z ? k.currency1 : k.currency0;
      d.swaps.push({ venue: "universal_router_v4", token_in: a === 0x06 ? tin : tin, token_out: tout, pool_key: k }); d.tokens.push(k.currency0, k.currency1);
    } else if (a === 0x07 || a === 0x09) {
      const [p] = decode(["(address,(address,uint24,int24,address,bytes)[],uint128,uint128)"], params[i]);
      let cur = lc(p[0]); const start = cur;
      for (const pk of p[1]) { const next = lc(pk[0]); const [c0, c1] = cur < next ? [cur, next] : [next, cur];
        d.swaps.push({ venue: "universal_router_v4", token_in: a === 0x07 ? cur : next, token_out: a === 0x07 ? next : cur, pool_key: { currency0: c0, currency1: c1, fee: Number(pk[1]), tick_spacing: Number(pk[2]), hooks: lc(pk[3]) } });
        d.tokens.push(cur, next); cur = next; }
      void start;
    } else if (!V4_ACTION[a]) d.notes.push(`v4_action_0x${a.toString(16)}_not_decoded`);
  });
}
function decodeInto(data: string, to: string, d: Decoded, depth = 0) {
  const sel = data.slice(0, 10).toLowerCase(); const e = ABI[sel];
  if (!e) { d.notes.push(`selector_${sel}_not_decoded`); if (depth === 0) d.method = "unknown"; return; }
  const types = e.sig.slice(e.sig.indexOf("(") + 1, -1); const args = decode(splitTop(types), "0x" + data.slice(10));
  if (depth === 0) d.method = e.sig; else d.notes.push(`multicall_inner:${e.sig}`);
  e.f(args, d, to);
}
function splitTop(s: string): string[] { const out: string[] = []; let dd = 0, cur = "";
  for (const ch of s) { if (ch === "(") dd++; if (ch === ")") dd--; if (ch === "," && dd === 0) { out.push(cur); cur = ""; } else cur += ch; }
  if (cur) out.push(cur); return out; }

export function decodeTx(tx: Tx): Decoded {
  const to = lc(tx.to); const data = (tx.data ?? "0x").toLowerCase();
  const d: Decoded = { method: "unknown", target: to, approvals: [], transfers: [], swaps: [], tokens: [], notes: [] };
  if (data === "0x" || data.length < 10) { d.method = "native_transfer"; return d; }
  try { decodeInto(data, to, d); } catch (e) { d.method = "decode_failed"; d.notes.push("abi_decode_failed: " + (e as Error).message); }
  for (const a of d.approvals) d.tokens.push(a.token);
  for (const t of d.transfers) d.tokens.push(t.token);
  d.tokens = [...new Set(d.tokens.map(lc))].filter((x) => isAddr(x));
  return d;
}

// ---------- spender / hook facts ----------
export type Verification = { address: string; source: string; status: "verified" | "not_found" | "lookup_failed"; match?: string | null; http?: number | null };
export type Lookup = (addr: string) => Promise<Verification>;
export const sourcifyLookup = (fetchFn: typeof fetch = fetch): Lookup => async (addr) => {
  try {
    const r = await fetchFn(`https://sourcify.dev/server/v2/contract/${CHAIN_ID}/${addr}`, { signal: AbortSignal.timeout(15000) });
    const j: any = await r.json().catch(() => ({}));
    if (r.status === 200 && j.match) return { address: lc(addr), source: "sourcify", status: "verified", match: j.match, http: 200 };
    if (r.status === 404) return { address: lc(addr), source: "sourcify", status: "not_found", match: null, http: 404 };
    return { address: lc(addr), source: "sourcify", status: "lookup_failed", http: r.status };
  } catch { return { address: lc(addr), source: "sourcify", status: "lookup_failed", http: null }; }
};

// ---------- policy (pure) ----------
export type Reason = { code: string; [k: string]: unknown };
export type Unknown = { what: string; reason: string; [k: string]: unknown };
export type Facts = {
  tx_sim?: { reverted: boolean; revert_data?: string | null; message?: string | null; rpc_error?: string | null } | null;
  approvals: (Approval & { spender_known: string | null; spender_is_contract: boolean | null; spender_verification: Verification | null; token_total_supply?: string | null })[];
  fresh_recipients?: { to: string; token: string; amount: string; kind: string }[];
  token_sims: { token: string; sim: any | null; error?: string | null; hook_verification?: Verification | null; token_verification?: Verification | null }[];
};
const r6 = (x: number) => Math.round(x * 1e6) / 1e6;
export function evaluate(f: Facts): { verdict: "allow" | "warn" | "block"; reasons: Reason[]; unknowns: Unknown[] } {
  const reasons: Reason[] = [], unknowns: Unknown[] = []; const blocks = new Set<string>();
  const B = (r: Reason) => { reasons.push(r); blocks.add(r.code); };
  if (f.tx_sim) {
    if (f.tx_sim.rpc_error) unknowns.push({ what: "tx_simulation", reason: "rpc_error: " + f.tx_sim.rpc_error });
    else if (f.tx_sim.reverted) B({ code: "tx_reverts", data: f.tx_sim.revert_data ?? null, message: f.tx_sim.message ?? null });
  }
  for (const a of f.approvals) {
    if (a.spender_known || BigInt(a.amount) === 0n) continue; // revocations and known spenders are fine
    const ts = a.token_total_supply ? BigInt(a.token_total_supply) : null;
    const large = a.unlimited || BigInt(a.amount) >= (ts !== null && ts > 0n && ts < LARGE_CAP ? ts : LARGE_CAP);
    const base = { spender: a.spender, token: a.token, kind: a.kind, amount: a.amount, large };
    if (a.spender_is_contract === false) reasons.push({ code: "approval_eoa_spender", ...base, severity: large ? "high" : "normal" });
    else if (a.spender_is_contract === null) { unknowns.push({ what: "spender_code", reason: "eth_getCode failed", spender: a.spender }); reasons.push({ code: "approval_unverified_spender", ...base, verification: "unknown", severity: large ? "high" : "normal" }); }
    else if (a.spender_verification?.status === "verified") reasons.push({ code: "approval_unknown_verified_spender", ...base, severity: "normal" });
    else {
      reasons.push({ code: "approval_unverified_spender", ...base, verification: a.spender_verification?.status ?? "not_checked", severity: large ? "high" : "normal" });
      if (a.spender_verification?.status !== "not_found") unknowns.push({ what: "spender_verification", reason: "free verification lookup failed", spender: a.spender });
    }
  }
  for (const r of f.fresh_recipients ?? []) reasons.push({ code: "transfer_to_fresh_eoa", ...r, severity: "normal" });
  for (const t of f.token_sims) {
    const s = t.sim;
    if (!s) { unknowns.push({ what: "token_simulation", token: t.token, reason: t.error ?? "not_run" }); continue; }
    if (!s.selected) {
      unknowns.push({ what: "token_simulation", token: t.token, reason: "no_pool_found: " + (s.no_pool_reason ?? "") });
      // 0.2: closed-source (not Sourcify-verified, or lookup failed) + no simulatable pool = stronger warn; verdict stays warn
      const vs = t.token_verification?.status ?? "not_checked";
      if (vs === "verified") reasons.push({ code: "no_supported_liquidity", token: t.token, severity: "normal" });
      else reasons.push({ code: "no_supported_liquidity_unverified_token", token: t.token, severity: "high", verification: vs });
      continue;
    }
    const sel = s.selected; const sim = s.simulation;
    if (sel.version === 4 && sel.hooks && sel.hooks !== ETH && !HOOK_ALLOWLIST[sel.hooks]) {
      reasons.push({ code: "main_liquidity_v4_hook", token: t.token, pool: sel.pool, hook: sel.hooks, hook_verification: t.hook_verification?.status ?? "not_checked" });
      unknowns.push({ what: "hook_behavior", token: t.token, hook: sel.hooks, reason: "hook logic may depend on caller, time, size or state; only the probe trade at the pinned block was simulated" });
    }
    if (!sim || sim.rpc_error) { unknowns.push({ what: "token_simulation", token: t.token, reason: "rpc_error: " + (sim?.rpc_error ?? "none") }); continue; }
    const r = sim.result;
    if (r.stage === "buy_reverted") { unknowns.push({ what: "sellability", token: t.token, reason: "buy leg reverted in all tried pools, so the sell leg could not be simulated", revert: r.revert }); reasons.push({ code: "buy_reverts", token: t.token, revert: r.revert }); continue; }
    if (r.stage === "sell_reverted" || r.stage === "sell_zero") { B({ code: "honeypot", token: t.token, stage: r.stage, revert: r.revert, pool: sel.pool, version: sel.version }); continue; }
    for (const [k, v] of [["buy_tax", r.buy_tax], ["sell_tax", r.sell_tax]] as const) {
      if (v === null || v === undefined) continue;
      if (v >= POLICY.block_tax_at_or_above) B({ code: k, token: t.token, pct: r6(v * 100) });
      else if (v > POLICY.warn_tax_above) reasons.push({ code: k, token: t.token, pct: r6(v * 100) });
    }
    if (r.round_trip_return !== null && r.round_trip_return < POLICY.warn_round_trip_below) reasons.push({ code: "low_round_trip_return", token: t.token, ratio: r.round_trip_return });
  }
  const verdict = blocks.size ? "block" : reasons.length || unknowns.some((u) => u.what !== "hook_behavior") ? "warn" : "allow";
  return { verdict, reasons, unknowns };
}

// ---------- orchestration ----------
export function txSimOverrides(tx: Tx, balanceWei: bigint) {
  const value = BigInt(tx.value ?? 0);
  // only top up native balance when the sender cannot cover value + gas headroom; recorded in the proof
  if (!tx.from || balanceWei >= value + 10n ** 16n) return {};
  return { [lc(tx.from)]: { balance: "0x" + (value + 10n ** 18n).toString(16) } };
}
export async function presign(rpc: Rpc, input: { tx?: Tx; token?: string }, block: number, opts: { lookup?: Lookup; blockHash?: string; sellSimOpts?: Record<string, unknown>; skipTokens?: string[] } = {}) {
  const t0 = performance.now(); const lookup = opts.lookup ?? sourcifyLookup();
  const tagH = "0x" + block.toString(16);
  const blockHash: string = opts.blockHash ?? (await rpc("eth_getBlockByNumber", [tagH, false]))?.hash;
  if (!/^0x[0-9a-f]{64}$/i.test(blockHash ?? "")) throw new Error("block_hash_unavailable");
  const tag = "0x" + block.toString(16); const unknownsExtra: Unknown[] = [];
  let decoded: Decoded | null = null; let txSim: any = null; let tokens: string[] = [];
  if (input.tx) {
    const tx = input.tx; if (!isAddr(tx.to)) throw new Error("tx.to must be an address");
    decoded = decodeTx(tx); tokens = decoded.tokens;
    for (const n of decoded.notes) if (/not_decoded|decode_failed/.test(n)) unknownsExtra.push({ what: "calldata", reason: n });
    const from = tx.from && isAddr(tx.from) ? lc(tx.from) : "0x000000000000000000000000000000000000dead";
    const bal = BigInt(await rpc("eth_getBalance", [from, tag]).catch(() => "0x0"));
    const ov = txSimOverrides({ ...tx, from }, bal);
    const call: Record<string, string> = { from, to: lc(tx.to), data: tx.data ?? "0x", value: "0x" + BigInt(tx.value ?? 0).toString(16), gas: "0x" + (30_000_000).toString(16) };
    const st = performance.now();
    try { const raw = await rpc("eth_call", [call, tag, ov]); txSim = { call, block: tag, state_overrides: ov, reverted: false, raw_result: raw }; }
    catch (e) {
      const m = String((e as Error).message);
      if (/revert/i.test(m)) { const data = (m.match(/data=(0x[0-9a-fA-F]*)/) ?? [])[1] ?? null; const dr = data ? decodeRevert(data) : null; txSim = { call, block: tag, state_overrides: ov, reverted: true, revert_data: data, message: dr?.message ?? m.slice(0, 200) }; }
      else txSim = { call, block: tag, state_overrides: ov, reverted: false, rpc_error: m.slice(0, 200) };
    }
    txSim.eth_call_ms = Math.round(performance.now() - st);
  } else if (input.token && isAddr(input.token)) tokens = [lc(input.token)];
  else throw new Error("need tx or token");

  const approvals: Facts["approvals"] = [];
  for (const a of decoded?.approvals ?? []) {
    const known = KNOWN_SPENDERS[a.spender] ?? null; let isC: boolean | null = null, ver: Verification | null = null, ts: string | null = null;
    if (!known && BigInt(a.amount) > 0n) {
      try { isC = ((await rpc("eth_getCode", [a.spender, tag])) as string).length > 2; } catch { isC = null; }
      if (isC) ver = await lookup(a.spender);
      try { const r = await rpc("eth_call", [{ to: a.token, data: "0x18160ddd" }, tag]); ts = typeof r === "string" && r.length >= 66 ? BigInt(r.slice(0, 66)).toString() : null; } catch { ts = null; }
      if (ts === null) unknownsExtra.push({ what: "token_total_supply", reason: "totalSupply() unavailable; 2^128 cap used", token: a.token });
    }
    approvals.push({ ...a, spender_known: known, spender_is_contract: isC, spender_verification: ver, token_total_supply: ts });
  }
  // fresh-EOA recipients: native value transfer (empty calldata) and ERC20 transfer/transferFrom
  const fresh_recipients: NonNullable<Facts["fresh_recipients"]> = [];
  if (input.tx) {
    const recips: { to: string; token: string; amount: string; kind: string }[] = [];
    const v = BigInt(input.tx.value ?? 0);
    if (v > 0n && (!input.tx.data || input.tx.data === "0x")) recips.push({ to: lc(input.tx.to), token: ETH, amount: v.toString(), kind: "native_transfer" });
    for (const t of decoded?.transfers ?? []) recips.push({ ...t, kind: "erc20_transfer" });
    for (const r of recips) {
      try {
        const code = await rpc("eth_getCode", [r.to, tag]) as string; const nonce = BigInt(await rpc("eth_getTransactionCount", [r.to, tag]) as string);
        if (code.length <= 2 && nonce === 0n) fresh_recipients.push(r);
      } catch { unknownsExtra.push({ what: "recipient_state", reason: "eth_getCode/eth_getTransactionCount failed", to: r.to }); }
    }
  }
  // quote assets are skipped for tx input only; a bare token input is always simulated
  const skip = new Set(input.tx ? [...(opts.skipTokens ?? [ETH, WETH, USDC])].map(lc) : []);
  const token_sims: Facts["token_sims"] = [];
  for (const tok of tokens.filter((x) => !skip.has(x))) {
    try {
      const s = await sellSim(rpc, tok, block, { blockHash, ...(opts.sellSimOpts ?? {}) } as any);
      let hv: Verification | null = null;
      if (s.selected?.version === 4 && s.selected.hooks && s.selected.hooks !== ETH) hv = await lookup(s.selected.hooks);
      const tv = s.selected ? null : await lookup(tok);
      token_sims.push({ token: tok, sim: s, hook_verification: hv, token_verification: tv });
    } catch (e) { token_sims.push({ token: tok, sim: null, error: String((e as Error).message).slice(0, 200) }); }
  }
  const ev = evaluate({ tx_sim: txSim, approvals, token_sims, fresh_recipients });
  ev.unknowns.push(...unknownsExtra);
  if (decoded && decoded.method === "unknown" && !decoded.swaps.length) ev.unknowns.push({ what: "tx_intent", reason: "calldata selector not in the decoder table; only the raw eth_call outcome is checked" });
  if (ev.verdict === "allow" && ev.unknowns.some((u) => u.what !== "hook_behavior")) ev.verdict = "warn";
  if (approvals.some((a) => a.spender_verification) || token_sims.some((t) => t.hook_verification || t.token_verification)) ev.unknowns.push({ what: "source_verification_coverage", reason: "Sourcify is the only free source used; not_found there does not prove a contract is unverified elsewhere" });
  return {
    chain_id: CHAIN_ID, block_number: block, block_hash: blockHash,
    input: input.tx ? { tx: { ...input.tx, value: input.tx.value === undefined ? undefined : String(input.tx.value) } } : { token: lc(input.token!) },
    decoded, tx_simulation: txSim, approvals, token_sims: token_sims.map((t) => ({ token: t.token, error: t.error ?? null, hook_verification: t.hook_verification ?? null, token_verification: t.token_verification ?? null, sell_simulation: t.sim })),
    verdict: ev.verdict, reasons: ev.reasons, unknowns: ev.unknowns, policy: { version: POLICY_VERSION, ...POLICY, known_spenders: KNOWN_SPENDERS, hook_allowlist: HOOK_ALLOWLIST },
    elapsed_ms: Math.round(performance.now() - t0),
  };
}
export async function signPresign(claims: Record<string, unknown>, signer: Signer, opts: { now?: number } = {}) {
  const inp: any = claims.input;
  if (!claims.block_hash) throw new Error("block_hash required");
  const input_sha256 = hex(sha256(new TextEncoder().encode(jcs(inp))));
  return await signProof(claims, { type: inp.tx ? "base_unsigned_tx" : "base_token", input_sha256, ...(inp.tx ? { to: lc(inp.tx.to), data_selector: String(inp.tx.data ?? "0x").slice(0, 10) } : { token: inp.token }) }, signer, opts);
}
