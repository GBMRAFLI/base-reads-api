// Sell simulation (prototype, free, NOT wired to any route): for one Base token, discover Uniswap v2/v3/v4 pools,
// pick the deepest by measured liquidity, and simulate a small buy then a sell of everything received in ONE read-only
// eth_call pinned to a block. A helper contract (contracts/SellSimHelper.sol) is injected with a code override at a
// synthetic address and funded with a balance override; nothing is deployed, signed as a transaction or sent.
// Output is factual simulation data only (no score, no verdict, no advice), signed in the attestation style.
import { keccak_256 } from "@noble/hashes/sha3";
import { domainBytes, jcs, keyIdOf, parseIsoSec, type Signer } from "./attestation.ts";
import { hex } from "./util.ts";
import { HELPER_RUNTIME, HELPER_SOLC, HELPER_SOURCE_SHA256 } from "./sellsim_helper.ts";

export type Rpc = (m: string, p: unknown[]) => Promise<any>;
export const CHAIN_ID = 8453;
export const WETH = "0x4200000000000000000000000000000000000006";
export const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
export const ETH = "0x0000000000000000000000000000000000000000";
export const V2_FACTORY = "0x8909dc15e40173ff4699343b6eb8132c65e18ec6";
export const V3_FACTORY = "0x33128a8fc17869897dce68ed026d694621f6fdfd";
export const POOL_MANAGER = "0x498581ff718922c3f8e6a244956af099b2652b2b";
export const STATE_VIEW = "0xa3c0c9b65bad0b08107aa264b0f3db444b867a71";
export const WETH_USDC_V3 = "0xd0b53d9277642d899df5c87a3966a349a798f224"; // 0.05% pool, used only to convert USDC depth to ETH
export const INITIALIZE_TOPIC = "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438";
export const HELPER_ADDR = "0x51a1a7e000000000000000000000000000c0ffee";
export const CALLER = "0x51a1a7e000000000000000000000000000000001";
export const AMOUNT_ETH = 10n ** 15n;      // 0.001 ETH / WETH
export const AMOUNT_USDC = 3_000_000n;     // 3 USDC (about 0.001 ETH)
export const USDC_BALANCE_SLOT = 9n;       // FiatToken balances mapping slot (checked live by balanceOf in tests/CLI)
export const SIM_GAS = 30_000_000;
const V3_FEES = [100, 500, 3000, 10000];
const V4_HOOKLESS: [number, number][] = [[100, 1], [500, 10], [3000, 60], [10000, 200]];
export const DOMAIN_SELLSIM = "sell-simulation-attestation/v1\n";
export const SELLSIM_SPEC = "sell-simulation-attestation";

// ---------- ABI helpers ----------
const sel = (sig: string) => hex(keccak_256(new TextEncoder().encode(sig)).slice(0, 4));
export const SEL = {
  balanceOf: sel("balanceOf(address)"), getPair: sel("getPair(address,address)"), getPool: sel("getPool(address,address,uint24)"),
  getReserves: sel("getReserves()"), token0: sel("token0()"), slot0: sel("slot0()"), liquidity: sel("liquidity()"),
  svSlot0: sel("getSlot0(bytes32)"), svLiquidity: sel("getLiquidity(bytes32)"),
  run: sel("run((uint8,address,address,address,uint24,int24,address,uint256))"),
};
export const isAddr = (a: unknown): a is string => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);
export function word(x: bigint | number | string): string {
  if (typeof x === "string") { if (!isAddr(x)) throw new Error("bad address"); return x.slice(2).toLowerCase().padStart(64, "0"); }
  let v = BigInt(x); if (v < 0n) v = (1n << 256n) + v;
  if (v < 0n || v >= 1n << 256n) throw new Error("word overflow");
  return v.toString(16).padStart(64, "0");
}
export function words(data: string): bigint[] {
  const h = data.startsWith("0x") ? data.slice(2) : data; const out: bigint[] = [];
  for (let i = 0; i + 64 <= h.length; i += 64) out.push(BigInt("0x" + h.slice(i, i + 64)));
  return out;
}
export const toSigned = (v: bigint, bits = 256) => v >= 1n << BigInt(bits - 1) ? v - (1n << BigInt(bits)) : v;
export const wordAddr = (v: bigint) => "0x" + v.toString(16).padStart(40, "0").slice(-40);
const hexBytes = (h: string) => Uint8Array.from((h.replace(/^0x/, "").match(/../g) ?? []).map((x) => parseInt(x, 16)));
export type PoolKey = { currency0: string; currency1: string; fee: number; tickSpacing: number; hooks: string };
export function poolId(k: PoolKey): string {
  return "0x" + hex(keccak_256(hexBytes(word(k.currency0) + word(k.currency1) + word(k.fee) + word(k.tickSpacing) + word(k.hooks))));
}
export function sortPair(a: string, b: string): [string, string] { const x = a.toLowerCase(), y = b.toLowerCase(); return x < y ? [x, y] : [y, x]; }
/** Initialize(bytes32 indexed id, address indexed c0, address indexed c1, uint24 fee, int24 tickSpacing, address hooks, uint160, int24) */
export function parseInitializeLog(l: { topics: string[]; data: string; blockNumber?: string; transactionHash?: string }) {
  if (!l?.topics || l.topics[0]?.toLowerCase() !== INITIALIZE_TOPIC || l.topics.length < 4) return null;
  const w = words(l.data); if (w.length < 5) return null;
  const key: PoolKey = { currency0: wordAddr(BigInt(l.topics[2])), currency1: wordAddr(BigInt(l.topics[3])), fee: Number(w[0]),
    tickSpacing: Number(toSigned(w[1])), hooks: wordAddr(w[2]) };
  return { id: l.topics[1].toLowerCase(), key, block: l.blockNumber ? Number(BigInt(l.blockNumber)) : null, tx: l.transactionHash ?? null };
}
export function decodeRevert(data: string): { selector: string | null; message: string | null; raw: string } {
  const raw = (data || "0x").toLowerCase();
  if (raw.length < 10) return { selector: null, message: raw === "0x" ? "empty_revert" : null, raw };
  const s = raw.slice(0, 10);
  if (s === "0x08c379a0") { try { const b = hexBytes(raw.slice(10)); const o = Number(words(hex(b.slice(0, 32)))[0]);
    const n = Number(words(hex(b.slice(o, o + 32)))[0]); return { selector: s, message: new TextDecoder().decode(b.slice(o + 32, o + 32 + n)), raw }; } catch { /* raw */ } }
  if (s === "0x4e487b71") return { selector: s, message: "panic_0x" + raw.slice(-2), raw };
  if (/^0x[0-9a-f]*$/.test(raw) && raw.length > 2 && !/[^\x20-\x7e]/.test(new TextDecoder().decode(hexBytes(raw)))) return { selector: null, message: new TextDecoder().decode(hexBytes(raw)), raw };
  return { selector: s, message: null, raw };
}
/** Decode run() return: (uint8 stage, bytes err, uint256[9] r). */
export function decodeRun(ret: string) {
  const w = words(ret); if (w.length < 11) throw new Error("short_return");
  const stage = Number(w[0]); const off = Number(w[1]) / 32; const r = w.slice(2, 11);
  const n = Number(w[off]); const errHex = "0x" + (ret.replace(/^0x/, "").slice((off + 1) * 64, (off + 1) * 64 + n * 2));
  return { stage, err: errHex, r };
}

// ---------- math ----------
const Q96 = 2n ** 96n;
/** Active-range virtual reserve of the quote asset from (L, sqrtPriceX96). */
export function virtualQuote(L: bigint, sqrtP: bigint, quoteIs0: boolean): bigint {
  if (sqrtP === 0n) return 0n; return quoteIs0 ? L * Q96 / sqrtP : L * sqrtP / Q96;
}
/** Spot price as raw token units per raw quote unit. */
export function spotTokenPerQuote(sqrtP: bigint, quoteIs0: boolean): number {
  const p = (Number(sqrtP) / 2 ** 96) ** 2; // token1 per token0
  return quoteIs0 ? p : 1 / p;
}
export const ratio = (a: bigint, b: bigint) => b === 0n ? null : Number(a * 10n ** 12n / b) / 1e12;
const round = (x: number | null, d = 6) => x === null || !Number.isFinite(x) ? null : Math.round(x * 10 ** d) / 10 ** d;
/** Transfer-level taxes from the helper's measured amounts (fractions 0..1, rounded to 1e-6).
 * buy_tax = 1 - received / amount the pool sent; sell_tax = 1 - (pool received / sent) * (received / amount the pool sent). */
export function taxes(r: bigint[], stage: number) {
  const [, buyPoolOut, buyReceived, sellSent, sellPoolIn, sellPoolOut, sellReceived] = r;
  const bt = buyPoolOut > 0n ? 1 - (ratio(buyReceived, buyPoolOut) ?? 0) : null;
  const st = stage === 0 || stage === 3 ? (sellSent > 0n && sellPoolOut > 0n ? 1 - (ratio(sellPoolIn, sellSent)! * ratio(sellReceived, sellPoolOut)!) : stage === 3 ? 1 : null) : null;
  return { buy_tax: round(bt), sell_tax: round(st) };
}

// ---------- discovery ----------
export type Candidate = { version: 2 | 3 | 4; pool: string; quote: string; fee: number | null; tick_spacing?: number; hooks?: string; key?: PoolKey;
  liquidity_raw: string; sqrt_price_x96?: string; quote_balance_raw?: string; reserves?: [string, string]; quote_depth_raw: string; quote_depth_eth: number | null; spot_token_per_quote: number | null;
  lp_fee_ppm: number | null; source: string };
type Ctx = { rpc: Rpc; tag: string; ethUsdc: number | null };
const call = (c: Ctx, to: string, data: string) => c.rpc("eth_call", [{ to, data: "0x" + data }, c.tag]);
const big = (x: string) => BigInt(!x || x === "0x" ? "0x0" : x);
function depthEth(c: Ctx, quote: string, raw: bigint): number | null {
  if (quote === WETH || quote === ETH) return Number(raw) / 1e18;
  if (quote === USDC) return c.ethUsdc ? Number(raw) / 1e6 / c.ethUsdc : null;
  return null;
}
export async function ethUsdcPrice(rpc: Rpc, tag: string): Promise<number | null> {
  try { const w = words(await rpc("eth_call", [{ to: WETH_USDC_V3, data: "0x" + SEL.slot0 }, tag])); return (Number(w[0]) / 2 ** 96) ** 2 * 1e12; } catch { return null; }
}
async function v2Candidates(c: Ctx, token: string, quotes: string[]): Promise<Candidate[]> {
  const out: Candidate[] = [];
  for (const q of quotes) {
    const pair = factoryAddr((await call(c, V2_FACTORY, SEL.getPair + word(token) + word(q)))); if (pair === ETH) continue;
    const [r0, r1] = words(await call(c, pair, SEL.getReserves));
    const quoteIs0 = sortPair(token, q)[0] === q; const rq = quoteIs0 ? r0 : r1, rt = quoteIs0 ? r1 : r0;
    out.push({ version: 2, pool: pair, quote: q, fee: 3000, liquidity_raw: (r0 * r1).toString(), reserves: [r0.toString(), r1.toString()], quote_depth_raw: rq.toString(),
      quote_depth_eth: depthEth(c, q, rq), spot_token_per_quote: rq > 0n ? Number(rt) / Number(rq) : null, lp_fee_ppm: 3000, source: "v2_factory.getPair" });
  }
  return out;
}
/** Factory getters always return a 32-byte word; "0x"/empty means the RPC gave no answer, NOT "no pool". */
export function factoryAddr(raw: unknown): string {
  if (typeof raw !== "string" || raw.length < 66) throw new Error("empty_factory_response");
  return wordAddr(BigInt(raw));
}
async function v3Candidates(c: Ctx, token: string, quotes: string[], notes: string[] = []): Promise<Candidate[]> {
  const out: Candidate[] = [];
  // every fee tier and quote is checked independently: one failing call must not drop the other pools
  for (const q of quotes) for (const fee of V3_FEES) {
    try {
      const pool = factoryAddr(await call(c, V3_FACTORY, SEL.getPool + word(token) + word(q) + word(fee))); if (pool === ETH) continue;
      const [sp] = words(await call(c, pool, SEL.slot0)); const [L] = words(await call(c, pool, SEL.liquidity));
      const qb = big(await call(c, q, SEL.balanceOf + word(pool)));
      const quoteIs0 = sortPair(token, q)[0] === q; const vq = virtualQuote(L, sp, quoteIs0);
      out.push({ version: 3, pool, quote: q, fee, liquidity_raw: L.toString(), sqrt_price_x96: sp.toString(), quote_depth_raw: vq.toString(),
        quote_depth_eth: depthEth(c, q, vq), quote_balance_raw: qb.toString(), spot_token_per_quote: sp > 0n ? spotTokenPerQuote(sp, quoteIs0) : null, lp_fee_ppm: fee, source: "v3_factory.getPool" });
    } catch (e) { notes.push(`v3 ${q.slice(0, 6)} fee ${fee}: ${String((e as Error).message).slice(0, 120)}`); }
  }
  return out;
}
async function v4Candidate(c: Ctx, token: string, key: PoolKey, source: string): Promise<Candidate | null> {
  const id = poolId(key); const s = words(await call(c, STATE_VIEW, SEL.svSlot0 + id.slice(2)));
  if (!s.length || s[0] === 0n) return null;
  const [L] = words(await call(c, STATE_VIEW, SEL.svLiquidity + id.slice(2)));
  const quote = key.currency0 === token ? key.currency1 : key.currency0; const quoteIs0 = key.currency0 === quote;
  const vq = virtualQuote(L, s[0], quoteIs0);
  return { version: 4, pool: id, quote, fee: key.fee, tick_spacing: key.tickSpacing, hooks: key.hooks, key, liquidity_raw: L.toString(), sqrt_price_x96: s[0].toString(),
    quote_depth_raw: vq.toString(), quote_depth_eth: depthEth(c, quote, vq), spot_token_per_quote: spotTokenPerQuote(s[0], quoteIs0), lp_fee_ppm: Number(s[3]), source };
}
/** Pools with in-range liquidity first (max 3). If none, pools that exist but have zero in-range liquidity
 *  (v3 L=0 / out-of-range positions) are still simulated: a swap can cross into out-of-range ticks. */
export function selectUsable(cands: Candidate[], max = 3): { usable: Candidate[]; mode: "active_liquidity" | "zero_active_liquidity_fallback" | "none" } {
  const act = cands.filter((x) => (x.quote_depth_eth ?? 0) > 0);
  if (act.length) return { usable: act.slice(0, max), mode: "active_liquidity" };
  const z = cands.filter((x) => x.version !== 4 || BigInt(x.sqrt_price_x96 ?? "0") > 0n)
    .sort((a, b) => { const k = (x: Candidate) => BigInt(x.quote_balance_raw ?? x.quote_depth_raw ?? "0"); const d = k(b) - k(a); return d > 0n ? 1 : d < 0n ? -1 : 0; });
  return z.length ? { usable: z.slice(0, max), mode: "zero_active_liquidity_fallback" } : { usable: [], mode: "none" };
}
/** First block at which `addr` has code (binary search over eth_getCode on an archive-capable RPC). */
export async function creationBlock(rpc: Rpc, addr: string, head: number): Promise<number | null> {
  const has = async (b: number) => { const c = await rpc("eth_getCode", [addr, "0x" + b.toString(16)]); return typeof c === "string" && c.length > 2; };
  if (!(await has(head))) return null;
  let lo = 0, hi = head; while (lo < hi) { const m = Math.floor((lo + hi) / 2); if (await has(m)) hi = m; else lo = m + 1; }
  return lo;
}
export type DiscoverOpts = { logsRpc?: Rpc; archiveRpc?: Rpc; logChunk?: number; logChunks?: number; notes?: string[] };
/** v4 pools from Initialize logs in the window right after the token was created (launchpads initialize there). */
export async function v4FromLogs(rpc: Rpc, token: string, from: number, to: number, chunk: number, maxChunks: number, notes: string[]) {
  const found = new Map<string, ReturnType<typeof parseInitializeLog>>();
  for (let i = 0, b = from; i < maxChunks && b <= to; i++, b += chunk) {
    const e = Math.min(b + chunk - 1, to);
    for (const pos of [2, 3]) {
      const topics: (string | null)[] = [INITIALIZE_TOPIC, null, null, null]; topics[pos] = "0x" + word(token);
      try {
        const logs = await rpc("eth_getLogs", [{ address: POOL_MANAGER, topics, fromBlock: "0x" + b.toString(16), toBlock: "0x" + e.toString(16) }]);
        for (const l of logs ?? []) { const p = parseInitializeLog(l); if (p) found.set(p.id, p); }
      } catch (err) { notes.push(`getLogs ${b}-${e}: ${String((err as Error).message).slice(0, 120)}`); }
    }
  }
  return [...found.values()];
}
export async function discover(rpc: Rpc, token: string, block: number, opts: DiscoverOpts = {}) {
  token = token.toLowerCase(); const tag = "0x" + block.toString(16); const notes = opts.notes ?? [];
  const c: Ctx = { rpc, tag, ethUsdc: await ethUsdcPrice(rpc, tag) };
  const quotes = [WETH, USDC].filter((q) => q !== token);
  const cands: Candidate[] = [];
  const safe = async <T>(name: string, f: () => Promise<T>): Promise<T | null> => { try { return await f(); } catch (e) { notes.push(`${name}: ${String((e as Error).message).slice(0, 160)}`); return null; } };
  cands.push(...(await safe("v2", () => v2Candidates(c, token, quotes)) ?? []));
  cands.push(...(await safe("v3", () => v3Candidates(c, token, quotes, notes)) ?? []));
  const keys = new Map<string, { key: PoolKey; source: string }>();
  for (const q of [ETH, ...quotes]) for (const [fee, ts] of V4_HOOKLESS) {
    const [c0, c1] = sortPair(token, q); const key = { currency0: c0, currency1: c1, fee, tickSpacing: ts, hooks: ETH }; keys.set(poolId(key), { key, source: "v4_hookless_enumeration" });
  }
  let created: number | null = null;
  if (opts.logsRpc && opts.archiveRpc) {
    created = await safe("creation_block", () => creationBlock(opts.archiveRpc!, token, block));
    if (created !== null) {
      const logs = await safe("v4_logs", () => v4FromLogs(opts.logsRpc!, token, created!, block, opts.logChunk ?? 1000, opts.logChunks ?? 3, notes)) ?? [];
      for (const l of logs) if (l) keys.set(l.id, { key: l.key, source: `v4_initialize_log(block ${l.block})` });
    }
  }
  for (const [, k] of keys) { const x = await safe("v4 " + poolId(k.key).slice(0, 10), () => v4Candidate(c, token, k.key, k.source)); if (x) cands.push(x); }
  cands.sort((a, b) => (b.quote_depth_eth ?? -1) - (a.quote_depth_eth ?? -1));
  return { candidates: cands, eth_usdc: c.ethUsdc, token_created_block: created, notes };
}

// ---------- simulation ----------
export function amountFor(quote: string): bigint { return quote === USDC ? AMOUNT_USDC : AMOUNT_ETH; }
export function slotOf(holder: string, mappingSlot: bigint): string {
  return "0x" + hex(keccak_256(hexBytes(word(holder) + word(mappingSlot))));
}
/** The exact eth_call (call object + block tag + state overrides) for one candidate pool. */
export function buildCall(token: string, p: Candidate, block: number) {
  const kind = p.version; const amountIn = amountFor(p.quote);
  const job = [word(kind), word(kind === 4 ? POOL_MANAGER : p.pool), word(p.quote), word(token.toLowerCase()), word(p.fee ?? 0), word(p.tick_spacing ?? 0), word(p.hooks ?? ETH), word(amountIn)];
  const data = "0x" + SEL.run + job.join("");
  const overrides: Record<string, any> = { [HELPER_ADDR]: { code: HELPER_RUNTIME, balance: "0x" + (10n ** 20n).toString(16) } };
  if (p.quote === USDC) overrides[USDC] = { stateDiff: { [slotOf(HELPER_ADDR, USDC_BALANCE_SLOT)]: "0x" + word(amountIn * 10n) } };
  return { call: { from: CALLER, to: HELPER_ADDR, data, gas: "0x" + SIM_GAS.toString(16) }, block: "0x" + block.toString(16), state_overrides: overrides, amount_in: amountIn.toString() };
}
const STAGES = ["ok", "buy_reverted", "sell_reverted", "sell_returned_zero"];
export function interpret(ret: string, p: Candidate) {
  const d = decodeRun(ret); const t = taxes(d.r, d.stage); const r = d.r;
  const lp = (p.lp_fee_ppm ?? 0) / 1e6;
  const idealBuy = p.spot_token_per_quote ? Number(r[0]) * (1 - lp) * p.spot_token_per_quote : null;
  return {
    stage: STAGES[d.stage] ?? String(d.stage), sellable: d.stage === 0,
    revert: d.stage === 1 || d.stage === 2 ? decodeRevert(d.err) : null,
    amounts: { buy_in: r[0].toString(), buy_pool_out: r[1].toString(), buy_received: r[2].toString(), sell_sent: r[3].toString(), sell_pool_in: r[4].toString(),
      sell_pool_out: r[5].toString(), sell_received: r[6].toString(), buy_gas: Number(r[7]), sell_gas: Number(r[8]) },
    buy_tax: t.buy_tax, sell_tax: t.sell_tax,
    // includes price impact, LP fee deviations and any hook fee; the LP fee itself is removed
    buy_shortfall_vs_spot: idealBuy && r[2] > 0n ? round(1 - Number(r[2]) / idealBuy) : null,
    round_trip_return: d.stage === 0 ? ratio(r[6], r[0]) : null,
  };
}
export async function simulate(rpc: Rpc, token: string, p: Candidate, block: number) {
  const c = buildCall(token, p, block); const t0 = performance.now();
  let raw: string | null = null, rpcError: string | null = null;
  try { raw = await rpc("eth_call", [c.call, c.block, c.state_overrides]); } catch (e) { rpcError = String((e as Error).message).slice(0, 300); }
  const ms = Math.round(performance.now() - t0);
  if (raw === null) return { call: c, raw_result: null, rpc_error: rpcError, result: null, eth_call_ms: ms };
  return { call: c, raw_result: raw, rpc_error: null, result: interpret(raw, p), eth_call_ms: ms };
}

// ---------- proof ----------
const b64e = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64d = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const isoSec = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");
export const sellsimSigningBytes = (env: Record<string, unknown>) => { const { signature: _s, ...rest } = env; return domainBytes(DOMAIN_SELLSIM, rest); };
export const PROOF_TTL_S = 86400;
export async function signProof(claims: Record<string, unknown>, subject: { token?: string; type?: string; [k: string]: unknown }, signer: Signer, opts: { now?: number; keyLabel?: string; issuerUrl?: string | null } = {}) {
  const now = opts.now ?? Date.now();
  const env: Record<string, unknown> = {
    spec: SELLSIM_SPEC, version: "0.1", canonicalization: "JCS", attestation_id: crypto.randomUUID(),
    issued_at: isoSec(now), expires_at: isoSec(now + PROOF_TTL_S * 1000),
    issuer: { name: "Base Reads Sell Simulation (prototype)", key_id: signer.keyId, key_label: opts.keyLabel ?? null, issuer_url: opts.issuerUrl ?? null },
    subject: subject.type ? { chain_id: CHAIN_ID, ...subject } : { type: "base_token", chain_id: CHAIN_ID, token: String(subject.token).toLowerCase() },
    helper: { solc: HELPER_SOLC, source_sha256: HELPER_SOURCE_SHA256, runtime_keccak256: "0x" + hex(keccak_256(hexBytes(HELPER_RUNTIME))) },
    claims,
    disclaimer: "Factual result of a read-only eth_call simulation at the stated block. Not a prediction, rating or recommendation.",
  };
  const sig = await signer.sign(sellsimSigningBytes(env));
  env.signature = { alg: "Ed25519", key_id: signer.keyId, value_b64: b64e(sig) };
  return env;
}
/** Signature check (same rules as verifyAttestation: key_id pinned to the public key, strict dates, max 24 h window).
 * `now` = null skips the expiry check (re-running an old proof is still meaningful: it is pinned to a block). */
export async function verifyProof(env: any, publicKeyB64: string, now: number | null = Date.now()): Promise<{ ok: boolean; reason?: string }> {
  if (!env || typeof env !== "object" || Array.isArray(env)) return { ok: false, reason: "not_an_object" };
  if (env.spec !== SELLSIM_SPEC || env.canonicalization !== "JCS") return { ok: false, reason: "unsupported_spec" };
  const s = env.signature; if (!s || s.alg !== "Ed25519" || typeof s.value_b64 !== "string") return { ok: false, reason: "bad_signature_block" };
  let raw: Uint8Array; try { raw = b64d(publicKeyB64); } catch { return { ok: false, reason: "bad_public_key" }; }
  if (raw.length !== 32) return { ok: false, reason: "bad_public_key" };
  const kid = await keyIdOf(raw); if (s.key_id !== kid || env.issuer?.key_id !== kid) return { ok: false, reason: "key_id_mismatch" };
  const iat = parseIsoSec(env.issued_at), exp = parseIsoSec(env.expires_at);
  if (iat === null || exp === null) return { ok: false, reason: "bad_dates" };
  if (exp < iat || exp - iat > PROOF_TTL_S * 1000) return { ok: false, reason: "bad_validity_window" };
  let sig: Uint8Array; try { sig = b64d(s.value_b64); } catch { return { ok: false, reason: "bad_signature" }; }
  const pk = await crypto.subtle.importKey("raw", raw as Uint8Array<ArrayBuffer>, { name: "Ed25519" }, false, ["verify"]);
  let good = false; try { good = await crypto.subtle.verify("Ed25519", pk, sig as Uint8Array<ArrayBuffer>, sellsimSigningBytes(env) as Uint8Array<ArrayBuffer>); } catch { good = false; }
  if (!good) return { ok: false, reason: "bad_signature" };
  if (now !== null && iat > now + 60_000) return { ok: false, reason: "issued_in_future" };
  if (now !== null && exp < now) return { ok: false, reason: "expired" };
  return { ok: true };
}
export { jcs };

/** Full check: discover, simulate on the deepest candidate, return unsigned claims. */
export async function sellSim(rpc: Rpc, token: string, block: number, opts: DiscoverOpts & { blockHash?: string } = {}) {
  if (!isAddr(token)) throw new Error("token must be 0x + 40 hex");
  token = token.toLowerCase(); const t0 = performance.now();
  const d = await discover(rpc, token, block, opts);
  // deepest pool first; if its buy leg reverts or the call fails, try the next one (max 3).
  // A sell-leg failure is a result, not a reason to switch pools.
  const { usable, mode } = selectUsable(d.candidates);
  let top: Candidate | null = null, sim: Awaited<ReturnType<typeof simulate>> | null = null;
  const attempts: { pool: string; version: number; outcome: string }[] = [];
  for (const c of usable) {
    top = c; sim = await simulate(rpc, token, c, block);
    const outcome = sim.rpc_error ? "rpc_error" : sim.result!.stage;
    attempts.push({ pool: c.pool, version: c.version, outcome });
    if (outcome !== "rpc_error" && outcome !== "buy_reverted") break;
  }
  return {
    chain_id: CHAIN_ID, block_number: block, block_hash: opts.blockHash ?? null, token,
    candidates: d.candidates.map(({ key: _k, ...x }) => x), eth_usdc_price: d.eth_usdc, token_created_block: d.token_created_block,
    selected: top ? { version: top.version, pool: top.pool, quote: top.quote, fee: top.fee, tick_spacing: top.tick_spacing ?? null, hooks: top.hooks ?? null, key: top.key ?? null, selection: (mode === "zero_active_liquidity_fallback" ? "zero in-range liquidity fallback; " : "") + (attempts.length > 1 ? "next candidate after buy-leg failure" : "max quote_depth_eth") } : null,
    attempts,
    simulation: sim, sellable: sim?.result ? sim.result.sellable : null,
    no_pool_reason: top ? null : "no v2/v3/v4 pool with WETH, ETH or USDC found by the discovery methods used",
    pool_mode: mode,
    discovery_notes: d.notes, elapsed_ms: Math.round(performance.now() - t0),
  };
}
