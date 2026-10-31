// Port of api/sales_log.py: identical record shapes and ids.
import { append } from "./store.ts";
import { iso, rid } from "./util.ts";
export const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
export const AUTH_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"; // EIP-3009 AuthorizationUsed(address,bytes32)
export const category = (route: string) => route === "/x402/preflight" ? "endpoint_check" : "chain_reads";
export type Rpc = (m: string, p: unknown[]) => Promise<any>;
export function selfWallets(payTo: string, env = (k: string) => Deno.env.get(k)) {
  const w = new Set([payTo.toLowerCase()]);
  for (const k of ["PAY_TO_ADDRESS"]) { const v = env(k); if (v) w.add(v.trim().toLowerCase()); }
  for (const x of (env("SELF_WALLETS") ?? "").split(",")) if (x.trim()) w.add(x.trim().toLowerCase());
  return w;
}
const csv = (v: string | undefined) => new Set((v ?? "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean));
export const MONITOR_UA_DEFAULT = "settledscout,vet402";
/** self = our own wallets; monitor = known verification/monitoring bots (MONITOR_WALLETS, or a User-Agent containing a
 * MONITOR_UA token); external = everyone else (organic buyer). null when the payer is unknown. Same rules as Python. */
export function payerClass(payer: string | null, payTo: string, env = (k: string) => Deno.env.get(k), ua?: string | null) {
  if (!payer) return null;
  const p = payer.toLowerCase();
  if (selfWallets(payTo, env).has(p)) return "self";
  if (csv(env("MONITOR_WALLETS")).has(p)) return "monitor";
  const u = (ua ?? "").toLowerCase();
  if (u && [...(csv(env("MONITOR_UA")).size ? csv(env("MONITOR_UA")) : csv(MONITOR_UA_DEFAULT))].some((t) => u.includes(t))) return "monitor";
  return "external";
}
/** Export-time view: re-apply the current wallet config to a stored outcome (older rows predate payerClass). */
export function reclassify(out: Record<string, any>, payTo: string, env = (k: string) => Deno.env.get(k)) {
  const o = { ...out }; let cls = payerClass(o.payer ?? null, payTo, env);
  if (o.payerClass === "monitor" && cls === "external") cls = "monitor"; // UA-based tag is only known at record time
  o.payerClass = cls; o.externalPayer = cls === "external";
  const own = cls === "self" || cls === "monitor";
  if (o.status === "verified_success" && own) { o.status = "excluded"; o.reason = cls + "_payer"; }
  else if (o.status === "excluded" && (o.reason === "self_payer" || o.reason === "monitor_payer")) {
    if (own) o.reason = cls + "_payer";
    else if (cls === "external" && o.onchain?.settled === true && o.outcome === "resource_delivered") { o.status = "verified_success"; o.reason = null; }
    else if (cls === "external") { o.status = "verified_failure"; o.reason = o.onchain?.reason || "resource_not_delivered"; }
  }
  return o;
}
/** Export view, in place: reclassify outcomes, then set each cost's revenue from its outcome
 * (amount only when verified_success, else 0). Costs without a matching outcome get revenue 0 and revenueUnmatched=true.
 * Pass ALL rows (before any time filter) so cross-references resolve. */
export function reconcile(recs: Record<string, any[]>, payTo: string, env = (k: string) => Deno.env.get(k)) {
  // Trial (unpaid) calls live in their own stream; drop any that reach these lists so they never count as sales.
  for (const k of ["executions", "outcomes", "costs"]) if (recs[k]) recs[k] = recs[k].filter((r) => r?.kind !== "trial");
  recs.outcomes = (recs.outcomes ?? []).map((o) => reclassify(o, payTo, env));
  const st = new Map(recs.outcomes.map((o) => [o.executionRef, o.status]));
  const amt = new Map((recs.executions ?? []).map((e) => [e.id, e.amount]));
  for (const c of recs.costs ?? []) {
    if (!st.has(c.executionRef)) { c.revenue = 0.0; c.revenueUnmatched = true; continue; }
    const a = amt.get(c.executionRef);
    c.revenue = st.get(c.executionRef) === "verified_success" && a != null ? parseInt(a) / 1e6 : 0.0;
  }
  return recs;
}
export async function verifyOnchain(rpc: Rpc, tx: string | undefined, asset: string, payTo: string, amount: string, payer: string | undefined,
  network = "eip155:8453", attempts = 4, wait = 2000, sleep = (ms: number) => new Promise((r) => setTimeout(r, ms)), nonce?: string | null, minConf = 1) {
  if (!tx) return { settled: false, reason: "no_tx_hash" };
  let rc: any = null;
  for (let i = 0; i < attempts; i++) {
    try { rc = await rpc("eth_getTransactionReceipt", [tx]); } catch { rc = null; }
    if (rc) break;
    if (i < attempts - 1) await sleep(wait);
  }
  if (!rc) return { settled: null, reason: "receipt_not_found_yet" };
  if (rc.status !== "0x1") return { settled: false, reason: "tx_reverted", block: parseInt(rc.blockNumber, 16) };
  for (const lg of rc.logs ?? []) {
    const t = lg.topics ?? [];
    if ((lg.address ?? "").toLowerCase() === asset.toLowerCase() && t.length === 3 && t[0] === TRANSFER) {
      const frm = "0x" + t[1].slice(-40), to = "0x" + t[2].slice(-40), v = BigInt(lg.data ?? "0x0");
      if (to.toLowerCase() === payTo.toLowerCase() && (payer == null || frm.toLowerCase() === payer.toLowerCase()) && v >= BigInt(amount))
      {
        if (nonce != null && !authUsed(rc, asset, frm, nonce)) return { settled: false, reason: "nonce_not_in_settlement_tx" };
        const block = parseInt(rc.blockNumber, 16);
        if (minConf > 1) { // finality: require minConf confirmations (the receipt block counts as 1)
          let head = NaN; try { head = parseInt(String(await rpc("eth_blockNumber", [])), 16); } catch { /* treated as unknown */ }
          const confirmations = Number.isFinite(head) ? head - block + 1 : 0;
          if (confirmations < minConf) return { settled: null, reason: "awaiting_confirmations", block, confirmations, required: minConf };
          return { settled: true, network, block, confirmations, from: frm, to, value: Number(v), nonceBound: nonce != null };
        }
        return { settled: true, network, block, from: frm, to, value: Number(v), nonceBound: nonce != null };
      }
    }
  }
  return { settled: false, reason: "no_matching_usdc_transfer" };
}
function authUsed(rc: any, asset: string, frm: string, nonce: string) {
  let n = nonce.toLowerCase(); if (n.startsWith("0x")) n = "0x" + n.slice(2).padStart(64, "0");
  return (rc.logs ?? []).some((lg: any) => { const t = (lg.topics ?? []).map((x: string) => x.toLowerCase());
    return (lg.address ?? "").toLowerCase() === asset.toLowerCase() && t.length === 3 && t[0] === AUTH_USED && t[1].slice(-40) === frm.toLowerCase().slice(2) && t[2] === n; });
}
export async function recordSale(route: string, req: Record<string, any>, st: Record<string, any>, times: [string, string, string],
  onchain: Record<string, any>, servedOk = true, env = (k: string) => Deno.env.get(k), ref: string | null = null, ua: string | null = null) {
  const tx = st.transaction ?? null, payer = (st.payer || "").toLowerCase() || null;
  const cand = rid("cand", "v1", category(route), route);
  const ex = await append("executions.jsonl", { id: rid("exec", tx, route), candidateRef: cand, category: category(route), protocolType: "x402",
    role: "seller", adapter: "x402-seller", route, amount: req.amount, asset: req.asset, network: req.network,
    payTo: req.payTo, payer, tx, status: st.success ? "succeeded" : "failed",
    startedAt: times[0], verifiedAt: times[1], settledAt: times[2], receipt: "payment_received", ...(ref ? { ref } : {}) });
  const cls = payerClass(payer, req.payTo, env, ua);
  let status: string, why: string | null;
  if (onchain.settled === true && cls === "external" && servedOk) { status = "verified_success"; why = null; }
  else if (onchain.settled === null || onchain.settled === undefined) { status = "inconclusive"; why = "deferred_onchain_check"; }
  else if (cls === "self" || cls === "monitor") { status = "excluded"; why = cls + "_payer"; }
  else { status = "verified_failure"; why = onchain.reason || "resource_not_delivered"; }
  const out = await append("outcomes.jsonl", { id: rid("out", tx, route), candidateRef: cand, executionRef: ex.id, category: category(route),
    status, reason: why, externalPayer: cls === "external", payerClass: cls, payer, onchain, outcome: servedOk ? "resource_delivered" : "not_delivered", verifiedAt: iso() });
  await append("costs.jsonl", { id: rid("cost", tx, route), candidateRef: cand, executionRef: ex.id, category: "settlement",
    amount: 0.0, currency: "USD", incurredAt: iso(), evidenceRef: `tx:${tx === null ? "None" : tx}`, measured: true,
    allocationMethod: "direct; facilitator pays gas, seller cost 0", revenue: status === "verified_success" ? parseInt(req.amount) / 1e6 : 0.0 });
  return out;
}
export async function recordObservation(route: string, queryHash: string, code: number, latencyMs: number | null, note?: string) {
  const rec: Record<string, unknown> & { id: string } = { id: rid("obs", route, queryHash, iso()), category: category(route), route,
    inputHash: queryHash, httpStatus: code, latencyMs, observedAt: iso(), method: "deterministic_code" };
  if (note) rec.note = note;
  return append("observations.jsonl", rec);
}
