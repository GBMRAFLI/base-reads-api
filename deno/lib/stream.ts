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
export async function verifyOnchain(rpc: Rpc, tx: string | undefined, asset: string, payTo: string, amount: string, payer: string | undefined,
  network = "eip155:8453", attempts = 4, wait = 2000, sleep = (ms: number) => new Promise((r) => setTimeout(r, ms)), nonce?: string | null) {
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
        return { settled: true, network, block: parseInt(rc.blockNumber, 16), from: frm, to, value: Number(v), nonceBound: nonce != null };
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
  onchain: Record<string, any>, servedOk = true, env = (k: string) => Deno.env.get(k)) {
  const tx = st.transaction ?? null, payer = (st.payer || "").toLowerCase() || null;
  const cand = rid("cand", "v1", category(route), route);
  const ex = await append("executions.jsonl", { id: rid("exec", tx, route), candidateRef: cand, category: category(route), protocolType: "x402",
    role: "seller", adapter: "x402-seller", route, amount: req.amount, asset: req.asset, network: req.network,
    payTo: req.payTo, payer, tx, status: st.success ? "succeeded" : "failed",
    startedAt: times[0], verifiedAt: times[1], settledAt: times[2], receipt: "payment_received" });
  const isSelf = payer ? selfWallets(req.payTo, env).has(payer) : null;
  let status: string, why: string | null;
  if (onchain.settled === true && isSelf === false && servedOk) { status = "verified_success"; why = null; }
  else if (onchain.settled === null || onchain.settled === undefined) { status = "inconclusive"; why = "deferred_onchain_check"; }
  else if (isSelf) { status = "excluded"; why = "self_payer"; }
  else { status = "verified_failure"; why = onchain.reason || "resource_not_delivered"; }
  const out = await append("outcomes.jsonl", { id: rid("out", tx, route), candidateRef: cand, executionRef: ex.id, category: category(route),
    status, reason: why, externalPayer: isSelf === false, payer, onchain, outcome: servedOk ? "resource_delivered" : "not_delivered", verifiedAt: iso() });
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
