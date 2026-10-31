// Replays a sell-simulation / pre-sign proof: checks the Ed25519 signature, then re-runs every recorded
// eth_call (same call object, same pinned block, same state overrides) and compares the raw results.
// Usage (from deno/): deno run -A tools/verify_sellsim.ts --pubkey <b64> [--rpc url] [--no-replay] proof.json
import { verifyProof } from "../lib/sellsim.ts";
const a = [...Deno.args]; const opt = (n: string) => { const i = a.indexOf(n); if (i < 0) return null; const v = a[i + 1]; a.splice(i, 2); return v; };
const flag = (n: string) => { const i = a.indexOf(n); if (i < 0) return false; a.splice(i, 1); return true; };
const pub = opt("--pubkey"), rpcUrl = opt("--rpc") ?? "https://mainnet.base.org", noReplay = flag("--no-replay");
if (!pub || !a[0]) { console.error("usage: --pubkey <b64> proof.json"); Deno.exit(2); }
const env = JSON.parse(await Deno.readTextFile(a[0]));
const sig = await verifyProof(env, pub, null);
export function collectCalls(claims: any): { where: string; call: unknown; block: string; overrides: unknown; raw: string | null }[] {
  const out: any[] = [];
  const ts = claims.tx_simulation; if (ts && ts.call) out.push({ where: "tx_simulation", call: ts.call, block: ts.block, overrides: ts.state_overrides ?? {}, raw: ts.reverted ? null : ts.raw_result ?? null });
  const sims = claims.token_sims ? claims.token_sims.map((t: any) => t.sell_simulation).filter(Boolean) : [claims];
  for (const s of sims) if (s.simulation?.call) out.push({ where: "sell_sim:" + s.token, call: s.simulation.call.call, block: s.simulation.call.block, overrides: s.simulation.call.state_overrides, raw: s.simulation.raw_result });
  return out;
}
const results: any[] = [];
if (!noReplay) for (const c of collectCalls(env.claims)) {
  const r = await fetch(rpcUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [c.call, c.block, c.overrides] }) });
  const d = await r.json(); const got = d.result ?? null;
  results.push({ where: c.where, match: c.raw === null ? got === null : got === c.raw, replay_error: d.error?.message?.slice(0, 120) ?? null });
}
const ok = sig.ok && results.every((x) => x.match);
console.log(JSON.stringify({ signature: sig, replay: noReplay ? "skipped" : results, ok }, null, 1));
Deno.exit(ok ? 0 : 1);
