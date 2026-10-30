// Pre-sign verdict CLI (local prototype, not wired to any route). Read-only: eth_call only, never signs/sends txs.
// Usage (from deno/): deno run -A tools/presign.ts --test-key <file> [--out dir] (--token 0x.. | --tx '{"to":..,"data":..}' | --cases cases.json)
import { presign, signPresign } from "../lib/presign.ts";
import { makeFallbackRpc, type RpcStat, testKeySigner } from "./sellsim.ts";
import type { Signer } from "../lib/attestation.ts";
const a = [...Deno.args]; const opt = (n: string) => { const i = a.indexOf(n); if (i < 0) return null; const v = a[i + 1]; a.splice(i, 2); return v; };
const keyPath = opt("--test-key"), out = opt("--out"), casesF = opt("--cases"), tok = opt("--token"), txj = opt("--tx");
const cases: { label: string; input: any }[] = casesF ? JSON.parse(await Deno.readTextFile(casesF)) : [];
if (tok) cases.push({ label: "token", input: { token: tok } }); if (txj) cases.push({ label: "tx", input: { tx: JSON.parse(txj) } });
let signer: Signer, label: string, publicKeyB64: string;
if (Deno.env.get("SIGNING_KEY_ENC_B64")) { const { envSigner, publicKeyInfo } = await import("../lib/sign.ts"); signer = await envSigner(); publicKeyB64 = (await publicKeyInfo()).public_key_b64; label = "issuer key (server environment)"; }
else { if (!keyPath) { console.error("--test-key required"); Deno.exit(2); } ({ signer, label, publicKeyB64 } = await testKeySigner(keyPath)); }
const stat: RpcStat = { calls: 0, errors: {}, fallbacks: 0 };
const urls = (Deno.env.get("SELLSIM_RPC") ?? "https://mainnet.base.org,https://base.drpc.org,https://base-rpc.publicnode.com").split(",");
const rpc = makeFallbackRpc(urls, stat);
const logsRpc = makeFallbackRpc((Deno.env.get("SELLSIM_LOGS_RPC") ?? "https://base.gateway.tenderly.co").split(","), stat);
const archiveRpc = makeFallbackRpc((Deno.env.get("SELLSIM_ARCHIVE_RPC") ?? "https://mainnet.base.org,https://base.drpc.org").split(","), stat);
const head = Number(BigInt(await rpc("eth_blockNumber", []))) - 3;
const blk = await rpc("eth_getBlockByNumber", ["0x" + head.toString(16), false]);
const rows: any[] = [];
for (const c of cases) {
  const t0 = performance.now(), before = stat.calls; let claims: any = null, err: string | null = null;
  try { claims = await presign(rpc, c.input, head, { blockHash: blk?.hash, sellSimOpts: { logsRpc, archiveRpc, notes: [] } }); } catch (e) { err = String((e as Error).message).slice(0, 200); }
  const ms = Math.round(performance.now() - t0);
  if (claims && out) await Deno.writeTextFile(`${out}/presign_proof_${c.label}.json`, JSON.stringify(await signPresign(claims, signer), null, 1));
  const ts = claims?.token_sims ?? [];
  const row = { label: c.label, kind: c.input.tx ? "tx" : "token", method: claims?.decoded?.method ?? null, verdict: claims?.verdict ?? null, reasons: claims?.reasons ?? [], unknowns: (claims?.unknowns ?? []).map((u: any) => u.what + ": " + u.reason),
    tx_reverted: claims?.tx_simulation?.reverted ?? null, tx_revert: claims?.tx_simulation?.message ?? null, tx_overrides: claims?.tx_simulation ? Object.keys(claims.tx_simulation.state_overrides ?? {}).length > 0 : null,
    tokens: ts.map((t: any) => { const s = t.sell_simulation; const r = s?.simulation?.result; return { token: t.token, version: s?.selected?.version ?? null, pool: s?.selected?.pool ?? null, hook: s?.selected?.hooks ?? null, sellable: s?.sellable ?? null, stage: r?.stage ?? null, buy_tax: r?.buy_tax ?? null, sell_tax: r?.sell_tax ?? null, round_trip_return: r?.round_trip_return ?? null, revert: r?.revert?.message ?? null, attempts: s?.attempts ?? [], error: t.error }; }),
    block: head, latency_ms: ms, rpc_calls: stat.calls - before, error: err };
  rows.push(row); console.log(JSON.stringify({ label: row.label, verdict: row.verdict, codes: row.reasons.map((r: any) => r.code), ms }));
}
if (out) await Deno.writeTextFile(`${out}/presign_rows.json`, JSON.stringify({ block: head, block_hash: blk?.hash ?? null, signer_key_id: signer.keyId, signer_label: label, public_key_b64: publicKeyB64, rpc_urls: urls, rpc_stat: stat, rows }, null, 1));
