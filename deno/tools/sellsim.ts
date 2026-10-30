// Local CLI for the sell-simulation prototype. Read-only: eth_call / eth_getCode / eth_getLogs on public RPCs only.
//   deno run -A tools/sellsim.ts --test-key <file> [--out <dir>] <token> [<token> ...]
//   deno run -A tools/sellsim.ts --test-key <file> --list <file with "label kind address" lines> --out <dir>
// Signing: if SIGNING_KEY_ENC_B64 / SIGNING_KEY_PASSPHRASE are set, the production issuer key is used (lib/sign.ts);
// otherwise a LOCAL THROWAWAY TEST KEY is loaded from --test-key (created with mode 0600 if missing). Keys are never printed.
// RPCs: SELLSIM_RPC (comma list, tried in order), SELLSIM_LOGS_RPC, SELLSIM_ARCHIVE_RPC.
import { sellSim, signProof } from "../lib/sellsim.ts";
import { keyIdOf, type Signer } from "../lib/attestation.ts";

export type RpcStat = { calls: number; errors: Record<string, number>; fallbacks: number };
export function makeFallbackRpc(urls: string[], stat: RpcStat) {
  return async (m: string, p: unknown[]) => {
    let last: Error | null = null;
    for (let i = 0; i < urls.length; i++) {
      for (let attempt = 0; attempt < 3; attempt++) {
        stat.calls++;
        try {
          const r = await fetch(urls[i], { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }), signal: AbortSignal.timeout(20000) });
          const txt = await r.text(); let d: any; try { d = JSON.parse(txt); } catch { throw new Error(`http_${r.status}`); }
          if (d.error) {
            const msg = String(d.error.message ?? "rpc_error");
            // execution reverts are results, not transport failures
            if (/revert/i.test(msg) && m === "eth_call") throw Object.assign(new Error(msg + (d.error.data ? " data=" + d.error.data : "")), { final: true });
            throw new Error(msg);
          }
          if (!("result" in d)) throw new Error("no_result");
          return d.result;
        } catch (e) {
          last = e as Error; const k = new URL(urls[i]).host + ": " + String(last.message).slice(0, 60); stat.errors[k] = (stat.errors[k] ?? 0) + 1;
          if ((e as any).final) throw e;
          if (/limit|429|rate|timeout|http_5/i.test(last.message)) { await new Promise((r) => setTimeout(r, 400 * (attempt + 1))); continue; }
          break;
        }
      }
      stat.fallbacks++;
    }
    throw last ?? new Error("rpc_failed");
  };
}
const b64e = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64d = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export async function testKeySigner(path: string): Promise<{ signer: Signer; publicKeyB64: string; label: string }> {
  let j: any;
  try { j = JSON.parse(await Deno.readTextFile(path)); } catch {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    j = { label: "THROWAWAY LOCAL TEST KEY - not the issuer key", public_key_b64: b64e(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey))),
      pkcs8_b64: b64e(new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey))) };
    await Deno.writeTextFile(path, JSON.stringify(j), { mode: 0o600, createNew: true });
  }
  const priv = await crypto.subtle.importKey("pkcs8", b64d(j.pkcs8_b64), { name: "Ed25519" }, false, ["sign"]);
  const keyId = await keyIdOf(b64d(j.public_key_b64));
  return { publicKeyB64: j.public_key_b64, label: j.label, signer: { keyId, sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", priv, m as Uint8Array<ArrayBuffer>)) } };
}

if (import.meta.main) {
  const a = [...Deno.args]; const opt = (n: string) => { const i = a.indexOf(n); if (i < 0) return null; const v = a[i + 1]; a.splice(i, 2); return v; };
  const keyPath = opt("--test-key"), out = opt("--out"), list = opt("--list");
  const tokens: { label: string; kind: string; address: string }[] = a.map((x) => ({ label: x, kind: "", address: x }));
  if (list) for (const l of (await Deno.readTextFile(list)).split("\n")) { const [label, kind, address] = l.trim().split(/\s+/); if (address) tokens.push({ label, kind, address }); }
  let signer: Signer, publicKeyB64: string, label: string;
  if (Deno.env.get("SIGNING_KEY_ENC_B64")) {
    const { envSigner, publicKeyInfo } = await import("../lib/sign.ts");
    signer = await envSigner(); publicKeyB64 = (await publicKeyInfo()).public_key_b64; label = "issuer key (server environment)";
  } else {
    if (!keyPath) { console.error("--test-key <file> required when no issuer key is configured"); Deno.exit(2); }
    ({ signer, publicKeyB64, label } = await testKeySigner(keyPath));
  }
  const stat: RpcStat = { calls: 0, errors: {}, fallbacks: 0 };
  const urls = (Deno.env.get("SELLSIM_RPC") ?? "https://mainnet.base.org,https://base.drpc.org,https://base-rpc.publicnode.com").split(",");
  const rpc = makeFallbackRpc(urls, stat);
  const logsRpc = makeFallbackRpc((Deno.env.get("SELLSIM_LOGS_RPC") ?? "https://base.gateway.tenderly.co").split(","), stat);
  const archiveRpc = makeFallbackRpc((Deno.env.get("SELLSIM_ARCHIVE_RPC") ?? "https://mainnet.base.org,https://base.drpc.org").split(","), stat);
  const head = Number(BigInt(await rpc("eth_blockNumber", []))) - 3;
  const blk = await rpc("eth_getBlockByNumber", ["0x" + head.toString(16), false]);
  const rows: any[] = [];
  for (const t of tokens) {
    const t0 = performance.now(); const before = stat.calls; let claims: any = null, err: string | null = null;
    try { claims = await sellSim(rpc, t.address, head, { logsRpc, archiveRpc, blockHash: blk?.hash ?? null, notes: [] }); } catch (e) { err = String((e as Error).message); }
    const ms = Math.round(performance.now() - t0);
    const proof = claims ? await signProof(claims, { token: t.address }, signer, { keyLabel: label }) : null;
    if (out && proof) await Deno.writeTextFile(`${out}/sellsim_proof_${t.label}.json`, JSON.stringify(proof, null, 1));
    const s = claims?.simulation?.result;
    const row = { label: t.label, kind: t.kind, token: t.address.toLowerCase(), block: head, version: claims?.selected?.version ?? null, pool: claims?.selected?.pool ?? null,
      quote: claims?.selected?.quote ?? null, fee: claims?.selected?.fee ?? null, hooks: claims?.selected?.hooks ?? null, depth_eth: claims?.candidates?.[0]?.quote_depth_eth ?? null,
      n_candidates: claims?.candidates?.length ?? 0, sellable: claims?.sellable ?? null, stage: s?.stage ?? null, buy_tax: s?.buy_tax ?? null, sell_tax: s?.sell_tax ?? null,
      buy_shortfall_vs_spot: s?.buy_shortfall_vs_spot ?? null, round_trip_return: s?.round_trip_return ?? null,
      revert: s?.revert?.message ?? s?.revert?.selector ?? null, rpc_error: claims?.simulation?.rpc_error ?? null, no_pool: claims?.no_pool_reason ?? null, error: err,
      token_created_block: claims?.token_created_block ?? null, discovery_notes: claims?.discovery_notes ?? [], latency_ms: ms, eth_call_ms: claims?.simulation?.eth_call_ms ?? null, rpc_calls: stat.calls - before };
    rows.push(row); console.log(JSON.stringify({ label: row.label, version: row.version, sellable: row.sellable, buy_tax: row.buy_tax, sell_tax: row.sell_tax, stage: row.stage, ms }));
  }
  if (out) await Deno.writeTextFile(`${out}/sellsim_rows.json`, JSON.stringify({ block: head, block_hash: blk?.hash ?? null, signer_key_id: signer.keyId, signer_label: label, public_key_b64: publicKeyB64, rpc_urls: urls, rpc_stat: stat, rows }, null, 1));
}
