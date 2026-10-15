// Port of the /base/* handlers (deterministic JSON-RPC reads only).
import { keccak_256 } from "@noble/hashes/sha3";
import { ADDR, HASH, hex } from "./util.ts";
export const REG = "0xb94704422c2a1e396835a571837aa5ae53285a95";
export type Rpc = (m: string, p: unknown[]) => Promise<any>;
export function makeRpc(url: string, f: typeof fetch = fetch): Rpc {
  return async (m, p) => {
    const r = await f(url, { method: "POST", headers: { "Content-Type": "application/json", "User-Agent": "base-reads/1.0" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }), signal: AbortSignal.timeout(15000) });
    const d = await r.json();
    if (d.error) throw new Error(d.error.message);
    return d.result;
  };
}
const k = (b: Uint8Array) => keccak_256(b);
export function namehash(n: string): Uint8Array {
  let h: Uint8Array = new Uint8Array(32);
  for (const l of n.split(".").filter(Boolean).reverse()) { const c = new Uint8Array(64); c.set(h); c.set(k(new TextEncoder().encode(l)), 32); h = k(c); }
  return h;
}
const big = (x: string) => BigInt(x === "0x" ? "0x0" : x);
export function decStr(r: string): string | null {
  const b = Uint8Array.from((r.slice(2).match(/../g) ?? []).map((x) => parseInt(x, 16)));
  if (b.length < 64) return null;
  const o = Number(BigInt("0x" + hex(b.slice(0, 32)))), n = Number(BigInt("0x" + hex(b.slice(o, o + 32))));
  return new TextDecoder().decode(b.slice(o + 32, o + 32 + n)) || null;
}
export class Chain {
  constructor(public rpc: Rpc, public usdc: string) {}
  call(to: string, data: string) { return this.rpc("eth_call", [{ to, data }, "latest"]); }
  async resolver(node: Uint8Array) { const r = await this.call(REG, "0x0178b8bf" + hex(node)); return "0x" + r.slice(-40); }
  async reverseName(a: string): Promise<string | null> {
    const node = namehash(a.slice(2).toLowerCase() + ".80002105.reverse"); const res = await this.resolver(node);
    let nm = big(res) ? decStr(await this.call(res, "0x691f3431" + hex(node))) : null;
    if (nm) { const fn = namehash(nm), fr = await this.resolver(fn);
      if (!big(fr) || ("0x" + (await this.call(fr, "0x3b3b57de" + hex(fn))).slice(-40)).toLowerCase() !== a.toLowerCase()) nm = null; }
    return nm;
  }
  async handle(path: string, q: Record<string, string>): Promise<[number, unknown]> {
    const rpc = this.rpc;
    const bal = async (a: string) => [big(await this.call(this.usdc, "0x70a08231" + a.slice(2).toLowerCase().padStart(64, "0"))), big(await rpc("eth_getBalance", [a, "latest"]))];
    if (path === "/base/address-intel") {
      const a = q.address ?? ""; if (!ADDR.test(a)) return [400, { error: "address must be 0x + 40 hex" }];
      const [raw, eth] = await bal(a); const code = await rpc("eth_getCode", [a, "latest"]);
      return [200, { chain: "base", address: a, usdc: Number(raw) / 1e6, eth: Number(eth) / 1e18, primary_basename: await this.reverseName(a),
        tx_count: Number(big(await rpc("eth_getTransactionCount", [a, "latest"]))), is_contract: !["0x", "0x0", ""].includes(code), block: Number(big(await rpc("eth_blockNumber", []))) }];
    }
    if (path === "/base/usdc-balance") {
      const a = q.address ?? ""; if (!ADDR.test(a)) return [400, { error: "address must be 0x + 40 hex" }];
      const [raw, eth] = await bal(a);
      return [200, { chain: "base", address: a, usdc: Number(raw) / 1e6, usdc_raw: raw.toString(), eth: Number(eth) / 1e18, eth_wei: eth.toString(), block: Number(big(await rpc("eth_blockNumber", []))) }];
    }
    if (path === "/base/tx-status") {
      const h = q.hash ?? ""; if (!HASH.test(h)) return [400, { error: "hash must be 0x + 64 hex" }];
      const rc = await rpc("eth_getTransactionReceipt", [h]); const head = Number(big(await rpc("eth_blockNumber", [])));
      if (!rc) { const tx = await rpc("eth_getTransactionByHash", [h]); return [200, { chain: "base", hash: h, status: tx ? "pending" : "not_found" }]; }
      const b = Number(big(rc.blockNumber));
      return [200, { chain: "base", hash: h, status: rc.status === "0x1" ? "success" : "failed", block: b, confirmations: head - b + 1, from: rc.from, to: rc.to ?? null,
        gas_used: Number(big(rc.gasUsed)), effective_gas_price_wei: big(rc.effectiveGasPrice ?? "0x0").toString(), logs: rc.logs.length }];
    }
    if (path === "/base/basename") {
      if (q.name) {
        let n = q.name.toLowerCase().trim(); if (!n.endsWith(".base.eth")) n += ".base.eth";
        if (!/^[a-z0-9-]+\.base\.eth$/.test(n)) return [400, { error: "invalid name" }];
        const node = namehash(n), res = await this.resolver(node);
        if (!big(res)) return [200, { name: n, address: null }];
        const a = "0x" + (await this.call(res, "0x3b3b57de" + hex(node))).slice(-40);
        return [200, { name: n, address: big(a) ? a : null, resolver: res }];
      }
      const a = q.address ?? ""; if (!ADDR.test(a)) return [400, { error: "give ?name= or ?address=" }];
      return [200, { address: a, primary_basename: await this.reverseName(a) }];
    }
    if (path === "/base/network") {
      const b = await rpc("eth_getBlockByNumber", ["latest", false]);
      return [200, { chain: "base", chain_id: 8453, block: Number(big(b.number)), block_age_s: Math.max(0, Math.floor(Date.now() / 1000) - Number(big(b.timestamp))),
        base_fee_gwei: Number(big(b.baseFeePerGas ?? "0x0")) / 1e9, gas_price_gwei: Number(big(await rpc("eth_gasPrice", []))) / 1e9 }];
    }
    throw new Error("unknown route");
  }
}
