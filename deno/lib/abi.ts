// Minimal ABI encoder/decoder for the types the pre-sign decoder needs (no external dependency).
// Types: address, bool, uintN, intN, bytesN (N<=32), bytes, string, T[] and (T1,T2,...) tuples.
import { keccak_256 } from "@noble/hashes/sha3";
import { hex } from "./util.ts";
export const selector = (sig: string) => "0x" + hex(keccak_256(new TextEncoder().encode(sig)).slice(0, 4));
function splitTop(s: string): string[] { const out: string[] = []; let d = 0, cur = "";
  for (const ch of s) { if (ch === "(") d++; if (ch === ")") d--; if (ch === "," && d === 0) { out.push(cur); cur = ""; } else cur += ch; }
  if (cur) out.push(cur); return out; }
const isTuple = (t: string) => t.startsWith("(") && t.endsWith(")");
const tupleTypes = (t: string) => splitTop(t.slice(1, -1));
const isArray = (t: string) => t.endsWith("[]");
const fixedArr = (t: string) => { const m = t.match(/^(.*)\[(\d+)\]$/); return m ? { it: m[1], n: Number(m[2]) } : null; };
export function isDynamic(t: string): boolean {
  if (t === "bytes" || t === "string" || isArray(t)) return true;
  const fa = fixedArr(t); if (fa) return isDynamic(fa.it);
  if (isTuple(t)) return tupleTypes(t).some(isDynamic); return false;
}
const headSize = (t: string): number => isDynamic(t) ? 32 : fixedArr(t) ? fixedArr(t)!.n * headSize(fixedArr(t)!.it) : isTuple(t) ? tupleTypes(t).reduce((a, x) => a + headSize(x), 0) : 32;
const W = (v: bigint) => { if (v < 0n) v += 1n << 256n; return v.toString(16).padStart(64, "0"); };
const padR = (h: string) => h + "0".repeat((64 - (h.length % 64)) % 64);
export function encode(types: string[], vals: unknown[]): string {
  let head = "", tail = ""; const hs = types.reduce((a, t) => a + headSize(t), 0);
  types.forEach((t, i) => {
    const e = encOne(t, vals[i]);
    if (isDynamic(t)) { head += W(BigInt(hs + tail.length / 2)); tail += e; } else head += e;
  });
  return head + tail;
}
function encOne(t: string, v: any): string {
  if (isArray(t)) { const it = t.slice(0, -2); return W(BigInt(v.length)) + encode(v.map(() => it), v); }
  if (isTuple(t)) return encode(tupleTypes(t), v);
  const fa = fixedArr(t); if (fa) return encode(Array(fa.n).fill(fa.it), v);
  if (t === "address") return String(v).slice(2).toLowerCase().padStart(64, "0");
  if (t === "bool") return W(v ? 1n : 0n);
  if (t.startsWith("uint") || t.startsWith("int")) return W(BigInt(v));
  if (t === "bytes" || t === "string") { const h = t === "string" ? hex(new TextEncoder().encode(v)) : String(v).replace(/^0x/, ""); return W(BigInt(h.length / 2)) + padR(h); }
  if (/^bytes\d+$/.test(t)) return padR(String(v).replace(/^0x/, ""));
  throw new Error("abi: unsupported " + t);
}
export function decode(types: string[], data: string, base = 0): any[] {
  const h = data.replace(/^0x/, ""); let p = base; const out: any[] = [];
  const word = (o: number) => { const s = h.slice(o * 2, o * 2 + 64); if (s.length < 64) throw new Error("abi: short data"); return BigInt("0x" + s); };
  for (const t of types) {
    if (isDynamic(t)) { const off = Number(word(p)); if (off > h.length / 2) throw new Error("abi: bad offset"); out.push(decOne(t, h, base + off)); p += 32; }
    else { out.push(decOne(t, h, p)); p += headSize(t); }
  }
  return out;
}
function decOne(t: string, h: string, o: number): any {
  const word = (x: number) => { const s = h.slice(x * 2, x * 2 + 64); if (s.length < 64) throw new Error("abi: short data"); return BigInt("0x" + s); };
  if (isArray(t)) { const n = Number(word(o)); if (n > 4096) throw new Error("abi: array too long"); const it = t.slice(0, -2); return decode(Array(n).fill(it), h, o + 32); }
  if (isTuple(t)) return decode(tupleTypes(t), h, o);
  const fa = fixedArr(t); if (fa) return decode(Array(fa.n).fill(fa.it), h, o);
  if (t === "address") return "0x" + word(o).toString(16).padStart(40, "0").slice(-40);
  if (t === "bool") return word(o) !== 0n;
  if (t.startsWith("uint")) return word(o);
  if (t.startsWith("int")) { const bits = Number(t.slice(3) || 256); const v = word(o) & ((1n << BigInt(bits)) - 1n); return v >= 1n << BigInt(bits - 1) ? v - (1n << BigInt(bits)) : v; }
  if (t === "bytes" || t === "string") { const n = Number(word(o)); if (n > h.length) throw new Error("abi: bad length"); const b = h.slice((o + 32) * 2, (o + 32) * 2 + n * 2); return t === "bytes" ? "0x" + b : new TextDecoder().decode(Uint8Array.from((b.match(/../g) ?? []).map((x) => parseInt(x, 16)))); }
  if (/^bytes\d+$/.test(t)) return "0x" + h.slice(o * 2, o * 2 + Number(t.slice(5)) * 2);
  throw new Error("abi: unsupported " + t);
}
export const call = (sig: string, vals: unknown[]) => selector(sig) + encode(splitTop(sig.slice(sig.indexOf("(") + 1, -1)), vals);
export const argTypes = (sig: string) => splitTop(sig.slice(sig.indexOf("(") + 1, -1));
