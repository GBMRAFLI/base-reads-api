import { sha256 } from "@noble/hashes/sha256";
export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const sha256hex = (s: string) => hex(sha256(new TextEncoder().encode(s)));
export const iso = (t = Date.now()) => new Date(t).toISOString();            // same as Python iso(): ...SS.mmmZ
export const isoSec = (t = Date.now()) => new Date(t).toISOString().slice(0, 19) + "Z";
const pyStr = (v: unknown) => v === null || v === undefined ? "None" : v === true ? "True" : v === false ? "False" : String(v);
export const rid = (prefix: string, ...parts: unknown[]) => prefix + "-" + sha256hex(parts.map(pyStr).join("|")).slice(0, 12);
export const b64json = (o: unknown, dumps: (v: unknown) => string) => btoa(unescape(encodeURIComponent(dumps(o))));
export const ADDR = /^0x[0-9a-fA-F]{40}$/, HASH = /^0x[0-9a-fA-F]{64}$/;
// Python: dict(x.split("=", 1) for x in qs.split("&") if "=" in x)  (no percent-decoding)
export function pyQuery(qs: string): Record<string, string> {
  const q: Record<string, string> = {};
  for (const x of qs.split("&")) if (x.includes("=")) { const i = x.indexOf("="); q[x.slice(0, i)] = x.slice(i + 1); }
  return q;
}
// Python urllib.parse.unquote
export function unquote(s: string): string { try { return decodeURIComponent(s); } catch { return s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))); } }
