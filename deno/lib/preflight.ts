// Port of api/preflight.py (facts, validation, Bazaar facts). Same facts schema and signatures.
import { sign } from "./sign.ts";
import { kv } from "./store.ts";
import { isoSec } from "./util.ts";
export const SCHEMA = "prepay-check/v1", UA = "gbmrafli-prepay-check/1.0";
const ADDR = /^0x[0-9a-fA-F]{40}$/;

// ---------- SSRF guard ----------
function v4(ip: string) { return ip.split(".").map(Number); }
export function ipAllowed(ip: string): boolean {
  if (ip.includes(":")) {
    const s = ip.toLowerCase();
    if (s === "::" || s === "::1") return false;
    if (/^(fe[89ab]|fc|fd|ff)/.test(s)) return false;                       // link-local, ULA, multicast
    const m = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); if (m) return ipAllowed(m[1]);
    if (s.startsWith("2001:db8") || s.startsWith("64:ff9b") || s.startsWith("100::")) return false;
    if (s.startsWith("2002:") || /^2001:0{0,4}:/.test(s) || s.startsWith("::")) return false; // 6to4, Teredo, IPv4-compatible (embed IPv4)
    return /^[23][0-9a-f]{0,3}:/.test(s);                                    // only global unicast 2000::/3

  }
  const [a, b] = v4(ip);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;           // this-net, private, loopback, multicast+reserved
  if (a === 169 && b === 254) return false;                                  // link-local / metadata
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;                        // CGNAT (Python: is_private)
  if (a === 198 && (b === 18 || b === 19)) return false;                     // benchmarking
  if (a === 192 && b === 0 && (v4(ip)[2] === 0 || v4(ip)[2] === 2)) return false;
  if ((a === 198 && b === 51) || (a === 203 && b === 0)) return false;       // documentation
  return true;
}
// Returns IPs, [] when the name does not exist, or null when DNS lookup itself is unavailable in the runtime.
export const ALLOWED_PORTS = new Set(["443", "8443"]);
export type Resolver = (host: string) => Promise<string[] | null>;
export const dnsResolver: Resolver = async (host) => {
  const out: string[] = []; let usable = false;
  for (const t of ["A", "AAAA"] as const) {
    try { out.push(...(await Deno.resolveDns(host, t)) as string[]); usable = true; }
    catch (e) { if ((e as Error)?.name === "NotFound") usable = true; }
  }
  return usable ? out : null;
};
const isIpLiteral = (h: string) => /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(":");
export async function checkUrl(url: string, resolver: Resolver = dnsResolver): Promise<{ u: URL | null; err: string | null }> {
  let u: URL; try { u = new URL(url); } catch { return { u: null, err: "unparseable url" }; }
  if (u.protocol !== "https:" || !u.hostname) return { u: null, err: "url must be https://host/..." };
  if (url.length > 2048) return { u: null, err: "url too long" };
  if (u.username || u.password) return { u: null, err: "credentials in url not allowed" };
  if (u.port && !ALLOWED_PORTS.has(u.port)) return { u: null, err: "port not allowed (443, 8443)" };
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const ips = isIpLiteral(host) ? [host] : await resolver(host);
  if (ips === null) return { u, err: null };   // no DNS API: rely on fetch (Deploy has no route to our private networks)
  if (!ips.length) return { u, err: "dns_unresolvable" };
  for (const ip of ips) if (!ipAllowed(ip)) return { u: null, err: "target resolves to a non-public address" };
  return { u, err: null };
}

// ---------- probe (one unpaid GET, no redirects) ----------
export type Fetcher = (u: string, init: RequestInit) => Promise<Response>;
/** Read at most `cap` bytes of a body, then cancel the stream (never buffers an unbounded response). */
async function readCapped(res: Response, cap: number): Promise<Uint8Array> {
  const out = new Uint8Array(cap); let n = 0;
  if (!res.body) return out.slice(0, 0);
  const rd = res.body.getReader();
  try {
    while (n < cap) { const { value, done } = await rd.read(); if (done) break; const take = Math.min(value.length, cap - n); out.set(value.subarray(0, take), n); n += take; }
  } catch { /* truncated */ } finally { rd.cancel().catch(() => {}); }
  return out.slice(0, n);
}
export async function probe(u: URL, timeoutMs = 8000, f: Fetcher = fetch): Promise<[Record<string, unknown>, any]> {
  const t0 = performance.now();
  let res: Response;
  try {
    res = await f(u.toString(), { method: "GET", redirect: "manual", headers: { "User-Agent": UA, "Accept": "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    const name = (e as Error)?.name === "TimeoutError" ? "TimeoutError" : "ConnectionError";
    return [{ reachable: false, error_class: name, latency_ms: Math.round(performance.now() - t0) }, null];
  }
  const buf = await readCapped(res, 65536);
  const lat = Math.round(performance.now() - t0);
  let ch: any = null;
  const pr = res.headers.get("payment-required");
  if (pr !== null) { try { ch = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(pr), (c) => c.charCodeAt(0)))); } catch { ch = { _unparseable: "header" }; } }
  else if (res.status === 402) { try { ch = JSON.parse(new TextDecoder().decode(buf)); } catch { ch = { _unparseable: "body" }; } }
  return [{ reachable: true, http_status: res.status, latency_ms: lat }, ch];
}

export function validateChallenge(ch: any): [boolean, string[], Record<string, unknown>[]] {
  if (ch === null || ch === undefined) return [false, ["no_402_challenge"], []];
  if (typeof ch === "object" && "_unparseable" in ch) return [false, ["challenge_" + ch._unparseable + "_not_json"], []];
  const p: string[] = [];
  if (ch.x402Version !== 1 && ch.x402Version !== 2) p.push("unknown_x402Version");
  const acc = ch.accepts;
  if (!Array.isArray(acc) || !acc.length) return [false, [...p, "accepts_missing_or_empty"], []];
  const out: Record<string, unknown>[] = [];
  acc.forEach((a: any, i: number) => {
    if (typeof a !== "object" || a === null || Array.isArray(a)) { p.push(`accepts[${i}]_not_object`); return; }
    const amt = "amount" in a ? a.amount : a.maxAmountRequired;
    const isInt = (x: unknown) => typeof x === "number" && Number.isInteger(x);
    const checks: [string, boolean][] = [
      ["scheme", typeof a.scheme === "string"], ["network", typeof a.network === "string"],
      ["amount", typeof amt === "string" && /^[0-9]+$/.test(amt)],
      ["asset", typeof a.asset === "string" && ADDR.test(a.asset)], ["payTo", typeof a.payTo === "string" && ADDR.test(a.payTo)],
      ["maxTimeoutSeconds", isInt(a.maxTimeoutSeconds) && a.maxTimeoutSeconds > 0 && a.maxTimeoutSeconds <= 3600]];
    for (const [f, ok] of checks) if (!ok) p.push(`accepts[${i}].${f}_invalid`);
    out.push({ scheme: a.scheme ?? null, network: a.network ?? null, amount: amt ?? null, asset: a.asset ?? null, payTo: a.payTo ?? null });
  });
  return [p.length === 0, p, out];
}

// ---------- Bazaar snapshot index (same shape as Python build_index) ----------
export type Index = { date: string; listings: number; hosts: Record<string, number>; wallet_hosts: Record<string, string[]>;
  resources: Record<string, { payers30d: unknown; calls30d: unknown; lastCalledAt: unknown; payTo: string[] }> };
export function hostOf(url: string) { try { return new URL(url).hostname.toLowerCase(); } catch { return ""; } }
export class IndexAssembler {
  hosts: Record<string, number> = {}; wallets = new Map<string, Set<string>>(); res: Index["resources"] = {}; n = 0;
  add(items: any[]) {
    for (const it of items) {
      this.n++;
      const u = it.resource || ""; const h = hostOf(u); if (!h) continue;
      this.hosts[h] = (this.hosts[h] ?? 0) + 1;
      for (const a of it.accepts || []) { const w = (a.payTo || "").toLowerCase(); if (w) { if (!this.wallets.has(w)) this.wallets.set(w, new Set()); this.wallets.get(w)!.add(h); } }
      const q = it.quality || {};
      this.res[u.split("?")[0]] = { payers30d: q.l30DaysUniquePayers ?? null, calls30d: q.l30DaysTotalCalls ?? null, lastCalledAt: q.lastCalledAt ?? null,
        payTo: [...new Set((it.accepts || []).filter((a: any) => a.payTo).map((a: any) => a.payTo.toLowerCase()))].sort() as string[] };
    }
  }
  build(date: string): Index {
    const wh: Record<string, string[]> = {}; for (const [w, s] of this.wallets) wh[w] = [...s].sort();
    return { date, listings: this.n, hosts: this.hosts, wallet_hosts: wh, resources: this.res };
  }
}
// KV values are capped at 64 KiB: store gzip(JSON) in 60 KB chunks
const CHUNK = 60000;
async function gz(s: string, mode: "c" | "d", data?: Uint8Array): Promise<Uint8Array> {
  const stream = mode === "c" ? new Blob([s]).stream().pipeThrough(new CompressionStream("gzip")) : new Blob([data! as Uint8Array<ArrayBuffer>]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
export async function saveIndex(idx: Index, keep = 60) {
  const k = await kv(); const z = await gz(JSON.stringify(idx), "c"); const n = Math.ceil(z.length / CHUNK);
  for (let i = 0; i < n; i++) await k.set(["snap", idx.date, i], z.slice(i * CHUNK, (i + 1) * CHUNK));
  await k.set(["snapdate", idx.date], n);
  const dates = await snapshotDates();
  for (const d of dates.slice(0, Math.max(0, dates.length - keep))) {
    for await (const e of k.list({ prefix: ["snap", d] })) await k.delete(e.key);
    await k.delete(["snapdate", d]);
  }
}
export async function snapshotDates(): Promise<string[]> {
  const k = await kv(); const out: string[] = [];
  for await (const e of k.list({ prefix: ["snapdate"] })) out.push(e.key[1] as string);
  return out.sort();
}
const idxCache = new Map<string, Index>();
export async function loadIndex(date: string): Promise<Index> {
  if (idxCache.has(date)) return idxCache.get(date)!;
  const k = await kv(); const parts: Uint8Array[] = [];
  for await (const e of k.list<Uint8Array>({ prefix: ["snap", date] })) parts.push(e.value);
  const all = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
  const idx = JSON.parse(new TextDecoder().decode(await gz("", "d", all))) as Index;
  if (idxCache.size > 16) idxCache.clear();
  idxCache.set(date, idx); return idx;
}
export function clearIndexCache() { idxCache.clear(); }
export async function bazaarFacts(url: string, paytoList: string[], maxTrend = 14) {
  const dates = await snapshotDates();
  if (!dates.length) return { available: false, reason: "no_snapshot" };
  const last = dates[dates.length - 1]; const idx = await loadIndex(last); const h = hostOf(url); const key = url.split("?")[0];
  const cur = idx.resources[key] ?? null; const listed = cur?.payTo ?? [];
  const wl: Record<string, unknown> = {};
  const ws = new Set([...paytoList.filter(Boolean).map((x) => x.toLowerCase()), ...listed]);
  for (const w of ws) { const hs = idx.wallet_hosts[w] ?? []; wl[w] = { hosts_using_wallet: hs.length, other_hosts_sample: hs.filter((x) => x !== h).slice(0, 10) }; }
  const trend = [];
  for (const d of dates.slice(-maxTrend)) { const r = (d === last ? idx : await loadIndex(d)).resources[key]; trend.push({ snapshot: d, payers30d: r ? r.payers30d : null, calls30d: r ? r.calls30d : null }); }
  return { available: true, snapshot_date: last, listed: cur !== null, listed_payTo: listed, host_listing_count: idx.hosts[h] ?? 0,
    payout_wallet_reuse: wl, last_called_at: cur ? cur.lastCalledAt : null, payer_trend: trend };
}

export async function preflight(url: string, opts: { resolver?: Resolver; fetcher?: Fetcher; now?: number; env?: (k: string) => string | undefined } = {}): Promise<[number, unknown]> {
  const { u, err } = await checkUrl(url, opts.resolver);
  if (!u) return [400, { error: err }];
  const base = { schema: SCHEMA, target: url, checked_at: isSoc(opts.now), disclaimer: "Deterministic observations only. Not advice to pay, buy or sell." };
  let reach: Record<string, unknown>, ch: any;
  if (err === "dns_unresolvable") { reach = { reachable: false, error_class: "dns_unresolvable" }; ch = null; }
  else [reach, ch] = await probe(u, 8000, opts.fetcher);
  const [valid, problems, acc] = validateChallenge(ch);
  const facts = { ...base, reachability: reach, challenge: { valid, problems, accepts: acc },
    bazaar: await bazaarFacts(url, acc.map((a) => a.payTo as string).filter(Boolean)) };
  return [200, await sign(facts, opts.env)];
}
function isSoc(now?: number) { return isoSec(now ?? Date.now()); }
