// Port of api/preflight.py (facts, validation, Bazaar facts). Same facts schema and signatures.
import { envSigner, sign } from "./sign.ts";
import { attest, type Rpc, type Signer } from "./attestation.ts";
import { Semaphore } from "./guards.ts";
/** A9: a target gets 5 s to answer. */
export const PROBE_TIMEOUT_MS = 5000;
/** Bounded outbound concurrency for target probes (protects third parties and this host). */
export let OUTBOUND = new Semaphore(4);
export function configureOutbound(n: number) { OUTBOUND = new Semaphore(n); }
const hexOf = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
export class SnapshotHashMismatch extends Error { override name = "SnapshotHashMismatch"; }
import { kv } from "./store.ts";
import { isoSec } from "./util.ts";
export const SCHEMA = "prepay-check/v1", UA = "base-reads-prepay-check/1.0";
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
export async function checkUrl(url: string, resolver: Resolver = dnsResolver): Promise<{ u: URL | null; err: string | null; ips?: string[] }> {
  let u: URL; try { u = new URL(url); } catch { return { u: null, err: "unparseable url" }; }
  if (u.protocol !== "https:" || !u.hostname) return { u: null, err: "url must be https://host/..." };
  if (url.length > 2048) return { u: null, err: "url too long" };
  if (u.username || u.password) return { u: null, err: "credentials in url not allowed" };
  if (u.port && !ALLOWED_PORTS.has(u.port)) return { u: null, err: "port not allowed (443, 8443)" };
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const ips = isIpLiteral(host) ? [host] : await resolver(host);
  // Refuse when we cannot see the addresses we would connect to: no DNS API, or no answers.
  if (ips === null) return { u: null, err: "dns resolution unavailable" };
  if (!ips.length) return { u, err: "dns_unresolvable" };
  for (const ip of ips) if (!ipAllowed(ip)) return { u: null, err: "target resolves to a non-public address" };
  return { u, err: null, ips };
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
// ---------- pinned HTTPS (no DNS rebinding) ----------
/** Opens a TCP connection to the already-checked IP and upgrades it to TLS with the ORIGINAL hostname (SNI + certificate
 * verification), the same as the Python PinnedHTTPSConnection. fetch() would resolve the name again. */
export type Connector = (ip: string, port: number, host: string) => Promise<{ readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array>; close(): void }>;
export const pinnedConnect: Connector = async (ip, port, host) => {
  const tcp = await Deno.connect({ hostname: ip, port, transport: "tcp" });
  try { return await Deno.startTls(tcp, { hostname: host, alpnProtocols: ["http/1.1"] }); } catch (e) { try { tcp.close(); } catch { /* consumed */ } throw e; }
};
export type RawResponse = { status: number; headers: Headers; body: Uint8Array };
/** One HTTP/1.1 GET over a pinned connection. Header block and body each capped at 64 KB; Connection: close; no redirects. */
export async function pinnedGet(u: URL, ip: string, timeoutMs = 8000, connect: Connector = pinnedConnect, cap = 65536): Promise<RawResponse> {
  const port = Number(u.port || 443); const host = u.hostname.replace(/^\[|\]$/g, "");
  let timer: ReturnType<typeof setTimeout> | undefined; let conn: Awaited<ReturnType<Connector>> | null = null;
  const work = (async () => {
    conn = await connect(ip, port, host);
    const hostHdr = u.port ? `${u.hostname}:${u.port}` : u.hostname;
    const req = `GET ${u.pathname || "/"}${u.search} HTTP/1.1\r\nHost: ${hostHdr}\r\nUser-Agent: ${UA}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n`;
    const w = conn.writable.getWriter(); await w.write(new TextEncoder().encode(req)); w.releaseLock();
    const rd = conn.readable.getReader(); let buf = new Uint8Array(0); const limit = cap * 2 + 8192;
    try {
      while (buf.length < limit) { const { value, done } = await rd.read(); if (done) break; const nb = new Uint8Array(buf.length + value.length); nb.set(buf); nb.set(value, buf.length); buf = nb; }
    } finally { rd.cancel().catch(() => {}); }
    return parseHttp(buf, cap);
  })();
  try {
    return await Promise.race([work, new Promise<never>((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error("timeout"), { name: "TimeoutError" })), timeoutMs); })]);
  } finally { clearTimeout(timer); try { (conn as any)?.close(); } catch { /* closed */ } }
}
export function parseHttp(buf: Uint8Array, cap = 65536): RawResponse {
  let he = -1; for (let i = 0; i + 3 < buf.length && i < cap; i++) if (buf[i] === 13 && buf[i + 1] === 10 && buf[i + 2] === 13 && buf[i + 3] === 10) { he = i; break; }
  if (he < 0) throw Object.assign(new Error("bad response"), { name: "ProtocolError" });
  const lines = new TextDecoder().decode(buf.subarray(0, he)).split("\r\n");
  const m = lines[0].match(/^HTTP\/1\.[01] (\d{3})/); if (!m) throw Object.assign(new Error("bad status"), { name: "ProtocolError" });
  const headers = new Headers();
  for (const l of lines.slice(1)) { const i = l.indexOf(":"); if (i > 0) try { headers.append(l.slice(0, i).trim(), l.slice(i + 1).trim()); } catch { /* invalid header */ } }
  let body = buf.subarray(he + 4);
  if ((headers.get("transfer-encoding") ?? "").toLowerCase().includes("chunked")) {
    const out: number[] = []; let p = 0; const td = new TextDecoder();
    while (p < body.length && out.length < cap) {
      let e = p; while (e + 1 < body.length && !(body[e] === 13 && body[e + 1] === 10)) e++;
      const n = parseInt(td.decode(body.subarray(p, e)).split(";")[0], 16); if (!Number.isFinite(n) || n === 0) break;
      const st = e + 2; for (let i = st; i < Math.min(st + n, body.length) && out.length < cap; i++) out.push(body[i]); p = st + n + 2;
    }
    body = Uint8Array.from(out);
  } else {
    const cl = Number(headers.get("content-length")); if (Number.isFinite(cl) && cl >= 0 && headers.has("content-length")) body = body.subarray(0, cl);
  }
  return { status: Number(m[1]), headers, body: body.slice(0, cap) };
}
/** One unpaid GET. Production: pinned to the checked IP (`ip`), no re-resolution. A Fetcher is only for tests. */
export async function probe(u: URL, timeoutMs = 8000, f?: Fetcher, ip?: string, connect: Connector = pinnedConnect): Promise<[Record<string, unknown>, any]> {
  const t0 = performance.now();
  let res: { status: number; headers: Headers }; let buf: Uint8Array;
  try {
    if (f) {
      const r = await f(u.toString(), { method: "GET", redirect: "manual", headers: { "User-Agent": UA, "Accept": "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
      res = r; buf = await readCapped(r, 65536);
    } else {
      if (!ip) throw Object.assign(new Error("no pinned ip"), { name: "ConnectionError" });
      const r = await pinnedGet(u, ip, timeoutMs, connect); res = r; buf = r.body;
    }
  } catch (e) {
    const name = (e as Error)?.name === "TimeoutError" ? "TimeoutError" : "ConnectionError";
    return [{ reachable: false, error_class: name, latency_ms: Math.round(performance.now() - t0) }, null];
  }
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
    const str = (x: unknown) => typeof x === "string" ? x : null; // summary: strings only (huge ints/objects -> null)
    out.push({ scheme: str(a.scheme), network: str(a.network), amount: str(amt), asset: str(a.asset), payTo: str(a.payTo) });
  });
  return [p.length === 0, p, out];
}

// ---------- Bazaar snapshot index (same shape as Python build_index) ----------
export type SnapTier = "full" | "reduced" | "aggregate";
export type SnapDateMeta = {
  /** Absent / legacy:true => flat ["snap", date, i] chunks (pre-generation format). */
  gen?: number | string; chunks: number; tier: SnapTier;
  status: "complete" | "partial" | null; listings: number; gzip_bytes: number;
  legacy?: boolean;
  /** sha256 (hex) of the stored gzip bytes; checked on every load (A11). Absent on older snapshots. */
  sha256?: string;
  /** ISO time of the successful save that produced this meta; null if unknown. */
  last_attempt_at?: string | null;
};
export type Index = { date: string; listings: number; hosts: Record<string, number>;
  /** Full tier: wallet -> host list. Reduced tier: wallet -> host count (number). */
  wallet_hosts: Record<string, string[] | number>;
  resources: Record<string, { payers30d: unknown; calls30d: unknown; lastCalledAt: unknown; payTo: string[] }>;
  coverage?: { pages_fetched: number; max_pages: number; items_indexed: number; bazaar_total: number | null; complete: boolean;
    status?: "complete" | "partial"; partial?: boolean; failed_pages?: number[] };
  status?: "complete" | "partial"; tier?: SnapTier;
  aggregate?: { hosts: number; payout_wallets: number } };
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
// KV values are capped at 64 KiB: store gzip(JSON) in 60 KB chunks under ["snap", date, gen, i]
export const CHUNK = 60000;
export const FULL_MAX_AGE_DAYS = 3;
/** Test hooks for crash injection. */
let _saveCrashAfterChunks: number | null = null;
let _saveCrashAfterFlip = false;
export function setSaveCrashAfterChunks(n: number | null) { _saveCrashAfterChunks = n; }
export function setSaveCrashAfterFlip(v: boolean) { _saveCrashAfterFlip = v; }
let _beforeFlip: (() => Promise<void>) | null = null;
/** Test hook: runs after chunks are written, before the snapdate flip. */
export function setBeforeFlip(f: (() => Promise<void>) | null) { _beforeFlip = f; }
/** Unique, time-ordered generation id for one save attempt. */
export function newGenId(now = Date.now()) { return String(now).padStart(15, "0") + "-" + crypto.randomUUID(); }
/** True when gen `g` is strictly older than the active gen `keep` (numeric gens predate string ids). */
export function genOlder(g: number | string, keep: number | string) {
  if (typeof keep === "number") return typeof g === "number" && g < keep;
  return typeof g === "number" || g < keep;
}
async function gz(s: string, mode: "c" | "d", data?: Uint8Array): Promise<Uint8Array> {
  const stream = mode === "c" ? new Blob([s]).stream().pipeThrough(new CompressionStream("gzip")) : new Blob([data! as Uint8Array<ArrayBuffer>]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
export function dayAge(date: string, today: string) {
  return Math.floor((Date.parse(today + "T00:00:00Z") - Date.parse(date + "T00:00:00Z")) / 86400000);
}
export function isLegacyMeta(meta: SnapDateMeta | number | null | undefined): boolean {
  if (meta == null) return false;
  if (typeof meta === "number") return true;
  return meta.legacy === true || meta.gen == null;
}
export async function readSnapMeta(date: string): Promise<SnapDateMeta | null> {
  const k = await kv(); const e = await k.get<SnapDateMeta | number>(["snapdate", date]);
  if (e.value == null) return null;
  if (typeof e.value === "number") {
    return { chunks: e.value, tier: "full", status: null, listings: 0, gzip_bytes: 0, legacy: true, last_attempt_at: null };
  }
  // Object without gen => legacy flat layout
  if (e.value.gen == null || e.value.legacy) {
    return { ...e.value, legacy: true, last_attempt_at: e.value.last_attempt_at ?? null };
  }
  return e.value;
}
export async function listSnapMetas(): Promise<{ date: string; meta: SnapDateMeta }[]> {
  const k = await kv(); const out: { date: string; meta: SnapDateMeta }[] = [];
  for await (const e of k.list<SnapDateMeta | number>({ prefix: ["snapdate"] })) {
    const date = e.key[1] as string;
    const m = await readSnapMeta(date);
    if (m) out.push({ date, meta: m });
  }
  return out.sort((a, b) => a.date.localeCompare(b.date));
}
/** Grace period before a non-active gen may be purged: covers saves still in progress and clock step-backs. */
export const GEN_PURGE_GRACE_MS = 60 * 60 * 1000;
/** Creation time encoded in a string gen id; NaN for numeric (pre-id) gens. */
export function genTime(g: number | string) { return typeof g === "string" ? Number(g.split("-")[0]) : NaN; }
/** Purge snap chunks for `date` that are not the active `keepGen`: legacy flat keys and numeric gens always,
 * string gens only once their id is older than GEN_PURGE_GRACE_MS (independent of ordering vs the active gen,
 * so a clock step-back can neither delete an in-progress save nor keep a stale one forever). keepGen null => no-op. */
export async function purgeOrphanGens(date: string, keepGen: number | string | null, now = Date.now()) {
  if (keepGen == null) return;
  const k = await kv();
  for await (const e of k.list({ prefix: ["snap", date] })) {
    const key = e.key;
    if (key.length === 3 && typeof key[2] === "number") { await k.delete(key); continue; } // legacy flat ["snap", date, i]
    if (key.length < 4) continue;
    const g = key[2];
    if (g === keepGen) continue;
    if (typeof g === "number") { await k.delete(key); continue; }
    if (typeof g === "string") { const t = genTime(g); if (!Number.isFinite(t) || now - t > GEN_PURGE_GRACE_MS) await k.delete(key); }
  }
}
/** Persist index via generationed chunks: write new gen, atomic flip snapdate, purge orphans. */
export async function saveIndex(idx: Index, _keep?: number, _skipRetention = false): Promise<SnapDateMeta> {
  if (!idx.tier) idx.tier = "full";
  const k = await kv();
  const prev = await k.get<SnapDateMeta | number>(["snapdate", idx.date]);
  // Unique id per attempt: concurrent saves for one date never share chunk keys.
  const newGen = newGenId();
  const z = await gz(JSON.stringify(idx), "c"); const n = Math.ceil(z.length / CHUNK) || 1;
  for (let i = 0; i < n; i++) {
    await k.set(["snap", idx.date, newGen, i], z.slice(i * CHUNK, (i + 1) * CHUNK));
    if (_saveCrashAfterChunks != null && i + 1 >= _saveCrashAfterChunks) {
      const err = new Error("save_crash_injected"); (err as any).name = "SaveCrash"; throw err;
    }
  }
  const attemptedAt = new Date().toISOString();
  const meta: SnapDateMeta = {
    gen: newGen, chunks: n, tier: idx.tier, status: idx.status ?? idx.coverage?.status ?? null,
    listings: idx.listings, gzip_bytes: z.length, legacy: false, last_attempt_at: attemptedAt,
    sha256: hexOf(await crypto.subtle.digest("SHA-256", z as Uint8Array<ArrayBuffer>)),
  };
  if (_beforeFlip) await _beforeFlip();
  const flipped = await k.atomic().check(prev).set(["snapdate", idx.date], meta).commit();
  if (!flipped.ok) {
    for (let i = 0; i < n; i++) await k.delete(["snap", idx.date, newGen, i]); // only this attempt's own chunks
    throw new Error("snapdate_cas_failed");
  }
  if (_saveCrashAfterFlip) {
    const err = new Error("save_crash_after_flip"); (err as any).name = "SaveCrashAfterFlip"; throw err;
  }
  // purge non-active gens past the grace period (recent ones may still be in progress)
  await purgeOrphanGens(idx.date, newGen);
  idxCache.delete(idx.date);
  return meta;
}
export async function snapshotDates(): Promise<string[]> {
  return (await listSnapMetas()).map((x) => x.date);
}
const idxCache = new Map<string, Index>();
export const IDX_CACHE_MAX = 3;
export async function loadIndex(date: string): Promise<Index> {
  if (idxCache.has(date)) return idxCache.get(date)!;
  const k = await kv();
  const meta = await readSnapMeta(date);
  if (!meta) throw new Error("no_snapshot");
  const parts: Uint8Array[] = [];
  if (isLegacyMeta(meta)) {
    // L2: legacy flat ["snap", date, i]
    const byI = new Map<number, Uint8Array>();
    for await (const e of k.list<Uint8Array>({ prefix: ["snap", date] })) {
      if (e.key.length === 3 && typeof e.key[2] === "number") byI.set(e.key[2] as number, e.value);
    }
    const idxs = [...byI.keys()].sort((a, b) => a - b);
    for (const i of idxs) parts.push(byI.get(i)!);
  } else {
    const gen = meta.gen!;
    for (let i = 0; i < meta.chunks; i++) {
      const e = await k.get<Uint8Array>(["snap", date, gen, i]);
      if (!e.value) throw new Error("missing_chunk");
      parts.push(e.value);
    }
  }
  if (!parts.length) throw new Error("empty_snapshot");
  const all = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
  if (!isLegacyMeta(meta) && meta.sha256 && hexOf(await crypto.subtle.digest("SHA-256", all)) !== meta.sha256) throw new SnapshotHashMismatch(date);
  const idx = JSON.parse(new TextDecoder().decode(await gz("", "d", all))) as Index;
  // bounded cache: a full index is ~10 MiB of heap at ~26k listings (measured), so keep only the newest few
  while (idxCache.size >= IDX_CACHE_MAX) idxCache.delete(idxCache.keys().next().value!);
  idxCache.set(date, idx); return idx;
}
export function clearIndexCache() { idxCache.clear(); }

/** Preflight bazaar facts: only a fresh full-tier snapshot (≤ FULL_MAX_AGE_DAYS). */
export async function bazaarFacts(url: string, paytoList: string[], maxTrend = 14, today = new Date().toISOString().slice(0, 10)) {
  const metas = await listSnapMetas();
  if (!metas.length) return { available: false, reason: "no_snapshot" };
  const full = [...metas].reverse().find((m) => (m.meta.tier ?? "full") === "full");
  // snapshot_age_days kept as an alias of age_days for backward compatibility.
  const tooOld = (date: string, tier: string) => { const age_days = dayAge(date, today);
    return { available: false, reason: "snapshot_too_old", snapshot_date: date, snapshot_tier: tier, requested_date: today,
      age_days, snapshot_age_days: age_days, max_age_days: FULL_MAX_AGE_DAYS }; };
  if (!full) { const newest = metas[metas.length - 1]; return tooOld(newest.date, newest.meta.tier ?? "full"); }
  if (dayAge(full.date, today) > FULL_MAX_AGE_DAYS) return tooOld(full.date, "full");
  const last = full.date; let idx: Index;
  try { idx = await loadIndex(last); } catch (e) {
    if (e instanceof SnapshotHashMismatch) return { available: false, reason: "snapshot_hash_mismatch", snapshot_date: last };
    throw e;
  }
  const h = hostOf(url); const key = url.split("?")[0];
  const cur = idx.resources[key] ?? null; const listedPayTo = cur?.payTo ?? [];
  const wl: Record<string, unknown> = {};
  const ws = new Set([...paytoList.filter(Boolean).map((x) => x.toLowerCase()), ...listedPayTo]);
  for (const w of ws) {
    const raw = idx.wallet_hosts[w];
    const hs = Array.isArray(raw) ? raw : [];
    wl[w] = { hosts_using_wallet: hs.length, other_hosts_sample: hs.filter((x) => x !== h).slice(0, 10) };
  }
  const trend: Record<string, unknown>[] = [];
  for (const { date: d, meta } of metas.slice(-maxTrend)) {
    if (meta.tier !== "full") {
      trend.push({ snapshot: d, tier: meta.tier, payers30d: null, calls30d: null });
      continue;
    }
    let r: any;
    try { r = (d === last ? idx : await loadIndex(d)).resources[key]; }
    catch (e) { if (!(e instanceof SnapshotHashMismatch)) throw e; trend.push({ snapshot: d, tier: "full", payers30d: null, calls30d: null, hash_mismatch: true }); continue; }
    trend.push({ snapshot: d, tier: "full", payers30d: r ? r.payers30d : null, calls30d: r ? r.calls30d : null });
  }
  const coverage = idx.coverage
    ? { ...idx.coverage, status: idx.coverage.status ?? idx.status, complete: idx.coverage.complete }
    : { complete: null as boolean | null, status: idx.status ?? null };
  const isComplete = coverage.complete === true;
  const found = cur !== null;
  const out: Record<string, unknown> = { available: true, snapshot_date: last, snapshot_sha256: full.meta.sha256 ?? null,
    listed: found ? true : (isComplete ? false : null), listed_payTo: listedPayTo,
    host_listing_count: idx.hosts[h] ?? 0, payout_wallet_reuse: wl,
    last_called_at: cur ? cur.lastCalledAt : null, payer_trend: trend, coverage };
  if (!found && !isComplete) out.listed_reason = "not_in_indexed_part";
  if (!isComplete) { out.host_listing_count_is_min = true; out.payout_wallet_reuse_is_min = true; }
  return out;
}

export async function preflight(url: string, opts: { resolver?: Resolver; fetcher?: Fetcher; connect?: Connector; now?: number; env?: (k: string) => string | undefined;
  rpc?: Rpc; signer?: Signer; issuerUrl?: string | null; ttlS?: number } = {}): Promise<[number, unknown]> {
  const { u, err, ips } = await checkUrl(url, opts.resolver);
  if (!u) return [400, { error: err }];
  const base = { schema: SCHEMA, target: url, checked_at: isSoc(opts.now), disclaimer: "Deterministic observations only. Not advice to pay, buy or sell." };
  let reach: Record<string, unknown>, ch: any;
  if (err === "dns_unresolvable") { reach = { reachable: false, error_class: "dns_unresolvable" }; ch = null; }
  else {
    const release = await OUTBOUND.acquire(); // bounded outbound concurrency (throws OutboundBusy when saturated)
    try { [reach, ch] = await probe(u, PROBE_TIMEOUT_MS, opts.fetcher, ips?.[0], opts.connect); } finally { release(); }
  }
  const [valid, problems, acc] = validateChallenge(ch);
  const facts = { ...base, reachability: reach, challenge: { valid, problems, accepts: acc },
    bazaar: await bazaarFacts(url, acc.map((a) => a.payTo as string).filter(Boolean)) };
  // Legacy {facts, signature} kept for existing verifiers; "attestation" is the v1.0 envelope (JCS-signed).
  const legacy = await sign(facts, opts.env);
  // Attestation failures never break the paid response: legacy facts are still served, attestation is null.
  let attestation: unknown = null;
  try { attestation = await attest(facts, { signer: opts.signer ?? await envSigner(opts.env), rpc: opts.rpc, now: opts.now, ttlS: opts.ttlS, issuerUrl: opts.issuerUrl }); }
  catch (e) { console.log("attestation failed:", (e as Error).name); }
  return [200, attestation ? { ...legacy, attestation } : { ...legacy, attestation: null, attestation_error: "attestation_unavailable" }];
}
function isSoc(now?: number) { return isoSec(now ?? Date.now()); }
