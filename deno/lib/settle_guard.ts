// Port of api/settle_guard.py (see SECURITY.md). Replay claims live in Deno KV with atomic checks, so they hold across isolates.
import * as LG from "./ledger.ts";
import { kv } from "./store.ts";
import { sha256hex } from "./util.ts";
export const MAX_HEADER = 16384, MIN_VALID_WINDOW = 6;
export const TX_RE = /^0x[0-9a-fA-F]{64}$/, ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
type Req = Record<string, any>;
export function parsePayment(sig: string | null): [Record<string, any> | null, string | null] {
  if (!sig || sig.length > MAX_HEADER) return [null, "payment header missing or too large"];
  try {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(sig) || sig.length % 4) throw 0;
    const p = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(sig), (c) => c.charCodeAt(0))));
    if (!p || typeof p !== "object" || Array.isArray(p)) throw 0;
    return [p, null];
  } catch { return [null, "bad payment header"]; }
}
export function authorization(p: Record<string, any>): Record<string, any> | null {
  const a = p.payload && typeof p.payload === "object" ? p.payload.authorization : null;
  return a && typeof a === "object" && !Array.isArray(a) ? a : null;
}
const int = (x: unknown, d: number) => { const s = String(x ?? d); if (!/^-?\d+$/.test(s)) throw new Error("malformed"); return BigInt(s); };
export const NONCE_RE = /^0x[0-9a-fA-F]{64}$/;
export const ACCEPTED_FIELDS = ["scheme", "network", "asset", "payTo", "amount"] as const;
const ADDR_FIELDS = new Set(["asset", "payTo"]);
/** null if acceptable, else a reason. Only `exact` EIP-3009 transferWithAuthorization is accepted (Permit2 and anything else rejected).
 * `accepted` must be present with all 5 fields equal to ours (addresses case-insensitive, everything else exact). Runs before the replay claim. */
export function precheck(p: Record<string, any>, req: Req, now = Math.floor(Date.now() / 1000)): string | null {
  if (isPermit2(p)) return "permit2_not_supported: pay with an EIP-3009 transferWithAuthorization (exact scheme)";
  const acc = p.accepted;
  if (!acc || typeof acc !== "object" || Array.isArray(acc)) return "accepted_missing";
  for (const k of ACCEPTED_FIELDS) {
    if (!(k in acc) || acc[k] === null || acc[k] === undefined) return `accepted.${k}_missing`;
    const a = String(acc[k]), b = String(req[k]);
    if (ADDR_FIELDS.has(k) ? a.toLowerCase() !== b.toLowerCase() : a !== b) return `accepted.${k}_mismatch`;
  }
  if (req.scheme !== "exact") return "scheme_not_supported";
  const a = authorization(p);
  if (!a) return "eip3009_authorization_required";
  try {
    if (!ADDR_RE.test(String(a.from ?? ""))) return "authorization_bad_from";
    if (!NONCE_RE.test(String(a.nonce ?? ""))) return "authorization_bad_nonce";
    if (String(a.to ?? "").toLowerCase() !== String(req.payTo).toLowerCase()) return "authorization_payee_mismatch";
    if (int(a.value, -1) !== BigInt(req.amount)) return "authorization_amount_mismatch";
    if (int(a.validAfter, 0) > BigInt(now)) return "authorization_not_yet_valid";
    if (int(a.validBefore, 0) < BigInt(now + MIN_VALID_WINDOW)) return "authorization_expired_or_expiring";
  } catch { return "authorization_malformed"; }
  return null;
}
/** Permit2 payloads carry no EIP-3009 nonce event, so the on-chain check could not bind the tx to this payment. */
export function isPermit2(p: Record<string, any>) {
  const inner = p.payload && typeof p.payload === "object" ? p.payload : {};
  const extra = p.accepted?.extra && typeof p.accepted.extra === "object" ? p.accepted.extra : {};
  return Object.keys(inner).some((k) => k.toLowerCase().includes("permit2")) || String(extra.assetTransferMethod ?? "").toLowerCase() === "permit2";
}
/** Replay key = the on-chain uniqueness unit of EIP-3009: (from, 32-byte nonce), lower-cased. Two different signatures/encodings
 * of the same authorization map to one key (stricter than hashing the header). Only called after precheck() passed. */
export function replayKey(p: Record<string, any>) {
  const a = authorization(p)!;
  return "auth:" + String(a.from).toLowerCase() + ":" + String(a.nonce).toLowerCase();
}
/** Hash of the canonical payload, stored with the claim for audit (not used as the key). */
export async function payloadHash(p: Record<string, any>) { return await sha256hex(canonicalJson(p)); }
function canonicalJson(o: unknown): string {
  if (Array.isArray(o)) return "[" + o.map(canonicalJson).join(",") + "]";
  if (o && typeof o === "object") return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson((o as any)[k])).join(",") + "}";
  return JSON.stringify(o);
}
/** Atomic check-and-set of a used payment authorization in KV, kept until validBefore (+60 s) or the TTL, whichever is later.
 * Never released: a signature is spent once seen, so concurrent or later duplicates are rejected consistently across isolates. */
/** Undo a claim this request made (versionstamp-free: only used right after our own claim, before any settle). */
export async function unclaim(key: string) { await (await kv()).delete(["nonce", key]); }
export async function claim(key: string, expiresAtSec: number | null = null, ttlMs = 3600_000, nowMs = Date.now(), meta: unknown = nowMs): Promise<boolean> {
  const k = await kv(); const kk = ["nonce", key];
  const expireIn = Math.max(ttlMs, expiresAtSec ? expiresAtSec * 1000 - nowMs : 0);
  return (await k.atomic().check({ key: kk, versionstamp: null }).set(kk, meta, { expireIn }).commit()).ok;
}
export function expiry(p: Record<string, any>, margin = 60): number | null {
  const a = authorization(p); const v = Number(a?.validBefore); return a && Number.isFinite(v) ? v + margin : null;
}
export function nonceOf(p: Record<string, any>): string | null {
  const n = String(authorization(p)?.nonce ?? ""); return NONCE_RE.test(n) ? n.toLowerCase() : null;
}
export const PENDING_TTL_MS = 3600_000;
/** Park a settled, undelivered check. `until` is fixed at the first park; re-parking keeps it. The KV record outlives
 * `until` by a day so the expiry sweep can see it; ["pendexp", until, key] indexes it for that sweep, and a check queued
 * on the per-target budget is also listed in ["pq", host, key] so new settles for that target queue behind it (FIFO). */
export async function setPending(key: string, rec: Record<string, any>, now = Date.now()) {
  const until = typeof rec.until === "number" ? rec.until : now + PENDING_TTL_MS; const r: Record<string, any> = { ...rec, until };
  const op = (await kv()).atomic().set(["pending", key], r, { expireIn: until - now + 86400_000 })
    .set(["pendexp", until, key], r.tx ?? null, { expireIn: until - now + 86400_000 });
  if (r.queued && r.host) op.set(["pq", r.host, until, key], r.tx ?? null, { expireIn: until - now + 86400_000 });
  await op.commit();
}
/** True if a settled check for this target is waiting in the budget queue (new settles must queue behind it). */
export async function queueHas(host: string, now = Date.now()): Promise<boolean> {
  for await (const _ of (await kv()).list({ start: ["pq", host, now], end: ["pq", host, Number.MAX_SAFE_INTEGER] }, { limit: 1 })) return true;
  return false;
}
export async function queueDel(host: string, until: number, key: string) { await (await kv()).delete(["pq", host, until, key]); }
/** Pending records whose `until` passed without being served: atomically removed (versionstamp-checked), then reported. */
export async function sweepExpiredPending(onExpired: (key: string, rec: any) => Promise<void>, now = Date.now(), limit = 100) {
  const k = await kv(); const out: string[] = [];
  for await (const ix of k.list<string | null>({ start: ["pendexp", 0], end: ["pendexp", now] }, { limit })) {
    const key = String(ix.key[2]); const e = await k.get<any>(["pending", key]);
    if (e.versionstamp === null || e.value?.until !== ix.key[1]) { await k.atomic().check(ix).delete(ix.key).commit(); continue; } // served or re-parked
    const op = k.atomic().check(e).check(ix).delete(e.key).delete(ix.key);
    if (e.value.queued && e.value.host) op.delete(["pq", e.value.host, e.value.until, key]);
    if ((await op.commit()).ok) { await onExpired(key, e.value); out.push(key); }
  }
  return out;
}
/** Atomically remove and return a parked delivery, so two concurrent retries cannot both be served. Expired -> null. */
export async function takePending(key: string, now = Date.now()): Promise<any | null> {
  const k = await kv(); const e = await k.get<any>(["pending", key]);
  if (e.versionstamp === null) return null;
  if (typeof e.value?.until === "number" && e.value.until <= now) return null; // left for the expiry sweep (incident)
  const r = await k.atomic().check(e).delete(["pending", key]).commit();
  return r.ok ? e.value : null;
}
/** Durable, atomic: a settlement tx hash is recorded in the append-only payment ledger (separate file, fsync'ed)
 * the first time it backs a sale; false if already used. Never stored in the KV store, so KV restores cannot re-open it. */
export async function claimTx(tx: string): Promise<boolean> {
  const k = await kv(); const kk = ["txused", tx.toLowerCase()];
  // defense in depth: written to both stores; a reuse is rejected if EITHER already has it
  const kvNew = (await k.atomic().check({ key: kk, versionstamp: null }).set(kk, Date.now()).commit()).ok;
  const ledgerNew = LG.consume("tx", tx);
  return kvNew && ledgerNew;
}
/** True if the authorization was already submitted for settlement, per the ledger OR the KV copy. */
export async function authUsed(key: string): Promise<boolean> {
  return LG.isConsumed("auth", key) || (await (await kv()).get(["authused", key])).versionstamp !== null;
}
/** Record an authorization as consumed in both stores (no expiry); false if EITHER already had it. */
export async function consumeAuth(key: string, meta: unknown): Promise<boolean> {
  const k = await kv(); const kk = ["authused", key];
  const kvNew = (await k.atomic().check({ key: kk, versionstamp: null }).set(kk, Date.now()).commit()).ok;
  const ledgerNew = LG.consume("auth", key, meta);
  return kvNew && ledgerNew;
}
/** Per-IP limit key: IPv4 as-is, IPv6 collapsed to its /64 (one subscriber/host usually owns a whole /64). */
export function ipKey(ip: string | null | undefined): string | null {
  if (!ip) return null;
  const s = ip.toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
  if (!s.includes(":")) return s;
  const m = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); if (m) return m[1];
  const [h, t] = s.split("::"); const head = h ? h.split(":") : [], tail = t !== undefined && t ? t.split(":") : [];
  const groups = t === undefined ? head : [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill("0"), ...tail];
  return groups.slice(0, 4).map((g) => (parseInt(g || "0", 16) || 0).toString(16)).join(":") + "::/64";
}
/** Failure cooldowns in Deno KV, shared by every instance. Counters ["fail", scope, who, bucket] are Deno.KvU64 incremented with
 * kv.atomic().sum() (server-side, never loses an increment). KV `sum` takes no expireIn, so the same atomic op deletes the
 * bucket two windows back, and purge() (hourly cron) removes the rest. A scope blocks when current + previous bucket >= limit.
 * Scopes that BLOCK: payer (settle failures of the verified signer), ip (verify + settle failures; IPv6 keyed on /64).
 * global: settle failures only, ALERT-ONLY (logs once per window above the threshold, never blocks: junk verify
 * failures from a few IPs must not lock out every buyer). */
export type Scope = "payer" | "ip";
export const FAIL_LIMITS: Record<Scope, number> = { payer: 3, ip: 10 };
export const GLOBAL_ALERT = 1000;
export class FailLimiter {
  alerts: string[] = [];
  constructor(public limits: Record<Scope, number> = FAIL_LIMITS, public windowMs = 600_000, public globalAlert = GLOBAL_ALERT) {}
  private bucket(now: number) { return Math.floor(now / this.windowMs); }
  async count(scope: Scope | "global", who: string, now = Date.now()) {
    const k = await kv(); const b = this.bucket(now);
    const [x, y] = await k.getMany<Deno.KvU64[]>([["fail", scope, who, b], ["fail", scope, who, b - 1]]);
    return Number(x.value?.value ?? 0n) + Number(y.value?.value ?? 0n);
  }
  /** First blocking scope over its limit, or null. The global counter is never consulted here. */
  async blocked(ids: Partial<Record<Scope, string | null>>, now = Date.now()): Promise<Scope | null> {
    for (const s of ["ip", "payer"] as Scope[]) {
      const who = s === "ip" ? ipKey(ids.ip) : ids.payer; if (!who) continue;
      if (await this.count(s, who, now) >= this.limits[s]) return s;
    }
    return null;
  }
  /** kind "verify": per-IP only (the payer is not proven yet). kind "settle": payer + IP + global (alert-only). */
  async fail(ids: Partial<Record<Scope, string | null>>, kind: "verify" | "settle", now = Date.now()) {
    const k = await kv(); const b = this.bucket(now); const tx = k.atomic();
    const add = (s: string, who: string) => tx.sum(["fail", s, who, b], 1n).delete(["fail", s, who, b - 2]);
    const ip = ipKey(ids.ip); if (ip) add("ip", ip);
    if (kind === "settle") { if (ids.payer) add("payer", ids.payer); add("global", "*"); }
    await tx.commit();
    if (kind === "settle" && await this.count("global", "*", now) >= this.globalAlert) {
      const ak = ["failalert", b];
      if ((await k.atomic().check({ key: ak, versionstamp: null }).set(ak, true, { expireIn: this.windowMs * 2 }).commit()).ok) {
        const msg = `ALERT: ${this.globalAlert}+ settle failures in the last window (global, alert-only, nothing blocked)`;
        this.alerts.push(msg); console.warn(msg);
      }
    }
  }
  /** Delete counter buckets older than the previous window (sum() cannot carry an expiry). */
  async purge(now = Date.now()) {
    const k = await kv(); const b = this.bucket(now); let n = 0;
    for await (const e of k.list({ prefix: ["fail"] })) if ((e.key[3] as number) < b - 1) { await k.delete(e.key); n++; }
    return n;
  }
  async clear() { const k = await kv(); for (const p of ["fail", "failalert", "inflight"]) for await (const e of k.list({ prefix: [p] })) await k.delete(e.key); }
}
/** Concurrency slots so a parallel burst cannot slip past blocked() before its failures are counted: at most `payer`
 * in-flight paid requests per payer and `ip` per IP (/64). Each slot is an atomic set-if-absent key with expireIn (crash-safe).
 * The IP slot is taken first; the payer slot only after the facilitator verified the signature (an unverified `from`
 * cannot occupy a victim's slots). Each slot stores a random token and is released with a versionstamp-checked delete,
 * so a slot that expired and was re-taken by another request is never freed by the original holder.
 * SLOT_TTL_MS covers the worst-case request (2 x 40 s facilitator + probe + on-chain check). */
export const SLOTS = { payer: 4, ip: 8 };
export const SLOT_TTL_MS = 190_000;
type Held = { key: Deno.KvKey; vs: string };
async function releaseHeld(held: Held[]) {
  const k = await kv();
  for (const h of held) await k.atomic().check({ key: h.key, versionstamp: h.vs }).delete(h.key).commit();
}
export async function acquireSlots(ids: { ip?: string | null; payer?: string | null }, slots = SLOTS, ttlMs = SLOT_TTL_MS): Promise<(() => Promise<void>) | null> {
  const k = await kv(); const held: Held[] = [];
  const release = () => releaseHeld(held);
  for (const [scope, who] of [["payer", ids.payer], ["ip", ipKey(ids.ip)]] as const) {
    if (!who) continue; let got = false;
    for (let i = 0; i < slots[scope] && !got; i++) {
      const key = ["inflight", scope, who, i];
      const r = await k.atomic().check({ key, versionstamp: null }).set(key, { at: Date.now(), token: crypto.randomUUID() }, { expireIn: ttlMs }).commit();
      if (r.ok) { held.push({ key, vs: r.versionstamp }); got = true; }
    }
    if (!got) { await release(); return null; }
  }
  return release;
}
export function payerOf(p: Record<string, any>) { const f = String(authorization(p)?.from ?? "").toLowerCase(); return ADDR_RE.test(f) ? f : null; }
