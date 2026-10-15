// Port of api/settle_guard.py (see SECURITY.md). Replay claims live in Deno KV with atomic checks, so they hold across isolates.
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
export async function setPending(key: string, rec: unknown) { await (await kv()).set(["pending", key], rec, { expireIn: 3600_000 }); }
/** Atomically remove and return a parked delivery, so two concurrent retries cannot both be served. */
export async function takePending(key: string): Promise<any | null> {
  const k = await kv(); const e = await k.get(["pending", key]);
  if (e.versionstamp === null) return null;
  const r = await k.atomic().check(e).delete(["pending", key]).commit();
  return r.ok ? e.value : null;
}
/** Durable, atomic: a settlement tx hash is stored in KV (no expiry) the first time it backs a sale; false if already used. */
export async function claimTx(tx: string): Promise<boolean> {
  const k = await kv(); const kk = ["txused", tx.toLowerCase()];
  return (await k.atomic().check({ key: kk, versionstamp: null }).set(kk, Date.now()).commit()).ok;
}
/** Failure cooldowns in Deno KV, shared by every instance: atomic counters ["fail", scope, who, bucket] (Deno.KvU64,
 * incremented by versionstamp compare-and-set, so no lost updates) with expireIn. A scope is blocked when the current + previous fixed bucket reach its limit.
 * Scopes: payer (settle failures; payer is the verified signer), ip (verify + settle failures), global (all failures). */
export type Scope = "payer" | "ip" | "global";
export const FAIL_LIMITS: Record<Scope, number> = { payer: 3, ip: 10, global: 200 };
export class FailLimiter {
  constructor(public limits: Record<Scope, number> = FAIL_LIMITS, public windowMs = 600_000) {}
  private bucket(now: number) { return Math.floor(now / this.windowMs); }
  async count(scope: Scope, who: string, now = Date.now()) {
    const k = await kv(); const b = this.bucket(now);
    const [x, y] = await k.getMany<Deno.KvU64[]>([["fail", scope, who, b], ["fail", scope, who, b - 1]]);
    return Number(x.value?.value ?? 0n) + Number(y.value?.value ?? 0n);
  }
  /** First scope that is over its limit, or null. */
  async blocked(ids: Partial<Record<Scope, string | null>>, now = Date.now()): Promise<Scope | null> {
    for (const s of ["global", "ip", "payer"] as Scope[]) {
      const who = s === "global" ? "*" : ids[s]; if (!who) continue;
      if (await this.count(s, who, now) >= this.limits[s]) return s;
    }
    return null;
  }
  async fail(ids: Partial<Record<Scope, string | null>>, now = Date.now()) {
    const k = await kv(); const b = this.bucket(now);
    for (const s of ["global", "ip", "payer"] as Scope[]) {
      const who = s === "global" ? "*" : ids[s]; if (!who) continue;
      const key = ["fail", s, who, b];
      for (let i = 0; i < 20; i++) { // atomic increment: compare-and-set on the versionstamp, entry expires after 2 windows
        const e = await k.get<Deno.KvU64>(key);
        const n = new Deno.KvU64((e.value?.value ?? 0n) + 1n);
        if ((await k.atomic().check(e).set(key, n, { expireIn: 2 * this.windowMs }).commit()).ok) break;
      }
    }
  }
  async clear() { const k = await kv(); for await (const e of k.list({ prefix: ["fail"] })) await k.delete(e.key); }
}
export function payerOf(p: Record<string, any>) { const f = String(authorization(p)?.from ?? "").toLowerCase(); return ADDR_RE.test(f) ? f : null; }
