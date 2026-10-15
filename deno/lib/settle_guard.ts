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
export function precheck(p: Record<string, any>, req: Req, now = Math.floor(Date.now() / 1000)): string | null {
  const acc = p.accepted;
  if (acc && typeof acc === "object" && !Array.isArray(acc))
    for (const k of ["scheme", "network", "asset", "payTo", "amount"])
      if (k in acc && String(acc[k]).toLowerCase() !== String(req[k]).toLowerCase()) return `accepted.${k}_mismatch`;
  const a = authorization(p);
  if (!a) return null;
  try {
    if (String(a.to ?? "").toLowerCase() !== String(req.payTo).toLowerCase()) return "authorization_payee_mismatch";
    if (int(a.value, -1) !== BigInt(req.amount)) return "authorization_amount_mismatch";
    if (int(a.validAfter, 0) > BigInt(now)) return "authorization_not_yet_valid";
    if (int(a.validBefore, 0) < BigInt(now + MIN_VALID_WINDOW)) return "authorization_expired_or_expiring";
    if (!ADDR_RE.test(String(a.from ?? ""))) return "authorization_bad_from";
  } catch { return "authorization_malformed"; }
  return null;
}
export async function replayKey(p: Record<string, any>, sig: string) {
  const a = authorization(p);
  if (a && a.nonce && a.from) return "auth:" + String(a.from).toLowerCase() + ":" + String(a.nonce).toLowerCase();
  return "sig:" + await sha256hex(sig);
}
/** Atomic check-and-set of a used payment authorization in KV, kept until validBefore (+60 s) or the TTL, whichever is later.
 * Never released: a signature is spent once seen, so concurrent or later duplicates are rejected consistently across isolates. */
export async function claim(key: string, expiresAtSec: number | null = null, ttlMs = 3600_000, nowMs = Date.now()): Promise<boolean> {
  const k = await kv(); const kk = ["nonce", key];
  const expireIn = Math.max(ttlMs, expiresAtSec ? expiresAtSec * 1000 - nowMs : 0);
  return (await k.atomic().check({ key: kk, versionstamp: null }).set(kk, nowMs, { expireIn }).commit()).ok;
}
export function expiry(p: Record<string, any>, margin = 60): number | null {
  const a = authorization(p); const v = Number(a?.validBefore); return a && Number.isFinite(v) ? v + margin : null;
}
export function nonceOf(p: Record<string, any>): string | null {
  const n = String(authorization(p)?.nonce ?? ""); return /^0x[0-9a-fA-F]{1,64}$/.test(n) ? n : null;
}
export async function setPending(key: string, rec: unknown) { await (await kv()).set(["pending", key], rec, { expireIn: 3600_000 }); }
/** Atomically remove and return a parked delivery, so two concurrent retries cannot both be served. */
export async function takePending(key: string): Promise<any | null> {
  const k = await kv(); const e = await k.get(["pending", key]);
  if (e.versionstamp === null) return null;
  const r = await k.atomic().check(e).delete(["pending", key]).commit();
  return r.ok ? e.value : null;
}
/** Atomically mark a settlement tx as used; false if it was already used for a served sale. */
export async function claimTx(tx: string): Promise<boolean> {
  const k = await kv(); const kk = ["txused", tx.toLowerCase()];
  return (await k.atomic().check({ key: kk, versionstamp: null }).set(kk, Date.now()).commit()).ok;
}
export class FailLimiter {
  m = new Map<string, number[]>();
  constructor(public limit = 3, public windowMs = 600_000) {}
  blocked(who: string | null, now = Date.now()) { return !!who && (this.m.get(who) ?? []).filter((t) => t > now - this.windowMs).length >= this.limit; }
  fail(who: string | null, now = Date.now()) { if (who) this.m.set(who, [...(this.m.get(who) ?? []).filter((t) => t > now - this.windowMs), now]); }
}
export function payerOf(p: Record<string, any>) { const f = String(authorization(p)?.from ?? "").toLowerCase(); return ADDR_RE.test(f) ? f : null; }
