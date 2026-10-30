// Trial keys: a request with a valid X-Trial-Key header is served without payment, up to a daily quota per key.
// Keys are stored only as SHA-256 hashes in a JSON file (TRIAL_KEYS_FILE). Missing or empty file = feature off.
// Any problem (unknown, revoked, expired, over quota, malformed, unreadable file) returns null and the caller
// continues with the normal 402 flow, so the response never reveals why a key was not accepted.
import { kv } from "./store.ts";
import { append } from "./store.ts";
import { iso, rid } from "./util.ts";

export const TRIAL_HEADER = "X-Trial-Key";
export const TRIAL_KEYS_FILE_DEFAULT = "/var/lib/base-reads/trial-keys.json";
export const KEY_RE = /^trk_[A-Za-z0-9_-]{43}$/; // trk_ + 32 random bytes base64url (no padding)
export const LABEL_RE = /^[a-z0-9][a-z0-9._-]{0,47}$/;
export const TRIAL_FILE = "trials.jsonl"; // separate stream: never part of executions/outcomes/costs
export type TrialEntry = { label: string; hash: string; created: string; expires?: string | null; revoked?: string | null };
type Env = (k: string) => string | undefined;

export function dailyLimit(env: Env): number {
  const raw = (env("TRIAL_DAILY_LIMIT") ?? "").trim();
  if (!/^[0-9]{1,7}$/.test(raw)) return 50;
  return Math.min(10_000, Math.max(1, Number(raw)));
}
export const keysPath = (env: Env) => env("TRIAL_KEYS_FILE") || TRIAL_KEYS_FILE_DEFAULT;

export async function hashKey(key: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
}
export function newKey(): string {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return "trk_" + btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function parseKeys(text: string): TrialEntry[] {
  if (!text.trim()) return [];
  const j = JSON.parse(text); const list = Array.isArray(j) ? j : j?.keys;
  if (!Array.isArray(list)) return [];
  return list.filter((e: any) => e && typeof e.label === "string" && typeof e.hash === "string" && /^[0-9a-f]{64}$/.test(e.hash));
}

/** File cache: re-stat at most every 5 s; re-read when mtime or size changed.
 * So a revoke (file rewrite) takes effect within a few seconds, without a restart. */
let cache: { path: string; checked: number; sig: string; byHash: Map<string, TrialEntry> } | null = null;
export function resetTrialCache() { cache = null; }
async function entries(env: Env, now: number): Promise<Map<string, TrialEntry>> {
  const path = keysPath(env); const ttl = 5000;
  if (cache && cache.path === path && now - cache.checked < ttl) return cache.byHash;
  let sig = "", byHash = new Map<string, TrialEntry>();
  try {
    const st = await Deno.stat(path); sig = `${st.mtime?.getTime() ?? 0}:${st.size}`;
    if (cache && cache.path === path && cache.sig === sig) { cache.checked = now; return cache.byHash; }
    for (const e of parseKeys(await Deno.readTextFile(path))) byHash.set(e.hash, e);
  } catch { byHash = new Map(); } // missing or unreadable file: feature off
  cache = { path, checked: now, sig, byHash };
  return byHash;
}
export const utcDay = (now: number) => new Date(now).toISOString().slice(0, 10);

/** Atomic per-key per-UTC-day counter in Deno KV: check + set guarded by the versionstamp, retried on conflict.
 * Counted on accept (before the route handler runs): a call that then fails with bad input still uses one unit. */
export async function takeQuota(label: string, limit: number, now: number): Promise<boolean> {
  const k = await kv(); const key = ["trial", "count", label, utcDay(now)];
  for (let i = 0; i < 20; i++) {
    const cur = await k.get<number>(key); const n = cur.value ?? 0;
    if (n >= limit) return false;
    const r = await k.atomic().check(cur).set(key, n + 1, { expireIn: 2 * 86_400_000 }).commit();
    if (r.ok) return true;
  }
  return false;
}
/** Returns the key label when the header holds a valid, active key (quota NOT taken); otherwise null. */
export async function resolveTrial(header: string | null, env: Env, now = Date.now()): Promise<string | null> {
  if (!header || !KEY_RE.test(header)) return null;
  const byHash = await entries(env, now); if (!byHash.size) return null;
  const e = byHash.get(await hashKey(header)); // lookup by hash: the plaintext is never compared or stored
  if (!e || e.revoked) return null;
  if (e.expires) { const t = Date.parse(e.expires); if (!Number.isFinite(t) || t <= now) return null; }
  return e.label;
}
/** Valid, active and under quota (takes one unit): the label, else null (normal 402 flow). */
export async function acceptTrial(header: string | null, env: Env, now = Date.now()): Promise<string | null> {
  const label = await resolveTrial(header, env, now);
  return label && await takeQuota(label, dailyLimit(env), now) ? label : null;
}
/** One record per served trial call. Label only: never the key or its hash. */
export function recordTrial(route: string, label: string, code: number, ref: string | null = null) {
  const at = iso();
  return append(TRIAL_FILE, { id: rid("trial", label, route, at, crypto.randomUUID()), kind: "trial", label, route, httpStatus: code,
    servedAt: at, ...(ref ? { ref } : {}) });
}
