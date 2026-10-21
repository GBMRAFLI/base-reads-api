// In-memory abuse guards for the paid Pre-pay Check (single process). Bounded maps; nothing here does I/O.
/** Fixed-window counter per key: allow(key) is true for the first `limit` calls in each `windowMs`. */
export class WindowLimiter {
  private m = new Map<string, { start: number; n: number }>();
  constructor(public limit: number, public windowMs = 60_000, public maxKeys = 50_000) {}
  allow(key: string, now = Date.now()): boolean {
    let e = this.m.get(key);
    if (!e || now - e.start >= this.windowMs) {
      if (e) this.m.delete(key); // re-insert: Map order stays oldest-window-first
      else if (this.m.size >= this.maxKeys) {
        this.prune(now);
        // M2: still full -> evict the oldest key instead of refusing new clients (a key spray cannot lock others out)
        while (this.m.size >= this.maxKeys) this.m.delete(this.m.keys().next().value!);
      }
      e = { start: now, n: 0 }; this.m.set(key, e);
    }
    if (e.n >= this.limit) return false;
    e.n++; return true;
  }
  get size() { return this.m.size; }
  private prune(now: number) { for (const [k, e] of this.m) { if (now - e.start >= this.windowMs) this.m.delete(k); else break; } } // ordered by window start
  clear() { this.m.clear(); }
}
/** Counting semaphore with a bounded wait queue and a wait timeout. */
export class Semaphore {
  private q: (() => void)[] = []; active = 0;
  constructor(public max: number, public maxWaiters = 32) {}
  /** Non-blocking: a releaser if a slot is free now, else null. */
  tryAcquire(): (() => void) | null {
    if (this.active >= this.max || this.q.length) return null;
    this.active++; return this.releaser();
  }
  async acquire(timeoutMs = 10_000): Promise<() => void> {
    if (this.active < this.max) { this.active++; return this.releaser(); }
    if (this.q.length >= this.maxWaiters) throw new OutboundBusy();
    return await new Promise<() => void>((res, rej) => {
      const go = () => { clearTimeout(t); this.active++; res(this.releaser()); };
      const t = setTimeout(() => { const i = this.q.indexOf(go); if (i >= 0) this.q.splice(i, 1); rej(new OutboundBusy()); }, timeoutMs);
      this.q.push(go);
    });
  }
  private releaser() { let done = false; return () => { if (done) return; done = true; this.active--; this.q.shift()?.(); }; }
}
export class OutboundBusy extends Error { override name = "OutboundBusy"; }
/** TTL cache keyed by payer + target; bounded (oldest evicted). */
export class ResultCache<T> {
  private m = new Map<string, { at: number; v: T }>();
  constructor(public ttlMs = 60_000, public max = 1000) {}
  get(k: string, now = Date.now()): T | null {
    const e = this.m.get(k); if (!e) return null;
    if (now - e.at >= this.ttlMs) { this.m.delete(k); return null; }
    return e.v;
  }
  set(k: string, v: T, now = Date.now()) {
    this.m.delete(k); while (this.m.size >= this.max) this.m.delete(this.m.keys().next().value!);
    this.m.set(k, { at: now, v });
  }
  clear() { this.m.clear(); }
}
const posInt = (v: string | undefined, d: number) => /^[0-9]{1,6}$/.test(v ?? "") && Number(v) >= 1 ? Number(v) : d;
/** IPv6 /48 aggregate key (IPv4: null). Used for an aggregate limit on top of the per-/64 key. */
export function ipv6Prefix48(ip: string | null | undefined): string | null {
  if (!ip) return null;
  const s = ip.toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
  if (!s.includes(":") || /^::ffff:\d+\.\d+\.\d+\.\d+$/.test(s)) return null;
  const [h, t] = s.split("::"); const head = h ? h.split(":") : [], tail = t ? t.split(":") : [];
  const g = t === undefined ? head : [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill("0"), ...tail];
  return g.slice(0, 3).map((x) => (parseInt(x || "0", 16) || 0).toString(16)).join(":") + "::/48";
}
/** Defaults: 60 unpaid 402s per IP (/64) and 600 per IPv6 /48 per minute; 3 pre-settle attempts per target+payer per minute; 10 outbound probes per target host per minute; 4 concurrent outbound probes; 60 s result cache. */
export function guardConfig(env: (k: string) => string | undefined) {
  return { unpaidPerMin: posInt(env("UNPAID_PER_MIN"), 60), unpaidPer48PerMin: posInt(env("UNPAID_PER_48_PER_MIN"), 600),
    hostPayerPerMin: posInt(env("PER_TARGET_PAYER_PER_MIN"), 3), perHostPerMin: posInt(env("OUTBOUND_PER_HOST_PER_MIN"), 10),
    outboundConcurrency: posInt(env("OUTBOUND_MAX_CONCURRENCY"), 4), cacheTtlMs: posInt(env("PREFLIGHT_CACHE_TTL_S"), 60) * 1000 };
}
