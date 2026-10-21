// In-memory abuse guards for the paid Pre-pay Check (single process). Bounded maps; nothing here does I/O.
/** Fixed-window counter per key: allow(key) is true for the first `limit` calls in each `windowMs`. */
export class WindowLimiter {
  private m = new Map<string, { start: number; n: number }>();
  constructor(public limit: number, public windowMs = 60_000, public maxKeys = 50_000) {}
  allow(key: string, now = Date.now()): boolean {
    let e = this.m.get(key);
    if (!e || now - e.start >= this.windowMs) {
      if (!e && this.m.size >= this.maxKeys) this.prune(now);
      if (!e && this.m.size >= this.maxKeys) return false; // still full: refuse rather than grow without bound
      e = { start: now, n: 0 }; this.m.set(key, e);
    }
    if (e.n >= this.limit) return false;
    e.n++; return true;
  }
  private prune(now: number) { for (const [k, e] of this.m) if (now - e.start >= this.windowMs) this.m.delete(k); }
  clear() { this.m.clear(); }
}
/** Counting semaphore with a bounded wait queue and a wait timeout. */
export class Semaphore {
  private q: (() => void)[] = []; active = 0;
  constructor(public max: number, public maxWaiters = 32) {}
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
/** Defaults: 60 unpaid 402s per IP per minute; 10 outbound probes per target host per minute; 4 concurrent outbound probes; 60 s result cache. */
export function guardConfig(env: (k: string) => string | undefined) {
  return { unpaidPerMin: posInt(env("UNPAID_PER_MIN"), 60), perHostPerMin: posInt(env("OUTBOUND_PER_HOST_PER_MIN"), 10),
    outboundConcurrency: posInt(env("OUTBOUND_MAX_CONCURRENCY"), 4), cacheTtlMs: posInt(env("PREFLIGHT_CACHE_TTL_S"), 60) * 1000 };
}
