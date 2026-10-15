// Daily Bazaar snapshot (Deno.cron 00:15 UTC only; never at startup). Bounded to keep hosting usage small:
// at most SNAPSHOT_MAX_PAGES pages (default 3, 1000 items each), 15 s per page, 1 retry, and at most one attempt
// (success or failure) per UTC calendar day. The stored index is a summary built from the fetched pages only; its
// `coverage` field says how much of the Bazaar it covers, and preflight facts report it.
import { IndexAssembler, saveIndex, UA, type Index } from "./preflight.ts";
import { kv } from "./store.ts";
const BAZAAR = Deno.env.get("BAZAAR_URL") ?? "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
export const PAGE = 1000, PAGE_TIMEOUT_MS = 15000, RETRIES = 1;
/** Parse SNAPSHOT_MAX_PAGES; default 3; clamp out-of-range integers to 1–50; non-integers fall back to 3. Always warns on invalid. */
export function maxPages(env: (k: string) => string | undefined = (k) => Deno.env.get(k), warn: (m: string) => void = console.warn) {
  const raw = env("SNAPSHOT_MAX_PAGES");
  if (raw === undefined || raw === "") return 3;
  const n = Number(raw);
  if (!Number.isInteger(n)) { warn(`SNAPSHOT_MAX_PAGES=${JSON.stringify(raw)} invalid; using 3`); return 3; }
  if (n < 1 || n > 50) { const c = Math.min(50, Math.max(1, n)); warn(`SNAPSHOT_MAX_PAGES=${n} out of range; clamped to ${c}`); return c; }
  return n;
}
export async function runSnapshot(f: typeof fetch = fetch, pages = maxPages(), date = new Date().toISOString().slice(0, 10)): Promise<Index> {
  const b = new IndexAssembler(); let off = 0, fetched = 0, total: number | null = null, complete = false;
  for (let page = 0; page < pages; page++) {
    let d: any = null;
    for (let attempt = 0; attempt <= RETRIES && !d; attempt++) {
      try { const r = await f(`${BAZAAR}?limit=${PAGE}&offset=${off}`, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(PAGE_TIMEOUT_MS) }); if (r.ok) d = await r.json(); else await r.body?.cancel(); }
      catch { /* retry once */ }
      if (!d && attempt === RETRIES) throw new Error("bazaar fetch failed");
    }
    const items = d.items ?? []; b.add(items); fetched++;
    if (typeof d.pagination?.total === "number") total = d.pagination.total;
    if (items.length < PAGE) { complete = true; break; }
    off += items.length;
  }
  const idx = b.build(date);
  idx.coverage = { pages_fetched: fetched, max_pages: pages, items_indexed: idx.listings, bazaar_total: total, complete: complete || (total !== null && idx.listings >= total) };
  await saveIndex(idx, 60); return idx; // 60-day retention; do not permanently delete older snapshots without an explicit decision
}
/** UTC calendar date (YYYY-MM-DD) for the attempt gate. */
export function utcDay(now = Date.now()) { return new Date(now).toISOString().slice(0, 10); }
/** Cron entry point: at most one attempt per UTC day (KV key recorded before fetching, so failures also consume the day). */
export async function scheduledSnapshot(f: typeof fetch = fetch, now = Date.now()): Promise<"skipped" | "ok" | "failed"> {
  const day = utcDay(now); const k = await kv(); const key: Deno.KvKey = ["snapattempt", day];
  const r = await k.atomic().check({ key, versionstamp: null }).set(key, now).commit();
  if (!r.ok) return "skipped"; // already attempted today, or another isolate took it
  try { await runSnapshot(f); return "ok"; } catch (e) { console.log("snapshot failed:", (e as Error).name); return "failed"; }
}
