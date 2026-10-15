// Daily Bazaar snapshot (Deno.cron 00:15 UTC only; never at startup). Bounded to keep hosting usage small:
// at most SNAPSHOT_MAX_PAGES pages (default 3, 1000 items each), 15 s per page, 1 retry, and at most one attempt
// (success or failure) per 24 h. The stored index is a summary built from the fetched pages only; its `coverage`
// field says how much of the Bazaar it covers, and preflight facts report it.
import { IndexAssembler, saveIndex, UA, type Index } from "./preflight.ts";
import { kv } from "./store.ts";
const BAZAAR = Deno.env.get("BAZAAR_URL") ?? "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
export const PAGE = 1000, PAGE_TIMEOUT_MS = 15000, RETRIES = 1, MIN_INTERVAL_MS = 24 * 3600_000;
export function maxPages(env: (k: string) => string | undefined = (k) => Deno.env.get(k)) {
  const n = Number(env("SNAPSHOT_MAX_PAGES") ?? 3); return Number.isInteger(n) && n >= 1 && n <= 50 ? n : 3;
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
  await saveIndex(idx, 14); return idx;
}
/** Cron entry point: at most one attempt per 24 h (recorded before fetching, so failures also wait a day). */
export async function scheduledSnapshot(f: typeof fetch = fetch, now = Date.now()): Promise<"skipped" | "ok" | "failed"> {
  const k = await kv(); const last = await k.get<number>(["snapattempt"]);
  if (typeof last.value === "number" && now - last.value < MIN_INTERVAL_MS) return "skipped";
  const r = await k.atomic().check(last).set(["snapattempt"], now).commit(); if (!r.ok) return "skipped"; // another isolate took it
  try { await runSnapshot(f); return "ok"; } catch (e) { console.log("snapshot failed:", (e as Error).name); return "failed"; }
}
