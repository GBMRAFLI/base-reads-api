// Daily Bazaar snapshot (Deno.cron 00:15 UTC only; never at startup). Bounded to keep hosting usage small:
// at most SNAPSHOT_MAX_PAGES pages (default 3, 1000 items each), 15 s per page, 1 retry, and at most one attempt
// (success or failure) per UTC calendar day. Status is complete | partial | failed; failed stores an error record
// (never an empty snapshot). Tiered retention demotes old indexes (no permanent deletion of day history).
import { IndexAssembler, saveIndex, loadIndex, snapshotDates, UA, type Index, clearIndexCache } from "./preflight.ts";
import { kv } from "./store.ts";

const BAZAAR = Deno.env.get("BAZAAR_URL") ?? "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
export const PAGE = 1000, PAGE_TIMEOUT_MS = 15000, RETRIES = 1;
export const SNAPATTEMPT_TTL_MS = 3 * 24 * 3600_000;
export const TIER_FULL_DAYS = 30, TIER_COMPRESSED_UNTIL = 90, TIER_AGGREGATE_FROM = 365;

export type SnapStatus = "complete" | "partial" | "failed";
export type SnapFail = { status: "failed"; date: string; error: string; at: string; failed_pages: number[] };
export type RunResult =
  | { status: "complete" | "partial"; index: Index }
  | { status: "failed"; fail: SnapFail };

/** Parse SNAPSHOT_MAX_PAGES; default 3; clamp out-of-range integers to 1–50; non-integers fall back to 3. Always warns on invalid. */
export function maxPages(env: (k: string) => string | undefined = (k) => Deno.env.get(k), warn: (m: string) => void = console.warn) {
  const raw = env("SNAPSHOT_MAX_PAGES");
  if (raw === undefined || raw === "") return 3;
  const n = Number(raw);
  if (!Number.isInteger(n)) { warn(`SNAPSHOT_MAX_PAGES=${JSON.stringify(raw)} invalid; using 3`); return 3; }
  if (n < 1 || n > 50) { const c = Math.min(50, Math.max(1, n)); warn(`SNAPSHOT_MAX_PAGES=${n} out of range; clamped to ${c}`); return c; }
  return n;
}

export function utcDay(now = Date.now()) { return new Date(now).toISOString().slice(0, 10); }

function attachStatus(idx: Index, pages: number, fetched: number, total: number | null, reachedEnd: boolean, failedPages: number[]): Index {
  const complete = (reachedEnd || (total !== null && idx.listings >= total)) && failedPages.length === 0;
  const status: SnapStatus = complete ? "complete" : "partial";
  idx.coverage = {
    pages_fetched: fetched, max_pages: pages, items_indexed: idx.listings, bazaar_total: total,
    complete, status, partial: status === "partial", failed_pages: failedPages,
  };
  idx.status = status;
  return idx;
}

/** Fetch up to `pages` Bazaar pages. Page failures are recorded; if nothing was indexed the result is failed (no empty snap). */
export async function runSnapshot(f: typeof fetch = fetch, pages = maxPages(), date = new Date().toISOString().slice(0, 10)): Promise<RunResult> {
  const b = new IndexAssembler(); let off = 0, fetched = 0, total: number | null = null, reachedEnd = false;
  const failedPages: number[] = [];
  for (let page = 0; page < pages; page++) {
    let d: any = null;
    for (let attempt = 0; attempt <= RETRIES && !d; attempt++) {
      try {
        const r = await f(`${BAZAAR}?limit=${PAGE}&offset=${off}`, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(PAGE_TIMEOUT_MS) });
        if (r.ok) d = await r.json(); else await r.body?.cancel();
      } catch { /* retry */ }
    }
    if (!d) {
      failedPages.push(page);
      off += PAGE; // skip ahead so later pages can still be attempted
      continue;
    }
    const items = d.items ?? []; b.add(items); fetched++;
    if (typeof d.pagination?.total === "number") total = d.pagination.total;
    if (items.length < PAGE) { reachedEnd = true; break; }
    off += items.length;
  }
  if (fetched === 0) {
    return { status: "failed", fail: { status: "failed", date, error: "bazaar fetch failed", at: new Date().toISOString(), failed_pages: failedPages } };
  }
  const idx = attachStatus(b.build(date), pages, fetched, total, reachedEnd, failedPages);
  await saveIndex(idx); // full tier; retention demotion is separate and never deletes day history
  await applyTierRetention(date);
  return { status: idx.status!, index: idx };
}

export async function saveFail(fail: SnapFail) {
  const k = await kv();
  await k.set(["snapfail", fail.date], fail);
}

export async function loadFail(date: string): Promise<SnapFail | null> {
  const k = await kv();
  return (await k.get<SnapFail>(["snapfail", date])).value ?? null;
}

export async function latestSnapStatus(date?: string | null): Promise<{ status: SnapStatus | null; failed_pages: number[] | null; error: string | null }> {
  if (!date) return { status: null, failed_pages: null, error: null };
  const fail = await loadFail(date);
  if (fail) return { status: "failed", failed_pages: fail.failed_pages, error: fail.error };
  try {
    const idx = await loadIndex(date);
    const st = (idx.status ?? idx.coverage?.status ?? (idx.coverage?.complete === true ? "complete" : idx.coverage ? "partial" : null)) as SnapStatus | null;
    return { status: st, failed_pages: idx.coverage?.failed_pages ?? null, error: null };
  } catch {
    return { status: null, failed_pages: null, error: null };
  }
}

/** Days between YYYY-MM-DD dates (UTC). */
export function dayAge(date: string, today: string) {
  return Math.floor((Date.parse(today + "T00:00:00Z") - Date.parse(date + "T00:00:00Z")) / 86400000);
}

/** Demote old snapshots in place: 0–30 full, 31–90 reduced (no per-resource map), 365+ aggregate counts. Never deletes the day. */
export async function applyTierRetention(today = utcDay()) {
  const k = await kv();
  const dates = await snapshotDates();
  for (const d of dates) {
    const age = dayAge(d, today);
    if (age < 0) continue;
    let idx: Index;
    try { idx = await loadIndex(d); } catch { continue; }
    const tier = idx.tier ?? "full";
    if (age >= TIER_AGGREGATE_FROM && tier !== "aggregate") {
      const agg: Index = {
        date: d, listings: idx.listings, hosts: {}, wallet_hosts: {}, resources: {},
        coverage: idx.coverage ? { ...idx.coverage, items_indexed: idx.listings } : undefined,
        status: idx.status ?? idx.coverage?.status,
        tier: "aggregate",
        aggregate: {
          hosts: Object.keys(idx.hosts ?? {}).length || (idx.aggregate?.hosts ?? 0),
          payout_wallets: Object.keys(idx.wallet_hosts ?? {}).length || (idx.aggregate?.payout_wallets ?? 0),
        },
      };
      clearIndexCache();
      await saveIndex(agg, /*keep*/ undefined, /*skipRetention*/ true);
    } else if (age > TIER_FULL_DAYS && age <= TIER_COMPRESSED_UNTIL && tier === "full") {
      const reduced: Index = {
        ...idx, resources: {}, tier: "reduced",
        // keep hosts + wallet_hosts for reuse facts within 90d; drop per-URL resources to shrink KV
      };
      clearIndexCache();
      await saveIndex(reduced, undefined, true);
    } else if (age > TIER_COMPRESSED_UNTIL && age < TIER_AGGREGATE_FROM && tier === "full") {
      // 91–364: still compressed (reduced), never delete
      const reduced: Index = { ...idx, resources: {}, tier: "reduced" };
      clearIndexCache();
      await saveIndex(reduced, undefined, true);
    }
  }
  // touch snaptier marker list is implicit via idx.tier inside the blob
  void k;
}

/**
 * Cron entry point. At most one attempt per UTC day:
 * - skip if today's snapdate or snapfail already exists (cold-start / redeploy safe)
 * - else atomic snapattempt gate with expireIn 3d
 * Failed attempts store snapfail only (no empty index).
 */
export async function scheduledSnapshot(f: typeof fetch = fetch, now = Date.now()): Promise<"skipped" | "ok" | "failed"> {
  const day = utcDay(now); const k = await kv();
  if ((await k.get(["snapdate", day])).value != null) return "skipped";
  if ((await k.get(["snapfail", day])).value != null) return "skipped";
  const key: Deno.KvKey = ["snapattempt", day];
  const r = await k.atomic().check({ key, versionstamp: null }).set(key, now, { expireIn: SNAPATTEMPT_TTL_MS }).commit();
  if (!r.ok) return "skipped";
  try {
    const out = await runSnapshot(f, maxPages(), day);
    if (out.status === "failed") { await saveFail(out.fail); return "failed"; }
    return "ok";
  } catch (e) {
    const fail: SnapFail = { status: "failed", date: day, error: (e as Error).message || (e as Error).name || "error", at: new Date().toISOString(), failed_pages: [] };
    await saveFail(fail);
    console.log("snapshot failed:", fail.error);
    return "failed";
  }
}
