// Daily Bazaar snapshot (Deno.cron 00:15 UTC only; never at startup). Bounded to keep hosting usage small:
// at most SNAPSHOT_MAX_PAGES pages (default 3, 1000 items each), 15 s per page, 1 retry, and at most one attempt
// (success or failure) per UTC calendar day. Status is complete | partial | failed; failed stores an error record
// (never an empty snapshot). Tiered retention demotes old indexes (never the newest; no day deletion).
import {
  IndexAssembler, saveIndex, loadIndex, listSnapMetas, readSnapMeta, dayAge, UA, type Index, type SnapTier, clearIndexCache,
} from "./preflight.ts";
export { dayAge } from "./preflight.ts";
import { kv } from "./store.ts";

const BAZAAR = Deno.env.get("BAZAAR_URL") ?? "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
export const PAGE = 1000, PAGE_TIMEOUT_MS = 15000, RETRIES = 1;
export const SNAPATTEMPT_TTL_MS = 3 * 24 * 3600_000;
/** 0–30 full; 31–364 reduced (counts only); 365+ aggregate. Newest day is never demoted. */
export const TIER_FULL_DAYS = 30, TIER_AGGREGATE_FROM = 365;

export type SnapStatus = "complete" | "partial" | "failed";
export type SnapFail = { status: "failed"; date: string; error: string; error_code: string; at: string; failed_pages: number[] };
export type RunResult =
  | { status: "complete" | "partial"; index: Index; meta: { gzip_bytes: number; chunks: number } }
  | { status: "failed"; fail: SnapFail };

/** Fixed error codes for signed metadata (L1). */
export function mapErrorCode(err: string): string {
  const s = (err || "").toLowerCase();
  if (s.includes("bazaar fetch failed") || s === "bazaar_fetch_failed") return "bazaar_fetch_failed";
  if (s.includes("timeout") || s.includes("abort")) return "timeout";
  if (s.includes("save_crash") || s.includes("snapdate_cas")) return "persist_error";
  return "snapshot_error";
}

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
  idx.status = status; idx.tier = "full";
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
    if (!d) { failedPages.push(page); off += PAGE; continue; }
    const items = d.items ?? []; b.add(items); fetched++;
    if (typeof d.pagination?.total === "number") total = d.pagination.total;
    if (items.length < PAGE) { reachedEnd = true; break; }
    off += items.length;
  }
  if (fetched === 0) {
    return { status: "failed", fail: { status: "failed", date, error: "bazaar fetch failed", error_code: "bazaar_fetch_failed", at: new Date().toISOString(), failed_pages: failedPages } };
  }
  const idx = attachStatus(b.build(date), pages, fetched, total, reachedEnd, failedPages);
  const meta = await saveIndex(idx);
  await applyTierRetention(date);
  return { status: idx.status!, index: idx, meta: { gzip_bytes: meta.gzip_bytes, chunks: meta.chunks } };
}

export async function saveFail(fail: SnapFail) {
  if (!fail.error_code) fail.error_code = mapErrorCode(fail.error);
  await (await kv()).set(["snapfail", fail.date], fail);
}
export async function loadFail(date: string): Promise<SnapFail | null> {
  return (await (await kv()).get<SnapFail>(["snapfail", date])).value ?? null;
}

export async function latestSnapStatus(date?: string | null): Promise<{ status: SnapStatus | null; failed_pages: number[] | null; error: string | null; error_code: string | null }> {
  if (!date) return { status: null, failed_pages: null, error: null, error_code: null };
  const fail = await loadFail(date);
  if (fail) return { status: "failed", failed_pages: fail.failed_pages, error: fail.error, error_code: fail.error_code || mapErrorCode(fail.error) };
  const meta = await readSnapMeta(date);
  if (!meta) return { status: null, failed_pages: null, error: null, error_code: null };
  return { status: (meta.status as SnapStatus | null) ?? null, failed_pages: null, error: null, error_code: null };
}


function targetTier(age: number): SnapTier {
  if (age >= TIER_AGGREGATE_FROM) return "aggregate";
  if (age > TIER_FULL_DAYS) return "reduced";
  return "full";
}

function toReduced(idx: Index): Index {
  const walletCounts: Record<string, number> = {};
  for (const [w, v] of Object.entries(idx.wallet_hosts ?? {})) {
    walletCounts[w] = typeof v === "number" ? v : v.length;
  }
  return {
    date: idx.date, listings: idx.listings, hosts: { ...idx.hosts }, wallet_hosts: walletCounts,
    resources: {}, coverage: idx.coverage, status: idx.status, tier: "reduced",
  };
}

function toAggregate(idx: Index): Index {
  const hostN = Object.keys(idx.hosts ?? {}).length || (idx.aggregate?.hosts ?? 0);
  let walletN = idx.aggregate?.payout_wallets ?? 0;
  if (!walletN) walletN = Object.keys(idx.wallet_hosts ?? {}).length;
  return {
    date: idx.date, listings: idx.listings, hosts: {}, wallet_hosts: {}, resources: {},
    coverage: idx.coverage ? { ...idx.coverage, items_indexed: idx.listings } : undefined,
    status: idx.status ?? idx.coverage?.status, tier: "aggregate",
    aggregate: { hosts: hostN, payout_wallets: walletN },
  };
}

/**
 * Demote old snapshots using snapdate.tier only (no gunzip unless a boundary is crossed).
 * Never demotes the newest successful snapshot (H1).
 * 0–30 full; 31–364 reduced counts; 365+ aggregate.
 */
export async function applyTierRetention(today = utcDay()) {
  const metas = await listSnapMetas();
  if (!metas.length) return;
  const newest = metas[metas.length - 1].date;
  for (const { date: d, meta } of metas) {
    if (d === newest) continue; // never demote the newest
    const age = dayAge(d, today);
    if (age < 0) continue;
    const want = targetTier(age);
    const have = meta.tier ?? "full";
    if (have === want) continue;
    if (have === "aggregate") continue; // already most compact
    if (want === "full") continue;
    // Boundary crossed: load once, rewrite.
    const idx = await loadIndex(d);
    const next = want === "aggregate" ? toAggregate(idx) : toReduced(idx);
    clearIndexCache();
    await saveIndex(next);
  }
}

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
    const msg = (e as Error).message || (e as Error).name || "error";
    const fail: SnapFail = { status: "failed", date: day, error: msg, error_code: mapErrorCode(msg), at: new Date().toISOString(), failed_pages: [] };
    await saveFail(fail);
    console.log("snapshot failed:", fail.error_code);
    return "failed";
  }
}
