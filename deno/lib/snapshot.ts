// Daily Bazaar snapshot (Deno.cron 00:15 UTC). Pages are folded into the index one at a time (memory cap 512 MB).
import { IndexAssembler, saveIndex, snapshotDates, UA } from "./preflight.ts";
import { kv } from "./store.ts";
const BAZAAR = Deno.env.get("BAZAAR_URL") ?? "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
export async function runSnapshot(f: typeof fetch = fetch, maxPages = 80, date = new Date().toISOString().slice(0, 10)) {
  const b = new IndexAssembler(); let off = 0;
  for (let page = 0; page < maxPages; page++) {
    let d: any = null;
    for (let attempt = 0; attempt < 3 && !d; attempt++) {
      try { const r = await f(`${BAZAAR}?limit=1000&offset=${off}`, { headers: { "User-Agent": UA }, signal: AbortSignal.timeout(40000) }); if (r.ok) d = await r.json(); }
      catch { /* retry */ }
      if (!d) { if (attempt === 2) throw new Error("bazaar fetch failed"); await new Promise((r) => setTimeout(r, 3000)); }
    }
    const items = d.items ?? []; b.add(items);
    if (items.length < 1000) break;
    off += items.length; await new Promise((r) => setTimeout(r, 500));
  }
  const idx = b.build(date); await saveIndex(idx); return idx.listings;
}
export async function snapshotIfMissing() {
  const today = new Date().toISOString().slice(0, 10);
  if ((await snapshotDates()).includes(today)) return;
  const k = await kv(); // single-flight lock across isolates (expires after 15 min)
  const lock = await k.atomic().check({ key: ["snaplock", today], versionstamp: null }).set(["snaplock", today], 1, { expireIn: 900000 }).commit();
  if (!lock.ok) return;
  await runSnapshot();
}
