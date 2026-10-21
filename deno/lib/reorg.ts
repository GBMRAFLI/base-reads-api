// A4: post-delivery settlement re-check, persisted in KV so it survives restarts. A cron sweep processes due records.
import { kv } from "./store.ts";
export type ReorgRec = { path: string; tx: string; payer: string; asset: string; payTo: string; amount: string; nonce: string;
  network: string; minConf: number; due: number; attempts: number };
const KEEP_MS = 7 * 86400_000, RETRY_MS = 300_000, MAX_ATTEMPTS = 3;
export async function scheduleReorgCheck(rec: Omit<ReorgRec, "due" | "attempts">, delayMs: number, now = Date.now()) {
  await (await kv()).set(["reorg", rec.tx], { ...rec, due: now + delayMs, attempts: 0 }, { expireIn: KEEP_MS });
}
/** Re-check due records. settled true -> done; null (not visible) -> retry later up to 3 attempts; otherwise -> incident. */
export async function sweepReorg(check: (r: ReorgRec) => Promise<any>, onIncident: (r: ReorgRec, why: string) => Promise<void>, now = Date.now(), limit = 50) {
  const k = await kv(); let n = 0; const done: string[] = [];
  for await (const e of k.list<ReorgRec>({ prefix: ["reorg"] })) {
    const r = e.value; if (r.due > now) continue; if (n++ >= limit) break;
    let oc: any; try { oc = await check(r); } catch { oc = { settled: null, reason: "recheck_error" }; }
    if (oc?.settled === true) { await k.delete(e.key); done.push(r.tx + ":ok"); continue; }
    if (oc?.settled === null && r.attempts + 1 < MAX_ATTEMPTS) { await k.set(e.key, { ...r, due: now + RETRY_MS, attempts: r.attempts + 1 }, { expireIn: KEEP_MS }); done.push(r.tx + ":retry"); continue; }
    await onIncident(r, "post_delivery_reorg:" + String(oc?.reason ?? oc?.settled)); await k.delete(e.key); done.push(r.tx + ":incident");
  }
  return done;
}
