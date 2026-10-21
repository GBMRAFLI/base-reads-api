// A4: post-delivery settlement re-check, persisted in KV so it survives restarts. A cron sweep processes due records.
import { kv } from "./store.ts";
export type ReorgRec = { path: string; tx: string; payer: string; asset: string; payTo: string; amount: string; nonce: string;
  network: string; minConf: number; due: number; attempts: number };
const KEEP_MS = 7 * 86400_000, RETRY_MS = 300_000, MAX_ATTEMPTS = 3;
export async function scheduleReorgCheck(rec: Omit<ReorgRec, "due" | "attempts">, delayMs: number, now = Date.now()) {
  const due = now + delayMs; await (await kv()).set(["reorg", due, rec.tx], { ...rec, due, attempts: 0 }, { expireIn: KEEP_MS });
}
/** Re-check due records. settled true -> done; null (not visible) -> retry later up to 3 attempts; otherwise -> incident. */
export async function sweepReorg(check: (r: ReorgRec) => Promise<any>, onIncident: (r: ReorgRec, why: string) => Promise<void>, now = Date.now(), limit = 50) {
  // L4: key ["reorg", due, tx]: only due records are listed; every state change is a versionstamp-checked atomic op,
  // so two overlapping sweeps cannot both report the same incident.
  const k = await kv(); const done: string[] = [];
  for await (const e of k.list<ReorgRec>({ start: ["reorg", 0], end: ["reorg", now + 1] }, { limit })) {
    const r = e.value;
    let oc: any; try { oc = await check(r); } catch { oc = { settled: null, reason: "recheck_error" }; }
    if (oc?.settled === true) { if ((await k.atomic().check(e).delete(e.key).commit()).ok) done.push(r.tx + ":ok"); continue; }
    if (oc?.settled === null && r.attempts + 1 < MAX_ATTEMPTS) {
      const due = now + RETRY_MS;
      if ((await k.atomic().check(e).delete(e.key).set(["reorg", due, r.tx], { ...r, due, attempts: r.attempts + 1 }, { expireIn: KEEP_MS }).commit()).ok) done.push(r.tx + ":retry");
      continue;
    }
    if (!(await k.atomic().check(e).delete(e.key).commit()).ok) continue; // another sweep took it
    await onIncident(r, "post_delivery_reorg:" + String(oc?.reason ?? oc?.settled)); done.push(r.tx + ":incident");
  }
  return done;
}
