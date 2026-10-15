// Storage: Deno KV (free tier: 1 GiB, 1M reads / 500k writes per month). Same record format as the Python
// sales_log JSONL files; export returns the same shape so the external collector and on-chain check are unchanged.
export type Rec = Record<string, unknown> & { id: string };
export const EXPORT_FILES = ["executions.jsonl", "outcomes.jsonl", "observations.jsonl", "costs.jsonl"] as const;
let kvP: Promise<Deno.Kv> | null = null;
export function kv(): Promise<Deno.Kv> { return kvP ??= Deno.openKv(Deno.env.get("KV_PATH") || undefined); }
export function useKv(k: Deno.Kv) { kvP = Promise.resolve(k); }
let seq = 0;
export async function append(name: string, rec: Rec): Promise<Rec> {
  const k = await kv();
  // key = [file, insertion-time, seq, id] keeps Python's append order for export
  await k.set(["rec", name, Date.now(), seq++, rec.id], rec);
  return rec;
}
export async function rows(name: string): Promise<Rec[]> {
  const k = await kv(); const out: Rec[] = [];
  for await (const e of k.list<Rec>({ prefix: ["rec", name] })) out.push(e.value);
  return out;
}
