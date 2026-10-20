// Merge rows from a ledger backup into the live payment ledger with INSERT OR IGNORE.
// Never restore the ledger by replacing the file: that could drop entries written after the backup and
// re-open spent authorizations. Merging only ever adds rows; existing rows are never changed.
// Usage (service may stay up; SQLite locking applies):
//   deno run --allow-read --allow-write ledger-merge.ts <live-ledger.sqlite3> <backup-ledger.sqlite3>
import { DatabaseSync } from "node:sqlite";
import { openLedger, closeLedger } from "../../deno/lib/ledger.ts";

export function mergeLedger(livePath: string, backupPath: string): { added: number; total: number } {
  const live = openLedger(livePath); // ensures schema + append-only triggers on the live file
  const src = new DatabaseSync(backupPath, { readOnly: true });
  const rows = src.prepare("SELECT kind, id, at, meta FROM consumed").all() as { kind: string; id: string; at: number; meta: string | null }[];
  src.close();
  const ins = live.prepare("INSERT OR IGNORE INTO consumed (kind, id, at, meta) VALUES (?, ?, ?, ?)");
  let added = 0;
  live.exec("BEGIN IMMEDIATE");
  try { for (const r of rows) added += Number(ins.run(r.kind, r.id, r.at, r.meta).changes); live.exec("COMMIT"); }
  catch (e) { live.exec("ROLLBACK"); throw e; }
  const total = Number((live.prepare("SELECT count(*) AS n FROM consumed").get() as { n: number }).n);
  closeLedger();
  return { added, total };
}

if (import.meta.main) {
  const [live, backup] = Deno.args;
  if (!live || !backup) { console.error("usage: ledger-merge.ts <live> <backup>"); Deno.exit(2); }
  console.log(JSON.stringify(mergeLedger(live, backup))); // counts only
}
