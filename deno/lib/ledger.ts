// Payment ledger: consumed payment authorizations (payer:nonce) and settlement tx hashes.
// Kept in its OWN SQLite file (LEDGER_PATH), separate from the KV store, so restoring or rolling back the KV
// (snapshots, caches, metadata) can never re-open a spent payment.
// - Append-only: UPDATE and DELETE are rejected by triggers; rows are only ever inserted.
// - Durable: WAL journal with synchronous=FULL, so an insert is fsync'ed to disk before it returns
//   (survives process crash and power loss, given a disk that honours fsync).
// - Atomic first-use: INSERT ... ON CONFLICT DO NOTHING; changes === 1 means this caller consumed it.
import { DatabaseSync } from "node:sqlite";

export type LedgerKind = "auth" | "tx";
let db: DatabaseSync | null = null;
let dbPath: string | null = null;

export function ledgerPath(env: (k: string) => string | undefined = (k) => Deno.env.get(k)) {
  const p = env("LEDGER_PATH");
  if (p) return p;
  const kvp = env("KV_PATH");
  return kvp ? kvp.replace(/[^/]*$/, "") + "ledger.sqlite3" : ":memory:";
}
/** Open (or return) the ledger. Without a path, the already-open ledger is reused, else LEDGER_PATH/KV_PATH decides. */
/** Startup guard: a file ledger is required. In-memory only with LEDGER_MEMORY_OK=1 and never on Base mainnet.
 * The ledger needs a local filesystem (node:sqlite); serverless hosts without one are not supported. */
export function ledgerConfigError(env: (k: string) => string | undefined): string | null {
  if (ledgerPath(env) !== ":memory:") return null;
  const net = env("NETWORK") ?? "eip155:8453";
  if (net === "eip155:8453") return "payment ledger needs a file: set LEDGER_PATH or KV_PATH (in-memory is never allowed on Base mainnet)";
  if (env("LEDGER_MEMORY_OK") !== "1") return "payment ledger needs a file: set LEDGER_PATH or KV_PATH (or LEDGER_MEMORY_OK=1 on testnet)";
  return null;
}
export function openLedger(path?: string): DatabaseSync {
  if (db && (path === undefined || dbPath === path)) return db;
  path ??= ledgerPath();
  db?.close();
  const d = new DatabaseSync(path);
  d.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=10000;
    CREATE TABLE IF NOT EXISTS consumed (kind TEXT NOT NULL, id TEXT NOT NULL, at INTEGER NOT NULL, meta TEXT,
      PRIMARY KEY (kind, id)) WITHOUT ROWID;
    CREATE TRIGGER IF NOT EXISTS consumed_no_update BEFORE UPDATE ON consumed BEGIN SELECT RAISE(ABORT, 'append-only'); END;
    CREATE TRIGGER IF NOT EXISTS consumed_no_delete BEFORE DELETE ON consumed BEGIN SELECT RAISE(ABORT, 'append-only'); END;`);
  db = d; dbPath = path; return d;
}
export function closeLedger() { db?.close(); db = null; dbPath = null; }

/** Record first use; true if this call consumed it, false if it was already in the ledger. */
export function consume(kind: LedgerKind, id: string, meta: unknown = null, now = Date.now()): boolean {
  const r = openLedger().prepare("INSERT INTO consumed (kind, id, at, meta) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING")
    .run(kind, id.toLowerCase(), now, meta == null ? null : JSON.stringify(meta));
  return Number(r.changes) === 1;
}
export function isConsumed(kind: LedgerKind, id: string): boolean {
  return !!openLedger().prepare("SELECT 1 FROM consumed WHERE kind = ? AND id = ?").get(kind, id.toLowerCase());
}
export function ledgerCount(): number {
  return Number((openLedger().prepare("SELECT count(*) AS n FROM consumed").get() as { n: number }).n);
}
/** One-time import of replay keys that older releases kept in the KV store (idempotent). */
export async function migrateFromKv(k: Deno.Kv): Promise<{ auth: number; tx: number }> {
  const out = { auth: 0, tx: 0 };
  for await (const e of k.list({ prefix: ["nonce"] })) if (typeof e.key[1] === "string" && consume("auth", e.key[1], { migrated: true })) out.auth++;
  for await (const e of k.list({ prefix: ["authused"] })) if (typeof e.key[1] === "string" && consume("auth", e.key[1], { migrated: true })) out.auth++;
  for await (const e of k.list({ prefix: ["txused"] })) if (typeof e.key[1] === "string" && consume("tx", e.key[1], { migrated: true })) out.tx++;
  return out;
}
