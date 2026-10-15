// Copies accounting and in-flight keys from the live KV (`src`, newer) into a restored KV copy (`dst`),
// so restoring an older KV file never loses a recorded sale. Spent payment authorizations and settlement tx
// hashes are NOT in the KV: they live in the separate append-only ledger (LEDGER_PATH), which no restore touches.
// Usage (service stopped): deno run --unstable-kv --allow-read --allow-write kv-merge.ts <live.sqlite3> <restored.sqlite3>
// Live values win for these prefixes. Keys only in `dst` are kept (never delete replay state).
// KV does not expose remaining TTLs, so copied keys get the policy below: records are kept without expiry,
// transient keys get a bounded TTL so they cannot block callers forever.
export const PROTECTED: Record<string, number | null> = {
  rec: null, // accounting records: permanent
  pending: 3600_000, // settle-pending markers: same TTL as setPending
  inflight: 600_000, // concurrency slots: short TTL, service is stopped during restore
};

export async function mergeProtected(srcPath: string, dstPath: string) {
  const src = await Deno.openKv(srcPath); const dst = await Deno.openKv(dstPath);
  const counts: Record<string, number> = {};
  try {
    for (const [prefix, ttl] of Object.entries(PROTECTED)) {
      counts[prefix] = 0;
      for await (const e of src.list({ prefix: [prefix] })) {
        const cur = await dst.get(e.key);
        if (cur.versionstamp !== null && JSON.stringify(cur.value) === JSON.stringify(e.value)) continue;
        await dst.set(e.key, e.value, ttl == null ? undefined : { expireIn: ttl });
        counts[prefix]++;
      }
    }
  } finally { src.close(); dst.close(); }
  return counts;
}

if (import.meta.main) {
  const [s, d] = Deno.args;
  if (!s || !d) { console.error("usage: kv-merge.ts <live> <restored>"); Deno.exit(2); }
  console.log(JSON.stringify(await mergeProtected(s, d))); // counts only, no values
}
