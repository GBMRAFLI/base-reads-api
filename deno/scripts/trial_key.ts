// Operator tool for trial keys. The plaintext key is written only to a new mode-600 file; stdout never shows a key or hash.
//   deno run --allow-read --allow-write --allow-env scripts/trial_key.ts generate --label NAME [--days D] [--out PATH]
//   deno run --allow-read --allow-write --allow-env scripts/trial_key.ts revoke --label NAME
//   deno run --allow-read --allow-env scripts/trial_key.ts list
// The keys file is TRIAL_KEYS_FILE (default /var/lib/base-reads/trial-keys.json), rewritten atomically
// with mode 600 and the owner of the previous file (or of its directory), so the service user can still read it.
import { hashKey, keysPath, LABEL_RE, newKey, parseKeys, type TrialEntry } from "../lib/trial.ts";

type Out = (s: string) => void;
const env = (k: string) => Deno.env.get(k);
function arg(a: string[], name: string): string | undefined { const i = a.indexOf(name); return i >= 0 ? a[i + 1] : undefined; }
async function load(path: string): Promise<TrialEntry[]> {
  try { return parseKeys(await Deno.readTextFile(path)); } catch (e) { if (e instanceof Deno.errors.NotFound) return []; throw e; }
}
async function save(path: string, list: TrialEntry[]) {
  const tmp = path + ".tmp-" + crypto.randomUUID().slice(0, 8);
  await Deno.writeTextFile(tmp, JSON.stringify({ keys: list }, null, 2) + "\n", { mode: 0o600, createNew: true });
  await Deno.chmod(tmp, 0o600);
  // Keep the file readable by the service: same owner as the previous file, else as its directory (state dir owner).
  try {
    let st: Deno.FileInfo; try { st = await Deno.stat(path); } catch { st = await Deno.stat(path.replace(/\/[^/]*$/, "") || "."); }
    if (st.uid != null && st.gid != null) await Deno.chown(tmp, st.uid, st.gid);
  } catch { /* not root: the file stays owned by the caller */ }
  await Deno.rename(tmp, path);
}
const sec = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

export async function main(a: string[], out: Out = console.log, err: Out = console.error, now = new Date()): Promise<number> {
  const cmd = a[0]; const path = keysPath(env);
  if (cmd === "list") {
    const list = await load(path);
    if (!list.length) { out("no trial keys"); return 0; }
    for (const e of list) out([e.label, "created=" + e.created, "expires=" + (e.expires ?? "never"), "revoked=" + (e.revoked ?? "no")].join("\t"));
    return 0;
  }
  const label = arg(a, "--label") ?? "";
  if ((cmd === "generate" || cmd === "revoke") && !LABEL_RE.test(label)) { err("--label must match " + LABEL_RE.source); return 2; }
  if (cmd === "generate") {
    const list = await load(path);
    if (list.some((e) => e.label === label)) { err("label already exists: " + label); return 1; }
    const daysRaw = arg(a, "--days"); let expires: string | null = null;
    if (daysRaw !== undefined) {
      if (!/^[0-9]{1,4}$/.test(daysRaw) || Number(daysRaw) < 1) { err("--days must be a whole number >= 1"); return 2; }
      expires = sec(new Date(now.getTime() + Number(daysRaw) * 86_400_000));
    }
    const dest = arg(a, "--out") ?? `./trial-key-${label}.txt`;
    const key = newKey();
    try { await Deno.writeTextFile(dest, key + "\n", { mode: 0o600, createNew: true }); await Deno.chmod(dest, 0o600); }
    catch (e) { err("cannot create key file (it must not exist yet): " + dest + " (" + (e as Error).name + ")"); return 1; }
    list.push({ label, hash: await hashKey(key), created: sec(now), expires, revoked: null });
    await save(path, list);
    out(`generated label=${label} key_file=${dest}${expires ? " expires=" + expires : ""}`);
    return 0;
  }
  if (cmd === "revoke") {
    const list = await load(path); const e = list.find((x) => x.label === label);
    if (!e) { err("no such label: " + label); return 1; }
    if (!e.revoked) { e.revoked = sec(now); await save(path, list); }
    out(`revoked label=${label} at=${e.revoked}`);
    return 0;
  }
  err("usage: trial_key.ts generate --label NAME [--days D] [--out PATH] | revoke --label NAME | list");
  return 2;
}
if (import.meta.main) Deno.exit(await main(Deno.args));
