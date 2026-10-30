// Trial keys: valid key bypasses the 402 within its daily quota; every other case is the unchanged 402.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { handler, resetGuards, exportRecords } from "../main.ts";
import { useKv, rows, append } from "../lib/store.ts";
import { reconcile } from "../lib/stream.ts";
import { dailyLimit, hashKey, KEY_RE, newKey, resetTrialCache, TRIAL_FILE } from "../lib/trial.ts";
import { main as cli } from "../scripts/trial_key.ts";

const P = JSON.parse(Deno.readTextFileSync(new URL("./fixtures/py_signed.json", import.meta.url)));
useKv(await Deno.openKv(":memory:"));
const dir = await Deno.makeTempDir(); const FILE = dir + "/trial-keys.json";
const TOKEN = "t".repeat(40);
const BASE: Record<string, string> = { SIGNING_KEY_PASSPHRASE: P.passphrase, SIGNING_KEY_ENC_B64: P.enc_b64, PUBLIC_URL: "https://h.example",
  SELF_WALLETS: "0x" + "77".repeat(20), LEDGER_MEMORY_OK: "1", TRIAL_KEYS_FILE: FILE, TRIAL_DAILY_LIMIT: "3", EXPORT_TOKEN: TOKEN };
let E: Record<string, string> = { ...BASE }; const env = (k: string) => E[k];
const rpc = async (m: string) => m === "eth_blockNumber" ? "0x10" : m === "eth_getBlockByNumber" ? { number: "0x10", timestamp: "0x" + Math.floor(Date.now() / 1000).toString(16), baseFeePerGas: "0x1" } : "0x1";
async function call(path: string, key?: string, ip = "198.51.100.7") {
  const bgs: Promise<unknown>[] = [];
  const h: Record<string, string> = { Host: "h.example" }; if (key !== undefined) h["X-Trial-Key"] = key;
  const r = await handler(new Request("http://h.example" + path, { headers: h }), { env, rpc, background: (p) => { bgs.push(p); }, ip });
  await Promise.all(bgs); return { status: r.status, body: await r.text(), pr: r.headers.get("PAYMENT-REQUIRED") };
}
async function writeKeys(list: unknown[]) { await Deno.writeTextFile(FILE, JSON.stringify({ keys: list })); resetTrialCache(); }
async function fresh(over: Record<string, string> = {}) { E = { ...BASE, ...over }; await resetGuards(); resetTrialCache(); }
const now = () => new Date().toISOString();

Deno.test("trial: valid key is served (no 402) and recorded with kind trial + label only", async () => {
  await fresh(); const key = newKey(); await writeKeys([{ label: "alpha", hash: await hashKey(key), created: now() }]);
  const r = await call("/base/network?ref=demo", key);
  assertEquals(r.status, 200, r.body); assertEquals(r.pr, null);
  const t = (await rows(TRIAL_FILE)).filter((x: any) => x.label === "alpha");
  assertEquals(t.length, 1); assertEquals(t[0].kind, "trial"); assertEquals(t[0].route, "/base/network"); assertEquals(t[0].ref, "demo");
  const s = JSON.stringify(await rows(TRIAL_FILE)); assert(!s.includes(key)); assert(!s.includes(await hashKey(key)));
  assertEquals((await rows("executions.jsonl")).length + (await rows("outcomes.jsonl")).length, 0, "no sale records");
});
Deno.test("trial: N+1 call in the same UTC day gets the normal 402", async () => {
  await fresh(); const key = newKey(); await writeKeys([{ label: "quota", hash: await hashKey(key), created: now() }]);
  const plain = await call("/base/network", undefined, "198.51.100.9");
  for (let i = 0; i < 3; i++) assert((await call("/base/network", key)).status !== 402);
  const over = await call("/base/network", key, "198.51.100.9");
  assertEquals(over.status, 402); assertEquals(over.body, plain.body); assertEquals(over.pr, plain.pr);
});
Deno.test("trial: wrong, malformed, revoked and expired keys get the byte-identical 402", async () => {
  await fresh(); const rk = newKey(), xk = newKey();
  await writeKeys([{ label: "rev", hash: await hashKey(rk), created: now(), revoked: now() },
    { label: "exp", hash: await hashKey(xk), created: now(), expires: "2020-01-01T00:00:00Z" }]);
  for (const path of ["/base/network", "/base/usdc-balance", "/x402/preflight"]) {
    const base = await call(path); assertEquals(base.status, 402);
    for (const k of [newKey(), "garbage", "", "trk_short", rk, xk]) {
      const r = await call(path, k); assertEquals(r.status, 402, path + " " + k.slice(0, 4)); assertEquals(r.body, base.body); assertEquals(r.pr, base.pr);
    }
  }
});
Deno.test("trial: missing or empty keys file = feature off", async () => {
  await fresh({ TRIAL_KEYS_FILE: dir + "/nope.json" }); assertEquals((await call("/base/network", newKey())).status, 402);
  await Deno.writeTextFile(FILE, ""); await fresh(); assertEquals((await call("/base/network", newKey())).status, 402);
});
Deno.test("trial: revoke takes effect on file change without restart", async () => {
  await fresh(); const key = newKey(); const e = { label: "live", hash: await hashKey(key), created: now() };
  await writeKeys([e]); assert((await call("/base/network", key)).status !== 402);
  await writeKeys([{ ...e, revoked: now() }]); assertEquals((await call("/base/network", key)).status, 402);
});
Deno.test("trial: rows never count as sales in reconcile or export", async () => {
  await fresh(); await append(TRIAL_FILE, { id: "trial-x", kind: "trial", label: "alpha", route: "/base/network", httpStatus: 200, servedAt: now() });
  const recs: Record<string, any[]> = { executions: [{ id: "e1", kind: "trial", amount: "1000" }], outcomes: [{ id: "o1", kind: "trial", executionRef: "e1", status: "verified_success", payer: "0x" + "12".repeat(20) }], costs: [{ id: "c1", kind: "trial", executionRef: "e1" }] };
  reconcile(recs, "0x" + "99".repeat(20), env);
  assertEquals([recs.executions.length, recs.outcomes.length, recs.costs.length], [0, 0, 0]);
  const [code, out]: any = await exportRecords("Bearer " + TOKEN, {}, env); assertEquals(code, 200);
  assertEquals(Object.keys(out.records).sort(), ["costs", "executions", "observations", "outcomes"]);
  assert(out.trials.length >= 1); assert(out.records.outcomes.every((o: any) => o.kind !== "trial"));
});
Deno.test("trial: TRIAL_DAILY_LIMIT default and clamp", () => {
  assertEquals(dailyLimit(() => undefined), 50); assertEquals(dailyLimit(() => "abc"), 50);
  assertEquals(dailyLimit(() => "0"), 1); assertEquals(dailyLimit(() => "999999"), 10000); assertEquals(dailyLimit(() => "7"), 7);
});
Deno.test("trial CLI: generate writes key only to a mode-600 file; list and stdout show no key or hash; duplicates refused", async () => {
  const kf = dir + "/cli-keys.json"; Deno.env.set("TRIAL_KEYS_FILE", kf);
  const out: string[] = [], err: string[] = []; const o = (s: string) => out.push(s), e = (s: string) => err.push(s);
  const dest = dir + "/k-bob.txt";
  assertEquals(await cli(["generate", "--label", "bob", "--days", "7", "--out", dest], o, e), 0);
  const key = (await Deno.readTextFile(dest)).trim(); assert(KEY_RE.test(key));
  assertEquals((await Deno.stat(dest)).mode! & 0o777, 0o600); assertEquals((await Deno.stat(kf)).mode! & 0o777, 0o600);
  const h = await hashKey(key); const file = await Deno.readTextFile(kf); assert(file.includes(h)); assert(!file.includes(key));
  assertEquals(await cli(["generate", "--label", "bob", "--out", dir + "/k2.txt"], o, e), 1);
  assertEquals(await cli(["list"], o, e), 0); assertEquals(await cli(["revoke", "--label", "bob"], o, e), 0);
  assertEquals(await cli(["list"], o, e), 0);
  const all = out.join("\n") + err.join("\n"); assert(!all.includes(key)); assert(!all.includes(h)); assert(!/[0-9a-f]{64}/.test(all));
  assert(out.some((l) => l.startsWith("bob\t") && l.includes("revoked=20")));
  Deno.env.delete("TRIAL_KEYS_FILE");
});
Deno.test("trial CLI: the subprocess stdout never contains the key", async () => {
  const kf = dir + "/sub-keys.json", dest = dir + "/k-sub.txt";
  const p = new Deno.Command(Deno.execPath(), { args: ["run", "--allow-read", "--allow-write", "--allow-env", new URL("../scripts/trial_key.ts", import.meta.url).pathname, "generate", "--label", "sub", "--out", dest],
    env: { TRIAL_KEYS_FILE: kf }, stdout: "piped", stderr: "piped" });
  const r = await p.output(); const so = new TextDecoder().decode(r.stdout) + new TextDecoder().decode(r.stderr);
  assertEquals(r.code, 0, so); const key = (await Deno.readTextFile(dest)).trim();
  assert(!so.includes(key)); assert(so.includes("label=sub"));
});
