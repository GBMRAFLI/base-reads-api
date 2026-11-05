// RWA Exitability Check: price, 402, pre-payment input check, not_disclosed handling, dataset schema, disclaimer.
// Values in the "synthetic" dataset below are made up for tests only and are never shipped.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { handler, resetGuards } from "../main.ts";
import { useKv } from "../lib/store.ts";
import { ROUTES } from "../lib/routes.ts";
import DISCOVERY from "../lib/discovery.json" with { type: "json" };
import SHIPPED from "../../spec/rwa-exitability-dataset.json" with { type: "json" };
import { dataset, NOT_DISCLOSED, RWA_DISCLAIMER, RWA_FIELDS, RWA_PATH, rwaHandle, useDataset, validateDataset, type Dataset } from "../lib/rwa.ts";
import { buildFrom, sanitizeOnchain } from "../scripts/rwa_dataset.ts";
import { hashKey, newKey, resetTrialCache } from "../lib/trial.ts";

const P = JSON.parse(Deno.readTextFileSync(new URL("./fixtures/py_signed.json", import.meta.url)));
useKv(await Deno.openKv(":memory:"));
const dir = await Deno.makeTempDir(); const FILE = dir + "/trial-keys.json";
const E: Record<string, string> = { SIGNING_KEY_PASSPHRASE: P.passphrase, SIGNING_KEY_ENC_B64: P.enc_b64, PUBLIC_URL: "https://h.example",
  SELF_WALLETS: "0x" + "77".repeat(20), LEDGER_MEMORY_OK: "1", TRIAL_KEYS_FILE: FILE, TRIAL_DAILY_LIMIT: "3" };
const env = (k: string) => E[k];
const get = async (qs: string, h: Record<string, string> = {}, ip = "198.51.100.9") => {
  const r = await handler(new Request("http://h.example" + RWA_PATH + qs, { headers: { Host: "h.example", ...h } }), { env, ip, background: () => {} });
  return { status: r.status, body: await r.json(), pr: r.headers.get("PAYMENT-REQUIRED") };
};
const SYNTH: Dataset = { version: "rwa-exitability-dataset/1", dataset_revision: 7, generated_at: "2026-01-01T00:00:00Z", assets: {
  JAAA: { fields: { redemption_path: { value: "SYNTHETIC test value", source_url: "https://issuer.example/synthetic", retrieved_at: "2026-01-01T00:00:00Z" },
    pause_freeze: { value: { paused: false, note: "SYNTHETIC" }, source_url: "https://issuer.example/synthetic2", retrieved_at: "2026-01-02T00:00:00Z" } } },
  USYC: { fields: {} }, mWIN: { fields: {} } } };

Deno.test("rwa: price is 5 USDC (5000000 atomic) in routes, 402 challenge and openapi", async () => {
  await resetGuards();
  assertEquals(ROUTES[RWA_PATH][0], 5_000_000);
  const r = await get("?asset=JAAA"); assertEquals(r.status, 402);
  assertEquals(r.body.accepts[0].amount, "5000000"); assert(r.pr);
  assertEquals(r.body.extensions.bazaar.info.input.queryParams, { asset: "JAAA" });
  assertEquals(r.body.extensions.bazaar.schema.properties.input.properties.queryParams.required, ["asset"]);
  const o = await (await handler(new Request("http://h.example/openapi.json"), { env })).json();
  assertEquals(o.paths[RWA_PATH].get["x-payment-info"].price, "5.000");
  const t = await (await handler(new Request("http://h.example/llms.txt"), { env })).text();
  assert(t.includes(RWA_PATH + " (5.000 USDC)"));
});
Deno.test("rwa: without payment -> 402 (also with no asset, for discovery probes); case-insensitive asset", async () => {
  await resetGuards();
  for (const qs of ["", "?asset=JAAA", "?asset=usyc", "?asset=MWIN", "?asset=mWIN&ref=a1"]) assertEquals((await get(qs)).status, 402, qs);
});
Deno.test("rwa: unknown asset -> 400 before any 402 challenge, still counted against the unpaid limit", async () => {
  await resetGuards();
  for (const qs of ["?asset=BTC", "?asset=JAAA2", "?asset=%25", "?asset=%3Cx%3E"]) {
    const r = await get(qs); assertEquals(r.status, 400, qs); assertEquals(r.pr, null); assert(r.body.error.includes("JAAA, USYC, mWIN"));
  }
  E.UNPAID_PER_MIN = "2"; await resetGuards();
  const st = []; for (let i = 0; i < 4; i++) st.push((await get("?asset=NOPE", {}, "203.0.113.50")).status);
  delete E.UNPAID_PER_MIN; await resetGuards();
  assert(st.includes(429), JSON.stringify(st));
});
Deno.test("rwa: shipped dataset passes schema validation and has the three initial assets", () => {
  assertEquals(validateDataset(SHIPPED), []);
  assertEquals(Object.keys(SHIPPED.assets).sort(), ["JAAA", "USYC", "mWIN"].sort());
  assertEquals((DISCOVERY as any)[RWA_PATH].params.asset.enum, Object.keys(SHIPPED.assets));
});
Deno.test("rwa: validation rejects values without a source, bad URLs, unknown fields and placeholder values", () => {
  const bad = (f: unknown) => validateDataset({ ...SYNTH, assets: { JAAA: { fields: f } } }).length > 0;
  assert(bad({ nav_freshness: { value: "x", source_url: "http://insecure.example", retrieved_at: "2026-01-01T00:00:00Z" } }));
  assert(bad({ nav_freshness: { value: "x", retrieved_at: "2026-01-01T00:00:00Z" } }));
  assert(bad({ nav_freshness: { value: "not_disclosed", source_url: "https://a.example", retrieved_at: "2026-01-01T00:00:00Z" } }));
  assert(bad({ nav_freshness: { value: "x", source_url: "https://a.example", retrieved_at: "yesterday" } }));
  assert(bad({ apy: { value: "x", source_url: "https://a.example", retrieved_at: "2026-01-01T00:00:00Z" } }));
  assert(validateDataset({ ...SYNTH, extra: 1 }).length > 0);
  assertEquals(validateDataset(SYNTH), []);
});
Deno.test("rwa: missing fields are not_disclosed (value and source); cited fields carry url + retrieved_at; confidence from coverage", () => {
  const keep = dataset();
  try {
    useDataset(SYNTH);
    const [c, o]: any = rwaHandle({ asset: "jaaa" }, new Date("2026-02-03T04:05:06.789Z"));
    assertEquals(c, 200); assertEquals(o.asset, "JAAA"); assertEquals(o.checked_at, "2026-02-03T04:05:06Z");
    assertEquals(Object.keys(o.fields), [...RWA_FIELDS]); assertEquals(Object.keys(o.sources), [...RWA_FIELDS]);
    assertEquals(o.fields.redemption_path, "SYNTHETIC test value");
    assertEquals(o.sources.redemption_path, { url: "https://issuer.example/synthetic", retrieved_at: "2026-01-01T00:00:00Z" });
    for (const f of ["transfer_eligibility", "nav_freshness", "redemption_timing", "instant_capacity"]) { assertEquals(o.fields[f], NOT_DISCLOSED, f); assertEquals(o.sources[f], NOT_DISCLOSED, f); }
    assertEquals([o.confidence.level, o.confidence.disclosed_fields, o.confidence.total_fields], ["low", 2, 6]);
    assertEquals(o.dataset, { version: "rwa-exitability-dataset/1", revision: 7, generated_at: "2026-01-01T00:00:00Z" });
    const [, u]: any = rwaHandle({ asset: "USYC" }); assertEquals(u.confidence.level, "none");
    for (const f of RWA_FIELDS) assertEquals(u.fields[f], NOT_DISCLOSED);
    assertEquals(rwaHandle({ asset: "XYZ" })[0], 400); assertEquals(rwaHandle({})[0], 400);
  } finally { useDataset(keep); }
});
Deno.test("rwa: disclaimer present (not a liquidity guarantee, not investment advice); no advice wording", () => {
  const [, o]: any = rwaHandle({ asset: "mWIN" });
  assertEquals(o.disclaimer, RWA_DISCLAIMER); assert(o.disclaimer.includes("Not a liquidity guarantee")); assert(o.disclaimer.includes("not investment advice"));
  const all = (JSON.stringify(o) + ROUTES[RWA_PATH][1] + JSON.stringify((DISCOVERY as any)[RWA_PATH])).toLowerCase();
  for (const w of ["buy now", "sell now", "recommend", "should buy", "should sell", "safe to"]) assert(!all.includes(w), w);
});
Deno.test("rwa: valid trial key is served the same JSON without payment", async () => {
  await resetGuards(); const key = newKey();
  await Deno.writeTextFile(FILE, JSON.stringify({ keys: [{ label: "rwa-t", hash: await hashKey(key), created: new Date().toISOString() }] })); resetTrialCache();
  const r = await get("?asset=USYC", { "X-Trial-Key": key }); assertEquals(r.status, 200);
  assertEquals(r.body.schema, "rwa-exitability/v1"); assertEquals(r.body.asset, "USYC");
  assertEquals((await get("?asset=NOPE", { "X-Trial-Key": key })).status, 400);
});
Deno.test("rwa: dataset build keeps only cited values and reports the rest", () => {
  const { out, dropped } = buildFrom([{ asset: "jaaa", fields: {
    nav_freshness: { value: "SYNTHETIC", source_url: "https://a.example/x", retrieved_at: "2026-01-01T00:00:00Z" },
    redemption_timing: { value: "SYNTHETIC", source_url: "", retrieved_at: "2026-01-01T00:00:00Z" },
    made_up: { value: 1, source_url: "https://a.example", retrieved_at: "2026-01-01T00:00:00Z" } } }, { asset: "ZZZ", fields: {} }],
    { dataset_revision: 3 }, new Date("2026-03-01T00:00:00Z"), ["JAAA", "USYC", "mWIN"]);
  assertEquals(validateDataset(out), []); assertEquals(out.dataset_revision, 4);
  assertEquals(Object.keys(out.assets.JAAA.fields), ["nav_freshness"]); assertEquals(dropped.length, 3);
});

// SYNTHETIC source files in the research hand-off shape (one per asset); made-up values, addresses and blocks.
const SRC_JAAA = { asset: "JAAA", fields: {
  pause_freeze: { value: "SYNTHETIC not paused", source_url: "https://explorer.example/address/0x" + "ab".repeat(20), retrieved_at: "2026-01-02T03:04:05Z",
    confidence: "high", refresh_method: "SYNTHETIC rpc read", note: "SYNTHETIC internal note",
    onchain: { chain: "Ethereum", address: "0x" + "ab".repeat(20), selector: "0x5c975abb", block: "123456", result: "0x" + "00".repeat(32), rpc: "https://rpc.example" } },
  redemption_path: { value: "SYNTHETIC issuer redemption", source_url: "https://issuer.example/synthetic", retrieved_at: "2026-01-02T03:04:05Z", confidence: "medium", refresh_method: "manual" },
  instant_capacity: { value: null, source_url: null, retrieved_at: "2026-01-02T03:04:05Z", confidence: "none" },
  nav_freshness: { value: "SYNTHETIC", source_url: "https://explorer.example/address/0x" + "12".repeat(20), retrieved_at: "2026-01-02T03:04:05Z", onchain: { chain: "ethereum", address: "0x12" } },
  transfer_eligibility: { value: { SYNTHETIC: true }, source_url: "https://docs.example/synthetic", retrieved_at: "2026-01-02T03:04:05Z", onchain: { chain: "ethereum", address: "0x" + "ab".repeat(20), function: "hook (reverted)", block: 1 } },
  redemption_timing: { value: "SYNTHETIC", source_url: "https://eth-mainnet.rpc.example/v3/x", retrieved_at: "2026-01-02T03:04:05Z" } },
  extra_top: "ignored" };
const SRC_USYC = { asset: "USYC", fields: { transfer_eligibility: { value: null, source_url: null, retrieved_at: null } } };
Deno.test("rwa: research hand-off shape builds; null -> not_disclosed; onchain sanitized; extra keys ignored", () => {
  const { out, dropped } = buildFrom([SRC_JAAA as any, SRC_USYC], null, new Date("2026-03-01T00:00:00Z"), ["JAAA", "USYC", "mWIN"]);
  assertEquals(validateDataset(out), []); assertEquals(out.dataset_revision, 1);
  const j: any = out.assets.JAAA.fields;
  assertEquals(Object.keys(j).sort(), ["pause_freeze", "redemption_path", "transfer_eligibility"]);
  assertEquals(j.transfer_eligibility, { value: { SYNTHETIC: true }, source_url: "https://docs.example/synthetic", retrieved_at: "2026-01-02T03:04:05Z" });
  assert(dropped.some((d) => d.startsWith("JAAA.redemption_timing: source_url looks like an RPC")));
  assertEquals(j.pause_freeze, { value: "SYNTHETIC not paused", source_url: "https://explorer.example/address/0x" + "ab".repeat(20), retrieved_at: "2026-01-02T03:04:05Z",
    onchain: { chain: "ethereum", address: "0x" + "ab".repeat(20), function: "0x5c975abb", block: 123456 } });
  assertEquals(Object.keys(j.redemption_path).sort(), ["retrieved_at", "source_url", "value"]);
  assertEquals(Object.keys(out.assets.USYC.fields), []);
  assert(dropped.some((d) => d.startsWith("JAAA.instant_capacity: no public source")));
  assert(dropped.some((d) => d.startsWith("USYC.transfer_eligibility: no public source")));
  assert(dropped.some((d) => d.startsWith("JAAA.nav_freshness: onchain")));
  const txt = JSON.stringify(out);
  for (const w of ["internal note", "rpc.example", "refresh_method", "\"confidence\"", "\"result\"", "extra_top", "selector"]) assert(!txt.includes(w), w);
  const keep = dataset();
  try {
    useDataset(out as Dataset);
    const [c, o]: any = rwaHandle({ asset: "JAAA" });
    assertEquals(c, 200);
    assertEquals(o.sources.pause_freeze, { url: "https://explorer.example/address/0x" + "ab".repeat(20), retrieved_at: "2026-01-02T03:04:05Z",
      onchain: { chain: "ethereum", address: "0x" + "ab".repeat(20), function: "0x5c975abb", block: 123456 } });
    assertEquals(o.sources.redemption_path, { url: "https://issuer.example/synthetic", retrieved_at: "2026-01-02T03:04:05Z" });
    assertEquals([o.fields.instant_capacity, o.sources.instant_capacity], [NOT_DISCLOSED, NOT_DISCLOSED]);
    assertEquals([o.confidence.level, o.confidence.disclosed_fields], ["medium", 3]);
    assert(!JSON.stringify(o.sources).includes("medium") && !JSON.stringify(o.fields).includes("refresh"));
  } finally { useDataset(keep); }
});
Deno.test("rwa: onchain citation validation", () => {
  assertEquals(sanitizeOnchain({ chain: "base", address: "0x" + "cd".repeat(20), function: "paused()", block: 9 }), { chain: "base", address: "0x" + "cd".repeat(20), function: "paused()", block: 9 });
  for (const o of [null, { chain: "base", address: "0x12", function: "paused()", block: 9 }, { chain: "base", address: "0x" + "cd".repeat(20), function: "paused(); drop", block: 9 },
    { chain: "base", address: "0x" + "cd".repeat(20), function: "paused()", block: -1 }, { chain: "base", address: "0x" + "cd".repeat(20), block: 9 }]) assertEquals(sanitizeOnchain(o), null);
  const ok = { value: "x", source_url: "https://explorer.example/a", retrieved_at: "2026-01-01T00:00:00Z" };
  const v = (f: unknown) => validateDataset({ version: "rwa-exitability-dataset/1", dataset_revision: 1, generated_at: "2026-01-01T00:00:00Z", assets: { JAAA: { fields: { pause_freeze: f } } } });
  assertEquals(v({ ...ok, onchain: { chain: "ethereum", address: "0x" + "ab".repeat(20), function: "0x5c975abb", block: 1 } }), []);
  assert(v({ ...ok, onchain: { chain: "ethereum", address: "0x" + "ab".repeat(20), function: "0x5c975abb", block: 1, result: "0x00" } }).length > 0);
  assert(v({ ...ok, confidence: "high" }).length > 0);
  assertEquals(v({ ...ok, onchain: { chain: "ethereum", address: "0x" + "ab".repeat(20), function: "asset()/totalAssets()", block: 1 } }), []);
  assert(v({ ...ok, onchain: { chain: "ethereum", address: "0x" + "ab".repeat(20), function: "hook (reverted)", block: 1 } }).length > 0);
});
Deno.test("rwa: garbage payment header + unknown asset is still counted as unpaid (400 then 429)", async () => {
  E.UNPAID_PER_MIN = "5"; await resetGuards();
  const st: number[] = [];
  for (let i = 0; i < 6; i++) { const r = await get("?asset=NOPE", { "PAYMENT-SIGNATURE": "garbage!!" }, "203.0.113.77"); st.push(r.status); assertEquals(r.pr, null); }
  delete E.UNPAID_PER_MIN; await resetGuards();
  assertEquals(st, [400, 400, 400, 400, 400, 429]);
});
