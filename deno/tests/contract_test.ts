import { assert, assertEquals } from "jsr:@std/assert@1";
import { canonical, pyDumps } from "../lib/canonical.ts";
import { decryptPem, publicKeyInfo, resetKey, sign, verify } from "../lib/sign.ts";
import { checkUrl, IndexAssembler, validateChallenge, preflight, saveIndex, bazaarFacts, clearIndexCache } from "../lib/preflight.ts";
import { ROUTES } from "../lib/routes.ts";
import { rid } from "../lib/util.ts";
import { useKv, rows } from "../lib/store.ts";
import { recordSale, verifyOnchain, TRANSFER } from "../lib/stream.ts";
import { bazaar, facClient, handler, reqFor, required, resetGuards, root, snapshotMeta, wellKnown } from "../main.ts";
import * as SG from "../lib/settle_guard.ts";
import { keyHistory } from "../lib/sign.ts";
import { AUTH_USED } from "../lib/stream.ts";
import { headers as cdpHeaders, jwt as cdpJwt } from "../lib/cdp_auth.ts";

const C = JSON.parse(Deno.readTextFileSync(new URL("./fixtures/contract.json", import.meta.url)));
const P = JSON.parse(Deno.readTextFileSync(new URL("./fixtures/py_signed.json", import.meta.url)));
useKv(await Deno.openKv(":memory:"));
const TOKEN = "t".repeat(40);
const ENV: Record<string, string> = { SIGNING_KEY_PASSPHRASE: P.passphrase, SIGNING_KEY_ENC_B64: P.enc_b64, EXPORT_TOKEN: TOKEN, SELF_WALLETS: "0x" + "77".repeat(20) };
const env = (k: string) => ENV[k];
for (const [k, v] of Object.entries(ENV)) Deno.env.set(k, v);
Deno.env.delete("PAY_TO_ADDRESS");

Deno.test("routes, prices and descriptions identical to Python", () => {
  assertEquals(Object.entries(ROUTES).map(([k, v]) => [k, v[0], v[1], v[2]]), C.routes);
});
Deno.test("root index body byte-identical", async () => {
  const r = await handler(new Request("http://h.example/"), { env }); assertEquals(await r.text(), C.root_body);
});
Deno.test("402 challenge body and PAYMENT-REQUIRED header byte-identical for every route", async () => {
  for (const k of Object.keys(ROUTES)) {
    const r = await handler(new Request("http://h.example" + k, { headers: { Host: "h.example" } }), { env });
    assertEquals(r.status, 402); assertEquals(await r.text(), C.required[k].body, k);
    assertEquals(r.headers.get("PAYMENT-REQUIRED"), C.required[k].header, k);
    assertEquals(r.headers.get("Access-Control-Expose-Headers"), "PAYMENT-REQUIRED, PAYMENT-RESPONSE");
    assertEquals(reqFor(k, env), C.req_for[k]);
  }
});
Deno.test("record ids identical (rid)", () => {
  assertEquals([rid("exec", null, "/base/network"), rid("cand", "v1", "chain_reads", "/base/network"), rid("out", "0x" + "ab".repeat(32), "/x402/preflight")], C.rid);
});
Deno.test("challenge validation identical", () => {
  const inputs = [{ x402Version: 2, accepts: [{ scheme: "exact", network: "n", amount: "10", asset: "0x" + "11".repeat(20), payTo: "0x" + "22".repeat(20), maxTimeoutSeconds: 60 }] },
    null, { _unparseable: "body" }, { x402Version: 3, accepts: [{ maxAmountRequired: "1.5", payTo: "0xbad", maxTimeoutSeconds: 0 }, 5] }, { x402Version: 1, accepts: [] }];
  assertEquals(inputs.map((c) => validateChallenge(c)), C.validate);
});
Deno.test("Bazaar index identical", () => {
  const b = new IndexAssembler();
  b.add([{ resource: "https://a.example/x?q=1", accepts: [{ payTo: "0x" + "AB".repeat(20) }, { payTo: "0x" + "cd".repeat(20) }], quality: { l30DaysUniquePayers: 3, l30DaysTotalCalls: 9, lastCalledAt: "2026-10-13T00:00:00Z" } },
    { resource: "https://b.example/y", accepts: [{ payTo: "0x" + "ab".repeat(20) }], quality: {} }, { resource: "nohost", accepts: [] }]);
  assertEquals(b.build("2026-10-13"), C.index);
});
Deno.test("canonical JSON identical to Python (unicode, escapes, key order)", () => {
  assertEquals(canonical({ b: [1, null, true, "é\u2028😀\"\\\n\t\x01"], a: { z: 0, A: -5 }, _: "" }), C.canonical);
});
Deno.test("same encrypted key -> same pubkey and byte-identical Ed25519 signature as Python", async () => {
  resetKey();
  assertEquals(await publicKeyInfo(), P.pubkey);
  assertEquals(canonical(P.envelope.facts), P.canonical);
  const e = await sign(P.envelope.facts); assertEquals(e, P.envelope);
  assert(await verify(P.envelope));
  const t = structuredClone(P.envelope); t.facts.challenge.valid = false; assert(!(await verify(t)));
});
Deno.test("wrong passphrase fails, missing secrets -> 503 on pubkey", async () => {
  const pem = new TextDecoder().decode(Uint8Array.from(atob(P.enc_b64), (c) => c.charCodeAt(0)));
  let threw = false; try { await decryptPem(pem, "wrong-passphrase-123456"); } catch { threw = true; } assert(threw);
  resetKey(); Deno.env.delete("SIGNING_KEY_ENC_B64");
  const r = await handler(new Request("http://h/x402/preflight/pubkey"), { env: (k) => k === "SIGNING_KEY_ENC_B64" ? undefined : env(k) });
  assertEquals(r.status, 503); await r.body?.cancel(); Deno.env.set("SIGNING_KEY_ENC_B64", P.enc_b64); resetKey();
});
Deno.test("SSRF guard rejects non-public answers", async () => {
  const res = (ips: string[]) => async () => ips;
  for (const bad of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.1", "::1", "fe80::1", "0.0.0.0", "240.0.0.1", "172.20.0.1", "fd00::1", "::ffff:127.0.0.1"])
    assertEquals((await checkUrl("https://evil.example/", res(["93.184.216.34", bad]))).err, "target resolves to a non-public address", bad);
  assertEquals((await checkUrl("https://ok.example/", res(["93.184.216.34"]))).err, null);
  for (const u of ["http://example.com", "https://127.0.0.1/x", "https://[::1]/", "file:///etc/passwd"]) assertEquals((await checkUrl(u, res(["93.184.216.34"]))).u, null, u);
  assertEquals((await checkUrl("https://nx.example/", res([]))).err, "dns_unresolvable");
  assertEquals((await checkUrl("https://ok.example/", async () => null)).err, null);            // DNS API unavailable
  assertEquals((await checkUrl("https://10.0.0.1/", async () => null)).u, null);               // literals still checked
});
Deno.test("preflight end-to-end: signed facts, bazaar facts from KV snapshot", async () => {
  clearIndexCache(); const b = new IndexAssembler();
  b.add([{ resource: "https://a.example/x", accepts: [{ payTo: "0x" + "22".repeat(20) }], quality: { l30DaysUniquePayers: 4, l30DaysTotalCalls: 8, lastCalledAt: "2026-10-13T00:00:00Z" } },
    { resource: "https://c.example/z", accepts: [{ payTo: "0x" + "22".repeat(20) }], quality: {} }]);
  await saveIndex(b.build("2026-10-13"));
  const ch = { x402Version: 2, accepts: [{ scheme: "exact", network: "eip155:8453", amount: "1000", asset: "0x" + "11".repeat(20), payTo: "0x" + "22".repeat(20), maxTimeoutSeconds: 60 }] };
  const fetcher = async () => new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": btoa(JSON.stringify(ch)) } });
  const [code, envl]: any = await preflight("https://a.example/x?q=1", { resolver: async () => ["93.184.216.34"], fetcher });
  assertEquals(code, 200); assert(await verify(envl));
  const f = envl.facts; assertEquals(Object.keys(f).sort(), ["bazaar", "challenge", "checked_at", "disclaimer", "reachability", "schema", "target"]);
  assert(f.challenge.valid); assertEquals(f.reachability.http_status, 402);
  assertEquals(f.bazaar.host_listing_count, 1); assertEquals(f.bazaar.payout_wallet_reuse["0x" + "22".repeat(20)].hosts_using_wallet, 2);
  assertEquals(f.bazaar.payer_trend, [{ snapshot: "2026-10-13", payers30d: 4, calls30d: 8 }]);
  assertEquals(f.bazaar.last_called_at, "2026-10-13T00:00:00Z");
  const big = { ...b.build("2026-10-14"), resources: Object.fromEntries(Array.from({ length: 5000 }, (_, i) => [`https://h${i}.example/r`, { payers30d: i, calls30d: i, lastCalledAt: null, payTo: [] }])) };
  await saveIndex(big); clearIndexCache(); // multi-chunk round trip (> 64 KiB KV value limit)
  assertEquals(((await bazaarFacts("https://h4999.example/r", [])) as any).payer_trend.at(-1), { snapshot: "2026-10-14", payers30d: 4999, calls30d: 4999 });
});

const pad = (a: string) => "0x" + "0".repeat(24) + a.slice(2);
const rc = (frm: string, to: string, v: number, asset: string, status = "0x1") => ({ status, blockNumber: "0x10", logs: [{ address: asset, topics: [TRANSFER, pad(frm), pad(to)], data: "0x" + v.toString(16) }] });
Deno.test("paid flow: verify -> serve -> settle -> on-chain check -> same records; export with bearer", async () => {
  const W2 = "0x" + "02".repeat(20); const tx = "0x" + "cd".repeat(32);
  const r = reqFor("/base/network", env);
  const calls: string[] = [];
  const fac = async (p: string) => { calls.push(p); return p === "/verify" ? { isValid: true } : { success: true, payer: W2, transaction: tx, network: "eip155:8453" }; };
  const nonce = rnd(); const rcpt = rc(W2, r.payTo, 1000, r.asset); rcpt.logs.push({ address: r.asset, topics: [AUTH_USED, pad(W2), nonce], data: "0x" });
  const rpc = async (m: string) => m === "eth_getTransactionReceipt" ? rcpt
    : m === "eth_getBlockByNumber" ? { number: "0x10", timestamp: "0x" + Math.floor(Date.now() / 1000).toString(16), baseFeePerGas: "0x3b9aca00" } : "0x3b9aca00";
  let bg: Promise<unknown> | null = null;
  const res = await handler(new Request("http://h/base/network", { headers: { "PAYMENT-SIGNATURE": pay("/base/network", { from: W2 }, nonce) } }), { env, fac, rpc, background: (p) => { bg = p; } });
  assertEquals(res.status, 200); assertEquals(calls, ["/verify", "/settle"]);
  const body = await res.json(); assertEquals(body.chain_id, 8453); assertEquals(body.base_fee_gwei, 1);
  assert(res.headers.get("PAYMENT-RESPONSE")); await bg;
  const o = (await rows("outcomes.jsonl")).at(-1) as any;
  assertEquals([o.status, o.category, o.externalPayer, o.id], ["verified_success", "chain_reads", true, rid("out", tx, "/base/network")]);
  const ex = (await rows("executions.jsonl")).at(-1) as any;
  assertEquals(Object.keys(ex).sort(), ["adapter", "amount", "asset", "candidateRef", "category", "id", "network", "payTo", "payer", "protocolType", "receipt", "role", "route", "settledAt", "startedAt", "status", "tx", "verifiedAt"]);
  assertEquals((await rows("costs.jsonl")).at(-1)!.revenue, 0.001);
  // export
  for (const auth of ["", "Bearer wrong", TOKEN]) { const x = await handler(new Request("http://h/internal/export", { headers: { Authorization: auth } }), { env }); assertEquals(x.status, 401); await x.body?.cancel(); }
  const x = await (await handler(new Request("http://h/internal/export", { headers: { Authorization: "Bearer " + TOKEN } }), { env })).json();
  assertEquals(Object.keys(x.records).sort(), ["costs", "executions", "observations", "outcomes"]);
  assertEquals(x.records.executions.at(-1).tx, tx); assertEquals(x.payTo, r.payTo);
  const y = await (await handler(new Request("http://h/internal/export?since=2999-01-01", { headers: { Authorization: "Bearer " + TOKEN } }), { env })).json();
  assertEquals(y.records.executions.length, 0);
  const weak = await handler(new Request("http://h/internal/export", { headers: { Authorization: "Bearer short" } }), { env: (k) => k === "EXPORT_TOKEN" ? "short" : env(k) });
  assertEquals(weak.status, 401); await weak.body?.cancel();
});
Deno.test("not charged on bad input or upstream error; invalid payment -> 402", async () => {
  const calls: string[] = []; const fac = async (p: string) => { calls.push(p); return { isValid: true }; };
  let r = await handler(new Request("http://h/base/usdc-balance?address=0xbad", { headers: { "X-PAYMENT": pay("/base/usdc-balance") } }), { env, fac });
  assertEquals(r.status, 400); await r.body?.cancel(); assertEquals(calls, ["/verify"]);
  r = await handler(new Request("http://h/base/network", { headers: { "X-PAYMENT": pay() } }), { env, fac, rpc: () => Promise.reject(new Error("down")) });
  assertEquals(r.status, 502); await r.body?.cancel(); assert(!calls.includes("/settle"));
  r = await handler(new Request("http://h/base/network", { headers: { "X-PAYMENT": pay() } }), { env, fac: async () => ({ isValid: false, invalidReason: "insufficient_funds" }) });
  assertEquals(r.status, 402); assertEquals(await r.json(), { error: "insufficient_funds" });
  r = await handler(new Request("http://h/base/network", { headers: { "X-PAYMENT": "%%%" } }), { env }); assertEquals(r.status, 400); await r.body?.cancel();
  r = await handler(new Request("http://h/nope"), { env }); assertEquals(r.status, 404); await r.body?.cancel();
});
Deno.test("on-chain check and outcome statuses match Python rules", async () => {
  const req = reqFor("/x402/preflight", env); const W = "0x" + "02".repeat(20), ME = "0x" + "77".repeat(20); const noSleep = async () => {};
  const f = (x: unknown) => verifyOnchain(async () => x, "0x" + "ab".repeat(32), req.asset, req.payTo, "1000", W, "eip155:8453", 4, 0, noSleep);
  assertEquals((await f(rc(W, req.payTo, 999, req.asset))).reason, "no_matching_usdc_transfer");
  assertEquals((await f(rc(W, "0x" + "01".repeat(20), 1000, req.asset))).reason, "no_matching_usdc_transfer");
  assertEquals((await f(rc(W, req.payTo, 1000, req.asset, "0x0"))).reason, "tx_reverted");
  assertEquals((await f(null)).settled, null);
  const self = await recordSale("/x402/preflight", req, { success: true, payer: ME, transaction: "0x" + "ee".repeat(32) }, ["a", "b", "c"],
    await verifyOnchain(async () => rc(ME, req.payTo, 1000, req.asset), "0x" + "ee".repeat(32), req.asset, req.payTo, "1000", ME), true, env) as any;
  assertEquals([self.status, self.reason, self.category], ["excluded", "self_payer", "endpoint_check"]);
  const inc = await recordSale("/base/network", req, { success: true, payer: W, transaction: "0x" + "ab".repeat(32) }, ["a", "b", "c"], await f(null), true, env) as any;
  assertEquals(inc.status, "inconclusive");
});
Deno.test("pyDumps matches Python spacing", () => { assertEquals(pyDumps({ a: [1, "x"], b: { c: null } }), '{"a": [1, "x"], "b": {"c": null}}'); });

Deno.test("bazaar block: info + schema for every route, real descriptions and output examples", () => {
  for (const k of Object.keys(ROUTES)) {
    const b = bazaar(k) as any;
    assertEquals(Object.keys(b).sort(), ["info", "schema"]);
    assertEquals([b.info.input.type, b.info.input.method, b.info.output.type], ["http", "GET", "json"], k);
    assert(Object.keys(b.info.output.example).length > 0, k);
    assertEquals(b.schema.properties.input.required, ["type", "method"]);
    for (const [, s] of Object.entries(b.schema.properties.input.properties.queryParams?.properties ?? {})) assert(((s as any).description ?? "").length > 15, k);
    assert(!JSON.stringify(b).includes("example.com"), k);
  }
});
Deno.test("CDP JWT byte-identical to Python for the same throwaway key, time and nonce", async () => {
  const v = C.cdp_jwt;
  assertEquals(await cdpJwt(v.key_id, v.secret, "POST", "api.cdp.coinbase.com", "/platform/v2/x402/settle", v.now, v.nonce), v.jwt);
  const [h, c] = v.jwt.split(".").slice(0, 2).map((x: string) => JSON.parse(atob(x.replace(/-/g, "+").replace(/_/g, "/"))));
  assertEquals(h, { alg: "EdDSA", kid: v.key_id, typ: "JWT", nonce: v.nonce });
  assertEquals(c, { sub: v.key_id, iss: "cdp", nbf: v.now, exp: v.now + 120, uris: ["POST api.cdp.coinbase.com/platform/v2/x402/settle"] });
});
Deno.test("CDP auth only when FACILITATOR is CDP AND keys are set; PayAI request unchanged", async () => {
  const keys: Record<string, string> = { CDP_API_KEY_ID: C.cdp_jwt.key_id, CDP_API_KEY_SECRET: C.cdp_jwt.secret };
  const ke = (k: string) => keys[k]; const none = (_: string) => undefined;
  const CDP = "https://api.cdp.coinbase.com/platform/v2/x402";
  assertEquals(await cdpHeaders("https://facilitator.payai.network", "/settle", ke), {});
  assertEquals(await cdpHeaders(CDP, "/settle", none), {});
  assertEquals(await cdpHeaders("https://api.cdp.coinbase.com.evil.example/x", "/settle", ke), {});
  const seen: { url: string; h: Headers }[] = [];
  const f = ((u: string, init: RequestInit) => { seen.push({ url: u, h: new Headers(init.headers) });
    return Promise.resolve(new Response(JSON.stringify({ success: true, transaction: "0x" + "ab".repeat(32), payer: "0x1", network: "eip155:8453" }))); }) as unknown as typeof fetch;
  const st = await facClient("https://facilitator.payai.network", ke, f)("/settle", { x: 1 });
  assertEquals([seen[0].url, seen[0].h.get("Authorization")], ["https://facilitator.payai.network/settle", null]);
  assertEquals(st.transaction, "0x" + "ab".repeat(32)); // CDP settle response uses the same fields (success, transaction, payer, network)
  await facClient(CDP, ke, f)("/settle", { x: 1 });
  assertEquals(seen[1].url, CDP + "/settle"); assert(seen[1].h.get("Authorization")!.startsWith("Bearer ey"));
});

// ---- settle hardening (SECURITY.md) ----
const PAYER = "0x" + "a1".repeat(20);
const rnd = () => "0x" + Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
function pay(path = "/base/network", over: Record<string, string> = {}, nonce = rnd()) {
  const r = reqFor(path, env); const now = Math.floor(Date.now() / 1000);
  const a = { from: PAYER, to: r.payTo, value: r.amount, validAfter: String(now - 5), validBefore: String(now + 300), nonce, ...over };
  return btoa(JSON.stringify({ x402Version: 2, accepted: r, payload: { authorization: a, signature: "0x" + "11".repeat(65) } }));
}
function rig(chain: { v: any }, settle?: () => any, delay = 0) {
  const calls: string[] = []; let tx = rnd();
  const fac = async (p: string) => { calls.push(p); if (delay) await new Promise((r) => setTimeout(r, delay));
    return p === "/verify" ? { isValid: true } : (settle ? settle() : { success: true, transaction: tx, payer: PAYER, network: "eip155:8453" }); };
  const rpc = async (m: string) => m === "eth_getBlockByNumber" ? { number: "0x10", timestamp: "0x" + Math.floor(Date.now() / 1000).toString(16), baseFeePerGas: "0x1" } : "0x1";
  const call = async (sig: string, path = "/base/network") => {
    const res = await handler(new Request("http://h" + path, { headers: { "PAYMENT-SIGNATURE": sig } }), { env, fac, rpc, check: async () => chain.v, background: () => {} });
    return [res.status, await res.json()] as [number, any];
  };
  return { calls, call, newTx: () => { tx = rnd(); } };
}
Deno.test("serve only after on-chain confirmation; facilitator success alone never serves", async () => {
  await resetGuards();
  for (const v of [{ settled: false, reason: "nonce_not_in_settlement_tx" }, { settled: null }]) {
    const t = rig({ v }); const [code] = await t.call(pay()); assert(code !== 200, JSON.stringify(v));
  }
  const ok = rig({ v: { settled: true } }); const [c, b] = await ok.call(pay()); assertEquals([c, b.chain_id], [200, 8453]);
});
Deno.test("pending confirmation parks the payment and the same request is served exactly once later", async () => {
  await resetGuards(); const chain = { v: { settled: null } as any }; const t = rig(chain); const sig = pay();
  assertEquals((await t.call(sig))[0], 202); assertEquals((await t.call(sig))[0], 202);
  chain.v = { settled: true }; assertEquals((await t.call(sig))[0], 200); assertEquals((await t.call(sig))[0], 409);
  assertEquals(t.calls.filter((x) => x === "/settle").length, 1);
});
Deno.test("duplicate signature: concurrent requests race on KV atomic check-and-set, exactly one wins", async () => {
  await resetGuards(); const t = rig({ v: { settled: true } }, undefined, 20); const sig = pay();
  const codes = (await Promise.all(Array.from({ length: 8 }, () => t.call(sig)))).map((x) => x[0]).sort();
  assertEquals(codes, [200, 409, 409, 409, 409, 409, 409, 409]); assertEquals(t.calls.filter((x) => x === "/settle").length, 1);
  assertEquals((await t.call(sig))[0], 409); // and later, consistently
});
Deno.test("prechecks before any facilitator call; settlement tx reuse; failed settle cooldown", async () => {
  await resetGuards(); const now = Math.floor(Date.now() / 1000); const t = rig({ v: { settled: true } });
  for (const [over, why] of [[{ validBefore: String(now + 2) }, "authorization_expired_or_expiring"], [{ validAfter: String(now + 60) }, "authorization_not_yet_valid"],
    [{ to: "0x" + "99".repeat(20) }, "authorization_payee_mismatch"], [{ value: "1" }, "authorization_amount_mismatch"]] as [Record<string, string>, string][]) {
    const [c, b] = await t.call(pay("/base/network", over)); assertEquals([c, b.error], [402, why]);
  }
  assertEquals(t.calls, []);
  assertEquals((await t.call("x".repeat(20000)))[0], 400);
  const fixed = rnd(); const u = rig({ v: { settled: true } }, () => ({ success: true, transaction: fixed, payer: PAYER }));
  assertEquals((await u.call(pay()))[0], 200); assertEquals(await u.call(pay()), [409, { error: "settlement transaction already used" }]);
  const f = rig({ v: { settled: false } }, () => ({ success: false, errorReason: "insufficient_funds" }));
  for (let i = 0; i < 3; i++) assertEquals((await f.call(pay()))[0], 402);
  assertEquals((await f.call(pay()))[0], 429);
});
Deno.test("on-chain check binds the EIP-3009 nonce (AuthorizationUsed in the same receipt)", async () => {
  const r = reqFor("/base/network", env); const n = "0x" + "4e".repeat(32); const pad = (a: string) => "0x" + "0".repeat(24) + a.slice(2).toLowerCase();
  const rcpt = (nt: string | null) => ({ status: "0x1", blockNumber: "0x5", logs: [{ address: r.asset, topics: [TRANSFER, pad(PAYER), pad(r.payTo)], data: "0x3e8" },
    ...(nt ? [{ address: r.asset, topics: [AUTH_USED, pad(PAYER), nt], data: "0x" }] : [])] });
  const f = (x: unknown, nonce: string | null) => verifyOnchain(async () => x, "0x" + "ab".repeat(32), r.asset, r.payTo, r.amount, PAYER, "eip155:8453", 1, 0, async () => {}, nonce) as Promise<any>;
  assertEquals((await f(rcpt(n), n)).nonceBound, true);
  assertEquals((await f(rcpt("0x" + "11".repeat(32)), n)).reason, "nonce_not_in_settlement_tx");
  assertEquals((await f(rcpt(null), n)).reason, "nonce_not_in_settlement_tx");
  assertEquals((await f(rcpt(null), null)).settled, true);
});
Deno.test("Host header cannot inject the challenge resource URL", () => {
  const e = (k: string) => k === "PUBLIC_URL" ? undefined : env(k);
  assertEquals(required("/base/network", "evil.example/x?y", e).resource.url, "https://invalid-host/base/network");
  assertEquals(required("/base/network", "h.example:8443", e).resource.url, "https://h.example:8443/base/network");
});
Deno.test("well-known, key history, fingerprints, signed snapshot metadata, facilitator in root", async () => {
  resetKey();
  const w: any = await wellKnown(env); assertEquals([w.alg, w.fingerprint_short.replaceAll(" ", "")], ["Ed25519", w.key_id]);
  assert(w.fingerprint.startsWith("SHA256:")); assertEquals(w.facilitator, root(env).facilitator); assertEquals(root(env).facilitator.name, "PayAI");
  const cdp = (k: string) => k === "FACILITATOR" ? "https://api.cdp.coinbase.com/platform/v2/x402" : env(k);
  assertEquals(root(cdp).facilitator, { name: "CDP", url: "https://api.cdp.coinbase.com/platform/v2/x402", auth: "none" });
  const hist = (k: string) => k === "SIGNING_KEY_HISTORY" ? JSON.stringify([{ public_key_b64: btoa("\x01".repeat(32)), created_at: "2026-10-01", retired_at: "2026-10-14" }, { public_key_b64: "bad" }])
    : k === "SIGNING_KEY_CREATED_AT" ? "2026-10-14T11:00:00Z" : env(k);
  const h: any = await keyHistory(hist);
  assertEquals([h.current.status, h.current.created_at, h.retired.length, h.retired[0].status], ["active", "2026-10-14T11:00:00Z", 1, "retired"]);
  const m: any = await snapshotMeta(); assertEquals(Object.keys(m.metadata).sort(), ["covered_listings", "last_updated", "started_at", "total_snapshots", "version"]);
  assertEquals(m.pubkey_url, "/x402/preflight/pubkey"); assert(await verify({ facts: m.metadata, signature: m.signature }));
  for (const p of ["/.well-known/x402-preflight", "/.well-known/bazaar-snapshot.json", "/.well-known/x402-preflight-key-history.json", "/bazaar/snapshots"]) {
    const res = await handler(new Request("http://h" + p), { env }); assertEquals(res.status, 200, p); await res.body?.cancel();
  }
});

Deno.test("Permit2 and non-EIP-3009 payloads rejected before the facilitator", async () => {
  await resetGuards(); const chain = { v: { settled: true } }; const t = rig(chain);
  const r = reqFor("/base/network", env);
  const p2 = { x402Version: 2, accepted: r, payload: { permit2Authorization: { from: PAYER, nonce: "1" }, signature: "0x" } };
  const viaExtra = { x402Version: 2, accepted: { ...r, extra: { ...r.extra, assetTransferMethod: "permit2" } }, payload: { authorization: {} } };
  for (const [body, why] of [[p2, "permit2_not_supported"], [viaExtra, "permit2_not_supported"], [{ x402Version: 2, payload: { signature: "0x" } }, "eip3009_authorization_required"]] as const) {
    const [c, out] = await t.call(btoa(JSON.stringify(body)));
    assertEquals(c, 402); assert(String(out.error).startsWith(why), out.error);
  }
  assertEquals(t.calls, []);
});
Deno.test("FailLimiter state lives in KV: shared by separate instances, atomic under concurrency", async () => {
  const a = new SG.FailLimiter(3, 60_000), b = new SG.FailLimiter(3, 60_000); await a.clear();
  const who = "0x" + "aa".repeat(20);
  await Promise.all([a.fail(who), b.fail(who), a.fail(who)]); // concurrent writers, no lost update
  assert(await b.blocked(who)); assert(!(await b.blocked("0x" + "bb".repeat(20))));
  assert(!(await b.blocked(who, Date.now() + 61_000))); // window expiry
  await a.clear(); assert(!(await b.blocked(who)));
});
Deno.test("used settlement tx hashes are stored durably in KV (atomic, no expiry)", async () => {
  const tx = rnd(); const [x, y] = await Promise.all([SG.claimTx(tx), SG.claimTx(tx)]);
  assertEquals([x, y].sort(), [false, true]); assertEquals(await SG.claimTx(tx), false);
});
