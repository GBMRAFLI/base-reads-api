import { assert, assertEquals } from "jsr:@std/assert@1";
import { useKv } from "../lib/store.ts";
import { bazaar, extensionStatus, facClient, handler, logBazaar, MAX_EXTENSIONS_BYTES, reqFor, required, resetGuards, withDiscovery } from "../main.ts";

const P = JSON.parse(Deno.readTextFileSync(new URL("./fixtures/py_signed.json", import.meta.url)));
useKv(await Deno.openKv(":memory:"));
const ENV: Record<string, string> = { SIGNING_KEY_PASSPHRASE: P.passphrase, SIGNING_KEY_ENC_B64: P.enc_b64, PUBLIC_URL: "https://api.example" };
const env = (k: string) => ENV[k];
const PAYER = "0x" + "a1".repeat(20);
const rnd = () => "0x" + Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
function payload(path = "/base/network", extra: Record<string, unknown> = {}): Record<string, any> {
  const r = reqFor(path, env); const now = Math.floor(Date.now() / 1000);
  const a = { from: PAYER, to: r.payTo, value: r.amount, validAfter: String(now - 5), validBefore: String(now + 300), nonce: rnd() };
  return { x402Version: 2, accepted: r, payload: { authorization: a, signature: "0x" + "11".repeat(65) }, ...extra };
}
const b64 = (o: unknown) => btoa(JSON.stringify(o));
const rpc = (async (m: string) => m === "eth_getBlockByNumber" ? { number: "0x10", timestamp: "0x" + Math.floor(Date.now() / 1000).toString(16), baseFeePerGas: "0x1" } : "0x1") as any;
function capture() {
  const bodies: { p: string; body: any }[] = [];
  const fac = async (p: string, body: unknown) => { bodies.push({ p, body: structuredClone(body) }); return p === "/verify" ? { isValid: true } : { success: false, errorReason: "unexpected_settle_error" }; };
  return { bodies, fac };
}

Deno.test("withDiscovery fills resource and bazaar from the server's 402 challenge", () => {
  const pl = payload(); const out = withDiscovery(pl, "/base/network", "h", env); const pr = required("/base/network", "h", env);
  assertEquals(out.resource, pr.resource); assertEquals(out.extensions, { bazaar: bazaar("/base/network") });
  assertEquals(out.resource.url, "https://api.example/base/network");
});
Deno.test("withDiscovery overwrites client resource/bazaar and discards other client extensions", () => {
  const pl = payload("/base/network", { resource: { url: "https://evil.example/x" }, extensions: { bazaar: { info: "fake" }, other: { a: 1 } } });
  const out = withDiscovery(pl, "/base/network", "h", env);
  assertEquals(out.resource.url, "https://api.example/base/network");
  assertEquals(out.extensions, { bazaar: bazaar("/base/network") });
  assertEquals(pl.resource, { url: "https://evil.example/x" }); // input not mutated
});
Deno.test("withDiscovery leaves the signed authorization, signature and accepted block untouched", () => {
  const pl = payload(); const before = JSON.stringify({ a: pl.accepted, p: pl.payload });
  const out = withDiscovery(pl, "/base/network", "h", env);
  assertEquals(JSON.stringify({ a: out.accepted, p: out.payload }), before); assertEquals(out.x402Version, 2);
});
Deno.test("facilitator gets injected payload on verify and settle; requirements are the server's", async () => {
  await resetGuards(); const { bodies, fac } = capture();
  const pl = payload("/base/network", { extensions: { bazaar: { info: "fake" } } });
  const r = await handler(new Request("https://api.example/base/network", { headers: { "PAYMENT-SIGNATURE": b64(pl) } }),
    { env, fac, rpc, check: async () => ({ settled: false, reason: "x" }), background: () => {} });
  await r.body?.cancel();
  assertEquals(bodies.map((b) => b.p), ["/verify", "/settle"]); // order unchanged
  for (const { body } of bodies) {
    assertEquals(body.paymentPayload.extensions, { bazaar: bazaar("/base/network") });
    assertEquals(body.paymentPayload.resource.url, "https://api.example/base/network");
    assertEquals(body.paymentPayload.payload, pl.payload);
    assertEquals(body.paymentRequirements, reqFor("/base/network", env));
  }
});
Deno.test("replay claim unchanged: same authorization with different extensions is refused the second time", async () => {
  await resetGuards(); const { bodies, fac } = capture(); const pl = payload();
  const deps = { env, fac, rpc, check: async () => ({ settled: false, reason: "x" }), background: () => {} };
  const r1 = await handler(new Request("https://api.example/base/network", { headers: { "PAYMENT-SIGNATURE": b64(pl) } }), deps); await r1.body?.cancel();
  const r2 = await handler(new Request("https://api.example/base/network", { headers: { "PAYMENT-SIGNATURE": b64({ ...pl, extensions: { x: 1 } }) } }), deps); await r2.body?.cancel();
  assert(r2.status === 402 || r2.status === 409, String(r2.status));
  assertEquals(bodies.filter((b) => b.p === "/settle").length, 1);
});
Deno.test("oversized client extensions are refused before any facilitator call", async () => {
  await resetGuards(); const { bodies, fac } = capture();
  const pl = payload("/base/network", { extensions: { pad: "x".repeat(MAX_EXTENSIONS_BYTES + 1) } });
  const r = await handler(new Request("https://api.example/base/network", { headers: { "PAYMENT-SIGNATURE": b64(pl) } }), { env, fac });
  assertEquals(r.status, 400); await r.body?.cancel(); assertEquals(bodies.length, 0);
});
Deno.test("EXTENSION-RESPONSES is decoded and attached non-enumerably", async () => {
  const hdr = btoa(JSON.stringify({ bazaar: { status: "processing" } }));
  const f = (async () => new Response(JSON.stringify({ isValid: true }), { headers: { "EXTENSION-RESPONSES": hdr } })) as typeof fetch;
  const out = await facClient("https://fac.example", env, f)("/verify", {});
  assertEquals(out.extensionResponses.bazaar.status, "processing"); assertEquals(Object.keys(out), ["isValid"]);
  assertEquals(extensionStatus("!!notbase64"), null); assertEquals(extensionStatus(null), null);
});
Deno.test("bazaar log line carries only status and a truncated, scrubbed reason", () => {
  const lines: string[] = []; const orig = console.log; console.log = (m: string) => lines.push(m);
  try {
    const res: any = {}; Object.defineProperty(res, "extensionResponses", { value: { bazaar: { status: "rejected", rejectedReason: "bad sig 0x" + "ab".repeat(65) + " \n" + "y".repeat(500), authorization: { nonce: "0x1" } } } });
    logBazaar("verify", "/base/network", res); logBazaar("verify", "/base/network", {});
  } finally { console.log = orig; }
  assertEquals(lines.length, 1); const l = lines[0];
  assert(l.startsWith("bazaar extension verify /base/network: rejected reason=bad sig 0x…"), l);
  assert(!l.includes("abab") && !l.includes("nonce") && !l.includes("\n") && l.length < 280, l);
});
Deno.test("L2 mainnet (incl. empty NETWORK=) never derives resource.url from Host; startup check refuses without PUBLIC_URL", async () => {
  const { publicUrlError } = await import("../main.ts");
  for (const net of [undefined, "", "eip155:8453"]) {
    const e = (k: string) => k === "PUBLIC_URL" ? undefined : k === "NETWORK" ? net : env(k);
    assert(publicUrlError(e)); let threw = false;
    try { required("/base/network", "evil.example", e); } catch { threw = true; }
    assert(threw, "required() must not fall back to Host on mainnet");
    const r = await handler(new Request("https://evil.example/base/network"), { env: e });
    assertEquals(r.status, 503); assert(!(await r.text()).includes("evil.example"));
  }
  assertEquals(publicUrlError(env), null);
  assertEquals(required("/base/network", "evil.example", env).resource.url, "https://api.example/base/network");
  const t = (k: string) => k === "PUBLIC_URL" ? undefined : k === "NETWORK" ? "eip155:84532" : env(k);
  assertEquals(publicUrlError(t), null);
});
Deno.test("L1 bazaar status is scrubbed to printable ASCII and truncated", () => {
  const lines: string[] = []; const orig = console.log; console.log = (m: string) => lines.push(m);
  try { const res: any = {}; Object.defineProperty(res, "extensionResponses", { value: { bazaar: { status: "ok\n\u001b[31mFAKE LINE " + "z".repeat(100) } } }); logBazaar("settle", "/base/network", res); }
  finally { console.log = orig; }
  assertEquals(lines.length, 1); const l = lines[0];
  assert(!/[^\x20-\x7e]/.test(l), l); assert(l.length <= "bazaar extension settle /base/network: ".length + 32, l);
});
