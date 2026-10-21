// Pre-pay Check Attestation v1.0. Every key here is an ephemeral Ed25519 key generated in memory per test run.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { attest, BASE_USDC, buildChecks, jcs, paytoCode, signingBytes, verifyAttestation, type Signer } from "../lib/attestation.ts";
import { verify as officialVerify } from "../../scripts/verify_attestation.ts";
import { preflight } from "../lib/preflight.ts";
import { verifyJcs } from "../lib/sign.ts";
import { handler, snapshotMeta } from "../main.ts";
import { useKv } from "../lib/store.ts";

const V = JSON.parse(Deno.readTextFileSync(new URL("../../spec/test-vectors.json", import.meta.url)));
const SCHEMA = JSON.parse(Deno.readTextFileSync(new URL("../../spec/prepay-check-attestation-v1.schema.json", import.meta.url)));
const b64e = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
async function ephemeral(): Promise<{ signer: Signer; pubB64: string; issuer: any }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)); const keyId = hex(await crypto.subtle.digest("SHA-256", raw)).slice(0, 16);
  return { pubB64: b64e(raw), issuer: { keys: [{ alg: "Ed25519", key_id: keyId, public_key_b64: b64e(raw), status: "active" }] },
    signer: { keyId, sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, m as Uint8Array<ArrayBuffer>)) } };
}
const ACC = { scheme: "exact", network: "eip155:8453", amount: "10000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: "0x" + "22".repeat(20) };
const facts = (over: Record<string, unknown> = {}) => ({ schema: "prepay-check/v1", target: "https://a.example/x", checked_at: "2026-10-21T05:00:00Z", disclaimer: "d",
  reachability: { reachable: true, http_status: 402, latency_ms: 5 }, challenge: { valid: true, problems: [], accepts: [ACC] }, bazaar: { available: true, snapshot_date: "2026-10-20", listed: true }, ...over });
const NOW = Date.parse("2026-10-21T05:00:00Z");
// Legacy {facts, signature} still uses the repo's pre-existing throwaway test key (fixtures/py_signed.json); attestations use ephemeral keys.
const P = JSON.parse(Deno.readTextFileSync(new URL("./fixtures/py_signed.json", import.meta.url)));
const E: Record<string, string> = { SIGNING_KEY_PASSPHRASE: P.passphrase, SIGNING_KEY_ENC_B64: P.enc_b64, PUBLIC_URL: "https://h.example/" };
const env = (x: string) => E[x];

Deno.test("JCS vectors match Python rfc8785 byte for byte", () => {
  for (const c of V.jcs) assertEquals(jcs(c.input), c.canonical);
  assertEquals(new TextDecoder().decode(signingBytes(V.signed.attestation)), V.signed.signing_bytes_utf8);
});
Deno.test("Python-signed vector verifies in Deno (library and official script)", async () => {
  assertEquals((await verifyAttestation(V.signed.attestation, V.signed.public_key_b64, null)).ok, true);
  assertEquals((await officialVerify(V.signed.attestation, V.signed.issuer, NOW))[0], true);
  assertEquals((await officialVerify(V.signed.attestation, V.signed.issuer, NOW + 3600_000))[1], "expired at 2026-10-21T05:15:00Z");
});
Deno.test("envelope shape, TTL, signature, tamper and expiry", async () => {
  const k = await ephemeral(); const rpc = async () => "0x";
  const e: any = await attest(facts(), { signer: k.signer, rpc, now: NOW, ttlS: 600, issuerUrl: "https://i.example/.well-known/issuer.json" });
  assertEquals(Object.keys(e).sort(), ["attestation_id", "canonicalization", "claims", "expires_at", "issued_at", "issuer", "signature", "spec", "subject", "version"]);
  assertEquals([e.spec, e.version, e.canonicalization, e.issued_at, e.expires_at], ["prepay-check-attestation", "1.0", "JCS", "2026-10-21T05:00:00Z", "2026-10-21T05:10:00Z"]);
  assertEquals(e.issuer, { name: "Base Reads Pre-pay Check", key_id: k.signer.keyId, issuer_url: "https://i.example/.well-known/issuer.json", contact: "gbmrafli@agentmail.to" });
  assertEquals(e.subject, { type: "x402_endpoint", url: "https://a.example/x" });
  assertEquals(Object.keys(e.signature).sort(), ["alg", "key_id", "value_b64"]);
  assert((await verifyAttestation(e, k.pubB64, NOW)).ok);
  assertEquals((await verifyAttestation(e, k.pubB64, NOW + 601_000)).reason, "expired");
  const t = structuredClone(e); t.claims.checks_failed.push("x"); assertEquals((await verifyAttestation(t, k.pubB64, NOW)).reason, "bad_signature");
  const t2 = structuredClone(e); t2.expires_at = "2030-01-01T00:00:00Z"; assertEquals((await verifyAttestation(t2, k.pubB64, NOW)).reason, "bad_signature");
  assertEquals((await attest(facts(), { signer: k.signer, now: NOW, ttlS: 10 ** 9 }) as any).expires_at, "2026-10-22T05:00:00Z"); // capped at 24h
  assertEquals((await attest(facts(), { signer: k.signer, now: NOW }) as any).expires_at, "2026-10-21T05:15:00Z"); // default 900 s
  const s = JSON.stringify(e).toLowerCase(); for (const w of ["verdict", "score", "recommend", "safe", "trust"]) assert(!s.includes(w), w);
});
Deno.test("checks: raw facts, pass/fail/not_applicable, no verdict", async () => {
  const st = (f: any, code: any) => Object.fromEntries(buildChecks(f, code).map((c) => [c.id, c.status]));
  const eoa = [{ address: ACC.payTo, kind: "eoa" as const, code_bytes: 0 }];
  assertEquals(st(facts(), eoa), { endpoint_reachable: "pass", http_402_returned: "pass", challenge_well_formed: "pass", network_is_base: "pass", asset_is_base_usdc: "pass", payto_is_eoa: "pass", bazaar_snapshot_available: "pass", listed_in_bazaar: "pass" });
  const bad = facts({ challenge: { valid: true, problems: [], accepts: [{ ...ACC, network: "eip155:1", asset: "0x" + "11".repeat(20) }] } });
  const r = buildChecks(bad, [{ address: ACC.payTo, kind: "contract", code_bytes: 23 }]);
  assertEquals(r.find((c) => c.id === "network_is_base"), { id: "network_is_base", status: "fail", observed: ["eip155:1"], expected: "eip155:8453" });
  assertEquals(r.find((c) => c.id === "asset_is_base_usdc"), { id: "asset_is_base_usdc", status: "fail", observed: ["0x" + "11".repeat(20)], expected: BASE_USDC });
  assertEquals(r.find((c) => c.id === "payto_is_eoa")!.status, "fail");
  const down = facts({ reachability: { reachable: false, error_class: "TimeoutError" }, challenge: { valid: false, problems: ["no_402_challenge"], accepts: [] }, bazaar: { available: false, reason: "no_snapshot" } });
  assertEquals(st(down, []), { endpoint_reachable: "fail", http_402_returned: "not_applicable", challenge_well_formed: "fail", network_is_base: "not_applicable", asset_is_base_usdc: "not_applicable", payto_is_eoa: "not_applicable", bazaar_snapshot_available: "fail", listed_in_bazaar: "not_applicable" });
  assertEquals(st(facts({ bazaar: { available: true, listed: null } }), [{ address: ACC.payTo, kind: null, code_bytes: null }]).payto_is_eoa, "not_applicable");
  const e: any = await attest(bad, { signer: (await ephemeral()).signer, rpc: async () => "0x6080", now: NOW });
  assertEquals(e.claims.checks_passed, ["endpoint_reachable", "http_402_returned", "challenge_well_formed", "bazaar_snapshot_available", "listed_in_bazaar"]);
  assertEquals(e.claims.checks_failed, ["network_is_base", "asset_is_base_usdc", "payto_is_eoa"]);
  for (const c of e.claims.checks) assert(SCHEMA.properties.claims.properties.checks.items.properties.id.enum.includes(c.id));
});
Deno.test("payTo eth_getCode: dedup, cap 4, rpc errors -> null, no rpc -> null", async () => {
  const calls: string[] = []; const rpc = async (_m: string, p: unknown[]) => { calls.push(p[0] as string); if ((p[0] as string).endsWith("33")) throw new Error("x"); return (p[0] as string).endsWith("44") ? "0xfe" : "0x"; };
  const addrs = ["0x" + "22".repeat(20), "0x" + "22".repeat(20).toUpperCase().replace("0X", "0x"), "0x" + "33".repeat(20), "0x" + "44".repeat(20), "0x" + "55".repeat(20), "0x" + "66".repeat(20), "bad"];
  const r = await paytoCode(addrs, rpc);
  assertEquals(r.map((x) => x.kind), ["eoa", null, "contract", "eoa"]); assertEquals(calls.length, 4); assertEquals(r[2].code_bytes, 1);
  assertEquals((await paytoCode([ACC.payTo]))[0].kind, null);
});
Deno.test("Deno-signed attestation verifies with the official Python script", async () => {
  const k = await ephemeral(); const e = await attest(facts(), { signer: k.signer, rpc: async () => "0x", now: Date.now() });
  const d = await Deno.makeTempDir(); await Deno.writeTextFile(d + "/a.json", JSON.stringify({ attestation: e })); await Deno.writeTextFile(d + "/i.json", JSON.stringify(k.issuer));
  const run = async (f: string) => (await new Deno.Command("python3", { args: [new URL("../../scripts/verify_attestation.py", import.meta.url).pathname, f, "--issuer", d + "/i.json"], stdout: "piped" }).output()).code;
  assertEquals(await run(d + "/a.json"), 0);
  (e as any).claims.facts.target = "https://evil.example/"; await Deno.writeTextFile(d + "/b.json", JSON.stringify(e)); assertEquals(await run(d + "/b.json"), 1);
  await Deno.remove(d, { recursive: true });
});
Deno.test("preflight returns legacy {facts, signature} plus the v1.0 attestation over the same facts", async () => {
  useKv(await Deno.openKv(":memory:"));
  const k = await ephemeral(); const ch = { x402Version: 2, accepts: [{ ...ACC, maxTimeoutSeconds: 60 }] };
  const fetcher = async () => new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": btoa(JSON.stringify(ch)) } });
  const [code, body]: any = await preflight("https://a.example/x", { resolver: async () => ["93.184.216.34"], fetcher, signer: k.signer, rpc: async () => "0x", now: NOW, ttlS: 300, env });
  assertEquals(code, 200); assert(body.facts && body.signature && body.attestation);
  assertEquals(body.attestation.claims.facts, body.facts);
  assert((await verifyAttestation(body.attestation, k.pubB64, NOW)).ok);
  assertEquals(body.attestation.claims.payto_code, [{ address: ACC.payTo, kind: "eoa", code_bytes: 0 }]);
});
Deno.test("issuer.json, schema endpoint, JCS-signed snapshot metadata", async () => {
  useKv(await Deno.openKv(":memory:"));
  const iss = await (await handler(new Request("http://h.example/.well-known/issuer.json"), { env })).json();
  assertEquals([iss.spec, iss.version, iss.canonicalization, iss.issuer.contact, iss.issuer.issuer_url, iss.keys[0].status], ["prepay-check-attestation", "1.0", "JCS", "gbmrafli@agentmail.to", "https://h.example/.well-known/issuer.json", "active"]);
  assert(!JSON.stringify(iss).toLowerCase().includes("private"));
  const sc = await handler(new Request("http://h.example/.well-known/prepay-check-attestation-v1.schema.json"), { env });
  assertEquals(sc.status, 200); assertEquals(await sc.json(), SCHEMA);
  const m = await snapshotMeta(env); assertEquals(m.signature.canonicalization, "JCS"); assert(await verifyJcs(m.metadata, m.signature));
});
