// Attack scenarios A1-A12 for the paid Pre-pay Check, plus outbound limits. Keys: repo throwaway test key (legacy
// signature) and in-memory ephemeral keys; nothing here touches the network (resolver/fetcher/rpc/facilitator are stubs).
import { assert, assertEquals } from "jsr:@std/assert@1";
import { abuse, handler, pendingSweep, reorgSweep, reqFor, resetGuards, snapshotMeta } from "../main.ts";
import { sweepReorg, scheduleReorgCheck } from "../lib/reorg.ts";
import * as SG from "../lib/settle_guard.ts";
import { useKv, rows, kv } from "../lib/store.ts";
import { clearIndexCache, configureOutbound, IndexAssembler, OUTBOUND, preflight, readSnapMeta, saveIndex } from "../lib/preflight.ts";
import { attest, verifyAttestation, type Signer } from "../lib/attestation.ts";
import { verify as officialVerify, verifySnapshotBinding } from "../../scripts/verify_attestation.ts";
import { Semaphore, WindowLimiter } from "../lib/guards.ts";

useKv(await Deno.openKv(":memory:"));
const P = JSON.parse(Deno.readTextFileSync(new URL("./fixtures/py_signed.json", import.meta.url)));
const BASE_ENV: Record<string, string> = { SIGNING_KEY_PASSPHRASE: P.passphrase, SIGNING_KEY_ENC_B64: P.enc_b64, PUBLIC_URL: "https://h.example", SELF_WALLETS: "0x" + "77".repeat(20), LEDGER_MEMORY_OK: "1", NETWORK: "eip155:84532" };
let E: Record<string, string> = { ...BASE_ENV }; const env = (k: string) => E[k];
const PAYER = "0x" + "a1".repeat(20); const PATH = "/x402/preflight";
const rnd = () => "0x" + Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
function pay(acceptedOver: Record<string, string> = {}, nonce = rnd()) {
  const r = reqFor(PATH, env); const now = Math.floor(Date.now() / 1000);
  const a = { from: PAYER, to: r.payTo, value: r.amount, validAfter: String(now - 5), validBefore: String(now + 300), nonce };
  return btoa(JSON.stringify({ x402Version: 2, accepted: { ...r, ...acceptedOver }, payload: { authorization: a, signature: "0x" + "11".repeat(65) } }));
}
const CH = (payTo = reqFor(PATH, env).payTo) => ({ x402Version: 2, accepts: [{ scheme: "exact", network: "eip155:8453", amount: "10000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo, maxTimeoutSeconds: 60 }] });
/** Rig with call counters for every outbound dependency. */
function rig(o: { settle?: () => any; chain?: { v: any }; fetchDelay?: number } = {}) {
  const n = { verify: 0, settle: 0, fetch: 0, dns: 0, rpc: 0 }; const chain = o.chain ?? { v: { settled: true } };
  const fac = async (p: string) => { if (p === "/verify") { n.verify++; return { isValid: true }; } n.settle++; return o.settle ? o.settle() : { success: true, transaction: rnd(), payer: PAYER, network: "eip155:84532" }; };
  const resolver = async () => { n.dns++; return ["93.184.216.34"]; };
  const fetcher = async () => { n.fetch++; if (o.fetchDelay) await new Promise((r) => setTimeout(r, o.fetchDelay)); return new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": btoa(JSON.stringify(CH())) } }); };
  const rpc = async () => { n.rpc++; return "0x"; };
  const bgs: Promise<unknown>[] = [];
  const call = async (sig: string | null, url = "https://t.example/x", ip = "198.51.100.7") => {
    const headers: Record<string, string> = sig ? { "PAYMENT-SIGNATURE": sig } : {};
    const res = await handler(new Request("http://h" + PATH + "?url=" + encodeURIComponent(url), { headers }),
      { env, fac, rpc, resolver, fetcher: fetcher as any, check: async () => chain.v, background: (p) => { bgs.push(p); }, ip });
    return [res.status, await res.json()] as [number, any];
  };
  return { n, call, bgs, chain, settle: (f: () => any) => { o.settle = f; } };
}
const fresh = async (over: Record<string, string> = {}) => {
  E = { ...BASE_ENV, ...over }; await resetGuards(); clearIndexCache();
  for (const p of ["reorg", "pending", "pendexp", "pq"]) for await (const e of (await kv()).list({ prefix: [p] })) await (await kv()).delete(e.key);
};

Deno.test("A1 verified payment that is never settled -> 402 and the target is never probed (settle before probe)", async () => {
  await fresh();
  const t = rig({ settle: () => ({ success: false, errorReason: "unexpected_settle_error" }) });
  const [c, b] = await t.call(pay()); assertEquals(c, 402); assert(b.error);
  assertEquals([t.n.settle, t.n.fetch], [1, 0]);
  const t2 = rig({ chain: { v: { settled: false, reason: "nonce_not_in_settlement_tx" } } });
  assertEquals((await t2.call(pay()))[0], 402); assertEquals(t2.n.fetch, 0);
  const t3 = rig({ chain: { v: { settled: null } } }); assertEquals((await t3.call(pay()))[0], 202); assertEquals(t3.n.fetch, 0);
  const t4 = rig(); assertEquals((await t4.call(pay(), "https://t4.example/x"))[0], 200); assertEquals(t4.n.fetch, 1); // control: settled -> probed once
});
Deno.test("A2 asset is not Base USDC -> rejected before verify/settle", async () => {
  await fresh(); const t = rig();
  const [c, b] = await t.call(pay({ asset: "0x" + "12".repeat(20) })); assertEquals([c, b.error], [402, "accepted.asset_mismatch"]);
  assertEquals([t.n.verify, t.n.settle, t.n.fetch], [0, 0, 0]);
});
Deno.test("A3 network is not Base -> rejected before verify/settle", async () => {
  await fresh(); const t = rig();
  const [c, b] = await t.call(pay({ network: "eip155:1" })); assertEquals([c, b.error], [402, "accepted.network_mismatch"]);
  assertEquals([t.n.verify, t.n.settle, t.n.fetch], [0, 0, 0]);
});
Deno.test("A4 settle ok, delivered, then a simulated reorg -> incident logged, delivery stands (re-check persisted in KV)", async () => {
  await fresh({ REORG_RECHECK_MS: "0" }); const t = rig();
  const [c, b] = await t.call(pay()); assertEquals(c, 200); assert(b.attestation); await Promise.all(t.bgs);
  const recs: any[] = []; for await (const e of (await kv()).list({ prefix: ["reorg"] })) recs.push(e.value);
  assertEquals(recs.length, 1); // L2: persisted (survives a restart), not an in-memory timer
  const done = await reorgSweep(env, async () => ({ settled: false, reason: "receipt_not_found" }), Date.now() + 1);
  assertEquals(done, [recs[0].tx + ":incident"]);
  const inc = (await rows("observations.jsonl")).filter((r: any) => r.inputHash === "incident");
  assertEquals(inc.at(-1)?.note, "post_delivery_reorg:receipt_not_found");
  const t2 = rig(); await t2.call(pay()); await Promise.all(t2.bgs);
  assertEquals((await reorgSweep(env, async () => ({ settled: null }), Date.now() + 1)).at(-1)?.endsWith(":retry"), true); // not visible yet: retried later
  const left = await reorgSweep(env, async () => ({ settled: true }), Date.now() + 600_000); assertEquals(left.length, 1); assert(left[0].endsWith(":ok"));
  for await (const _ of (await kv()).list({ prefix: ["reorg"] })) throw new Error("records must be cleared");
});
Deno.test("A5 replay of the same payment header -> rejected (nonce ledger), settled once, probed once", async () => {
  await fresh(); const t = rig(); const sig = pay();
  assertEquals((await t.call(sig))[0], 200);
  for (let i = 0; i < 3; i++) { const [c] = await t.call(sig); assert(c === 409 || c === 402, String(c)); }
  assertEquals([t.n.settle, t.n.fetch], [1, 1]);
});
Deno.test("A6 100 unpaid requests in a minute -> per-IP limit; unpaid 402 does no DNS/GET/RPC/facilitator work", async () => {
  await fresh(); const t = rig(); const codes: number[] = [];
  for (let i = 0; i < 100; i++) codes.push((await t.call(null))[0]);
  assertEquals([codes.filter((c) => c === 402).length, codes.filter((c) => c === 429).length], [60, 40]);
  assertEquals(t.n, { verify: 0, settle: 0, fetch: 0, dns: 0, rpc: 0 });
  assertEquals((await t.call(null, "https://t.example/x", "203.0.113.9"))[0], 402); // other IPs unaffected
  const w = new WindowLimiter(2, 1000); assert(w.allow("a", 0)); assert(w.allow("a", 1)); assert(!w.allow("a", 2)); assert(w.allow("a", 1000)); // window resets
});
Deno.test("A7 pay once then 100 requests for the same target -> one probe; cache 60 s per payer+target; then a new payment probes again", async () => {
  await fresh({ PREFLIGHT_CACHE_TTL_S: "1" }); const t = rig(); const sig = pay();
  assertEquals((await t.call(sig))[0], 200);
  const codes: number[] = []; for (let i = 0; i < 100; i++) codes.push((await t.call(sig))[0]);
  assert(codes.every((c) => c === 409 || c === 402)); assertEquals(t.n.fetch, 1); // same header: rejected, needs a new payment
  const [c2, b2] = await t.call(pay()); assertEquals(c2, 200); assertEquals(t.n.fetch, 1); // new payment inside TTL: cached result, no new probe
  assert(b2.attestation);
  await new Promise((r) => setTimeout(r, 1100));
  assertEquals((await t.call(pay()))[0], 200); assertEquals(t.n.fetch, 2); // after TTL: probed again
});
Deno.test("H1 global per-target budget: failed settles never consume it; full target -> 503 before settlement (not charged)", async () => {
  await fresh({ OUTBOUND_PER_HOST_PER_MIN: "3", PER_TARGET_PAYER_PER_MIN: "100" });
  const bad = rig({ settle: () => ({ success: false, errorReason: "unexpected_settle_error" }) });
  for (let i = 0; i < 2; i++) assertEquals((await bad.call(pay(), "https://t.example/f" + i))[0], 402); // reservation released each time
  const t = rig();
  for (let i = 0; i < 3; i++) assertEquals((await t.call(pay(), "https://t.example/p" + i))[0], 200);
  const [c, b] = await t.call(pay(), "https://t.example/p9"); assertEquals([c, b.charged, b.scope], [503, false, "target"]);
  assertEquals([t.n.verify, t.n.settle, t.n.fetch], [3, 3, 3]);
  assertEquals((await t.call(pay(), "https://other.example/p"))[0], 200); // other targets unaffected
});
Deno.test("H1 per target+payer limit before settlement: 3/min, then 429 not charged; other payers' budget unaffected", async () => {
  await fresh(); const t = rig();
  for (let i = 0; i < 3; i++) assertEquals((await t.call(pay(), "https://t.example/q" + i))[0], 200);
  const [c, b] = await t.call(pay(), "https://t.example/q9"); assertEquals([c, b.scope, b.charged], [429, "target_payer", false]);
  assertEquals(t.n.settle, 3);
  assertEquals((await t.call(pay(), "https://u.example/q"))[0], 200);
});
Deno.test("M1 no free outbound slot -> 503 before settlement (not charged); one in-flight probe per payer", async () => {
  await fresh(); configureOutbound(1); const t = rig({ fetchDelay: 80 });
  const first = t.call(pay(), "https://m.example/a");
  await new Promise((r) => setTimeout(r, 20));
  const [c, b] = await t.call(pay(), "https://m2.example/b"); assertEquals([c, b.charged], [503, false]);
  assertEquals((await first)[0], 200); assertEquals(t.n.settle, 1); assertEquals(OUTBOUND.active, 0);
  configureOutbound(4); const t2 = rig({ fetchDelay: 80 });
  const p1 = t2.call(pay(), "https://m3.example/a"); await new Promise((r) => setTimeout(r, 20));
  const [c2, b2] = await t2.call(pay(), "https://m4.example/b"); assertEquals([c2, b2.charged], [503, false]); // same payer, slots free
  assertEquals((await p1)[0], 200); assertEquals(t2.n.settle, 1);
  const s = new Semaphore(1, 4); const r = s.tryAcquire()!; assertEquals(s.tryAcquire(), null); r(); assert(s.tryAcquire());
});
Deno.test("M2 full limiter table evicts the oldest key instead of refusing new clients; IPv6 /48 aggregate", async () => {
  const w = new WindowLimiter(1, 60_000, 3);
  for (const k of ["a", "b", "c"]) assert(w.allow(k, 0));
  assert(w.allow("d", 1)); assertEquals(w.size, 3); // new client admitted; "a" evicted
  assert(w.allow("a", 2)); assert(!w.allow("d", 3));
  await fresh({ UNPAID_PER_48_PER_MIN: "5" }); const t = rig(); const codes: number[] = [];
  for (let i = 0; i < 8; i++) codes.push((await t.call(null, "https://t.example/x", "2001:db8:1:" + (i + 1).toString(16) + "::1"))[0]);
  assertEquals([codes.filter((c) => c === 402).length, codes.filter((c) => c === 429).length], [5, 3]);
  assertEquals((await t.call(null, "https://t.example/x", "2001:db8:2::1"))[0], 402); // other /48 unaffected
});
Deno.test("L1 pending retry probes the paid url (not the retry query), at most 3 attempts", async () => {
  await fresh(); let fail = true; const seen: string[] = [];
  const t = rig(); const sig = pay();
  const fetcher0 = async (u: string) => { seen.push(new URL(u).host); return new Response("{}", { status: 402 }); };
  const call = async (url: string) => { const r = await handler(new Request("http://h" + PATH + "?url=" + encodeURIComponent(url), { headers: { "PAYMENT-SIGNATURE": sig } }),
    { env, fac: async (p: string) => p === "/verify" ? { isValid: true } : { success: true, transaction: rnd(), payer: PAYER, network: "eip155:84532" },
      rpc: async () => "0x", resolver: async (h: string) => { seen.push(h); if (fail && seen.length > 1) throw new Error("internal"); return ["93.184.216.34"]; }, fetcher: fetcher0 as any, check: async () => ({ settled: true }), background: () => {}, ip: "198.51.100.7" });
    return [r.status, await r.json()] as [number, any]; };
  void t;
  assertEquals((await call("https://paid.example/x"))[0], 502);
  assertEquals((await call("https://other.example/x"))[0], 502);
  assert(seen.every((h) => h === "paid.example"), seen.join());
  const [c3, b3] = await call("https://other.example/x"); assertEquals(c3, 502); assertEquals(b3.attempts_left, 0);
  fail = false; const [c4, b4] = await call("https://paid.example/x"); assertEquals(c4, 502); assert(String(b4.error).includes("after 3 attempts"));
  const inc = (await rows("observations.jsonl")).filter((r: any) => r.inputHash === "incident"); assertEquals(inc.at(-1)?.note, "pending_retries_exhausted");
});
Deno.test("L1 pending retries are subject to the per target+payer limit", async () => {
  await fresh({ PER_TARGET_PAYER_PER_MIN: "1" }); const t = rig({ chain: { v: { settled: null } } }); const sig = pay();
  assertEquals((await t.call(sig, "https://r.example/x"))[0], 202); // settled, not yet visible; parked with url (slot counted 1)
  t.chain.v = { settled: true };
  const [c, b] = await t.call(sig, "https://r.example/x"); assertEquals([c, b.scope], [429, "target_payer"]); assertEquals(t.n.fetch, 0);
  await resetGuards(); assertEquals((await t.call(sig, "https://ignored.example/"))[0], 200); assertEquals(t.n.fetch, 1);
});
Deno.test("bounded outbound concurrency: never more than N probes in flight", async () => {
  await fresh(); configureOutbound(2); let live = 0, peak = 0;
  const fetcher = async () => { live++; peak = Math.max(peak, live); await new Promise((r) => setTimeout(r, 30)); live--; return new Response("{}", { status: 402 }); };
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign"]) as CryptoKeyPair;
  const signer: Signer = { keyId: "0".repeat(16), sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", k.privateKey, m as Uint8Array<ArrayBuffer>)) };
  await Promise.all(Array.from({ length: 10 }, (_, i) => preflight("https://c" + i + ".example/", { resolver: async () => ["93.184.216.34"], fetcher: fetcher as any, signer, env })));
  assertEquals(peak, 2); assertEquals(OUTBOUND.active, 0);
  const s = new Semaphore(1, 1); const r1 = await s.acquire(); const p2 = s.acquire(50); let busy = false; try { await s.acquire(50); } catch { busy = true; } assert(busy, "queue bound");
  r1(); (await p2)(); configureOutbound(4);
});
Deno.test("A8 target http://169.254.169.254/ -> rejected (target_url_allowed=false), not settled, not probed", async () => {
  await fresh(); const t = rig();
  for (const u of ["http://169.254.169.254/", "https://169.254.169.254/latest/meta-data/", "https://127.0.0.1/", "https://[::1]/"]) {
    const [c, b] = await t.call(pay(), u); assertEquals([c, b.target_url_allowed, b.charged], [400, false, false], u);
  }
  assertEquals([t.n.settle, t.n.fetch], [0, 0]);
});
Deno.test("A9 target slower than 5 s -> 5 s timeout and checks_failed includes responds_within_5000ms", async () => {
  await fresh();
  const slow = (_u: string, init?: RequestInit) => new Promise<Response>((_, rej) => init!.signal!.addEventListener("abort", () => rej(init!.signal!.reason)));
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign"]) as CryptoKeyPair;
  const signer: Signer = { keyId: "0".repeat(16), sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", k.privateKey, m as Uint8Array<ArrayBuffer>)) };
  const t0 = performance.now();
  const [c, b]: any = await preflight("https://slow.example/", { resolver: async () => ["93.184.216.34"], fetcher: slow as any, signer, env });
  const ms = performance.now() - t0;
  assertEquals(c, 200); assert(ms >= 4900 && ms < 6500, String(ms));
  assertEquals(b.facts.reachability.error_class, "TimeoutError");
  assert(b.attestation.claims.checks_failed.includes("responds_within_5000ms"));
});
async function snap(resource: string, payTo: string) {
  const b = new IndexAssembler(); const D = new Date().toISOString().slice(0, 10);
  b.add([{ resource, accepts: [{ payTo }], quality: { l30DaysUniquePayers: 1, l30DaysTotalCalls: 2 } }]);
  await saveIndex(b.build(D)); clearIndexCache(); return D;
}
Deno.test("A10 402 payTo differs from the Bazaar snapshot -> pay_to_matches_snapshot false (fact, no verdict)", async () => {
  await fresh(); await snap("https://m.example/x", "0x" + "33".repeat(20));
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign"]) as CryptoKeyPair;
  const signer: Signer = { keyId: "0".repeat(16), sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", k.privateKey, m as Uint8Array<ArrayBuffer>)) };
  const fetcher = async () => new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": btoa(JSON.stringify(CH("0x" + "44".repeat(20)))) } });
  const [, b]: any = await preflight("https://m.example/x", { resolver: async () => ["93.184.216.34"], fetcher: fetcher as any, signer, env });
  assertEquals(b.attestation.claims.pay_to_matches_snapshot, false);
  const ck = b.attestation.claims.checks.find((c: any) => c.id === "pay_to_matches_snapshot");
  assertEquals(ck, { id: "pay_to_matches_snapshot", status: "fail", observed: { challenge: ["0x" + "44".repeat(20)], snapshot: ["0x" + "33".repeat(20)] } });
  for (const w of ["verdict", "score", "safe", "scam", "recommend"]) assert(!JSON.stringify(b.attestation).toLowerCase().includes(w), w);
});
Deno.test("A11 tampered Bazaar snapshot: service detects the hash mismatch; verifier rejects a hash that differs from the published one", async () => {
  await fresh(); const D = await snap("https://n.example/x", "0x" + "33".repeat(20));
  const meta = (await readSnapMeta(D))!; assert(/^[0-9a-f]{64}$/.test(meta.sha256!));
  const pub = await (await handler(new Request("http://h/bazaar/snapshots"), { env })).json();
  assertEquals(pub.snapshots.find((x: any) => x.date === D).sha256, meta.sha256); // published per date
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", k.publicKey));
  const kid = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", raw)), (x) => x.toString(16).padStart(2, "0")).join("").slice(0, 16);
  const signer: Signer = { keyId: kid, sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", k.privateKey, m as Uint8Array<ArrayBuffer>)) };
  const fetcher = async () => new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": btoa(JSON.stringify(CH("0x" + "33".repeat(20)))) } });
  const [, ok]: any = await preflight("https://n.example/x", { resolver: async () => ["93.184.216.34"], fetcher: fetcher as any, signer, env });
  assertEquals(ok.facts.bazaar.snapshot_sha256, meta.sha256);
  assertEquals(verifySnapshotBinding(ok.attestation, pub)[0], true);
  const forged = { snapshots: [{ ...pub.snapshots[0], sha256: "f".repeat(64) }] };
  assertEquals(verifySnapshotBinding(ok.attestation, forged), [false, "snapshot hash does not match the published snapshot"]);
  // tamper with a stored chunk: the service refuses to use it
  const c0 = await (await kv()).get<Uint8Array>(["snap", D, meta.gen!, 0]); const bad = new Uint8Array(c0.value!); bad[bad.length - 9] ^= 0xff;
  await (await kv()).set(["snap", D, meta.gen!, 0], bad); clearIndexCache();
  const [, tam]: any = await preflight("https://n.example/x", { resolver: async () => ["93.184.216.34"], fetcher: fetcher as any, signer, env });
  assertEquals([tam.facts.bazaar.available, tam.facts.bazaar.reason], [false, "snapshot_hash_mismatch"]);
  // python verifier: same binding rule
  const d = await Deno.makeTempDir();
  await Deno.writeTextFile(d + "/a.json", JSON.stringify(ok)); await Deno.writeTextFile(d + "/s.json", JSON.stringify(forged)); await Deno.writeTextFile(d + "/s_ok.json", JSON.stringify(pub));
  await Deno.writeTextFile(d + "/i.json", JSON.stringify({ keys: [{ key_id: kid, public_key_b64: btoa(String.fromCharCode(...raw)), status: "active" }] }));
  const py = async (s: string) => (await new Deno.Command("python3", { args: [new URL("../../scripts/verify_attestation.py", import.meta.url).pathname, d + "/a.json", "--issuer", d + "/i.json", "--snapshots", d + s], stdout: "piped" }).output()).code;
  assertEquals([await py("/s_ok.json"), await py("/s.json")], [0, 1]);
  await Deno.remove(d, { recursive: true });
});
Deno.test("A12 an attestation from yesterday -> rejected (expires_at passed) by the library and both official verifiers", async () => {
  await fresh();
  const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", k.publicKey)); const pub = btoa(String.fromCharCode(...raw));
  const kid = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", raw)), (x) => x.toString(16).padStart(2, "0")).join("").slice(0, 16);
  const signer: Signer = { keyId: kid, sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", k.privateKey, m as Uint8Array<ArrayBuffer>)) };
  const facts = { schema: "prepay-check/v1", target: "https://y.example/", checked_at: "x", disclaimer: "d", reachability: { reachable: false, error_class: "TimeoutError" }, challenge: { valid: false, problems: [], accepts: [] }, bazaar: { available: false, reason: "no_snapshot" } };
  const y: any = await attest(facts, { signer, now: Date.now() - 86400_000 });
  assertEquals((await verifyAttestation(y, pub)).reason, "expired");
  const iss = { keys: [{ key_id: kid, public_key_b64: pub, status: "active" }] };
  assert((await officialVerify(y, iss))[1].startsWith("expired at "));
  const d = await Deno.makeTempDir(); await Deno.writeTextFile(d + "/a.json", JSON.stringify(y)); await Deno.writeTextFile(d + "/i.json", JSON.stringify(iss));
  const py = await new Deno.Command("python3", { args: [new URL("../../scripts/verify_attestation.py", import.meta.url).pathname, d + "/a.json", "--issuer", d + "/i.json"], stdout: "piped" }).output();
  assertEquals(py.code, 1); assert(new TextDecoder().decode(py.stdout).startsWith("FAIL expired at "));
  await Deno.remove(d, { recursive: true });
});

Deno.test("M1 (re-audit 3) target capacity full -> 503 + Retry-After, no facilitator call, not charged", async () => {
  await fresh({ OUTBOUND_PER_HOST_PER_MIN: "1", PER_TARGET_PAYER_PER_MIN: "100" }); const t = rig();
  assertEquals((await t.call(pay(), "https://full.example/a"))[0], 200);
  const n0 = { ...t.n };
  const res = await handler(new Request("http://h" + PATH + "?url=" + encodeURIComponent("https://full.example/b"), { headers: { "PAYMENT-SIGNATURE": pay() } }),
    { env, fac: async () => { throw new Error("facilitator must not be called"); }, rpc: async () => "0x", resolver: async () => ["93.184.216.34"], fetcher: (async () => { throw new Error("no probe"); }) as any, check: async () => ({ settled: true }), background: () => {}, ip: "198.51.100.7" });
  const b = await res.json(); assertEquals([res.status, b.charged, res.headers.get("Retry-After")], [503, false, "60"]);
  assertEquals(t.n, n0);
});
Deno.test("M1 (re-audit 3) attacker keeps the target budget used up: the honest buyer is never charged without a result", async () => {
  await fresh({ OUTBOUND_PER_HOST_PER_MIN: "3", PER_TARGET_PAYER_PER_MIN: "1000" }); const t = rig();
  for (let m = 0; m < 3; m++) {
    if (m) await resetGuards(); // each new minute the attacker pays first and uses the whole budget
    for (let i = 0; i < 3; i++) assertEquals((await t.call(pay(), "https://v.example/a" + m + i))[0], 200);
    const s0 = t.n.settle; const honest = pay();
    const [c, b] = await t.call(honest, "https://v.example/honest");
    assertEquals([c, b.charged], [503, false]); assertEquals(t.n.settle, s0); // refused BEFORE settlement: nothing paid
    const [c2] = await t.call(honest, "https://v.example/honest"); assertEquals(c2, 503); // same authorization reusable, still unspent
  }
  await resetGuards(); const honest = pay(); const [c3, b3] = await t.call(honest, "https://v.example/honest"); // capacity free: paid AND served
  assertEquals(c3, 200); assert(b3.attestation);
  for await (const _ of (await kv()).list({ prefix: ["pending"] })) throw new Error("no paid check may be left pending");
});
Deno.test("M1 (re-audit 3) a failed settle releases the reservation (budget and slot)", async () => {
  await fresh({ OUTBOUND_PER_HOST_PER_MIN: "1", PER_TARGET_PAYER_PER_MIN: "100" });
  const bad = rig({ settle: () => ({ success: false, errorReason: "unexpected_settle_error" }) });
  assertEquals((await bad.call(pay(), "https://r1.example/a"))[0], 402); assertEquals(OUTBOUND.active, 0);
  assert(abuse(env).perHost.peek("r1.example"));
  const t = rig(); assertEquals((await t.call(pay(), "https://r1.example/b"))[0], 200); assert(!abuse(env).perHost.peek("r1.example"));
});
Deno.test("M1 (re-audit 2) a pending check that expires unserved -> atomically removed and logged as an incident", async () => {
  await fresh(); const now = Date.now();
  await SG.setPending("k1", { path: PATH, tx: "0xabc", times: {}, url: "https://e.example/", tries: 0 }, now);
  assertEquals((await pendingSweep(now + 60_000)).length, 0); // not yet expired
  assertEquals(await SG.takePending("k1", now + SG.PENDING_TTL_MS + 1), null); // expired: not served
  assertEquals(await pendingSweep(now + SG.PENDING_TTL_MS + 1), ["k1"]);
  assertEquals((await pendingSweep(now + SG.PENDING_TTL_MS + 2)).length, 0); // reported once
  const inc = (await rows("observations.jsonl")).filter((r: any) => r.inputHash === "incident"); assertEquals(inc.at(-1)?.note, "pending_expired_unserved");
});
Deno.test("L3 (re-audit 2) signed snapshot meta is cached for 60 s", async () => {
  await fresh(); const now = Date.now();
  const a = await snapshotMeta(env, now); assert(a === await snapshotMeta(env, now + 59_000)); assert(a !== await snapshotMeta(env, now + 61_000));
});
Deno.test("L4 (re-audit 2) reorg sweep lists only due records; concurrent sweeps report an incident once", async () => {
  await fresh(); const now = Date.now();
  const base = { path: PATH, payer: PAYER, asset: "a", payTo: "p", amount: "1", nonce: "n", network: "eip155:84532", minConf: 1 };
  await scheduleReorgCheck({ ...base, tx: "0xdue" }, 0, now); await scheduleReorgCheck({ ...base, tx: "0xlater" }, 3600_000, now);
  let checked: string[] = []; let incidents = 0;
  const chk = async (r: any) => { checked.push(r.tx); await new Promise((x) => setTimeout(x, 10)); return { settled: false, reason: "gone" }; };
  await Promise.all([sweepReorg(chk, async () => { incidents++; }, now + 1), sweepReorg(chk, async () => { incidents++; }, now + 1)]);
  assertEquals(incidents, 1); assert(!checked.includes("0xlater"));
  checked = []; await sweepReorg(chk, async () => { incidents++; }, now + 1); assertEquals(checked, []);
});
