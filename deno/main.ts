// GBMRAFLI Base Reads on Deno Deploy: receive-only x402 v2 seller on Base mainnet. Never signs or sends funds.
// Same routes, 402 challenges, signed facts, export endpoint and record format as api/index.py. Zero LLM.
import { pyDumps } from "./lib/canonical.ts";
import { Chain, makeRpc, type Rpc } from "./lib/chain.ts";
import { preflight, type Fetcher, type Resolver } from "./lib/preflight.ts";
import { PAY_TO_DEFAULT, ROUTES } from "./lib/routes.ts";
import DISCOVERY from "./lib/discovery.json" with { type: "json" };
import { CDP_HOST, enabled as cdpEnabled, headers as cdpHeaders } from "./lib/cdp_auth.ts";
import * as SG from "./lib/settle_guard.ts";
import { SCHEMA, snapshotDates, loadIndex } from "./lib/preflight.ts";
import { isoOrNull, keyHistory, publicKeyInfo, sign, SigningUnavailable } from "./lib/sign.ts";
import { snapshotIfMissing, runSnapshot } from "./lib/snapshot.ts";
import { EXPORT_FILES, rows } from "./lib/store.ts";
import { recordObservation, recordSale, verifyOnchain } from "./lib/stream.ts";
import { ADDR, b64json, iso, pyQuery, sha256hex, unquote } from "./lib/util.ts";

const USDCS: Record<string, string> = { "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e" };
export type Deps = { env: (k: string) => string | undefined; rpc?: Rpc; fac?: (p: string, body: unknown) => Promise<any>;
  resolver?: Resolver; fetcher?: Fetcher; background?: (p: Promise<unknown>) => void;
  check?: (tx: string, r: any, payer: string | undefined) => Promise<any>; ip?: string };
const cfg = (env: Deps["env"]) => {
  const NETWORK = env("NETWORK") ?? "eip155:8453";
  return { FAC: env("FACILITATOR") ?? "https://facilitator.payai.network", RPC: env("RPC") ?? "https://mainnet.base.org",
    PAY_TO: env("PAY_TO_ADDRESS") || PAY_TO_DEFAULT, PUBLIC: env("PUBLIC_URL") ?? "", NETWORK, USDC: USDCS[NETWORK] };
};
export function reqFor(path: string, env: Deps["env"]) {
  const c = cfg(env);
  return { scheme: "exact", network: c.NETWORK, amount: String(ROUTES[path][0]), asset: c.USDC, payTo: c.PAY_TO, maxTimeoutSeconds: 120,
    extra: { name: c.NETWORK === "eip155:8453" ? "USD Coin" : "USDC", version: "2" } };
}
type Disc = { params: Record<string, unknown>; required: string[]; output: unknown };
/** extensions.bazaar in the declareDiscoveryExtension format (info + JSON schema); same bytes as api/index.py bazaar(). */
export function bazaar(path: string) {
  const ex = ROUTES[path][2], d = (DISCOVERY as Record<string, Disc>)[path];
  const inp: Record<string, unknown> = { type: "http", method: "GET" };
  const inpS: Record<string, unknown> = { type: { type: "string", const: "http" }, method: { type: "string", enum: ["GET", "HEAD", "DELETE"] } };
  if (Object.keys(d.params).length) { inp.queryParams = ex; inpS.queryParams = { type: "object", properties: d.params, required: d.required }; }
  return { info: { input: inp, output: { type: "json", example: d.output } },
    schema: { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object",
      properties: { input: { type: "object", properties: inpS, required: ["type", "method"], additionalProperties: false },
        output: { type: "object", properties: { type: { type: "string" }, example: { type: "object" } }, required: ["type"] } },
      required: ["input"] } };
}
const HOST_RE = /^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$/;
/** The Host header is client-controlled; only a plain hostname[:port] may appear in the challenge's resource URL. */
export const safeHost = (h: string) => HOST_RE.test(h) ? h : "invalid-host";
export function facilitatorInfo(env: Deps["env"]) {
  const fac = cfg(env).FAC; let h = ""; try { h = new URL(fac).hostname.toLowerCase(); } catch { /* keep "" */ }
  const name = h === CDP_HOST ? "CDP" : (h === "payai.network" || h.endsWith(".payai.network")) ? "PayAI" : h;
  return { name, url: fac, auth: cdpEnabled(fac, env) ? "cdp_jwt" : "none" };
}
export function root(env: Deps["env"]) {
  const c = cfg(env);
  return { service: "GBMRAFLI Base Reads", network: c.NETWORK, protocol: "x402 v2", facilitator: facilitatorInfo(env),
    free: ["/.well-known/x402-preflight", "/.well-known/x402-preflight-key-history.json", "/.well-known/bazaar-snapshot.json", "/x402/preflight/pubkey", "/bazaar/snapshots"],
    routes: Object.fromEntries(Object.entries(ROUTES).map(([k, v]) => [k, { price_usdc: v[0] / 1e6, description: v[1] }])) };
}
export async function wellKnown(env: Deps["env"]) {
  const pub = await publicKeyInfo(env);
  return { service: "GBMRAFLI Base Reads", schema: SCHEMA, alg: "Ed25519", key_id: pub.key_id, public_key_b64: pub.public_key_b64,
    fingerprint: pub.fingerprint, fingerprint_short: pub.fingerprint_short, created_at: pub.created_at,
    verify: ["Take the paid /x402/preflight response body: {facts, signature}.",
      "Serialize facts as canonical JSON: keys sorted, separators (',', ':'), ASCII-only escapes (Python json.dumps(facts, sort_keys=True, separators=(',', ':'))).",
      "Verify signature.value_b64 (base64) over those bytes with Ed25519 (RFC 8032) and public_key_b64 (32-byte raw key).",
      "Check signature.key_id matches key_id here; key_id = first 16 hex chars of sha256(raw public key)."],
    facilitator: facilitatorInfo(env), repo: env("REPO_URL") ?? "https://github.com/GBMRAFLI/base-reads-api",
    routes: { pubkey: "/x402/preflight/pubkey", key_history: "/.well-known/x402-preflight-key-history.json", paid_check: "/x402/preflight", snapshots: "/bazaar/snapshots", snapshot_meta: "/.well-known/bazaar-snapshot.json" } };
}
/** Free, signed metadata about the daily Bazaar snapshot series (no snapshot contents). */
export async function snapshotMeta(env: Deps["env"] = (k) => Deno.env.get(k)) {
  const dates = await snapshotDates(); const last = dates.at(-1) ?? null;
  const meta = { version: 1, started_at: dates[0] ?? null, last_updated: last, total_snapshots: dates.length,
    covered_listings: last ? Object.keys(((await loadIndex(last)) as any).resources ?? {}).length : 0 };
  const e = await sign(meta, env);
  return { metadata: e.facts, signature: e.signature, pubkey_url: "/x402/preflight/pubkey" };
}
const SNAP_SUM = new Map<string, Record<string, unknown>>();
export async function snapshotSummary(limit = 30) {
  const out: Record<string, unknown>[] = [];
  for (const d of (await snapshotDates()).slice(-limit).reverse()) {
    if (!SNAP_SUM.has(d)) {
      const idx: any = await loadIndex(d); const res: Record<string, any> = idx.resources ?? {};
      const vals = Object.values(res);
      SNAP_SUM.set(d, { date: d, resources: vals.length, hosts: Object.keys(idx.hosts ?? {}).length, payout_wallets: Object.keys(idx.wallet_hosts ?? {}).length,
        calls30d_total: vals.reduce((a, r) => a + (r.calls30d || 0), 0), payers30d_total: vals.reduce((a, r) => a + (r.payers30d || 0), 0) });
    }
    out.push(SNAP_SUM.get(d)!);
  }
  return { source: "x402 Bazaar discovery API, crawled daily at 00:15 UTC", snapshots: out };
}
export function required(path: string, host: string, env: Deps["env"]) {
  const [, desc] = ROUTES[path]; const c = cfg(env);
  return { x402Version: 2, error: "PAYMENT-SIGNATURE header is required", resource: { url: (c.PUBLIC || ("https://" + safeHost(host))) + path, description: desc, mimeType: "application/json" },
    accepts: [reqFor(path, env)], extensions: { bazaar: bazaar(path) } };
}
export function facClient(base: string, env: Deps["env"], f: typeof fetch = fetch) {
  return async (p: string, body: unknown) => {
    const r = await f(base + p, { method: "POST", headers: { "Content-Type": "application/json", "User-Agent": "gbmrafli-base-reads/1.0", ...(await cdpHeaders(base, p, env)) }, body: pyDumps(body), signal: AbortSignal.timeout(40000) });
    try { return await r.json(); } catch { return {}; }
  };
}
function timingSafeEq(a: string, b: string) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b); let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return d === 0;
}
export async function exportRecords(auth: string, q: Record<string, string>, env: Deps["env"]): Promise<[number, unknown]> {
  const tok = env("EXPORT_TOKEN") ?? ""; const given = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (tok.length < 32 || !timingSafeEq(given, tok)) return [401, { error: "unauthorized" }];
  const since = unquote(q.since ?? ""); const c = cfg(env); const out: Record<string, unknown[]> = {};
  for (const n of EXPORT_FILES) out[n.split(".")[0]] = (await rows(n)).filter((r: any) => !since || ((r.startedAt || r.verifiedAt || r.observedAt || r.incurredAt || "") >= since));
  return [200, { payTo: c.PAY_TO, network: c.NETWORK, asset: c.USDC, exportedAt: iso(), records: out }];
}
const HDRS = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE" };
const send = (code: number, obj: unknown, hd: Record<string, string> = {}) => new Response(pyDumps(obj), { status: code, headers: { ...HDRS, ...hd } });
const b64 = (o: unknown) => b64json(o, pyDumps);

export async function handler(req: Request, d: Deps): Promise<Response> {
  if (req.method !== "GET") return send(501, { error: "unsupported method" });
  const env = d.env; const c = cfg(env); const rpc = d.rpc ?? makeRpc(c.RPC); const fac = d.fac ?? facClient(c.FAC, env);
  const raw = req.url.slice(req.url.indexOf("/", 8)); const qi = raw.indexOf("?");
  const path = qi < 0 ? raw : raw.slice(0, qi), qs = qi < 0 ? "" : raw.slice(qi + 1); const q = pyQuery(qs);
  if (path === "/" || path === "/index.json") return send(200, root(env));
  if (path === "/.well-known/x402-preflight") {
    try { return send(200, await wellKnown(env)); } catch (e) { if (e instanceof SigningUnavailable) return send(503, { error: "signing key unavailable" }); throw e; }
  }
  if (path === "/bazaar/snapshots") return send(200, await snapshotSummary());
  if (path === "/.well-known/bazaar-snapshot.json" || path === "/.well-known/x402-preflight-key-history.json") {
    try { return send(200, path.includes("bazaar") ? await snapshotMeta(env) : await keyHistory(env)); }
    catch (e) { if (e instanceof SigningUnavailable) return send(503, { error: "signing key unavailable" }); throw e; }
  }
  if (path === "/internal/export") { const [code, obj] = await exportRecords(req.headers.get("Authorization") ?? "", q, env); return send(code, obj); }
  if (path === "/x402/preflight/pubkey") {
    try { return send(200, await publicKeyInfo(env)); } catch (e) { if (e instanceof SigningUnavailable) return send(503, { error: "signing key unavailable" }); throw e; }
  }
  if (!(path in ROUTES)) return send(404, { error: "not found" });
  if (path === "/x402/preflight" && !ADDR.test(c.PAY_TO)) return send(503, { error: "payee not configured" });
  const tReq = iso();
  const sig = req.headers.get("PAYMENT-SIGNATURE") ?? req.headers.get("X-PAYMENT");
  if (!sig) { const pr = required(path, req.headers.get("Host") ?? "", env); return send(402, pr, { "PAYMENT-REQUIRED": b64(pr) }); }
  const [code, out, hd] = await paid(path, q, qs, sig, tReq, d, c, rpc, fac);
  return send(code, out, hd);
}

const FAILS = new SG.FailLimiter();
export async function resetGuards() { await FAILS.clear(); }
export const MAINNET = "eip155:8453";
/** ONCHAIN_CHECK=log (serve on facilitator success) is refused on Base mainnet: block is forced there. */
export function onchainMode(env: Deps["env"]): "block" | "log" {
  const m = env("ONCHAIN_CHECK") ?? "block";
  return m === "log" && (env("NETWORK") ?? MAINNET) !== MAINNET ? "log" : "block";
}
/** Non-fatal configuration problems, logged once at startup. */
export function startupWarnings(env: Deps["env"]): string[] {
  const w: string[] = []; const ca = env("SIGNING_KEY_CREATED_AT");
  if (ca && !isoOrNull(ca)) w.push("SIGNING_KEY_CREATED_AT is not strict ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ); published as null");
  try { const h = JSON.parse(env("SIGNING_KEY_HISTORY") || "[]");
    if (!Array.isArray(h)) w.push("SIGNING_KEY_HISTORY is not a JSON list; ignored");
    else h.forEach((k: any, i: number) => { for (const f of ["created_at", "retired_at"]) if (k?.[f] != null && !isoOrNull(k[f])) w.push(`SIGNING_KEY_HISTORY[${i}].${f} is not strict ISO-8601 UTC; published as null`); });
  } catch { w.push("SIGNING_KEY_HISTORY is not valid JSON; ignored"); }
  return w;
}
export function assertOnchainMode(env: Deps["env"]) {
  if (env("ONCHAIN_CHECK") === "log" && (env("NETWORK") ?? MAINNET) === MAINNET) throw new Error("ONCHAIN_CHECK=log is not allowed on Base mainnet");
}
/** Facilitator error codes we pass through to clients (x402 spec); anything else becomes "facilitator_error". */
export const FAC_ERRORS = new Set(["insufficient_funds", "invalid_exact_evm_payload_authorization_valid_after",
  "invalid_exact_evm_payload_authorization_valid_before", "invalid_exact_evm_payload_authorization_value",
  "invalid_exact_evm_payload_signature", "invalid_exact_evm_payload_recipient_mismatch", "invalid_network", "invalid_payload",
  "invalid_payment_requirements", "invalid_scheme", "unsupported_scheme", "invalid_x402_version", "invalid_transaction_state",
  "settle_exact_svm_block_height_exceeded", "unexpected_verify_error", "unexpected_settle_error", "payment_expired"]);
export const facErr = (x: unknown) => typeof x === "string" && FAC_ERRORS.has(x) ? x : "facilitator_error";
/** PAYMENT-RESPONSE is always rebuilt from validated fields; facilitator bodies are never echoed. */
const payResp = (network: string, ok: boolean, tx: string | null, payer: string | null, why?: string) =>
  ({ "PAYMENT-RESPONSE": b64(ok ? { success: true, transaction: tx, network, payer } : { success: false, errorReason: why ?? null, transaction: tx ?? "", network, payer }) });
const noPay = (why: unknown, network: string) => payResp(network, false, null, null, String(why));
type Cfg = ReturnType<typeof cfg>;
/** precheck -> limits -> replay claim -> verify -> handler -> settle -> independent on-chain check -> serve (same rules as api/index.py paid()).
 * Serve ONLY when Base shows the USDC Transfer(payer -> payTo, >= amount) and AuthorizationUsed(payer, nonce) in the same receipt.
 * The payer is always the signed authorization's `from`, never the facilitator's word. An unconfirmed receipt parks the payment (202). */
async function paid(path: string, q: Record<string, string>, qs: string, sig: string, tReq: string, d: Deps, c: Cfg, rpc: Rpc,
  fac: (p: string, body: unknown) => Promise<any>): Promise<[number, unknown, Record<string, string>]> {
  const env = d.env; const mode = onchainMode(env); const N = c.NETWORK;
  const [payload, err] = SG.parsePayment(sig);
  if (err || !payload) return [400, { error: err }, {}];
  const r = reqFor(path, env);
  const bad = SG.precheck(payload, r); // before the claim: malformed/foreign payloads never consume a nonce slot
  if (bad) return [402, { error: bad }, noPay(bad, N)];
  const who = SG.payerOf(payload)!; const nonce = SG.nonceOf(payload)!; const ids = { ip: d.ip ?? null, payer: who };
  const check = d.check ?? ((tx: string, rq: any, payer: string | undefined) => verifyOnchain(rpc, tx, rq.asset, rq.payTo, rq.amount, payer, N, 3, 1000, undefined, nonce));
  const bg = d.background ?? (() => {});
  const sale = (tx: string) => ({ success: true, transaction: tx, payer: who, network: N });
  const log = (tx: string, oc: any, served: boolean, times: [string, string, string]) => {
    bg((async () => {
      try { await recordSale(path, r, sale(tx), times, oc, served, env); await recordObservation(path, (await sha256hex(qs)).slice(0, 16), served ? 200 : 402, null); }
      catch (e) { console.log("sales log write failed:", (e as Error).name); }
    })());
  };
  const mismatch = (why: string) => bg(recordObservation(path, "settle-mismatch", 502, null, why).catch(() => {}));
  const run = async (): Promise<[number, unknown]> => {
    if (path === "/x402/preflight") {
      const u = unquote(q.url ?? "");
      return u ? await preflight(u, { resolver: d.resolver, fetcher: d.fetcher, env }) : [400, { error: "give ?url=https://..." }];
    }
    return await new Chain(rpc, c.USDC).handle(path, q);
  };
  const release = await SG.acquireSlots(ids);
  if (!release) return [429, { error: "too many concurrent payments, retry shortly", scope: "concurrency" }, {}];
  try { return await paidLocked(); } finally { await release(); }
  async function paidLocked(): Promise<[number, unknown, Record<string, string>]> {
  const lim = await FAILS.blocked(ids); // checked while holding a slot: bursts cannot overshoot by more than the slot count
  if (lim) return [429, { error: "too many failed payments, retry later", scope: lim }, {}];
  const key = SG.replayKey(payload!);
  if (!await SG.claim(key, SG.expiry(payload!), undefined, undefined, { at: Date.now(), payload_sha256: await SG.payloadHash(payload!) })) {
    const pend = await SG.takePending(key);
    if (pend && pend.path === path) {
      const oc: any = await check(pend.tx, r, who);
      if (oc.settled === null) { await SG.setPending(key, pend); return [202, { status: "settled_pending_onchain_confirmation", transaction: pend.tx }, payResp(N, true, pend.tx, who)]; }
      if (oc.settled === false) { log(pend.tx, oc, false, pend.times); return [402, { error: "settlement not confirmed on-chain: " + String(oc.reason) }, {}]; }
      let code: number, out: unknown;
      try { [code, out] = await run(); } catch { await SG.setPending(key, pend); return [502, { error: "upstream error, retry the same request" }, {}]; }
      if (code !== 200) { await SG.setPending(key, pend); return [code, out, {}]; }
      log(pend.tx, oc, true, pend.times); return [200, out, payResp(N, true, pend.tx, who)];
    }
    if (pend) await SG.setPending(key, pend);
    return [409, { error: "payment authorization already used or in flight" }, noPay("replay", N)];
  }
  const body = { x402Version: 2, paymentPayload: payload, paymentRequirements: r };
  const v = await fac("/verify", body); const tVer = iso();
  if (!v.isValid) { const why = facErr(v.invalidReason); await FAILS.fail({ ip: ids.ip }, "verify"); return [402, { error: why }, noPay(why, N)]; }
  let code: number, out: unknown;
  try { [code, out] = await run(); } catch (e) {
    if (e instanceof SigningUnavailable) return [503, { error: "signing unavailable, not charged" }, {}];
    return [502, { error: "upstream error, not charged" }, {}];
  }
  if (code !== 200) return [code, out, {}]; // bad input: not settled, not charged
  const st = await fac("/settle", body); const tSet = iso(); const times: [string, string, string] = [tReq, tVer, tSet];
  const tx: string | null = typeof st.transaction === "string" && SG.TX_RE.test(st.transaction) ? st.transaction.toLowerCase() : null;
  if (typeof st.payer === "string" && st.payer.toLowerCase() !== who) mismatch("facilitator_payer_differs_from_signed_from");
  if (!st.success) {
    const oc: any = tx ? await check(tx, r, who) : { settled: false, reason: "no_tx_hash" };
    if (oc.settled === true && tx && await SG.claimTx(tx)) { // facilitator said failed, chain says paid: honor it
      log(tx, { ...oc, note: "settle_reported_failure_but_confirmed_onchain" }, true, times);
      return [200, out, payResp(N, true, tx, who)];
    }
    const why = facErr(st.errorReason); await FAILS.fail(ids, "settle");
    return [402, { error: why }, payResp(N, false, tx, who, why)];
  }
  if (!tx) { mismatch("settle_success_without_valid_tx_hash"); return [502, { error: "settlement response invalid, contact support with your payment" }, {}]; }
  if (!await SG.claimTx(tx)) { mismatch("settlement_tx_reused"); return [409, { error: "settlement transaction already used" }, noPay("replay", N)]; }
  const oc: any = await check(tx, r, who);
  if (mode === "log") {
    log(tx, oc, true, times); if (oc.settled !== true) mismatch("onchain_" + String(oc.reason));
    return [200, out, payResp(N, true, tx, who)];
  }
  if (oc.settled === true) { log(tx, oc, true, times); return [200, out, payResp(N, true, tx, who)]; }
  if (oc.settled === null) {
    await SG.setPending(key, { path, tx, times });
    return [202, { status: "settled_pending_onchain_confirmation", transaction: tx,
      retry: "repeat the same request with the same payment header; it is served once the transfer is confirmed on Base" }, payResp(N, true, tx, who)];
  }
  log(tx, oc, false, times);
  return [402, { error: "settlement not confirmed on-chain: " + String(oc.reason) }, payResp(N, false, tx, who, "not_confirmed_onchain")];
}
}

if (import.meta.main) {
  const env = (k: string) => Deno.env.get(k);
  if ((env("SNAPSHOT_SCHEDULER") ?? "1") === "1") {
    Deno.cron("bazaar-snapshot", "15 0 * * *", async () => { await runSnapshot(); });
    Deno.cron("fail-counter-purge", "7 * * * *", async () => { await FAILS.purge(); });
    snapshotIfMissing().catch((e) => console.log("snapshot failed:", (e as Error).name));
  }
  for (const w of startupWarnings(env)) console.warn("WARNING:", w);
  assertOnchainMode(env); // refuse to start with ONCHAIN_CHECK=log on Base mainnet
  Deno.serve({ port: Number(env("PORT") ?? 8000) }, (req, info) => handler(req, { env, ip: (info.remoteAddr as Deno.NetAddr).hostname }));
}
