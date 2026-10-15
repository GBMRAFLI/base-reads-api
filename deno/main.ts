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
import { keyHistory, publicKeyInfo, sign, SigningUnavailable } from "./lib/sign.ts";
import { snapshotIfMissing, runSnapshot } from "./lib/snapshot.ts";
import { EXPORT_FILES, rows } from "./lib/store.ts";
import { recordObservation, recordSale, verifyOnchain } from "./lib/stream.ts";
import { ADDR, b64json, iso, pyQuery, sha256hex, unquote } from "./lib/util.ts";

const USDCS: Record<string, string> = { "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e" };
export type Deps = { env: (k: string) => string | undefined; rpc?: Rpc; fac?: (p: string, body: unknown) => Promise<any>;
  resolver?: Resolver; fetcher?: Fetcher; background?: (p: Promise<unknown>) => void;
  check?: (tx: string, r: any, payer: string | undefined) => Promise<any> };
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
export async function snapshotMeta() {
  const dates = await snapshotDates(); const last = dates.at(-1) ?? null;
  const meta = { version: 1, started_at: dates[0] ?? null, last_updated: last, total_snapshots: dates.length,
    covered_listings: last ? Object.keys(((await loadIndex(last)) as any).resources ?? {}).length : 0 };
  const e = await sign(meta);
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
    try { return send(200, path.includes("bazaar") ? await snapshotMeta() : await keyHistory(env)); }
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
export function resetGuards() { FAILS.m.clear(); }
const noPay = (why: unknown, network: string) => ({ "PAYMENT-RESPONSE": b64({ success: false, errorReason: why ?? null, network }) });
type Cfg = ReturnType<typeof cfg>;
/** verify -> handler -> settle -> independent on-chain check -> serve (same rules as api/index.py paid()).
 * block (default): serve ONLY when Base shows the USDC Transfer(payer -> payTo, >= amount) and, for EIP-3009, AuthorizationUsed(payer, nonce)
 * in the same receipt. Facilitator success alone never serves; an unconfirmed receipt parks the payment (202) until a retry finds it. */
async function paid(path: string, q: Record<string, string>, qs: string, sig: string, tReq: string, d: Deps, c: Cfg, rpc: Rpc,
  fac: (p: string, body: unknown) => Promise<any>): Promise<[number, unknown, Record<string, string>]> {
  const env = d.env; const mode = env("ONCHAIN_CHECK") ?? "block";
  const [payload, err] = SG.parsePayment(sig);
  if (err || !payload) return [400, { error: err }, {}];
  const r = reqFor(path, env); const nonce = SG.nonceOf(payload);
  const check = d.check ?? ((tx: string, rq: any, payer: string | undefined) => verifyOnchain(rpc, tx, rq.asset, rq.payTo, rq.amount, payer, c.NETWORK, 3, 1000, undefined, nonce));
  const bg = d.background ?? (() => {});
  const log = (stx: any, oc: any, served: boolean, times: [string, string, string]) => {
    bg((async () => {
      try { await recordSale(path, r, stx, times, oc, served, env); await recordObservation(path, sha256hex(qs).slice(0, 16), served ? 200 : 402, null); }
      catch (e) { console.log("sales log write failed:", (e as Error).name); }
    })());
  };
  const mismatch = (why: string) => bg(recordObservation(path, "settle-mismatch", 502, null, why).catch(() => {}));
  const run = async (): Promise<[number, unknown]> => {
    if (path === "/x402/preflight") {
      const u = unquote(q.url ?? "");
      return u ? await preflight(u, { resolver: d.resolver, fetcher: d.fetcher }) : [400, { error: "give ?url=https://..." }];
    }
    return await new Chain(rpc, c.USDC).handle(path, q);
  };
  const key = await SG.replayKey(payload, sig);
  if (!await SG.claim(key, SG.expiry(payload))) {
    const pend = await SG.takePending(key);
    if (pend && pend.path === path) {
      const oc: any = await check(pend.tx, r, pend.payer);
      if (oc.settled === null) { await SG.setPending(key, pend); return [202, { status: "settled_pending_onchain_confirmation", transaction: pend.tx }, { "PAYMENT-RESPONSE": b64(pend.st) }]; }
      if (oc.settled === false) { log(pend.st, oc, false, pend.times); return [402, { error: "settlement not confirmed on-chain: " + String(oc.reason) }, {}]; }
      let code: number, out: unknown;
      try { [code, out] = await run(); } catch { await SG.setPending(key, pend); return [502, { error: "upstream error, retry the same request" }, {}]; }
      if (code !== 200) { await SG.setPending(key, pend); return [code, out, {}]; }
      log(pend.st, oc, true, pend.times); return [200, out, { "PAYMENT-RESPONSE": b64(pend.st) }];
    }
    if (pend) await SG.setPending(key, pend);
    return [409, { error: "payment authorization already used or in flight" }, noPay("replay", c.NETWORK)];
  }
  const bad = SG.precheck(payload, r);
  if (bad) return [402, { error: bad }, noPay(bad, c.NETWORK)];
  const who = SG.payerOf(payload);
  if (FAILS.blocked(who)) return [429, { error: "too many failed settlements, retry later" }, {}];
  const body = { x402Version: 2, paymentPayload: payload, paymentRequirements: r };
  const v = await fac("/verify", body); const tVer = iso();
  if (!v.isValid) return [402, { error: v.invalidReason ?? "invalid" }, noPay(v.invalidReason, c.NETWORK)];
  let code: number, out: unknown;
  try { [code, out] = await run(); } catch (e) {
    if (e instanceof SigningUnavailable) return [503, { error: "signing unavailable, not charged" }, {}];
    return [502, { error: "upstream error, not charged" }, {}];
  }
  if (code !== 200) return [code, out, {}]; // bad input: not settled, not charged
  const st = await fac("/settle", body); const tSet = iso(); const times: [string, string, string] = [tReq, tVer, tSet];
  const tx: string | null = typeof st.transaction === "string" && SG.TX_RE.test(st.transaction) ? st.transaction : null;
  const payer: string | undefined = typeof st.payer === "string" && SG.ADDR_RE.test(st.payer) ? st.payer : (who ?? undefined);
  if (!st.success) {
    const oc: any = tx ? await check(tx, r, payer) : { settled: false, reason: "no_tx_hash" };
    if (oc.settled === true && tx && await SG.claimTx(tx)) { // facilitator said failed, chain says paid: honor it
      log({ ...st, success: true, transaction: tx, payer }, { ...oc, note: "settle_reported_failure_but_confirmed_onchain" }, true, times);
      return [200, out, { "PAYMENT-RESPONSE": b64({ ...st, success: true, transaction: tx }) }];
    }
    FAILS.fail(who);
    return [402, { error: st.errorReason ?? "settle failed" }, { "PAYMENT-RESPONSE": b64(st) }];
  }
  if (!tx) { mismatch("settle_success_without_valid_tx_hash"); return [502, { error: "settlement response invalid, contact support with your payment" }, {}]; }
  if (!await SG.claimTx(tx)) { mismatch("settlement_tx_reused"); return [409, { error: "settlement transaction already used" }, noPay("replay", c.NETWORK)]; }
  const oc: any = await check(tx, r, payer);
  if (mode === "log") {
    log(st, oc, true, times); if (oc.settled !== true) mismatch("onchain_" + String(oc.reason));
    return [200, out, { "PAYMENT-RESPONSE": b64(st) }];
  }
  if (oc.settled === true) { log(st, oc, true, times); return [200, out, { "PAYMENT-RESPONSE": b64(st) }]; }
  if (oc.settled === null) {
    await SG.setPending(key, { path, tx, payer: payer ?? null, st, times });
    return [202, { status: "settled_pending_onchain_confirmation", transaction: tx,
      retry: "repeat the same request with the same payment header; it is served once the transfer is confirmed on Base" }, { "PAYMENT-RESPONSE": b64(st) }];
  }
  log(st, oc, false, times);
  return [402, { error: "settlement not confirmed on-chain: " + String(oc.reason) }, { "PAYMENT-RESPONSE": b64(st) }];
}

if (import.meta.main) {
  const env = (k: string) => Deno.env.get(k);
  if ((env("SNAPSHOT_SCHEDULER") ?? "1") === "1") {
    Deno.cron("bazaar-snapshot", "15 0 * * *", async () => { await runSnapshot(); });
    snapshotIfMissing().catch((e) => console.log("snapshot failed:", (e as Error).name));
  }
  Deno.serve({ port: Number(env("PORT") ?? 8000) }, (req) => handler(req, { env }));
}
