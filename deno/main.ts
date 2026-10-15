// GBMRAFLI Base Reads on Deno Deploy: receive-only x402 v2 seller on Base mainnet. Never signs or sends funds.
// Same routes, 402 challenges, signed facts, export endpoint and record format as api/index.py. Zero LLM.
import { pyDumps } from "./lib/canonical.ts";
import { Chain, makeRpc, type Rpc } from "./lib/chain.ts";
import { preflight, type Fetcher, type Resolver } from "./lib/preflight.ts";
import { PAY_TO_DEFAULT, ROUTES } from "./lib/routes.ts";
import { publicKeyInfo, SigningUnavailable } from "./lib/sign.ts";
import { snapshotIfMissing, runSnapshot } from "./lib/snapshot.ts";
import { EXPORT_FILES, rows } from "./lib/store.ts";
import { recordObservation, recordSale, verifyOnchain } from "./lib/stream.ts";
import { ADDR, b64json, iso, pyQuery, sha256hex, unquote } from "./lib/util.ts";

const USDCS: Record<string, string> = { "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e" };
export type Deps = { env: (k: string) => string | undefined; rpc?: Rpc; fac?: (p: string, body: unknown) => Promise<any>;
  resolver?: Resolver; fetcher?: Fetcher; background?: (p: Promise<unknown>) => void };
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
export function required(path: string, host: string, env: Deps["env"]) {
  const [, desc, ex] = ROUTES[path]; const c = cfg(env);
  return { x402Version: 2, error: "PAYMENT-SIGNATURE header is required", resource: { url: (c.PUBLIC || ("https://" + host)) + path, description: desc, mimeType: "application/json" },
    accepts: [reqFor(path, env)], extensions: { bazaar: { info: { input: { type: "http", method: "GET", queryParams: ex }, output: { type: "json" } }, discoverable: true } } };
}
function facClient(base: string) {
  return async (p: string, body: unknown) => {
    const r = await fetch(base + p, { method: "POST", headers: { "Content-Type": "application/json", "User-Agent": "gbmrafli-base-reads/1.0" }, body: pyDumps(body), signal: AbortSignal.timeout(40000) });
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
  const env = d.env; const c = cfg(env); const rpc = d.rpc ?? makeRpc(c.RPC); const fac = d.fac ?? facClient(c.FAC);
  const raw = req.url.slice(req.url.indexOf("/", 8)); const qi = raw.indexOf("?");
  const path = qi < 0 ? raw : raw.slice(0, qi), qs = qi < 0 ? "" : raw.slice(qi + 1); const q = pyQuery(qs);
  if (path === "/" || path === "/index.json")
    return send(200, { service: "GBMRAFLI Base Reads", network: c.NETWORK, protocol: "x402 v2",
      routes: Object.fromEntries(Object.entries(ROUTES).map(([k, v]) => [k, { price_usdc: v[0] / 1e6, description: v[1] }])) });
  if (path === "/internal/export") { const [code, obj] = await exportRecords(req.headers.get("Authorization") ?? "", q, env); return send(code, obj); }
  if (path === "/x402/preflight/pubkey") {
    try { return send(200, await publicKeyInfo()); } catch (e) { if (e instanceof SigningUnavailable) return send(503, { error: "signing key unavailable" }); throw e; }
  }
  if (!(path in ROUTES)) return send(404, { error: "not found" });
  if (path === "/x402/preflight" && !ADDR.test(c.PAY_TO)) return send(503, { error: "payee not configured" });
  const tReq = iso();
  const sig = req.headers.get("PAYMENT-SIGNATURE") ?? req.headers.get("X-PAYMENT");
  if (!sig) { const pr = required(path, req.headers.get("Host") ?? "", env); return send(402, pr, { "PAYMENT-REQUIRED": b64(pr) }); }
  let payload: unknown;
  try { payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(sig), (ch) => ch.charCodeAt(0)))); } catch { return send(400, { error: "bad payment header" }); }
  const r = reqFor(path, env); const body = { x402Version: 2, paymentPayload: payload, paymentRequirements: r };
  const v = await fac("/verify", body); const tVer = iso();
  if (!v.isValid) return send(402, { error: v.invalidReason ?? "invalid" }, { "PAYMENT-RESPONSE": b64({ success: false, errorReason: v.invalidReason ?? null, network: c.NETWORK }) });
  let code: number, out: unknown;
  try {
    if (path === "/x402/preflight") {
      const u = unquote(q.url ?? "");
      [code, out] = u ? await preflight(u, { resolver: d.resolver, fetcher: d.fetcher }) : [400, { error: "give ?url=https://..." }];
    } else [code, out] = await new Chain(rpc, c.USDC).handle(path, q);
  } catch (e) {
    if (e instanceof SigningUnavailable) return send(503, { error: "signing unavailable, not charged" });
    return send(502, { error: "upstream error, not charged" });
  }
  if (code !== 200) return send(code, out); // bad input: not settled, not charged
  const st = await fac("/settle", body);
  if (!st.success) return send(402, { error: st.errorReason ?? "settle failed" }, { "PAYMENT-RESPONSE": b64(st) });
  const tSet = iso();
  const after = (async () => { // deliver first, then verify on-chain and record (same records as Python)
    try {
      const oc = await verifyOnchain(rpc, st.transaction, r.asset, r.payTo, r.amount, st.payer, c.NETWORK);
      await recordSale(path, r, st, [tReq, tVer, tSet], oc, true, env);
      await recordObservation(path, sha256hex(qs).slice(0, 16), 200, null);
    } catch (e) { console.log("sales log write failed:", (e as Error).name); }
  })();
  (d.background ?? (() => {}))(after);
  return send(200, out, { "PAYMENT-RESPONSE": b64(st) });
}

if (import.meta.main) {
  const env = (k: string) => Deno.env.get(k);
  if ((env("SNAPSHOT_SCHEDULER") ?? "1") === "1") {
    Deno.cron("bazaar-snapshot", "15 0 * * *", async () => { await runSnapshot(); });
    snapshotIfMissing().catch((e) => console.log("snapshot failed:", (e as Error).name));
  }
  Deno.serve({ port: Number(env("PORT") ?? 8000) }, (req) => handler(req, { env }));
}
