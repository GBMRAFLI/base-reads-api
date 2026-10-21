// Base Reads on Deno Deploy: receive-only x402 v2 seller on Base mainnet. Never signs or sends funds.
// Same routes, 402 challenges, signed facts, export endpoint and record format as api/index.py. Zero LLM.
import { pyDumps } from "./lib/canonical.ts";
import { Chain, makeRpc, type Rpc } from "./lib/chain.ts";
import { preflight, type Fetcher, type Resolver } from "./lib/preflight.ts";
import { PAY_TO_DEFAULT, ROUTES } from "./lib/routes.ts";
import DISCOVERY from "./lib/discovery.json" with { type: "json" };
import { CDP_HOST, enabled as cdpEnabled, headers as cdpHeaders } from "./lib/cdp_auth.ts";
import * as SG from "./lib/settle_guard.ts";
import * as LG from "./lib/ledger.ts";
import { SCHEMA, snapshotDates, loadIndex, readSnapMeta, checkUrl, configureOutbound, hostOf } from "./lib/preflight.ts";
import { guardConfig, ipv6Prefix48, ResultCache, WindowLimiter } from "./lib/guards.ts";
import { OUTBOUND } from "./lib/preflight.ts";
import { scheduleReorgCheck, sweepReorg, type ReorgRec } from "./lib/reorg.ts";
import { isoOrNull, keyHistory, loadKey, publicKeyInfo, sign, signJcs, SigningUnavailable } from "./lib/sign.ts";
import { CANON, CONTACT, ISSUER_NAME, SPEC, VERSION } from "./lib/attestation.ts";
import ATT_SCHEMA from "../spec/prepay-check-attestation-v1.schema.json" with { type: "json" };
import { scheduledSnapshot, latestSnapStatus, loadFail, mapErrorCode } from "./lib/snapshot.ts";
import { EXPORT_FILES, kv, rows } from "./lib/store.ts";
import { recordObservation, recordSale, verifyOnchain } from "./lib/stream.ts";
import { ADDR, b64json, iso, pyQuery, sha256hex, unquote } from "./lib/util.ts";

const USDCS: Record<string, string> = { "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e" };
export type Deps = { env: (k: string) => string | undefined; rpc?: Rpc; fac?: (p: string, body: unknown) => Promise<any>;
  resolver?: Resolver; fetcher?: Fetcher; background?: (p: Promise<unknown>) => void;
  check?: (tx: string, r: any, payer: string | undefined) => Promise<any>; ip?: string;
 };
const cfg = (env: Deps["env"]) => {
  const NETWORK = env("NETWORK") || "eip155:8453"; // empty NETWORK= means mainnet
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
  else inpS.queryParams = { type: "object", properties: {}, additionalProperties: false }; // no inputs: declare an empty input schema (see api/index.py)
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
const REF_RE = /^[A-Za-z0-9._-]{1,64}$/;
/** Optional ?ref= attribution tag: logged with paid calls only, never part of the price, challenge or requirements.
 * Self-reported and unverified. If ref appears more than once, the first occurrence wins (same as Python clean_ref). */
export function cleanRef(qs: string): string | null {
  for (const x of qs.split("&")) if (x.startsWith("ref=")) { let v: string; try { v = unquote(x.slice(4)); } catch { return null; } return REF_RE.test(v) ? v : null; }
  return null;
}
/** Query string without ref params, so the logged input hash does not depend on attribution. */
export const stripRef = (qs: string) => qs.split("&").filter((x) => x && !x.startsWith("ref=") && x !== "ref").join("&");
export const VERIFY_402INDEX_DEFAULT = "be918d4df21371f971ccaa589e4ed1adbe9a077a824950b1db21cebfbbf5ae3c";
/** 402index ownership token: INDEX_VERIFY_TOKEN if set, else the built-in constant. Served with no trailing newline. */
export const verifyToken = (env: Deps["env"]) => env("INDEX_VERIFY_TOKEN") || VERIFY_402INDEX_DEFAULT;
export const FAVICON_B64 = "AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0lIA/9JSAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP8AAAAAAAAAAAAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/AAAAAAAAAADSUgD/0lIA/9JSAP/SUgD/0lIA///////////////////////SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAA0lIA/9JSAP/SUgD/0lIA/9JSAP//////0lIA/9JSAP/SUgD//////9JSAP/SUgD/0lIA/9JSAP8AAAAA0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD//////9JSAP/SUgD/0lIA///////SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA///////////////////////SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP8AAAAA0lIA/9JSAP/SUgD/0lIA/9JSAP//////0lIA/9JSAP/SUgD//////9JSAP/SUgD/0lIA/9JSAP8AAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD//////9JSAP/SUgD/0lIA///////SUgD/0lIA/9JSAP/SUgD/AAAAAAAAAADSUgD/0lIA/9JSAP/SUgD/0lIA///////////////////////SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAAAAAAAAAAAAA0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADSUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0lIA/9JSAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="; // 16x16 ICO from scripts/gen_favicon.py
export const FREE_PATHS = new Set(["/", "/index.json", "/favicon.ico", "/llms.txt", "/openapi.json", "/.well-known/402index-verify.txt", "/.well-known/x402-preflight", "/.well-known/x402-preflight-key-history.json", "/.well-known/issuer.json", "/.well-known/prepay-check-attestation-v1.schema.json", "/.well-known/bazaar-snapshot.json", "/x402/preflight/pubkey", "/bazaar/snapshots"]);
/** OpenAPI 3.1 for the paid routes, generated from ROUTES + discovery.json so prices cannot drift from the 402 challenge. */
export function openapi(env: Deps["env"]) {
  const c = cfg(env); const D = DISCOVERY as Record<string, any>; const paths: Record<string, unknown> = {};
  for (const [k, [price, desc]] of Object.entries(ROUTES)) {
    const d = D[k];
    const params = Object.entries(d.params as Record<string, any>).map(([n, sch]) => ({ name: n, in: "query", required: d.required.includes(n), description: sch.description ?? "",
      schema: Object.fromEntries(Object.entries(sch).filter(([kk]) => kk !== "description")) }));
    paths[k] = { get: { operationId: k.replace(/^\/+|\/+$/g, "").replaceAll("/", "_").replaceAll("-", "_"), summary: desc.split(". ")[0].slice(0, 120), description: desc, parameters: params,
      responses: { "200": { description: "Result (served after the payment is confirmed on-chain)", content: { "application/json": { example: d.output } } },
        "402": { description: "Payment required: x402 v2 challenge in the PAYMENT-REQUIRED header and body" } },
      "x-payment-info": { protocols: ["x402"], pricingMode: "fixed", price: (price / 1e6).toFixed(3), amount: String(price), currency: "USDC", asset: c.USDC, network: c.NETWORK, payTo: c.PAY_TO } } };
  }
  return { openapi: "3.1.0", info: { title: "Base Reads", version: "1.0.0", contact: { email: "gbmrafli@agentmail.to" },
    description: "Pay-per-call read API for Base over x402 v2. Deterministic data, no advice.",
    "x-guidance": "Call any path with GET. Without payment you get HTTP 402 and a PAYMENT-REQUIRED challenge (x402 v2, exact scheme, USDC on Base). Sign an EIP-3009 transferWithAuthorization for the stated amount and retry with the PAYMENT-SIGNATURE header; the JSON is returned once the transfer is confirmed on-chain." },
    paths };
}
export function llmsTxt(env: Deps["env"]) {
  const c = cfg(env); const N = c.NETWORK;
  const net = N === "eip155:8453" ? "Base mainnet" : N === "eip155:84532" ? "Base Sepolia" : N;
  const L = ["# Base Reads", "", `> Pay-per-call read API for ${net} over x402 v2. Each paid route answers GET without payment with HTTP 402 and a PAYMENT-REQUIRED challenge; retry with a PAYMENT-SIGNATURE header to get JSON.`, "",
    "## Payment", "", "- Protocol: x402 v2, scheme exact", `- Network: ${N} (${net})`, `- Asset: USDC ${c.USDC}`, "- Authorization: EIP-3009 transferWithAuthorization only (Permit2 is rejected)",
    "- Responses are served only after the transfer is confirmed on-chain", "- Optional ?ref=<tag> (A-Z a-z 0-9 . _ -, max 64) is recorded for attribution and never changes price or challenge", "",
    "## Paid routes (GET, JSON)", "",
    ...Object.entries(ROUTES).map(([k, v]) => `- ${k} (${(v[0] / 1e6).toFixed(3)} USDC): ${v[1]}`),
    "", "## What the responses are", "", "- Verifiable facts only: /base/network, /base/usdc-balance, /base/address-intel and /base/tx-status (once mined) include the Base block number they refer to, so those readings can be reproduced against any Base RPC node",
    "- No verdicts, opinions, scores or predictions, no buy/sell advice, and no language model in the response path",
    "- Compared with a free RPC endpoint: values are normalized (decimal and raw units, gwei, confirmations), pinned to a block number, and several reads are combined into one call",
    "", "## Usage pattern", "", `- To get signed facts about an x402 endpoint before paying it, you can call /x402/preflight?url=<endpoint> (${(ROUTES["/x402/preflight"][0] / 1e6).toFixed(3)} USDC). Facts only, no guarantee.`,
    "- /base/network and /base/usdc-balance responses list related_routes (path and price) for follow-up reads",
    "", "## Discovery (free)", "", "- / : service index with routes and prices", "- /openapi.json : OpenAPI 3.1 description of the paid routes with prices", "- /bazaar/snapshots : daily Bazaar snapshot summary",
    "- /.well-known/bazaar-snapshot.json : signed snapshot series metadata", "- /.well-known/x402-preflight : Pre-pay Check schema and signing key",
    "- /.well-known/x402-preflight-key-history.json : signing key history",
    "- /.well-known/issuer.json : attestation issuer, contact and signing keys (active and retired)", "- /.well-known/prepay-check-attestation-v1.schema.json : JSON Schema of the signed attestation (CC0)", "- /x402/preflight/pubkey : Ed25519 public key for verifying signed facts",
    "- Each 402 challenge carries extensions.bazaar (input schema and output example) for x402 Bazaar listing", "", "Facts only, no investment advice.", ""];
  return L.join("\n");
}
export function root(env: Deps["env"]) {
  const c = cfg(env);
  return { service: "Base Reads", network: c.NETWORK, protocol: "x402 v2", facilitator: facilitatorInfo(env),
    free: ["/llms.txt", "/openapi.json", "/.well-known/402index-verify.txt", "/.well-known/x402-preflight", "/.well-known/x402-preflight-key-history.json", "/.well-known/issuer.json", "/.well-known/prepay-check-attestation-v1.schema.json", "/.well-known/bazaar-snapshot.json", "/x402/preflight/pubkey", "/bazaar/snapshots"],
    routes: Object.fromEntries(Object.entries(ROUTES).map(([k, v]) => [k, { price_usdc: v[0] / 1e6, description: v[1] }])) };
}
export async function wellKnown(env: Deps["env"]) {
  const pub = await publicKeyInfo(env);
  return { service: "Base Reads", schema: SCHEMA, alg: "Ed25519", key_id: pub.key_id, public_key_b64: pub.public_key_b64,
    fingerprint: pub.fingerprint, fingerprint_short: pub.fingerprint_short, created_at: pub.created_at,
    attestation: { spec: SPEC, version: VERSION, canonicalization: CANON, issuer: "/.well-known/issuer.json", schema: "/.well-known/prepay-check-attestation-v1.schema.json" },
    verify: ["Take the paid /x402/preflight response body: {facts, signature} (legacy form; the v1.0 envelope is in \"attestation\", see /.well-known/issuer.json).",
      "Serialize facts as canonical JSON: keys sorted, separators (',', ':'), ASCII-only escapes (Python json.dumps(facts, sort_keys=True, separators=(',', ':'))).",
      "Verify signature.value_b64 (base64) over those bytes with Ed25519 (RFC 8032) and public_key_b64 (32-byte raw key).",
      "Check signature.key_id matches key_id here; key_id = first 16 hex chars of sha256(raw public key)."],
    facilitator: facilitatorInfo(env), repo: env("REPO_URL") ?? "https://github.com/GBMRAFLI/base-reads-api",
    routes: { pubkey: "/x402/preflight/pubkey", key_history: "/.well-known/x402-preflight-key-history.json", paid_check: "/x402/preflight", snapshots: "/bazaar/snapshots", snapshot_meta: "/.well-known/bazaar-snapshot.json" } };
}
/** Attestation issuer document: identity, contact and every signing key (active + retired) so old attestations stay verifiable. */
export async function issuerDoc(env: Deps["env"]) {
  const h = await keyHistory(env); const base = cfg(env).PUBLIC.replace(/\/+$/, "");
  return { spec: SPEC, version: VERSION, issuer: { name: ISSUER_NAME, contact: CONTACT, issuer_url: base ? base + "/.well-known/issuer.json" : null },
    canonicalization: CANON, signature_alg: "Ed25519", keys: [h.current, ...h.retired],
    schema: "/.well-known/prepay-check-attestation-v1.schema.json",
    key_policy: "Signing keys are generated and held only in the production server environment and are never published or exported. Rotation adds the new key as active and keeps old keys listed as retired with retired_at.",
    verify: ["Remove the \"signature\" member from the attestation object.",
      "Serialize the rest with RFC 8785 JSON Canonicalization Scheme (JCS) as UTF-8 bytes.",
      "Find the key in keys[] whose key_id equals signature.key_id; key_id = first 16 hex chars of sha256(raw 32-byte public key).",
      "Verify signature.value_b64 (base64) over those bytes with Ed25519 (RFC 8032).",
      "Optionally reject if now > expires_at, or if the key was retired before issued_at."] };
}
/** Free, signed metadata about the daily Bazaar snapshot series (no snapshot contents). */
/** L3: the signed snapshot meta is cached for 60 s (it reads up to 31 KV entries and signs on every build). */
let META_CACHE: { at: number; v: unknown } | null = null; const META_TTL_MS = 60_000;
export async function snapshotMeta(env: Deps["env"] = (k) => Deno.env.get(k), now = Date.now()) {
  if (META_CACHE && now - META_CACHE.at < META_TTL_MS) return META_CACHE.v as Awaited<ReturnType<typeof buildSnapshotMeta>>;
  const v = await buildSnapshotMeta(env); META_CACHE = { at: now, v }; return v;
}
async function buildSnapshotMeta(env: Deps["env"]) {
  const dates = await snapshotDates(); const last = dates.at(-1) ?? null; // last successful snapdate
  const today = new Date().toISOString().slice(0, 10);
  const todayFail = await loadFail(today);
  const st = await latestSnapStatus(last);
  const status = todayFail && (!last || today >= last) ? "failed" as const : st.status;
  const failed_pages = todayFail && status === "failed" ? todayFail.failed_pages : st.failed_pages;
  // L1: fixed error codes only (never free-form exception text in the signed payload)
  const last_error = todayFail && status === "failed"
    ? (todayFail.error_code || mapErrorCode(todayFail.error))
    : (st.error_code ?? null);
  // L2/L3: covered_listings == listings; last_attempt_at from stored meta or fail record only (null if unknown)
  let covered = 0;
  let last_attempt_at: string | null = todayFail?.at ?? null;
  if (last) {
    const { readSnapMeta } = await import("./lib/preflight.ts");
    const m = await readSnapMeta(last);
    covered = m?.listings ?? 0;
    if (!last_attempt_at) last_attempt_at = m?.last_attempt_at ?? null;
  }
  const lastSha = last ? ((await (await import("./lib/preflight.ts")).readSnapMeta(last))?.sha256 ?? null) : null;
  // L3: per-day content hashes of the recent snapshots are inside the signed meta, so a verifier can bind any recent
  // attestation's snapshot_sha256 to a signed value (not only the newest day).
  const { readSnapMeta: rsm } = await import("./lib/preflight.ts"); const snapshot_sha256: Record<string, string | null> = {};
  for (const d of dates.slice(-30)) snapshot_sha256[d] = (await rsm(d))?.sha256 ?? null;
  const meta = { version: 1, started_at: dates[0] ?? null, last_updated: last, last_sha256: lastSha, snapshot_sha256,
    last_attempt_at, total_snapshots: dates.length, covered_listings: covered,
    last_status: status, last_failed_pages: failed_pages, last_error };
  return { metadata: meta, signature: await signJcs(meta, env), pubkey_url: "/x402/preflight/pubkey" };
}
const SNAP_SUM = new Map<string, Record<string, unknown>>();
export async function snapshotSummary(limit = 30) {
  const out: Record<string, unknown>[] = [];
  for (const d of (await snapshotDates()).slice(-limit).reverse()) {
    if (!SNAP_SUM.has(d)) {
      const idx: any = await loadIndex(d); const res: Record<string, any> = idx.resources ?? {};
      const vals = Object.values(res);
      const hosts = idx.tier === "aggregate" ? (idx.aggregate?.hosts ?? 0) : Object.keys(idx.hosts ?? {}).length;
      const wallets = idx.tier === "aggregate" ? (idx.aggregate?.payout_wallets ?? 0) : Object.keys(idx.wallet_hosts ?? {}).length;
      const status = (await latestSnapStatus(d)).status ?? idx.status ?? idx.coverage?.status ?? null;
      const sm = await readSnapMeta(d);
      SNAP_SUM.set(d, { date: d, sha256: sm?.sha256 ?? null, status, resources: idx.tier === "full" ? vals.length : (idx.listings ?? 0), hosts, payout_wallets: wallets,
        calls30d_total: vals.reduce((a: number, r: any) => a + (r.calls30d || 0), 0), payers30d_total: vals.reduce((a: number, r: any) => a + (r.payers30d || 0), 0) });
    }
    out.push(SNAP_SUM.get(d)!);
  }
  return { source: "x402 Bazaar discovery API, crawled daily at 00:15 UTC", latest: latestOf(out), snapshots: out };
}
/** Freshness and completeness of the newest snapshot: date, status (complete | partial | failed | null), listing count, age in days, fresh (age <= 3 days). */
export function latestOf(out: Record<string, any>[], now = Date.now()) {
  const s = out[0]; if (!s) return { date: null, status: null, listings: 0, age_days: null, fresh: false };
  const age = Math.max(0, Math.floor((now - Date.parse(s.date + "T00:00:00Z")) / 86400000));
  return { date: s.date, status: s.status ?? null, listings: s.resources ?? 0, age_days: age, fresh: age <= 3 };
}
/** On Base mainnet (including empty NETWORK=) paid routes need PUBLIC_URL: resource URLs never come from the Host header.
 * Missing PUBLIC_URL is a startup warning, not a refusal, so free routes stay up on any host; paid routes answer 503. */
export function publicUrlError(env: Deps["env"]): string | null {
  return cfg(env).NETWORK === MAINNET && !cfg(env).PUBLIC ? "PUBLIC_URL is required on Base mainnet (resource URLs are never derived from the Host header)" : null;
}
export function resourceOrigin(host: string, env: Deps["env"]): string {
  const c = cfg(env); if (c.PUBLIC) return c.PUBLIC;
  const e = publicUrlError(env); if (e) throw new Error(e);
  return "https://" + safeHost(host); // testnet / local only
}
export function required(path: string, host: string, env: Deps["env"]) {
  const [, desc] = ROUTES[path];
  return { x402Version: 2, error: "PAYMENT-SIGNATURE header is required", resource: { url: resourceOrigin(host, env) + path, description: desc, mimeType: "application/json" },
    accepts: [reqFor(path, env)], extensions: { bazaar: bazaar(path) } };
}
export function facClient(base: string, env: Deps["env"], f: typeof fetch = fetch) {
  return async (p: string, body: unknown) => {
    const r = await f(base + p, { method: "POST", headers: { "Content-Type": "application/json", "User-Agent": "base-reads/1.0", ...(await cdpHeaders(base, p, env)) }, body: pyDumps(body), signal: AbortSignal.timeout(40000) });
    let out: any; try { out = await r.json(); } catch { out = {}; }
    if (!out || typeof out !== "object" || Array.isArray(out)) out = {};
    const er = extensionStatus(r.headers.get("EXTENSION-RESPONSES"));
    if (er) Object.defineProperty(out, "extensionResponses", { value: er, enumerable: false });
    return out;
  };
}
/** Decode the facilitator EXTENSION-RESPONSES header (base64 JSON keyed by extension name); null when absent or malformed. */
export function extensionStatus(h: string | null): Record<string, any> | null {
  if (!h || h.length > 16384) return null;
  try { const o = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(h.trim()), (ch) => ch.charCodeAt(0))));
    return o && typeof o === "object" && !Array.isArray(o) ? o : null; } catch { return null; }
}
/** One log line with the bazaar extension outcome only (status and short reason); never logs payloads or keys. */
export function logBazaar(stage: string, path: string, res: any) {
  const b = res?.extensionResponses?.bazaar; if (!b || typeof b !== "object") return;
  const status = typeof b.status === "string" ? b.status.replace(/[^\x20-\x7e]/g, " ").slice(0, 32) : "unknown";
  const why = typeof b.rejectedReason === "string" ? " reason=" + b.rejectedReason.replace(/[^\x20-\x7e]/g, " ").replace(/0x[0-9a-fA-F]{16,}/g, "0x…").slice(0, 200) : "";
  console.log(`bazaar extension ${stage} ${path}: ${status}${why}`);
}
/** Max size of client-sent paymentPayload.extensions, measured on the re-serialized JSON (JSON.stringify of the parsed value,
 * UTF-8 bytes), not on the raw header; the whole header is already capped at MAX_HEADER (16 KB). Larger values are refused before any claim. */
export const MAX_EXTENSIONS_BYTES = 8192;
export function extensionsTooLarge(payload: Record<string, any>): boolean {
  if (payload.extensions === undefined) return false;
  try { return new TextEncoder().encode(JSON.stringify(payload.extensions) ?? "").length > MAX_EXTENSIONS_BYTES; } catch { return true; }
}
/** Facilitator-bound copy of the payment payload: resource and extensions are always the server's own values from the
 * 402 challenge (client-sent extensions are dropped, never forwarded). Both keys sit outside the EIP-3009 signature;
 * the signed accepted/payload blocks are passed through unchanged and the input object is not mutated. */
export function withDiscovery(payload: Record<string, any>, path: string, host: string, env: Deps["env"]): Record<string, any> {
  const pr = required(path, host, env);
  return { ...payload, resource: pr.resource, extensions: { bazaar: pr.extensions.bazaar } };
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
const HDRS = { "Content-Type": "application/json", "X-Content-Type-Options": "nosniff", "Access-Control-Allow-Origin": "*", "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE" };
const send = (code: number, obj: unknown, hd: Record<string, string> = {}) => new Response(pyDumps(obj), { status: code, headers: { ...HDRS, ...hd } });
const b64 = (o: unknown) => b64json(o, pyDumps);

/** HEAD on free routes: same status and headers as GET, no body. Paid routes keep their previous behaviour (501). */
export async function handler(req: Request, d: Deps): Promise<Response> {
  if (req.method === "HEAD") {
    const raw = req.url.slice(req.url.indexOf("/", 8)); const qi = raw.indexOf("?"); // same raw path as GET routing
    if (!FREE_PATHS.has(qi < 0 ? raw : raw.slice(0, qi))) return send(501, { error: "unsupported method" });
    const r = await handleGet(new Request(req.url, { method: "GET", headers: req.headers }), d); await r.body?.cancel();
    return new Response(null, { status: r.status, headers: r.headers });
  }
  return await handleGet(req, d);
}
/** Liveness for deploys: signing key loads and a KV write/read/delete round-trip works. Outputs only booleans. */
export async function health(env: Deps["env"]): Promise<[number, Record<string, boolean>]> {
  let signing = false, store = false;
  try { await loadKey(env); signing = true; } catch { /* reported as false */ }
  try {
    const k = await kv(); const key = ["health", crypto.randomUUID()]; const v = crypto.randomUUID();
    await k.set(key, v, { expireIn: 60_000 }); store = (await k.get(key)).value === v; await k.delete(key);
  } catch { store = false; }
  const ok = signing && store; return [ok ? 200 : 503, { ok, signing, store }];
}
async function handleGet(req: Request, d: Deps): Promise<Response> {
  if (req.method !== "GET") return send(501, { error: "unsupported method" });
  const env = d.env; const c = cfg(env); const rpc = d.rpc ?? makeRpc(c.RPC); const fac = d.fac ?? facClient(c.FAC, env);
  const raw = req.url.slice(req.url.indexOf("/", 8)); const qi = raw.indexOf("?");
  const path = qi < 0 ? raw : raw.slice(0, qi), qs = qi < 0 ? "" : raw.slice(qi + 1); const q = pyQuery(qs);
  if (path === "/" || path === "/index.json") return send(200, root(env));
  if (path === "/openapi.json") return send(200, openapi(env), { "Cache-Control": "public, max-age=3600" });
  if (path === "/favicon.ico") return new Response(Uint8Array.from(atob(FAVICON_B64), (ch) => ch.charCodeAt(0)), { status: 200, headers: { ...HDRS, "Content-Type": "image/x-icon", "Cache-Control": "public, max-age=86400" } });
  if (path === "/.well-known/402index-verify.txt") return new Response(verifyToken(env), { status: 200, headers: { ...HDRS, "Content-Type": "text/plain; charset=utf-8" } });
  if (path === "/healthz") { // local deploy checks only: any non-loopback peer (incl. proxied clients) gets 404
    if (!d.ip || !isLoopback(d.ip)) return send(404, { error: "not found" });
    return send(...await health(env), { "Cache-Control": "no-store" });
  }
  if (path === "/llms.txt") return new Response(llmsTxt(env), { status: 200, headers: { ...HDRS, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
  if (path === "/.well-known/x402-preflight") {
    try { return send(200, await wellKnown(env)); } catch (e) { if (e instanceof SigningUnavailable) return send(503, { error: "signing key unavailable" }); throw e; }
  }
  if (path === "/bazaar/snapshots") return send(200, await snapshotSummary());
  if (path === "/.well-known/prepay-check-attestation-v1.schema.json") return send(200, ATT_SCHEMA);
  if (path === "/.well-known/issuer.json") {
    try { return send(200, await issuerDoc(env)); } catch (e) { if (e instanceof SigningUnavailable) return send(503, { error: "signing key unavailable" }); throw e; }
  }
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
  if (publicUrlError(env)) return send(503, { error: "public origin not configured" }); // mainnet without PUBLIC_URL: never use Host
  if (!sig) {
    // A6: unpaid 402s are pure computation (no DNS, GET or RPC) and limited per client IP.
    // IPv6: per-/64 key plus a per-/48 aggregate, so a prefix spray is bounded without filling the per-client table.
    const p48 = ipv6Prefix48(d.ip);
    if (d.ip && (!abuse(env).unpaid.allow(SG.ipKey(d.ip) ?? d.ip) || (p48 !== null && !abuse(env).unpaid48.allow(p48)))) {
      return send(429, { error: "too many unpaid requests, retry later", scope: "ip" }, { "Retry-After": "60" });
    }
    const pr = required(path, req.headers.get("Host") ?? "", env); return send(402, pr, { "PAYMENT-REQUIRED": b64(pr) });
  }
  const [code, out, hd] = await paid(path, q, qs, sig, tReq, d, c, rpc, fac, req.headers.get("Host") ?? "");
  return send(code, out, hd);
}

const FAILS = new SG.FailLimiter();
type Abuse = { unpaid: WindowLimiter; unpaid48: WindowLimiter; hostPayer: WindowLimiter; perHost: WindowLimiter; cache: ResultCache<unknown>; probing: Set<string> };
let ABUSE: Abuse | null = null;
/** Per-process abuse guards (A6 unpaid limit, per-target outbound limit, A7 payer+target cache, outbound concurrency). */
export function abuse(env: Deps["env"]): Abuse {
  if (!ABUSE) {
    const g = guardConfig(env); configureOutbound(g.outboundConcurrency);
    ABUSE = { unpaid: new WindowLimiter(g.unpaidPerMin), unpaid48: new WindowLimiter(g.unpaidPer48PerMin), hostPayer: new WindowLimiter(g.hostPayerPerMin),
      perHost: new WindowLimiter(g.perHostPerMin), cache: new ResultCache(g.cacheTtlMs), probing: new Set() };
  }
  return ABUSE;
}
/** A4 sweep with the production on-chain check; incidents go to the observations log. */
export async function reorgSweep(env: Deps["env"], check?: (r: ReorgRec) => Promise<any>, now = Date.now()) {
  const rpc = makeRpc(cfg(env).RPC);
  const chk = check ?? ((x: ReorgRec) => verifyOnchain(rpc, x.tx, x.asset, x.payTo, x.amount, x.payer, x.network, 3, 1000, undefined, x.nonce, x.minConf));
  return await sweepReorg(chk, async (x, why) => {
    console.log("INCIDENT", why, x.path, x.tx);
    await recordObservation(x.path, "incident", 0, null, why);
  }, now);
}
/** M1: a settled check whose pending window passed unserved is logged as an incident (refund path: SECURITY.md). */
export async function pendingSweep(now = Date.now()) {
  return await SG.sweepExpiredPending(async (_key, rec) => {
    console.log("INCIDENT pending_expired_unserved", rec.path, rec.tx);
    await recordObservation(String(rec.path ?? "/x402/preflight"), "incident", 0, null, "pending_expired_unserved");
  }, now);
}
export async function resetGuards() { await FAILS.clear(); ABUSE = null; META_CACHE = null; }
export const MAINNET = "eip155:8453";
/** MIN_CONFIRMATIONS clamped to 1..64 (non-numeric or empty -> 1). */
export function minConfirmations(env: Deps["env"]): number {
  const n = Math.floor(Number(env("MIN_CONFIRMATIONS") || 1)); return Number.isFinite(n) ? Math.min(64, Math.max(1, n)) : 1;
}
/** Sent with every "authorization already used" 402: a submitted authorization is spent even if settlement failed. */
export const REUSE_HINT = "this authorization was already submitted for settlement and cannot be reused, even if that attempt failed; sign a new authorization with a new nonce";
/** ONCHAIN_CHECK=log (serve on facilitator success) is refused on Base mainnet: block is forced there. */
export function onchainMode(env: Deps["env"]): "block" | "log" {
  const m = env("ONCHAIN_CHECK") ?? "block";
  return m === "log" && (env("NETWORK") || MAINNET) !== MAINNET ? "log" : "block";
}
/** Non-fatal configuration problems, logged once at startup. */
export function startupWarnings(env: Deps["env"]): string[] {
  const w: string[] = []; const ca = env("SIGNING_KEY_CREATED_AT");
  if (publicUrlError(env)) w.push("PUBLIC_URL is not set on Base mainnet: paid routes answer 503 until it is set (free routes stay up)");
  if (ca && !isoOrNull(ca)) w.push("SIGNING_KEY_CREATED_AT is not strict ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ); published as null");
  try { const h = JSON.parse(env("SIGNING_KEY_HISTORY") || "[]");
    if (!Array.isArray(h)) w.push("SIGNING_KEY_HISTORY is not a JSON list; ignored");
    else h.forEach((k: any, i: number) => { for (const f of ["created_at", "retired_at"]) if (k?.[f] != null && !isoOrNull(k[f])) w.push(`SIGNING_KEY_HISTORY[${i}].${f} is not strict ISO-8601 UTC; published as null`); });
  } catch { w.push("SIGNING_KEY_HISTORY is not valid JSON; ignored"); }
  return w;
}
export function assertOnchainMode(env: Deps["env"]) {
  if (env("ONCHAIN_CHECK") === "log" && (env("NETWORK") || MAINNET) === MAINNET) throw new Error("ONCHAIN_CHECK=log is not allowed on Base mainnet");
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
  fac: (p: string, body: unknown) => Promise<any>, host = ""): Promise<[number, unknown, Record<string, string>]> {
  const env = d.env; const mode = onchainMode(env); const N = c.NETWORK;
  const [payload, err] = SG.parsePayment(sig);
  if (err || !payload) return [400, { error: err }, {}];
  const r = reqFor(path, env);
  if (extensionsTooLarge(payload)) return [400, { error: "payment payload extensions too large" }, {}];
  const bad = SG.precheck(payload, r); // before the claim: malformed/foreign payloads never consume a nonce slot
  if (bad) return [402, { error: bad }, noPay(bad, N)];
  const who = SG.payerOf(payload)!; const nonce = SG.nonceOf(payload)!; const ids = { ip: d.ip ?? null, payer: who };
  const minConf = minConfirmations(env);
  const check = d.check ?? ((tx: string, rq: any, payer: string | undefined) => verifyOnchain(rpc, tx, rq.asset, rq.payTo, rq.amount, payer, N, 3, 1000, undefined, nonce, minConf));
  const bg = d.background ?? (() => {});
  const sale = (tx: string) => ({ success: true, transaction: tx, payer: who, network: N });
  const log = (tx: string, oc: any, served: boolean, times: [string, string, string]) => {
    bg((async () => {
      try { await recordSale(path, r, sale(tx), times, oc, served, env, cleanRef(qs)); await recordObservation(path, (await sha256hex(stripRef(qs))).slice(0, 16), served ? 200 : 402, null); }
      catch (e) { console.log("sales log write failed:", (e as Error).name); }
    })());
  };
  const mismatch = (why: string) => bg(recordObservation(path, "settle-mismatch", 502, null, why).catch(() => {}));
  // Pre-pay Check settles BEFORE probing the target (A1): an unsettled payment never causes outbound traffic.
  const settleFirst = path === "/x402/preflight";
  const G = abuse(env);
  const cacheKey = (u: string) => who + "|" + u;
  /** Probe the PAID url (or serve the payer+target cache, A7). The caller holds an outbound slot (M1). */
  const runPreflight = async (u: string): Promise<[number, unknown]> => {
    if (!u) return [400, { error: "give ?url=https://..." }];
    const hit = G.cache.get(cacheKey(u)); if (hit) return [200, hit];
    const ttlRaw = env("ATTESTATION_TTL_S") ?? ""; const ttl = /^[0-9]{1,6}$/.test(ttlRaw) ? Number(ttlRaw) : undefined; // normTtl: int >= 1 else 900
    const res = await preflight(u, { resolver: d.resolver, fetcher: d.fetcher, env, rpc, ttlS: ttl, slotHeld: true,
      issuerUrl: c.PUBLIC ? c.PUBLIC.replace(/\/+$/, "") + "/.well-known/issuer.json" : null });
    if (res[0] === 200) G.cache.set(cacheKey(u), res[1]);
    return res;
  };
  const run = async (): Promise<[number, unknown]> => {
    if (path === "/x402/preflight") return await runPreflight(unquote(q.url ?? ""));
    return await new Chain(rpc, c.USDC).handle(path, q);
  };
  /** M1: reserve one global outbound slot and the payer's single probe slot, without waiting. null -> busy. */
  const reserve = (): (() => void) | null => {
    if (G.probing.has(who)) return null;
    const rel = OUTBOUND.tryAcquire(); if (!rel) return null;
    G.probing.add(who); let done = false;
    return () => { if (done) return; done = true; G.probing.delete(who); rel(); };
  };
  const BUSY503: [number, unknown, Record<string, string>] = [503, { error: "probe capacity busy, retry shortly", charged: false }, { "Retry-After": "5" }];
  /** Pending retry of a settled Pre-pay Check (L1): uses the url that was paid for, the per target+payer limit,
   * the global per-target budget, an outbound slot, and at most 3 attempts. */
  const MAX_TRIES = 3;
  const retryPending = async (key: string, pend: any, oc: any): Promise<[number, unknown, Record<string, string>]> => {
    const u: string = typeof pend.url === "string" ? pend.url : "";
    const tries: number = Number.isInteger(pend.tries) ? pend.tries : 0;
    if (!u || tries >= MAX_TRIES) {
      bg(recordObservation(path, "incident", 0, null, "pending_retries_exhausted").catch(() => {}));
      return [502, { error: "payment settled but the check could not be completed after " + MAX_TRIES + " attempts; contact support with your transaction", transaction: pend.tx }, payResp(N, true, pend.tx, who)];
    }
    const cached = G.cache.get(cacheKey(u));
    if (!cached) {
      if (!G.hostPayer.allow(hostOf(u) + "|" + who)) { await SG.setPending(key, pend); return [429, { error: "too many attempts for this target, retry later", scope: "target_payer", transaction: pend.tx }, { "Retry-After": "60" }]; }
      // M1: a check already queued on the target budget skips the budget (it was settled first; served ahead of new settles)
      if (!pend.queued && !G.perHost.allow(hostOf(u))) { await SG.setPending(key, pend); return [202, { status: "settled_queued_target_budget", transaction: pend.tx, retry: "repeat the same request after 60 s" }, payResp(N, true, pend.tx, who)]; }
    }
    const slot = cached ? () => {} : reserve();
    if (!slot) { await SG.setPending(key, pend); return [503, { error: "probe capacity busy, retry shortly", transaction: pend.tx }, { "Retry-After": "5" }]; }
    let code = 0, out: unknown = null;
    try { [code, out] = await runPreflight(u); } catch { code = 0; } finally { slot(); }
    if (code !== 200) { await SG.setPending(key, { ...pend, tries: tries + 1 }); return [502, { error: "upstream error, retry the same request", transaction: pend.tx, attempts_left: MAX_TRIES - tries - 1 }, {}]; }
    if (pend.queued && pend.host) await SG.queueDel(pend.host, pend.until, key);
    log(pend.tx, oc, true, pend.times); return [200, out, payResp(N, true, pend.tx, who)];
  };
  const busy: [number, unknown, Record<string, string>] = [429, { error: "too many concurrent payments, retry shortly", scope: "concurrency" }, {}];
  const release = await SG.acquireSlots({ ip: ids.ip }); // per-IP slot now; per-payer slot only after verify (L1)
  if (!release) return busy;
  const held: { payer: (() => Promise<void>) | null; slot: (() => void) | null } = { payer: null, slot: null };
  try { return await paidLocked(); } finally { held.slot?.(); if (held.payer) await held.payer(); await release(); }
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
      if (settleFirst) return await retryPending(key, pend, oc);
      let code: number, out: unknown;
      try { [code, out] = await run(); } catch { await SG.setPending(key, pend); return [502, { error: "upstream error, retry the same request" }, {}]; }
      if (code !== 200) { await SG.setPending(key, pend); return [code, out, {}]; }
      log(pend.tx, oc, true, pend.times); return [200, out, payResp(N, true, pend.tx, who)];
    }
    if (pend) await SG.setPending(key, pend);
    return [409, { error: "payment authorization already used or in flight" }, noPay("replay", N)];
  }
  // KV claim is only an in-flight lock; the append-only ledger is the source of truth for spent authorizations,
  // so a rolled-back or restored KV can never let a spent authorization through again.
  if (await SG.authUsed(key)) return [402, { error: "payment authorization already used", hint: REUSE_HINT }, noPay("replay", N)];
  const body = { x402Version: 2, paymentPayload: withDiscovery(payload!, path, host, env), paymentRequirements: r };
  const v = await fac("/verify", body); const tVer = iso(); logBazaar("verify", path, v);
  if (!v.isValid) { const why = facErr(v.invalidReason); await FAILS.fail({ ip: ids.ip }, "verify"); return [402, { error: why }, noPay(why, N)]; }
  held.payer = await SG.acquireSlots({ payer: who }); // L1: a forged `from` never reaches this line
  if (!held.payer) { await SG.unclaim(key); return busy; } // not settled: the same authorization may be retried
  if (await FAILS.blocked({ payer: who })) { await SG.unclaim(key); return [429, { error: "too many failed payments, retry later", scope: "payer" }, {}]; }
  let code = 0, out: unknown = null;
  if (settleFirst) {
    // Cheap input checks before settlement (not charged, authorization released): URL shape, SSRF policy (A8), per-target budget.
    const u = unquote(q.url ?? "");
    if (!u) { await SG.unclaim(key); return [400, { error: "give ?url=https://...", charged: false }, {}]; }
    const chk = await checkUrl(u, d.resolver);
    if (!chk.u) { await SG.unclaim(key); return [400, { error: chk.err, target_url_allowed: false, charged: false }, {}]; }
    if (!G.cache.get(cacheKey(u))) {
      // H1: before settlement only a per target+payer limit applies; the global per-target budget is counted after settlement.
      if (!G.hostPayer.allow(hostOf(u) + "|" + who)) {
        await SG.unclaim(key); return [429, { error: "too many checks of this target by this payer in the last minute, retry later", scope: "target_payer", charged: false }, { "Retry-After": "60" }];
      }
      // M1: reserve the outbound slot now; if none is free, refuse before settlement (not charged).
      held.slot = reserve();
      if (!held.slot) { await SG.unclaim(key); return BUSY503; }
    }
  } else {
    try { [code, out] = await run(); } catch (e) {
      if (e instanceof SigningUnavailable) return [503, { error: "signing unavailable, not charged" }, {}];
      return [502, { error: "upstream error, not charged" }, {}];
    }
    if (code !== 200) return [code, out, {}]; // bad input: not settled, not charged
  }
  /** A4: persist a post-delivery settlement re-check in KV (survives restarts); the reorg-recheck cron processes it. */
  const watchReorg = (tx: string) => {
    const ms = /^[0-9]{1,7}$/.test(env("REORG_RECHECK_MS") ?? "") ? Number(env("REORG_RECHECK_MS")) : 120_000;
    bg(scheduleReorgCheck({ path, tx, payer: who, asset: r.asset, payTo: r.payTo, amount: r.amount, nonce, network: N, minConf }, ms)
      .catch((e) => console.log("reorg schedule failed:", (e as Error).name)));
  };
  /** Serve after settlement. Settle-first routes run the handler now; if it cannot finish, the payment is parked
   * and the same request is served on retry (pending path). */
  const deliver = async (tx: string, oc: any, times: [string, string, string]): Promise<[number, unknown, Record<string, string>]> => {
    if (settleFirst) {
      const u = unquote(q.url ?? "");
      // H1: the global per-target budget is counted only after a successful settlement; over budget -> queue, never refuse.
      // M1: FIFO: while settled checks for this target wait in the queue, a new settle queues behind them.
      if (!G.cache.get(cacheKey(u)) && (await SG.queueHas(hostOf(u)) || !G.perHost.allow(hostOf(u)))) {
        held.slot?.(); held.slot = null;
        await SG.setPending(key, { path, tx, times, url: u, tries: 0, queued: true, host: hostOf(u) });
        return [202, { status: "settled_queued_target_budget", transaction: tx, retry: "repeat the same request with the same payment header after 60 s" }, payResp(N, true, tx, who)];
      }
      let ok = false;
      try { [code, out] = await runPreflight(u); ok = code === 200; } catch { ok = false; } finally { held.slot?.(); held.slot = null; }
      if (!ok) {
        await SG.setPending(key, { path, tx, times, url: u, tries: 1 });
        return [502, { error: "payment settled but the check could not complete; repeat the same request to receive it", transaction: tx }, payResp(N, true, tx, who)];
      }
    }
    log(tx, oc, true, times); watchReorg(tx);
    return [200, out, payResp(N, true, tx, who)];
  };
  // point of no return: record the authorization as consumed (fsync'ed) before asking for settlement
  if (!await SG.consumeAuth(key, { path, payload_sha256: await SG.payloadHash(payload!) })) return [402, { error: "payment authorization already used", hint: REUSE_HINT }, noPay("replay", N)];
  const st = await fac("/settle", body); const tSet = iso(); logBazaar("settle", path, st); const times: [string, string, string] = [tReq, tVer, tSet];
  const tx: string | null = typeof st.transaction === "string" && SG.TX_RE.test(st.transaction) ? st.transaction.toLowerCase() : null;
  if (typeof st.payer === "string" && st.payer.toLowerCase() !== who) mismatch("facilitator_payer_differs_from_signed_from");
  if (!st.success) {
    const oc: any = tx ? await check(tx, r, who) : { settled: false, reason: "no_tx_hash" };
    if (oc.settled === true && tx && await SG.claimTx(tx)) { // facilitator said failed, chain says paid: honor it
      return await deliver(tx, { ...oc, note: "settle_reported_failure_but_confirmed_onchain" }, times);
    }
    const why = facErr(st.errorReason); await FAILS.fail(ids, "settle");
    return [402, { error: why, hint: REUSE_HINT }, payResp(N, false, tx, who, why)]; // the authorization is spent
  }
  if (!tx) { mismatch("settle_success_without_valid_tx_hash"); return [502, { error: "settlement response invalid, contact support with your payment" }, {}]; }
  if (!await SG.claimTx(tx)) { mismatch("settlement_tx_reused"); return [409, { error: "settlement transaction already used" }, noPay("replay", N)]; }
  const oc: any = await check(tx, r, who);
  if (mode === "log") {
    if (oc.settled !== true) mismatch("onchain_" + String(oc.reason));
    return await deliver(tx, oc, times);
  }
  if (oc.settled === true) return await deliver(tx, oc, times);
  if (oc.settled === null) {
    held.slot?.(); held.slot = null;
    await SG.setPending(key, { path, tx, times, ...(settleFirst ? { url: unquote(q.url ?? ""), tries: 0 } : {}) });
    return [202, { status: "settled_pending_onchain_confirmation", transaction: tx,
      retry: "repeat the same request with the same payment header; it is served once the transfer is confirmed on Base" }, payResp(N, true, tx, who)];
  }
  log(tx, oc, false, times);
  return [402, { error: "settlement not confirmed on-chain: " + String(oc.reason) }, payResp(N, false, tx, who, "not_confirmed_onchain")];
}
}

/** Behind a local reverse proxy (TRUST_PROXY=1) the peer is loopback; use the last X-Forwarded-For hop the proxy appended. */
/** Loopback: 127.0.0.0/8, ::1, and IPv4-mapped ::ffff:127.x.x.x. */
export function isLoopback(ip: string) {
  const v = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (v === "::1" || v === "0:0:0:0:0:0:0:1") return true;
  const v4 = v.startsWith("::ffff:") ? v.slice(7) : v;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v4);
  return !!m && m.slice(1).every((x) => Number(x) <= 255);
}
/** Bind address: HOST if set, else loopback when behind a proxy, else all interfaces. */
export const bindHost = (env: Deps["env"]) => env("HOST") ?? (env("TRUST_PROXY") === "1" ? "127.0.0.1" : "0.0.0.0");
export function clientIp(req: Request, peer: string, env: Deps["env"]) {
  if (env("TRUST_PROXY") !== "1" || !isLoopback(peer)) return peer;
  const hop = (req.headers.get("x-forwarded-for") ?? "").split(",").pop()?.trim() ?? "";
  return /^[0-9a-fA-F:.]{2,45}$/.test(hop) ? hop : peer;
}

if (import.meta.main) {
  const env = (k: string) => Deno.env.get(k);
  if ((env("SNAPSHOT_SCHEDULER") ?? "1") === "1") {
    Deno.cron("bazaar-snapshot", "15 0 * * *", async () => { await scheduledSnapshot(); }); // bounded, max once per UTC day
    Deno.cron("fail-counter-purge", "7 0 * * *", async () => { await FAILS.purge(); });
    Deno.cron("pending-expiry", "*/5 * * * *", async () => { await pendingSweep(); }); // M1: unserved paid checks -> incident
    Deno.cron("reorg-recheck", "*/2 * * * *", async () => { await reorgSweep(env); }); // A4: persisted post-delivery re-checks
  }
  for (const w of startupWarnings(env)) console.warn("WARNING:", w);
  const lerr = LG.ledgerConfigError(env); if (lerr) throw new Error(lerr); // refuse to start without a durable ledger
  LG.openLedger(LG.ledgerPath(env));
  const mig = await LG.migrateFromKv(await kv()); // one-time import of replay keys kept in KV by older releases
  if (mig.auth || mig.tx) console.log("ledger: imported", JSON.stringify(mig));
  assertOnchainMode(env); // refuse to start with ONCHAIN_CHECK=log on Base mainnet
  Deno.serve({ hostname: bindHost(env), port: Number(env("PORT") ?? 8000) },
    (req, info) => handler(req, { env, ip: clientIp(req, (info.remoteAddr as Deno.NetAddr).hostname, env) }));
}
