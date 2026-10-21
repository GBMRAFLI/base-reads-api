// Pre-pay Check Attestation v1.0: an Ed25519-signed envelope around the Pre-pay Check facts.
// Signed bytes = RFC 8785 (JCS) canonical JSON of the envelope without its "signature" member.
// The signing key lives only in the production server environment; this module never reads key material
// itself: it receives a Signer (production: lib/sign.ts loadKey; tests: an ephemeral in-memory key).
import canonicalizeMod from "canonicalize";
const canonicalize = canonicalizeMod as unknown as (v: unknown) => string | undefined;

export const SPEC = "prepay-check-attestation";
export const VERSION = "1.0";
export const CANON = "JCS";
export const ISSUER_NAME = "Base Reads Pre-pay Check";
export const CONTACT = "gbmrafli@agentmail.to";
export const BASE_NETWORKS = ["eip155:8453", "base"];
export const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
export const DEFAULT_TTL_S = 900;
export const MAX_PAYTO_CODE_LOOKUPS = 4;

export type Signer = { keyId: string; sign: (msg: Uint8Array) => Promise<Uint8Array> };
export type Rpc = (m: string, p: unknown[]) => Promise<any>;
export type Check = { id: string; status: "pass" | "fail" | "not_applicable"; observed: unknown; expected?: unknown };

const b64e = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64d = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export function jcs(v: unknown): string {
  const s = canonicalize(v);
  if (typeof s !== "string") throw new Error("value cannot be canonicalized");
  return s;
}
/** Domain-separation prefixes: a signature from one domain never verifies in another (or as legacy facts). */
export const DOMAIN_ATTESTATION = "prepay-check-attestation/v1\n";
export const DOMAIN_SNAPSHOT_META = "bazaar-snapshot-meta/v1\n";
export const domainBytes = (domain: string, v: unknown) => new TextEncoder().encode(domain + jcs(v));
export const signingBytes = (envelope: Record<string, unknown>) => {
  const { signature: _s, ...rest } = envelope; return domainBytes(DOMAIN_ATTESTATION, rest);
};
const ISO_SEC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
/** Strict second-precision UTC timestamp -> ms, or null (unparseable, NaN, or not a real date). */
export function parseIsoSec(x: unknown): number | null {
  if (typeof x !== "string" || !ISO_SEC.test(x)) return null;
  const t = Date.parse(x); if (!Number.isFinite(t)) return null;
  return new Date(t).toISOString().replace(".000Z", "Z") === x ? t : null;
}
export const MAX_VALIDITY_S = 86400, CLOCK_SKEW_S = 60;
/** TTL: integer >= 1 (capped at 24 h), anything else -> default 900 s. */
export function normTtl(x: unknown): number {
  return typeof x === "number" && Number.isInteger(x) && x >= 1 ? Math.min(x, MAX_VALIDITY_S) : DEFAULT_TTL_S;
}
const isoSec = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");

export type PaytoCode = { address: string; kind: "eoa" | "eip7702_delegated" | "contract" | null; code_bytes: number | null; delegate?: string };
/** eth_getCode for each distinct payTo (capped). kind: "eoa" (no code), "eip7702_delegated" (EOA whose code is the
 * EIP-7702 designator 0xef0100 || delegate address), "contract", or null (lookup failed). */
export function classifyCode(address: string, code: string): PaytoCode {
  const n = Math.floor((code.length - 2) / 2);
  if (n === 0) return { address, kind: "eoa", code_bytes: 0 };
  if (n === 23 && code.toLowerCase().startsWith("0xef0100")) return { address, kind: "eip7702_delegated", code_bytes: 23, delegate: "0x" + code.slice(8).toLowerCase() };
  return { address, kind: "contract", code_bytes: n };
}
/** Each eth_getCode lookup is bounded (lookups run in parallel), so probe + RPC always fit inside the probe slot. */
export const ATTEST_RPC_TIMEOUT_MS = 5000;
export async function paytoCode(payTos: string[], rpc?: Rpc, timeoutMs = ATTEST_RPC_TIMEOUT_MS): Promise<PaytoCode[]> {
  const uniq = [...new Set(payTos.filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a)).map((a) => a.toLowerCase()))].slice(0, MAX_PAYTO_CODE_LOOKUPS);
  return await Promise.all(uniq.map(async (address) => {
    if (!rpc) return { address, kind: null, code_bytes: null };
    try {
      let t: ReturnType<typeof setTimeout> | undefined;
      const code = await Promise.race([rpc("eth_getCode", [address, "latest"]),
        new Promise((_, rej) => { t = setTimeout(() => rej(new Error("rpc_timeout")), timeoutMs); })]).finally(() => clearTimeout(t));
      if (typeof code !== "string" || !/^0x[0-9a-fA-F]*$/.test(code)) return { address, kind: null, code_bytes: null };
      return classifyCode(address, code);
    } catch { return { address, kind: null, code_bytes: null }; }
  }));
}

const challengePayTos = (facts: any) => [...new Set(((facts.challenge?.accepts ?? []) as any[]).map((a) => a?.payTo).filter((x) => typeof x === "string").map((x: string) => x.toLowerCase()))].sort();
/** true / false when the resource is listed in a usable snapshot with payTo values and the 402 named payTo values; else null. */
export function payToMatchesSnapshot(facts: any): boolean | null {
  const bz = facts.bazaar ?? {}; const live = challengePayTos(facts);
  if (!bz.available || bz.listed !== true || !Array.isArray(bz.listed_payTo) || !bz.listed_payTo.length || !live.length) return null;
  const snap = [...new Set(bz.listed_payTo.map((x: unknown) => String(x).toLowerCase()))].sort();
  return snap.length === live.length && snap.every((x, i) => x === live[i]);
}
/** Raw-fact checks. Each states what was observed; there is no overall verdict or score. */
export function buildChecks(facts: any, code: Awaited<ReturnType<typeof paytoCode>>): Check[] {
  const reach = facts.reachability ?? {}; const ch = facts.challenge ?? {}; const acc: any[] = ch.accepts ?? []; const bz = facts.bazaar ?? {};
  const out: Check[] = [];
  out.push({ id: "endpoint_reachable", status: reach.reachable ? "pass" : "fail", observed: reach.reachable ? (reach.http_status ?? null) : (reach.error_class ?? null) });
  out.push({ id: "http_402_returned", status: !reach.reachable ? "not_applicable" : reach.http_status === 402 ? "pass" : "fail", observed: reach.http_status ?? null, expected: 402 });
  out.push({ id: "challenge_well_formed", status: ch.valid ? "pass" : "fail", observed: ch.problems ?? [] });
  const str = (x: unknown) => typeof x === "string" ? x : null; // summary carries strings only (anything else -> null)
  const nets = acc.map((a) => str(a?.network));
  out.push({ id: "network_is_base", status: !acc.length ? "not_applicable" : nets.every((n) => (n !== null && BASE_NETWORKS.includes(n))) ? "pass" : "fail", observed: nets, expected: "eip155:8453" });
  const assets = acc.map((a) => str(a?.asset)?.toLowerCase() ?? null);
  out.push({ id: "asset_is_base_usdc", status: !acc.length ? "not_applicable" : assets.every((x) => x === BASE_USDC) ? "pass" : "fail", observed: assets, expected: BASE_USDC });
  const known = code.filter((c) => c.kind !== null);
  out.push({ id: "payto_is_eoa", status: !code.length || known.length < code.length ? "not_applicable" : known.every((c) => c.kind === "eoa") ? "pass" : "fail",
    observed: code.map((c) => c.kind === "eip7702_delegated" ? { address: c.address, kind: c.kind, delegate: c.delegate ?? null } : { address: c.address, kind: c.kind }) });
  out.push({ id: "bazaar_snapshot_available", status: bz.available ? "pass" : "fail", observed: bz.available ? (bz.snapshot_date ?? null) : (bz.reason ?? null) });
  out.push({ id: "listed_in_bazaar", status: !bz.available || bz.listed === null || bz.listed === undefined ? "not_applicable" : bz.listed ? "pass" : "fail", observed: bz.available ? (bz.listed ?? null) : null });
  // A9: latency fact against a fixed 5 s budget (the probe itself times out at 5 s).
  const lat = typeof reach.latency_ms === "number" ? reach.latency_ms : null;
  out.push({ id: "responds_within_5000ms", status: reach.reachable ? (lat !== null && lat <= 5000 ? "pass" : "fail") : reach.error_class === "TimeoutError" ? "fail" : "not_applicable",
    observed: reach.reachable ? lat : (reach.error_class ?? null), expected: "<= 5000 ms" });
  // A10: payTo in the live 402 vs payTo recorded for this resource in the Bazaar snapshot (fact only).
  const m = payToMatchesSnapshot(facts);
  out.push({ id: "pay_to_matches_snapshot", status: m === null ? "not_applicable" : m ? "pass" : "fail",
    observed: { challenge: challengePayTos(facts), snapshot: Array.isArray(bz.listed_payTo) ? [...new Set(bz.listed_payTo.map((x: unknown) => String(x).toLowerCase()))].sort() : null } });
  return out;
}

export async function attest(facts: Record<string, any>, opts: { signer: Signer; rpc?: Rpc; now?: number; ttlS?: number; issuerUrl?: string | null }) {
  const now = opts.now ?? Date.now(); const ttl = normTtl(opts.ttlS);
  const code = await paytoCode((facts.challenge?.accepts ?? []).map((a: any) => a.payTo).filter(Boolean), opts.rpc);
  const checks = buildChecks(facts, code);
  const env: Record<string, unknown> = {
    spec: SPEC, version: VERSION, canonicalization: CANON, attestation_id: crypto.randomUUID(),
    issued_at: isoSec(now), expires_at: isoSec(now + ttl * 1000),
    issuer: { name: ISSUER_NAME, key_id: opts.signer.keyId, issuer_url: opts.issuerUrl ?? null, contact: CONTACT },
    subject: { type: "x402_endpoint", url: facts.target },
    claims: { facts, payto_code: code, pay_to_matches_snapshot: payToMatchesSnapshot(facts), checks, checks_passed: checks.filter((c) => c.status === "pass").map((c) => c.id),
      checks_failed: checks.filter((c) => c.status === "fail").map((c) => c.id) },
  };
  const sig = await opts.signer.sign(signingBytes(env));
  env.signature = { alg: "Ed25519", key_id: opts.signer.keyId, value_b64: b64e(sig) };
  return env;
}

/** key_id = first 16 hex chars of sha256(raw 32-byte public key). */
export async function keyIdOf(raw: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", raw as Uint8Array<ArrayBuffer>)), (x) => x.toString(16).padStart(2, "0")).join("").slice(0, 16);
}
/** Verify with a raw 32-byte public key (base64). Pins signature.key_id and issuer.key_id to that key (and to
 * expectedKeyId if given), checks dates are strict, issued_at <= now + 60 s, 0 <= expires_at - issued_at <= 86400 s,
 * and (unless now is null) that it has not expired. */
export async function verifyAttestation(envelope: any, publicKeyB64: string, now: number | null = Date.now(), expectedKeyId?: string): Promise<{ ok: boolean; reason?: string }> {
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) return { ok: false, reason: "not_an_object" };
  if (envelope.spec !== SPEC || envelope.version !== VERSION || envelope.canonicalization !== CANON) return { ok: false, reason: "unsupported_spec" };
  const s = envelope.signature; if (!s || s.alg !== "Ed25519" || typeof s.value_b64 !== "string") return { ok: false, reason: "bad_signature_block" };
  let raw: Uint8Array; try { raw = b64d(publicKeyB64); } catch { return { ok: false, reason: "bad_public_key" }; }
  if (raw.length !== 32) return { ok: false, reason: "bad_public_key" };
  const kid = await keyIdOf(raw);
  if (s.key_id !== kid || envelope.issuer?.key_id !== kid || (expectedKeyId !== undefined && expectedKeyId !== kid)) return { ok: false, reason: "key_id_mismatch" };
  const iat = parseIsoSec(envelope.issued_at), exp = parseIsoSec(envelope.expires_at);
  if (iat === null || exp === null) return { ok: false, reason: "bad_dates" };
  if (exp < iat || exp - iat > MAX_VALIDITY_S * 1000) return { ok: false, reason: "bad_validity_window" };
  let sig: Uint8Array; try { sig = b64d(s.value_b64); } catch { return { ok: false, reason: "bad_signature" }; }
  const pk = await crypto.subtle.importKey("raw", raw as Uint8Array<ArrayBuffer>, { name: "Ed25519" }, false, ["verify"]);
  let good = false; try { good = await crypto.subtle.verify("Ed25519", pk, sig as Uint8Array<ArrayBuffer>, signingBytes(envelope) as Uint8Array<ArrayBuffer>); } catch { good = false; }
  if (!good) return { ok: false, reason: "bad_signature" };
  if (now !== null && iat > now + CLOCK_SKEW_S * 1000) return { ok: false, reason: "issued_in_future" };
  if (now !== null && exp < now) return { ok: false, reason: "expired" };
  return { ok: true };
}
