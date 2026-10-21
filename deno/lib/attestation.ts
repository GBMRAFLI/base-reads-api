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
export const signingBytes = (envelope: Record<string, unknown>) => {
  const { signature: _s, ...rest } = envelope; return new TextEncoder().encode(jcs(rest));
};
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
export async function paytoCode(payTos: string[], rpc?: Rpc): Promise<PaytoCode[]> {
  const uniq = [...new Set(payTos.filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a)).map((a) => a.toLowerCase()))].slice(0, MAX_PAYTO_CODE_LOOKUPS);
  return await Promise.all(uniq.map(async (address) => {
    if (!rpc) return { address, kind: null, code_bytes: null };
    try {
      const code = await rpc("eth_getCode", [address, "latest"]);
      if (typeof code !== "string" || !/^0x[0-9a-fA-F]*$/.test(code)) return { address, kind: null, code_bytes: null };
      return classifyCode(address, code);
    } catch { return { address, kind: null, code_bytes: null }; }
  }));
}

/** Raw-fact checks. Each states what was observed; there is no overall verdict or score. */
export function buildChecks(facts: any, code: Awaited<ReturnType<typeof paytoCode>>): Check[] {
  const reach = facts.reachability ?? {}; const ch = facts.challenge ?? {}; const acc: any[] = ch.accepts ?? []; const bz = facts.bazaar ?? {};
  const out: Check[] = [];
  out.push({ id: "endpoint_reachable", status: reach.reachable ? "pass" : "fail", observed: reach.reachable ? (reach.http_status ?? null) : (reach.error_class ?? null) });
  out.push({ id: "http_402_returned", status: !reach.reachable ? "not_applicable" : reach.http_status === 402 ? "pass" : "fail", observed: reach.http_status ?? null, expected: 402 });
  out.push({ id: "challenge_well_formed", status: ch.valid ? "pass" : "fail", observed: ch.problems ?? [] });
  const nets = acc.map((a) => a.network ?? null);
  out.push({ id: "network_is_base", status: !acc.length ? "not_applicable" : nets.every((n) => BASE_NETWORKS.includes(n)) ? "pass" : "fail", observed: nets, expected: "eip155:8453" });
  const assets = acc.map((a) => typeof a.asset === "string" ? a.asset.toLowerCase() : null);
  out.push({ id: "asset_is_base_usdc", status: !acc.length ? "not_applicable" : assets.every((x) => x === BASE_USDC) ? "pass" : "fail", observed: assets, expected: BASE_USDC });
  const known = code.filter((c) => c.kind !== null);
  out.push({ id: "payto_is_eoa", status: !code.length || known.length < code.length ? "not_applicable" : known.every((c) => c.kind === "eoa" || c.kind === "eip7702_delegated") ? "pass" : "fail",
    observed: code.map((c) => ({ address: c.address, kind: c.kind })) });
  out.push({ id: "bazaar_snapshot_available", status: bz.available ? "pass" : "fail", observed: bz.available ? (bz.snapshot_date ?? null) : (bz.reason ?? null) });
  out.push({ id: "listed_in_bazaar", status: !bz.available || bz.listed === null || bz.listed === undefined ? "not_applicable" : bz.listed ? "pass" : "fail", observed: bz.available ? (bz.listed ?? null) : null });
  return out;
}

export async function attest(facts: Record<string, any>, opts: { signer: Signer; rpc?: Rpc; now?: number; ttlS?: number; issuerUrl?: string | null }) {
  const now = opts.now ?? Date.now(); const ttl = opts.ttlS && opts.ttlS > 0 ? Math.min(Math.floor(opts.ttlS), 86400) : DEFAULT_TTL_S;
  const code = await paytoCode((facts.challenge?.accepts ?? []).map((a: any) => a.payTo).filter(Boolean), opts.rpc);
  const checks = buildChecks(facts, code);
  const env: Record<string, unknown> = {
    spec: SPEC, version: VERSION, canonicalization: CANON, attestation_id: crypto.randomUUID(),
    issued_at: isoSec(now), expires_at: isoSec(now + ttl * 1000),
    issuer: { name: ISSUER_NAME, key_id: opts.signer.keyId, issuer_url: opts.issuerUrl ?? null, contact: CONTACT },
    subject: { type: "x402_endpoint", url: facts.target },
    claims: { facts, payto_code: code, checks, checks_passed: checks.filter((c) => c.status === "pass").map((c) => c.id),
      checks_failed: checks.filter((c) => c.status === "fail").map((c) => c.id) },
  };
  const sig = await opts.signer.sign(signingBytes(env));
  env.signature = { alg: "Ed25519", key_id: opts.signer.keyId, value_b64: b64e(sig) };
  return env;
}

/** Verify signature (+ optional expiry) with a raw 32-byte public key given as base64. */
export async function verifyAttestation(envelope: any, publicKeyB64: string, now: number | null = Date.now()): Promise<{ ok: boolean; reason?: string }> {
  if (envelope?.spec !== SPEC || envelope?.canonicalization !== CANON) return { ok: false, reason: "unsupported_spec" };
  const s = envelope.signature; if (!s || s.alg !== "Ed25519") return { ok: false, reason: "bad_signature_block" };
  const pk = await crypto.subtle.importKey("raw", b64d(publicKeyB64), { name: "Ed25519" }, false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", pk, b64d(s.value_b64), signingBytes(envelope))) return { ok: false, reason: "bad_signature" };
  if (now !== null && Date.parse(envelope.expires_at) < now) return { ok: false, reason: "expired" };
  return { ok: true };
}
