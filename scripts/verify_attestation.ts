// Official verifier for Pre-pay Check Attestation v1.0 (CC0). Deno:
//   deno run --allow-net --allow-read scripts/verify_attestation.ts FILE|- --issuer URL_OR_FILE --key-id KEY_ID [--snapshots URL_OR_FILE] [--ignore-expiry]
// --issuer and --key-id are required and must come from a source you trust; issuer.issuer_url inside the attestation
// is never used, because whoever made the attestation also chose that URL.
// FILE is the attestation object or a /x402/preflight response body containing "attestation".
// Exit 0 = signature valid (and not expired), 1 = invalid, 2 = usage/input error. Says nothing about whether to pay.
import canonicalizeMod from "npm:canonicalize@2.1.0";
const canonicalize = canonicalizeMod as unknown as (v: unknown) => string;
const DOMAIN = "prepay-check-attestation/v1\n";
const b64d = (s: string) => { if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error("not base64"); return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
export function ts(x: unknown): number | null {
  if (typeof x !== "string" || !ISO.test(x)) return null;
  const t = Date.parse(x); if (!Number.isFinite(t)) return null;
  return new Date(t).toISOString().replace(".000Z", "Z") === x ? t : null;
}

/** Strict JSON parse: standard JSON.parse plus rejection of duplicate object keys (checked with a small scanner). */
export function strictParse(text: string): any {
  const v = JSON.parse(text); // rejects NaN/Infinity, trailing commas, etc.
  let i = 0; const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const str = (): string => { const s = i; i++; while (text[i] !== '"') { if (text[i] === "\\") i++; i++; } i++; return JSON.parse(text.slice(s, i)); };
  const val = (): void => {
    ws(); const c = text[i];
    if (c === "{") {
      i++; const seen = new Set<string>(); ws();
      if (text[i] === "}") { i++; return; }
      for (;;) { ws(); const k = str(); if (seen.has(k)) throw new Error("duplicate JSON key: " + JSON.stringify(k)); seen.add(k); ws(); i++; val(); ws(); if (text[i++] === "}") return; }
    } else if (c === "[") {
      i++; ws(); if (text[i] === "]") { i++; return; }
      for (;;) { val(); ws(); if (text[i++] === "]") return; }
    } else if (c === '"') str();
    else { while (i < text.length && !",]} \t\n\r".includes(text[i])) i++; }
  };
  val(); return v;
}
async function load(src: string): Promise<any> {
  if (/^https?:\/\//.test(src)) return strictParse(await (await fetch(src, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(15000) })).text());
  return strictParse(src === "-" ? new TextDecoder().decode(await new Response(Deno.stdin.readable).arrayBuffer()) : await Deno.readTextFile(src));
}
export async function verify(att: any, issuer: any, now = Date.now(), checkExpiry = true, expectedKeyId?: string): Promise<[boolean, string]> {
  if (!att || typeof att !== "object" || Array.isArray(att) || !issuer || typeof issuer !== "object") return [false, "attestation and issuer must be JSON objects"];
  if (att.spec !== "prepay-check-attestation" || att.version !== "1.0" || att.canonicalization !== "JCS") return [false, "unsupported spec/version/canonicalization"];
  const sig = att.signature; if (!sig || sig.alg !== "Ed25519" || typeof sig.value_b64 !== "string") return [false, "bad signature block"];
  if (expectedKeyId !== undefined && sig.key_id !== expectedKeyId) return [false, "signature.key_id is not the expected key"];
  if (att.issuer?.key_id !== sig.key_id) return [false, "issuer.key_id differs from signature.key_id"];
  const ks = (Array.isArray(issuer.keys) ? issuer.keys : []).filter((x: any) => x?.key_id === sig.key_id);
  if (ks.length !== 1) return [false, "signature.key_id not listed exactly once by issuer"];
  const k = ks[0]; let raw: Uint8Array; try { raw = b64d(k.public_key_b64); } catch { return [false, "issuer public key is not base64"]; }
  if (raw.length !== 32 || hex(await crypto.subtle.digest("SHA-256", raw as Uint8Array<ArrayBuffer>)).slice(0, 16) !== k.key_id) return [false, "issuer key_id does not match its public key"];
  const iat = ts(att.issued_at), exp = ts(att.expires_at);
  if (iat === null || exp === null) return [false, "issued_at/expires_at unparseable"];
  if (exp < iat || exp - iat > 86400_000) return [false, "validity window must be 0..86400 s"];
  if (k.status === "active") { if ("retired_at" in k) return [false, "active key must not carry retired_at"]; }
  else if (k.status === "retired") { const r = ts(k.retired_at); if (r === null || iat > r) return [false, "issued after key was retired"]; }
  else return [false, "unknown key status"];
  const { signature: _s, ...rest } = att;
  let ok = false;
  try {
    const pk = await crypto.subtle.importKey("raw", raw as Uint8Array<ArrayBuffer>, { name: "Ed25519" }, false, ["verify"]);
    ok = await crypto.subtle.verify("Ed25519", pk, b64d(sig.value_b64) as Uint8Array<ArrayBuffer>, new TextEncoder().encode(DOMAIN + canonicalize(rest)));
  } catch { ok = false; }
  if (!ok) return [false, "bad signature"];
  if (iat > now + 60_000) return [false, "issued_at is in the future"];
  if (checkExpiry && exp < now) return [false, "expired at " + att.expires_at];
  return [true, `valid: key_id ${k.key_id}, issued ${att.issued_at}, expires ${att.expires_at}`];
}
/** A11: bind the attestation's Bazaar facts to the published snapshot hash (the /bazaar/snapshots document). */
export function verifySnapshotBinding(att: any, snapshots: any): [boolean, string] {
  const bz = att?.claims?.facts?.bazaar;
  if (!bz || bz.available !== true) return [true, "no snapshot facts to bind"];
  if (typeof bz.snapshot_sha256 !== "string") return [false, "attestation carries no snapshot hash"];
  const e = (Array.isArray(snapshots?.snapshots) ? snapshots.snapshots : []).filter((x: any) => x?.date === bz.snapshot_date);
  if (e.length !== 1) return [false, "snapshot " + bz.snapshot_date + " is not published exactly once"];
  if (e[0].sha256 !== bz.snapshot_sha256) return [false, "snapshot hash does not match the published snapshot"];
  return [true, "snapshot " + bz.snapshot_date + " hash matches"];
}
if (import.meta.main) {
  const a = [...Deno.args]; if (!a.length || a[0] === "-h" || a[0] === "--help") { console.log("usage: verify_attestation.ts FILE|- --issuer URL_OR_FILE --key-id KEY_ID [--snapshots URL_OR_FILE] [--ignore-expiry]"); Deno.exit(2); }
  const src = a.shift()!; let issuerSrc: string | null = null; let checkExpiry = true; let keyId: string | undefined; let snapSrc: string | null = null;
  while (a.length) { const x = a.shift()!; if (x === "--issuer" && a.length) issuerSrc = a.shift()!; else if (x === "--key-id" && a.length) keyId = a.shift()!; else if (x === "--snapshots" && a.length) snapSrc = a.shift()!; else if (x === "--ignore-expiry") checkExpiry = false; else { console.log("unknown argument: " + x); Deno.exit(2); } }
  let body: any; try { body = await load(src); } catch (e) { console.log("FAIL " + (e as Error).message); Deno.exit(1); }
  const att = body && typeof body === "object" && "attestation" in body ? body.attestation : body;
  // never fall back to att.issuer.issuer_url: an attacker controls it and could point it at their own issuer document
  if (!issuerSrc) { console.log("no issuer document: pass --issuer (the attestation's own issuer_url is never trusted)"); Deno.exit(2); }
  if (!keyId) { console.log("no pinned key: pass --key-id (pinning the expected key_id is mandatory)"); Deno.exit(2); }
  let iss: any; try { iss = await load(issuerSrc!); } catch (e) { console.log("FAIL issuer: " + (e as Error).message); Deno.exit(1); }
  let [ok, why] = await verify(att, iss, Date.now(), checkExpiry, keyId);
  if (ok && snapSrc) { let sd: any; try { sd = await load(snapSrc); } catch (e) { console.log("FAIL snapshots: " + (e as Error).message); Deno.exit(1); } const [o2, w2] = verifySnapshotBinding(att, sd); if (!o2) [ok, why] = [false, w2]; else why += "; " + w2; }
  console.log((ok ? "OK " : "FAIL ") + why); Deno.exit(ok ? 0 : 1);
}
