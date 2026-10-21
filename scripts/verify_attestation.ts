// Official verifier for Pre-pay Check Attestation v1.0 (CC0). Deno:
//   deno run --allow-net --allow-read scripts/verify_attestation.ts FILE|- [--issuer URL_OR_FILE] [--ignore-expiry]
// FILE is the attestation object or a /x402/preflight response body containing "attestation".
// Exit 0 = signature valid (and not expired), 1 = invalid, 2 = usage/input error. Says nothing about whether to pay.
import canonicalizeMod from "npm:canonicalize@2.1.0";
const canonicalize = canonicalizeMod as unknown as (v: unknown) => string;
const b64d = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
const isoNow = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");

async function load(src: string): Promise<any> {
  if (/^https?:\/\//.test(src)) return await (await fetch(src, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(15000) })).json();
  return JSON.parse(src === "-" ? new TextDecoder().decode(await new Response(Deno.stdin.readable).arrayBuffer()) : await Deno.readTextFile(src));
}
export async function verify(att: any, issuer: any, now = Date.now(), checkExpiry = true): Promise<[boolean, string]> {
  if (att?.spec !== "prepay-check-attestation" || att?.version !== "1.0" || att?.canonicalization !== "JCS") return [false, "unsupported spec/version/canonicalization"];
  const sig = att.signature ?? {}; if (sig.alg !== "Ed25519") return [false, "signature.alg must be Ed25519"];
  const k = (issuer?.keys ?? []).find((x: any) => x?.key_id === sig.key_id); if (!k) return [false, "signature.key_id not listed by issuer"];
  const raw = b64d(k.public_key_b64);
  if (raw.length !== 32 || hex(await crypto.subtle.digest("SHA-256", raw)).slice(0, 16) !== k.key_id) return [false, "issuer key_id does not match its public key"];
  if (k.status === "retired" && k.retired_at && att.issued_at > k.retired_at) return [false, "issued after key was retired"];
  const { signature: _s, ...rest } = att;
  const pk = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  let ok = false; try { ok = await crypto.subtle.verify("Ed25519", pk, b64d(sig.value_b64), new TextEncoder().encode(canonicalize(rest))); } catch { ok = false; }
  if (!ok) return [false, "bad signature"];
  if (checkExpiry && isoNow(now) > att.expires_at) return [false, "expired at " + att.expires_at];
  return [true, `valid: key_id ${k.key_id}, issued ${att.issued_at}, expires ${att.expires_at}`];
}
if (import.meta.main) {
  const a = [...Deno.args]; if (!a.length || a[0] === "-h" || a[0] === "--help") { console.log("usage: verify_attestation.ts FILE|- [--issuer URL_OR_FILE] [--ignore-expiry]"); Deno.exit(2); }
  const src = a.shift()!; let issuerSrc: string | null = null; let checkExpiry = true;
  while (a.length) { const x = a.shift()!; if (x === "--issuer" && a.length) issuerSrc = a.shift()!; else if (x === "--ignore-expiry") checkExpiry = false; else { console.log("unknown argument: " + x); Deno.exit(2); } }
  const body = await load(src); const att = body.attestation ?? body;
  issuerSrc ??= att?.issuer?.issuer_url ?? null; if (!issuerSrc) { console.log("no issuer document: pass --issuer"); Deno.exit(2); }
  const [ok, why] = await verify(att, await load(issuerSrc!), Date.now(), checkExpiry);
  console.log((ok ? "OK " : "FAIL ") + why); Deno.exit(ok ? 0 : 1);
}
