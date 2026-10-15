// Ed25519 signing compatible with the Python service: same encrypted PEM (PKCS#8 PBES2 scrypt + AES-256-CBC),
// same passphrase, same pubkey/key_id, same canonical bytes. Secrets come from env and are never logged.
import { scrypt } from "@noble/hashes/scrypt";
import { sha256 } from "@noble/hashes/sha256";
import { canonical } from "./canonical.ts";

export class SigningUnavailable extends Error {}
const b64d = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64e = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

type Node = { tag: number; start: number; len: number; hdr: number };
function rd(b: Uint8Array, p: number): Node {
  const tag = b[p]; let len = b[p + 1]; let hdr = 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[p + 2 + i]; hdr = 2 + n; }
  return { tag, start: p + hdr, len, hdr };
}
function kids(b: Uint8Array, n: Node): Node[] {
  const out: Node[] = []; let p = n.start;
  while (p < n.start + n.len) { const c = rd(b, p); out.push(c); p = c.start + c.len; }
  return out;
}
const val = (b: Uint8Array, n: Node) => b.slice(n.start, n.start + n.len);
const int = (b: Uint8Array, n: Node) => val(b, n).reduce((a, x) => a * 256 + x, 0);
const oid = (b: Uint8Array, n: Node) => hex(val(b, n));
const OID_PBES2 = "2a864886f70d01050d", OID_SCRYPT = "2b06010401da47040b", OID_AES256CBC = "60864801650304012a";

export async function decryptPem(pem: string, pass: string): Promise<Uint8Array> {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = b64d(body);
  const top = rd(der, 0); const [alg, enc] = kids(der, top);
  const [algOid, algParams] = kids(der, alg);
  if (oid(der, algOid) !== OID_PBES2) throw new Error("not PBES2");
  const [kdf, encScheme] = kids(der, algParams);
  const [kdfOid, kdfParams] = kids(der, kdf);
  if (oid(der, kdfOid) !== OID_SCRYPT) throw new Error("KDF is not scrypt");
  const kp = kids(der, kdfParams);
  const salt = val(der, kp[0]), N = int(der, kp[1]), r = int(der, kp[2]), p = int(der, kp[3]);
  const dkLen = kp[4] ? int(der, kp[4]) : 32;
  const [encOid, ivN] = kids(der, encScheme);
  if (oid(der, encOid) !== OID_AES256CBC) throw new Error("cipher is not aes256-CBC");
  const key = scrypt(new TextEncoder().encode(pass), salt, { N, r, p, dkLen, maxmem: 256 * 1024 * 1024 });
  const ck = await crypto.subtle.importKey("raw", key as Uint8Array<ArrayBuffer>, { name: "AES-CBC" }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv: val(der, ivN) }, ck, val(der, enc)));
}

let cached: Promise<{ priv: CryptoKey; pubRaw: Uint8Array }> | null = null;
export function resetKey() { cached = null; }
export function loadKey(env: (k: string) => string | undefined = (k) => Deno.env.get(k)) {
  if (cached) return cached;
  cached = (async () => {
    const pass = env("SIGNING_KEY_PASSPHRASE") ?? "";
    if (pass.length < 16) throw new SigningUnavailable("SIGNING_KEY_PASSPHRASE missing or too short");
    const enc = env("SIGNING_KEY_ENC_B64");
    if (!enc) throw new SigningUnavailable("SIGNING_KEY_ENC_B64 missing");
    const pkcs8 = await decryptPem(new TextDecoder().decode(b64d(enc)), pass);
    const priv = await crypto.subtle.importKey("pkcs8", pkcs8 as Uint8Array<ArrayBuffer>, { name: "Ed25519" }, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", priv);
    const pubRaw = b64d(jwk.x!.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - jwk.x!.length % 4) % 4));
    return { priv, pubRaw };
  })();
  cached.catch(() => { cached = null; });
  return cached;
}
/** Identity of a raw Ed25519 public key: key_id, SSH-style fingerprint, grouped short form (same as Python key_meta). */
export function keyMeta(raw: Uint8Array, createdAt: string | null = null) {
  const d = sha256(raw); const kid = hex(d).slice(0, 16);
  return { alg: "Ed25519", public_key_b64: b64e(raw), key_id: kid, fingerprint: "SHA256:" + b64e(d).replace(/=+$/, ""),
    fingerprint_short: kid.match(/.{4}/g)!.join(" "), created_at: createdAt };
}
export async function publicKeyInfo(env: (k: string) => string | undefined = (k) => Deno.env.get(k)) {
  const { pubRaw } = await loadKey();
  return keyMeta(pubRaw, env("SIGNING_KEY_CREATED_AT") || null);
}
export async function keyHistory(env: (k: string) => string | undefined = (k) => Deno.env.get(k)) {
  let retired: any[] = []; try { const x = JSON.parse(env("SIGNING_KEY_HISTORY") || "[]"); if (Array.isArray(x)) retired = x; } catch { /* ignore */ }
  const out: Record<string, unknown>[] = [];
  for (const k of retired) {
    let raw: Uint8Array; try { raw = b64d(k.public_key_b64); } catch { continue; }
    if (raw.length === 32) out.push({ ...keyMeta(raw, k.created_at ?? null), retired_at: k.retired_at ?? null, status: "retired" });
  }
  return { current: { ...(await publicKeyInfo(env)), status: "active" }, retired: out };
}
export async function sign(facts: Record<string, unknown>) {
  const { priv } = await loadKey(); const pub = await publicKeyInfo();
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", priv, new TextEncoder().encode(canonical(facts))));
  return { facts, signature: { alg: "Ed25519", key_id: pub.key_id, public_key_b64: pub.public_key_b64, value_b64: b64e(sig),
    signed_over: "canonical JSON of facts (sorted keys, no whitespace)" } };
}
export async function verify(env: { facts: unknown; signature: { public_key_b64: string; value_b64: string } }) {
  const pk = await crypto.subtle.importKey("raw", b64d(env.signature.public_key_b64), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", pk, b64d(env.signature.value_b64), new TextEncoder().encode(canonical(env.facts)));
}
