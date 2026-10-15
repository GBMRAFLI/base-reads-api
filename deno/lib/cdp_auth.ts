// Port of api/cdp_auth.py: one short-lived EdDSA JWT per CDP facilitator request, same claims as the official CDP SDK.
// Active ONLY when FACILITATOR points at api.cdp.coinbase.com AND CDP_API_KEY_ID / CDP_API_KEY_SECRET are set.
export const CDP_HOST = "api.cdp.coinbase.com";
type Env = (k: string) => string | undefined;
const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
const host = (u: string) => { try { return new URL(u).hostname; } catch { return ""; } };
export const enabled = (facilitator: string, env: Env) => host(facilitator) === CDP_HOST && !!env("CDP_API_KEY_ID") && !!env("CDP_API_KEY_SECRET");
const PKCS8_ED25519 = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
async function key(secret: string) {
  const raw = Uint8Array.from(atob(secret.trim()), (c) => c.charCodeAt(0));
  if (raw.length !== 64) throw new Error("CDP_API_KEY_SECRET must be a base64 Ed25519 key (64 bytes)");
  const der = new Uint8Array([...PKCS8_ED25519, ...raw.slice(0, 32)]);
  return await crypto.subtle.importKey("pkcs8", der as Uint8Array<ArrayBuffer>, { name: "Ed25519" }, false, ["sign"]);
}
function nonce16() { const r = crypto.getRandomValues(new Uint8Array(16)); return Array.from(r, (x) => String(x % 10)).join(""); }
export async function jwt(keyId: string, secret: string, method: string, h: string, path: string, now?: number, nonce?: string) {
  const t = Math.floor(now ?? Date.now() / 1000);
  const header = { alg: "EdDSA", kid: keyId, typ: "JWT", nonce: nonce ?? nonce16() };
  const claims = { sub: keyId, iss: "cdp", nbf: t, exp: t + 120, uris: [`${method} ${h}${path}`] };
  const si = enc(header) + "." + enc(claims);
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", await key(secret), new TextEncoder().encode(si)));
  return si + "." + b64url(sig);
}
/** Authorization header for POST {facilitator}{op}, or {} when CDP auth is not active (PayAI path unchanged). */
export async function headers(facilitator: string, op: string, env: Env): Promise<Record<string, string>> {
  if (!enabled(facilitator, env)) return {};
  const u = new URL(facilitator.replace(/\/+$/, "") + op);
  return { Authorization: "Bearer " + await jwt(env("CDP_API_KEY_ID")!, env("CDP_API_KEY_SECRET")!, "POST", u.hostname, u.pathname) };
}
