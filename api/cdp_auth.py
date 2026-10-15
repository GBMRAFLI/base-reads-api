"""CDP facilitator auth: one short-lived EdDSA JWT per request, same claims as the official CDP SDK
(header alg/kid/typ/nonce; claims sub, iss="cdp", nbf, exp=+120s, uris=["METHOD host/path"]).
Used ONLY when FACILITATOR points at api.cdp.coinbase.com AND CDP_API_KEY_ID / CDP_API_KEY_SECRET are set.
The secret is the base64 Ed25519 key from the CDP portal (64 bytes: seed + public key). Never logged."""
import base64, json, os, secrets, time, urllib.parse
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
CDP_HOST = "api.cdp.coinbase.com"
def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def enabled(facilitator, env=os.environ):
    return urllib.parse.urlsplit(facilitator).hostname == CDP_HOST and bool(env.get("CDP_API_KEY_ID")) and bool(env.get("CDP_API_KEY_SECRET"))
def _key(secret):
    raw = base64.b64decode(secret.strip())
    if len(raw) != 64: raise ValueError("CDP_API_KEY_SECRET must be a base64 Ed25519 key (64 bytes)")
    return eddsa.import_private_key(raw[:32])
def jwt(key_id, secret, method, host, path, now=None, nonce=None):
    now = int(now if now is not None else time.time())
    header = {"alg": "EdDSA", "kid": key_id, "typ": "JWT", "nonce": nonce or "".join(secrets.choice("0123456789") for _ in range(16))}
    claims = {"sub": key_id, "iss": "cdp", "nbf": now, "exp": now + 120, "uris": [f"{method} {host}{path}"]}
    si = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + b64url(json.dumps(claims, separators=(",", ":")).encode())
    return si + "." + b64url(eddsa.new(_key(secret), "rfc8032").sign(si.encode()))
def headers(facilitator, op, env=os.environ):
    """Authorization header for POST {facilitator}{op}, or {} when CDP auth is not active (PayAI path unchanged)."""
    if not enabled(facilitator, env): return {}
    u = urllib.parse.urlsplit(facilitator.rstrip("/") + op)
    return {"Authorization": "Bearer " + jwt(env["CDP_API_KEY_ID"], env["CDP_API_KEY_SECRET"], "POST", u.hostname, u.path)}
