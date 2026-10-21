#!/usr/bin/env python3
"""Official verifier for Pre-pay Check Attestation v1.0 (CC0).
Usage: verify_attestation.py FILE|- [--issuer URL_OR_FILE] [--ignore-expiry]
FILE is either the attestation object or a /x402/preflight response body that contains "attestation".
Needs: pip install rfc8785 pycryptodome. Exit code 0 = signature valid (and not expired), 1 = invalid, 2 = usage/input error.
Checks only the signature, key and validity window; it says nothing about whether to pay an endpoint."""
import base64, hashlib, json, sys, time, urllib.request
import rfc8785
from Crypto.Signature import eddsa

def load(src):
    if src.startswith("https://") or src.startswith("http://"):
        req = urllib.request.Request(src, headers={"Accept": "application/json", "User-Agent": "prepay-check-verify/1.0"})
        return json.loads(urllib.request.urlopen(req, timeout=15).read())
    return json.load(sys.stdin if src == "-" else open(src))

def verify(att, issuer, now=None, check_expiry=True):
    if att.get("spec") != "prepay-check-attestation" or att.get("version") != "1.0" or att.get("canonicalization") != "JCS":
        return False, "unsupported spec/version/canonicalization"
    sig = att.get("signature") or {}
    if sig.get("alg") != "Ed25519": return False, "signature.alg must be Ed25519"
    keys = [k for k in issuer.get("keys", []) if k.get("key_id") == sig.get("key_id")]
    if not keys: return False, "signature.key_id not listed by issuer"
    k = keys[0]; raw = base64.b64decode(k["public_key_b64"])
    if len(raw) != 32 or hashlib.sha256(raw).hexdigest()[:16] != k["key_id"]: return False, "issuer key_id does not match its public key"
    if k.get("status") == "retired" and k.get("retired_at") and att["issued_at"] > k["retired_at"]: return False, "issued after key was retired"
    msg = rfc8785.dumps({x: v for x, v in att.items() if x != "signature"})
    try: eddsa.new(eddsa.import_public_key(raw), "rfc8032").verify(msg, base64.b64decode(sig["value_b64"]))
    except (ValueError, KeyError): return False, "bad signature"
    now_s = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if now is None else now))
    if check_expiry and now_s > att["expires_at"]: return False, "expired at " + att["expires_at"]
    return True, "valid: key_id %s, issued %s, expires %s" % (k["key_id"], att["issued_at"], att["expires_at"])

def main(argv):
    if not argv or argv[0] in ("-h", "--help"): print(__doc__); return 2
    src, issuer_src, check_expiry = argv[0], None, True
    i = 1
    while i < len(argv):
        if argv[i] == "--issuer" and i + 1 < len(argv): issuer_src = argv[i + 1]; i += 2
        elif argv[i] == "--ignore-expiry": check_expiry = False; i += 1
        else: print("unknown argument: " + argv[i]); return 2
    body = load(src); att = body.get("attestation", body)
    issuer_src = issuer_src or (att.get("issuer") or {}).get("issuer_url")
    if not issuer_src: print("no issuer document: pass --issuer"); return 2
    ok, why = verify(att, load(issuer_src), check_expiry=check_expiry)
    print(("OK " if ok else "FAIL ") + why); return 0 if ok else 1

if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
