#!/usr/bin/env python3
"""Official verifier for Pre-pay Check Attestation v1.0 (CC0).
Usage: verify_attestation.py FILE|- --issuer URL_OR_FILE --key-id KEY_ID [--snapshots URL_OR_FILE] [--ignore-expiry]
--issuer and --key-id are required: the issuer document and the key_id must come from a source you trust (for example
the service's own /.well-known/issuer.json fetched once and pinned). issuer.issuer_url inside the attestation is never used,
because whoever made the attestation also chose that URL.
FILE is either the attestation object or a /x402/preflight response body that contains "attestation".
Needs: pip install rfc8785 pycryptodome. Exit code 0 = signature valid (and not expired), 1 = invalid, 2 = usage/input error.
Checks only the signature, key and validity window; it says nothing about whether to pay an endpoint."""
import base64, calendar, hashlib, json, re, sys, time, urllib.request
import rfc8785
from Crypto.Signature import eddsa

DOMAIN = b"prepay-check-attestation/v1\n"
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise ValueError("duplicate JSON key: %r" % k)
        d[k] = v
    return d
def _no_const(x): raise ValueError("non-standard JSON constant: " + x)
def strict_loads(text):
    """JSON parse that rejects duplicate keys and NaN/Infinity."""
    return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_const)
def ts(x):
    if not isinstance(x, str) or not ISO.match(x): return None
    try: return calendar.timegm(time.strptime(x, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError: return None
def load(src):
    if src.startswith("https://") or src.startswith("http://"):
        req = urllib.request.Request(src, headers={"Accept": "application/json", "User-Agent": "prepay-check-verify/1.0"})
        return strict_loads(urllib.request.urlopen(req, timeout=15).read().decode("utf-8"))
    return strict_loads(sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read())

def verify(att, issuer, now=None, check_expiry=True, expected_key_id=None):
    if not isinstance(att, dict) or not isinstance(issuer, dict): return False, "attestation and issuer must be JSON objects"
    if att.get("spec") != "prepay-check-attestation" or att.get("version") != "1.0" or att.get("canonicalization") != "JCS":
        return False, "unsupported spec/version/canonicalization"
    sig = att.get("signature")
    if not isinstance(sig, dict) or sig.get("alg") != "Ed25519" or not isinstance(sig.get("value_b64"), str): return False, "bad signature block"
    if expected_key_id is not None and sig.get("key_id") != expected_key_id: return False, "signature.key_id is not the expected key"
    if (att.get("issuer") or {}).get("key_id") != sig.get("key_id"): return False, "issuer.key_id differs from signature.key_id"
    keys = [k for k in issuer.get("keys", []) if isinstance(k, dict) and k.get("key_id") == sig.get("key_id")]
    if len(keys) != 1: return False, "signature.key_id not listed exactly once by issuer"
    k = keys[0]
    try: raw = base64.b64decode(k["public_key_b64"], validate=True)
    except Exception: return False, "issuer public key is not base64"
    if len(raw) != 32 or hashlib.sha256(raw).hexdigest()[:16] != k["key_id"]: return False, "issuer key_id does not match its public key"
    iat, exp = ts(att.get("issued_at")), ts(att.get("expires_at"))
    if iat is None or exp is None: return False, "issued_at/expires_at unparseable"
    if exp < iat or exp - iat > 86400: return False, "validity window must be 0..86400 s"
    if k.get("status") == "active":
        if "retired_at" in k: return False, "active key must not carry retired_at"
    elif k.get("status") == "retired":
        r = ts(k.get("retired_at"))
        if r is None or iat > r: return False, "issued after key was retired"
    else: return False, "unknown key status"
    msg = DOMAIN + rfc8785.dumps({x: v for x, v in att.items() if x != "signature"})
    try: eddsa.new(eddsa.import_public_key(raw), "rfc8032").verify(msg, base64.b64decode(sig["value_b64"], validate=True))
    except Exception: return False, "bad signature"
    now = time.time() if now is None else now
    if iat > now + 60: return False, "issued_at is in the future"
    if check_expiry and exp < now: return False, "expired at " + att["expires_at"]
    return True, "valid: key_id %s, issued %s, expires %s" % (k["key_id"], att["issued_at"], att["expires_at"])

def verify_snapshot_binding(att, snapshots):
    """A11: bind the attestation's Bazaar facts to the published snapshot hash (the /bazaar/snapshots document)."""
    bz = ((att.get("claims") or {}).get("facts") or {}).get("bazaar") or {}
    if bz.get("available") is not True: return True, "no snapshot facts to bind"
    if not isinstance(bz.get("snapshot_sha256"), str): return False, "attestation carries no snapshot hash"
    e = [x for x in (snapshots.get("snapshots") if isinstance(snapshots, dict) and isinstance(snapshots.get("snapshots"), list) else []) if isinstance(x, dict) and x.get("date") == bz.get("snapshot_date")]
    if len(e) != 1: return False, "snapshot %s is not published exactly once" % bz.get("snapshot_date")
    if e[0].get("sha256") != bz["snapshot_sha256"]: return False, "snapshot hash does not match the published snapshot"
    return True, "snapshot %s hash matches" % bz["snapshot_date"]

def main(argv):
    if not argv or argv[0] in ("-h", "--help"): print(__doc__); return 2
    src, issuer_src, check_expiry, key_id, snap_src = argv[0], None, True, None, None
    i = 1
    while i < len(argv):
        if argv[i] == "--issuer" and i + 1 < len(argv): issuer_src = argv[i + 1]; i += 2
        elif argv[i] == "--ignore-expiry": check_expiry = False; i += 1
        elif argv[i] == "--key-id" and i + 1 < len(argv): key_id = argv[i + 1]; i += 2
        elif argv[i] == "--snapshots" and i + 1 < len(argv): snap_src = argv[i + 1]; i += 2
        else: print("unknown argument: " + argv[i]); return 2
    try: body = load(src)
    except ValueError as e: print("FAIL " + str(e)); return 1
    att = body.get("attestation", body) if isinstance(body, dict) else body
    if not isinstance(att, dict): print("FAIL attestation is not an object"); return 1
    # never fall back to att.issuer.issuer_url: an attacker controls it and could point it at their own issuer document
    if not issuer_src: print("no issuer document: pass --issuer (the attestation's own issuer_url is never trusted)"); return 2
    if not key_id: print("no pinned key: pass --key-id (pinning the expected key_id is mandatory)"); return 2
    try: iss = load(issuer_src)
    except ValueError as e: print("FAIL issuer: " + str(e)); return 1
    ok, why = verify(att, iss, check_expiry=check_expiry, expected_key_id=key_id)
    if ok and snap_src:
        try: sd = load(snap_src)
        except ValueError as e: print("FAIL snapshots: " + str(e)); return 1
        ok2, why2 = verify_snapshot_binding(att, sd)
        ok, why = (ok2, why2) if not ok2 else (True, why + "; " + why2)
    print(("OK " if ok else "FAIL ") + why); return 0 if ok else 1

if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
