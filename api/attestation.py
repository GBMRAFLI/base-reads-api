"""Pre-pay Check Attestation v1.0 (Python reference, byte-compatible with deno/lib/attestation.ts).
Signed bytes = RFC 8785 (JCS) canonical JSON of the envelope without its "signature" member.
The signing key is held only in the production server environment; callers pass a signer
(production: preflight.env_signer; tests: an ephemeral in-memory key). Zero LLM; facts only, no verdict."""
import base64, re, time, uuid
import rfc8785

SPEC, VERSION, CANON = "prepay-check-attestation", "1.0", "JCS"
ISSUER_NAME, CONTACT = "Base Reads Pre-pay Check", "gbmrafli@agentmail.to"
BASE_NETWORKS = ("eip155:8453", "base")
BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
DEFAULT_TTL_S, MAX_PAYTO_CODE_LOOKUPS = 900, 4
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")

def jcs(o): return rfc8785.dumps(o)
def signing_bytes(env): return jcs({k: v for k, v in env.items() if k != "signature"})
def iso(t): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))

def classify_code(address, code):
    """eoa (no code) | eip7702_delegated (code = 0xef0100 || delegate) | contract."""
    n = (len(code) - 2) // 2
    if n == 0: return {"address": address, "kind": "eoa", "code_bytes": 0}
    if n == 23 and code.lower().startswith("0xef0100"): return {"address": address, "kind": "eip7702_delegated", "code_bytes": 23, "delegate": "0x" + code[8:].lower()}
    return {"address": address, "kind": "contract", "code_bytes": n}
def payto_code(pay_tos, rpc=None):
    seen, out = [], []
    for a in pay_tos:
        if isinstance(a, str) and ADDR.match(a) and a.lower() not in seen: seen.append(a.lower())
    for a in seen[:MAX_PAYTO_CODE_LOOKUPS]:
        rec = {"address": a, "kind": None, "code_bytes": None}
        if rpc:
            try:
                code = rpc("eth_getCode", [a, "latest"])
                if isinstance(code, str) and re.fullmatch(r"0x[0-9a-fA-F]*", code): rec = classify_code(a, code)
            except Exception: pass
        out.append(rec)
    return out

def build_checks(facts, code):
    reach = facts.get("reachability") or {}; ch = facts.get("challenge") or {}; acc = ch.get("accepts") or []; bz = facts.get("bazaar") or {}
    out = []
    out.append({"id": "endpoint_reachable", "status": "pass" if reach.get("reachable") else "fail",
                "observed": reach.get("http_status") if reach.get("reachable") else reach.get("error_class")})
    out.append({"id": "http_402_returned", "status": "not_applicable" if not reach.get("reachable") else "pass" if reach.get("http_status") == 402 else "fail",
                "observed": reach.get("http_status"), "expected": 402})
    out.append({"id": "challenge_well_formed", "status": "pass" if ch.get("valid") else "fail", "observed": ch.get("problems") or []})
    nets = [a.get("network") for a in acc]
    out.append({"id": "network_is_base", "status": "not_applicable" if not acc else "pass" if all(n in BASE_NETWORKS for n in nets) else "fail",
                "observed": nets, "expected": "eip155:8453"})
    assets = [a["asset"].lower() if isinstance(a.get("asset"), str) else None for a in acc]
    out.append({"id": "asset_is_base_usdc", "status": "not_applicable" if not acc else "pass" if all(x == BASE_USDC for x in assets) else "fail",
                "observed": assets, "expected": BASE_USDC})
    known = [c for c in code if c["kind"] is not None]
    out.append({"id": "payto_is_eoa", "status": "not_applicable" if not code or len(known) < len(code) else "pass" if all(c["kind"] in ("eoa", "eip7702_delegated") for c in known) else "fail",
                "observed": [{"address": c["address"], "kind": c["kind"]} for c in code]})
    out.append({"id": "bazaar_snapshot_available", "status": "pass" if bz.get("available") else "fail",
                "observed": bz.get("snapshot_date") if bz.get("available") else bz.get("reason")})
    out.append({"id": "listed_in_bazaar", "status": "not_applicable" if not bz.get("available") or bz.get("listed") is None else "pass" if bz["listed"] else "fail",
                "observed": bz.get("listed") if bz.get("available") else None})
    return out

def attest(facts, signer, rpc=None, now=None, ttl_s=None, issuer_url=None):
    """signer = (key_id, sign(bytes) -> 64-byte signature)."""
    now = time.time() if now is None else now
    ttl = min(int(ttl_s), 86400) if ttl_s and ttl_s > 0 else DEFAULT_TTL_S
    key_id, sign_fn = signer
    code = payto_code([a.get("payTo") for a in (facts.get("challenge") or {}).get("accepts") or []], rpc)
    checks = build_checks(facts, code)
    env = {"spec": SPEC, "version": VERSION, "canonicalization": CANON, "attestation_id": str(uuid.uuid4()),
           "issued_at": iso(now), "expires_at": iso(int(now) + ttl),
           "issuer": {"name": ISSUER_NAME, "key_id": key_id, "issuer_url": issuer_url, "contact": CONTACT},
           "subject": {"type": "x402_endpoint", "url": facts.get("target")},
           "claims": {"facts": facts, "payto_code": code, "checks": checks,
                      "checks_passed": [c["id"] for c in checks if c["status"] == "pass"],
                      "checks_failed": [c["id"] for c in checks if c["status"] == "fail"]}}
    env["signature"] = {"alg": "Ed25519", "key_id": key_id, "value_b64": base64.b64encode(sign_fn(signing_bytes(env))).decode()}
    return env

def verify(env, public_key_b64, now=None, check_expiry=True):
    from Crypto.Signature import eddsa
    if env.get("spec") != SPEC or env.get("canonicalization") != CANON: return False, "unsupported_spec"
    s = env.get("signature") or {}
    if s.get("alg") != "Ed25519": return False, "bad_signature_block"
    pk = eddsa.import_public_key(base64.b64decode(public_key_b64))
    try: eddsa.new(pk, "rfc8032").verify(signing_bytes(env), base64.b64decode(s["value_b64"]))
    except (ValueError, KeyError): return False, "bad_signature"
    if check_expiry and iso(time.time() if now is None else now) > env["expires_at"]: return False, "expired"
    return True, None
