"""Writes deno/tests/fixtures/contract.json from the Python implementation (the reference contract).
The Deno tests compare their output against it; tests/test_preflight.py checks the file is current."""
import base64, json, os, sys, tempfile
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
def cdp_vector():
    """Deterministic JWT for a THROWAWAY Ed25519 key (seed 0x00..0x1f), fixed time and nonce."""
    sys.path.insert(0, os.path.join(R, "api")); import cdp_auth
    from Crypto.PublicKey import ECC
    seed = bytes(range(32)); pub = ECC.construct(curve="ed25519", seed=seed).public_key().export_key(format="raw")
    secret = base64.b64encode(seed + pub).decode()
    return {"key_id": "test-key-id", "secret": secret, "now": 1792800000, "nonce": "0123456789012345",
            "jwt": cdp_auth.jwt("test-key-id", secret, "POST", "api.cdp.coinbase.com", "/platform/v2/x402/settle", now=1792800000, nonce="0123456789012345")}
def build():
    os.environ.pop("PUBLIC_URL", None); os.environ.pop("NETWORK", None)
    os.environ.setdefault("DATA_STORE", tempfile.mkdtemp()); os.environ["SNAPSHOT_DIR"] = tempfile.mkdtemp()
    sys.path.insert(0, os.path.join(R, "api")); import index as IX, preflight as PF, sales_log as MS
    items = [{"resource": "https://a.example/x?q=1", "accepts": [{"payTo": "0x" + "AB" * 20}, {"payTo": "0x" + "cd" * 20}], "quality": {"l30DaysUniquePayers": 3, "l30DaysTotalCalls": 9, "lastCalledAt": "2026-10-13T00:00:00Z"}},
             {"resource": "https://b.example/y", "accepts": [{"payTo": "0x" + "ab" * 20}], "quality": {}}, {"resource": "nohost", "accepts": []}]
    os.environ.pop("FACILITATOR", None); root = IX.root()
    ch = [{"x402Version": 2, "accepts": [{"scheme": "exact", "network": "n", "amount": "10", "asset": "0x" + "11" * 20, "payTo": "0x" + "22" * 20, "maxTimeoutSeconds": 60}]},
          None, {"_unparseable": "body"}, {"x402Version": 3, "accepts": [{"maxAmountRequired": "1.5", "payTo": "0xbad", "maxTimeoutSeconds": 0}, 5]}, {"x402Version": 1, "accepts": []}]
    return {
        "routes": [[k, v[0], v[1], v[2]] for k, v in IX.ROUTES.items()],
        "root_body": json.dumps(root),
        "llms_txt": IX.llms_txt(),
        "favicon_b64": IX.FAVICON_B64,
        "openapi_body": json.dumps(IX.openapi()),
        "ref": [[q, IX.clean_ref(q)] for q in ["", "ref=agent.x_1-2", "a=1&ref=ok", "ref=" + "a" * 64, "ref=" + "a" * 65, "ref=bad%20x", "ref=%3Cscript%3E", "ref=", "ref=caf%C3%A9", "ref=a%2Eb", "ref=abc%0A", "ref=abc%0D%0A", "ref=first&ref=second", "ref=bad%20x&ref=good"]],
        "strip_ref": [[q, IX.strip_ref(q)] for q in ["", "ref=a", "address=0x1&ref=a", "ref=a&address=0x1", "a=1&ref=x&b=2&ref=y", "a=1&ref", "a=1&referrer=z"]],
        "required": {k: {"body": json.dumps(IX.required(k, "h.example")), "header": IX.b64(IX.required(k, "h.example"))} for k in IX.ROUTES},
        "req_for": {k: IX.req_for(k) for k in IX.ROUTES},
        "rid": [MS.rid("exec", None, "/base/network"), MS.rid("cand", "v1", "chain_reads", "/base/network"), MS.rid("out", "0x" + "ab" * 32, "/x402/preflight")],
        "validate": [list(PF.validate_challenge(c)) for c in ch],
        "index": PF.build_index(items, "2026-10-13"),
        "cdp_jwt": cdp_vector(),
        "canonical": PF.canonical({"b": [1, None, True, "é\u2028😀\"\\\n\t\x01"], "a": {"z": 0, "A": -5}, "_": ""}).decode(),
    }
if __name__ == "__main__":
    json.dump(build(), open(os.path.join(R, "deno", "tests", "fixtures", "contract.json"), "w"), indent=1, sort_keys=True); print("ok")
