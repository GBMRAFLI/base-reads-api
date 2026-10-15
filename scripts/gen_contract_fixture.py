"""Writes deno/tests/fixtures/contract.json from the Python implementation (the reference contract).
The Deno tests compare their output against it; tests/test_preflight.py checks the file is current."""
import base64, json, os, sys, tempfile
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
def build():
    os.environ.pop("PUBLIC_URL", None); os.environ.pop("NETWORK", None)
    os.environ.setdefault("DATA_STORE", tempfile.mkdtemp()); os.environ["SNAPSHOT_DIR"] = tempfile.mkdtemp()
    sys.path.insert(0, os.path.join(R, "api")); import index as IX, preflight as PF, sales_log as MS
    items = [{"resource": "https://a.example/x?q=1", "accepts": [{"payTo": "0x" + "AB" * 20}, {"payTo": "0x" + "cd" * 20}], "quality": {"l30DaysUniquePayers": 3, "l30DaysTotalCalls": 9, "lastCalledAt": "2026-10-13T00:00:00Z"}},
             {"resource": "https://b.example/y", "accepts": [{"payTo": "0x" + "ab" * 20}], "quality": {}}, {"resource": "nohost", "accepts": []}]
    root = {"service": "GBMRAFLI Base Reads", "network": IX.NETWORK, "protocol": "x402 v2", "routes": {k: {"price_usdc": v[0] / 1e6, "description": v[1]} for k, v in IX.ROUTES.items()}}
    ch = [{"x402Version": 2, "accepts": [{"scheme": "exact", "network": "n", "amount": "10", "asset": "0x" + "11" * 20, "payTo": "0x" + "22" * 20, "maxTimeoutSeconds": 60}]},
          None, {"_unparseable": "body"}, {"x402Version": 3, "accepts": [{"maxAmountRequired": "1.5", "payTo": "0xbad", "maxTimeoutSeconds": 0}, 5]}, {"x402Version": 1, "accepts": []}]
    return {
        "routes": [[k, v[0], v[1], v[2]] for k, v in IX.ROUTES.items()],
        "root_body": json.dumps(root),
        "required": {k: {"body": json.dumps(IX.required(k, "h.example")), "header": IX.b64(IX.required(k, "h.example"))} for k in IX.ROUTES},
        "req_for": {k: IX.req_for(k) for k in IX.ROUTES},
        "rid": [MS.rid("exec", None, "/base/network"), MS.rid("cand", "v1", "chain_reads", "/base/network"), MS.rid("out", "0x" + "ab" * 32, "/x402/preflight")],
        "validate": [list(PF.validate_challenge(c)) for c in ch],
        "index": PF.build_index(items, "2026-10-13"),
        "canonical": PF.canonical({"b": [1, None, True, "é\u2028😀\"\\\n\t\x01"], "a": {"z": 0, "A": -5}, "_": ""}).decode(),
    }
if __name__ == "__main__":
    json.dump(build(), open(os.path.join(R, "deno", "tests", "fixtures", "contract.json"), "w"), indent=1, sort_keys=True); print("ok")
