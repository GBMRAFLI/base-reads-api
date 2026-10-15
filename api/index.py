"""GBMRAFLI Base Reads: receive-only x402 v2 seller on Base mainnet. Never signs or sends funds.
Zero-LLM: every route is 100% deterministic code (JSON-RPC reads only)."""
import json, os, re, base64, time, urllib.request, urllib.parse, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import preflight as PF
import sales_log as MS
iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from Crypto.Hash import keccak as _k
def keccak(b): h = _k.new(digest_bits=256); h.update(b); return h.digest()
FAC = os.environ.get("FACILITATOR", "https://facilitator.payai.network")
RPC = os.environ.get("RPC", "https://mainnet.base.org")
PAY_TO_DEFAULT = "0x427F423908233DbCA2C51e4c6AE36D18f821641c"  # public receive-only payee wallet
PAY_TO = os.environ.get("PAY_TO_ADDRESS") or PAY_TO_DEFAULT  # receive-only payee
PUBLIC = os.environ.get("PUBLIC_URL", "")
NETWORK = os.environ.get("NETWORK", "eip155:8453")
USDC = {"eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e"}[NETWORK]
PORT = int(os.environ.get("PORT", 8443))
REG = "0xb94704422c2a1e396835a571837aa5ae53285a95"  # Basenames registry on Base
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$"); HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
ROUTES = {
 "/base/usdc-balance": (1000, "Base mainnet USDC + ETH balance for any address (live eth_call). Query: ?address=0x...", {"address": "0x4200000000000000000000000000000000000016"}),
 "/base/tx-status": (2000, "Base mainnet transaction status: success/failed/pending, block, confirmations, gas used, from/to. Query: ?hash=0x...", {"hash": "0x" + "0"*64}),
 "/base/basename": (3000, "Resolve a Basename (name.base.eth) to its Base address, or an address to its primary Basename. Query: ?name=jesse.base.eth or ?address=0x...", {"name": "jesse.base.eth"}),
 "/base/address-intel": (5000, "One call: Base USDC balance, ETH balance, verified primary Basename, tx count (nonce) and is_contract for an address. Query: ?address=0x...", {"address": "0x2211d1d0020daea8039e46cf1367962070d77da9"}),
 "/x402/preflight": (1000, "Pre-pay Check: Ed25519-signed deterministic facts about an x402 endpoint before you pay it: challenge validity, reachability and latency, host listing count, payout wallet reuse across hosts, last-called and payer trend from Bazaar snapshots. Facts only, no advice. Query: ?url=https://...", {"url": "https://api.example.com/paid"}),
 "/base/network": (1000, "Base mainnet head: block number, block age seconds, base fee and gas price in gwei.", {}),
}
def rpc(m, p):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(), {"Content-Type": "application/json", "User-Agent": "gbmrafli-base-reads/1.0"})
    d = json.loads(urllib.request.urlopen(r, timeout=15).read())
    if "error" in d: raise ValueError(d["error"].get("message"))
    return d["result"]
def call(to, data): return rpc("eth_call", [{"to": to, "data": data}, "latest"])
def namehash(n):
    h = b"\0"*32
    for l in reversed([x for x in n.split(".") if x]): h = keccak(h + keccak(l.encode()))
    return h
def resolver(node): r = call(REG, "0x0178b8bf" + node.hex()); return "0x" + r[-40:]
def dec_str(r):
    b = bytes.fromhex(r[2:]);
    if len(b) < 64: return None
    o = int.from_bytes(b[:32], "big"); n = int.from_bytes(b[o:o+32], "big"); return b[o+32:o+32+n].decode() or None
def reverse_name(a):
    node = namehash(a[2:].lower() + ".80002105.reverse"); res = resolver(node)
    nm = dec_str(call(res, "0x691f3431" + node.hex())) if int(res, 16) else None
    if nm:
        fn = namehash(nm); fr = resolver(fn)
        if not int(fr, 16) or ("0x" + call(fr, "0x3b3b57de" + fn.hex())[-40:]).lower() != a.lower(): nm = None
    return nm
def handle(path, q):
    if path == "/x402/preflight":
        u = urllib.parse.unquote(q.get("url", ""))
        if not u: return 400, {"error": "give ?url=https://..."}
        return PF.preflight(u)
    if path == "/base/address-intel":
        a = q.get("address", "")
        if not ADDR.match(a): return 400, {"error": "address must be 0x + 40 hex"}
        raw = int(call(USDC, "0x70a08231" + a[2:].lower().rjust(64, "0")), 16); eth = int(rpc("eth_getBalance", [a, "latest"]), 16)
        code = rpc("eth_getCode", [a, "latest"])
        return 200, {"chain": "base", "address": a, "usdc": raw / 1e6, "eth": eth / 1e18, "primary_basename": reverse_name(a), "tx_count": int(rpc("eth_getTransactionCount", [a, "latest"]), 16), "is_contract": code not in ("0x", "0x0", ""), "block": int(rpc("eth_blockNumber", []), 16)}
    if path == "/base/usdc-balance":
        a = q.get("address", "")
        if not ADDR.match(a): return 400, {"error": "address must be 0x + 40 hex"}
        raw = int(call(USDC, "0x70a08231" + a[2:].lower().rjust(64, "0")), 16); eth = int(rpc("eth_getBalance", [a, "latest"]), 16)
        return 200, {"chain": "base", "address": a, "usdc": raw / 1e6, "usdc_raw": str(raw), "eth": eth / 1e18, "eth_wei": str(eth), "block": int(rpc("eth_blockNumber", []), 16)}
    if path == "/base/tx-status":
        h = q.get("hash", "")
        if not HASH.match(h): return 400, {"error": "hash must be 0x + 64 hex"}
        rc = rpc("eth_getTransactionReceipt", [h]); head = int(rpc("eth_blockNumber", []), 16)
        if not rc:
            tx = rpc("eth_getTransactionByHash", [h]); return 200, {"chain": "base", "hash": h, "status": "pending" if tx else "not_found"}
        b = int(rc["blockNumber"], 16)
        return 200, {"chain": "base", "hash": h, "status": "success" if rc["status"] == "0x1" else "failed", "block": b, "confirmations": head - b + 1, "from": rc["from"], "to": rc.get("to"), "gas_used": int(rc["gasUsed"], 16), "effective_gas_price_wei": str(int(rc.get("effectiveGasPrice", "0x0"), 16)), "logs": len(rc["logs"])}
    if path == "/base/basename":
        if q.get("name"):
            n = q["name"].lower().strip()
            if not n.endswith(".base.eth"): n += ".base.eth"
            if not re.match(r"^[a-z0-9-]+\.base\.eth$", n): return 400, {"error": "invalid name"}
            node = namehash(n); res = resolver(node)
            if int(res, 16) == 0: return 200, {"name": n, "address": None}
            a = "0x" + call(res, "0x3b3b57de" + node.hex())[-40:]
            return 200, {"name": n, "address": None if int(a, 16) == 0 else a, "resolver": res}
        a = q.get("address", "")
        if not ADDR.match(a): return 400, {"error": "give ?name= or ?address="}
        node = namehash(a[2:].lower() + ".80002105.reverse"); res = resolver(node)
        nm = dec_str(call(res, "0x691f3431" + node.hex())) if int(res, 16) else None
        if nm:  # forward-verify
            fn = namehash(nm); fr = resolver(fn)
            if not int(fr, 16) or ("0x" + call(fr, "0x3b3b57de" + fn.hex())[-40:]).lower() != a.lower(): nm = None
        return 200, {"address": a, "primary_basename": nm}
    if path == "/base/network":
        b = rpc("eth_getBlockByNumber", ["latest", False])
        return 200, {"chain": "base", "chain_id": 8453, "block": int(b["number"], 16), "block_age_s": max(0, int(time.time()) - int(b["timestamp"], 16)), "base_fee_gwei": int(b.get("baseFeePerGas", "0x0"), 16) / 1e9, "gas_price_gwei": int(rpc("eth_gasPrice", []), 16) / 1e9}
def req_for(path):
    return {"scheme": "exact", "network": NETWORK, "amount": str(ROUTES[path][0]), "asset": USDC, "payTo": PAY_TO, "maxTimeoutSeconds": 120, "extra": {"name": "USD Coin" if NETWORK == "eip155:8453" else "USDC", "version": "2"}}
def required(path, host=""):
    price, desc, ex = ROUTES[path]
    return {"x402Version": 2, "error": "PAYMENT-SIGNATURE header is required", "resource": {"url": (PUBLIC or ("https://" + host)) + path, "description": desc, "mimeType": "application/json"},
            "accepts": [req_for(path)], "extensions": {"bazaar": {"info": {"input": {"type": "http", "method": "GET", "queryParams": ex}, "output": {"type": "json"}}, "discoverable": True}}}
def fac(p, body):
    r = urllib.request.Request(FAC + p, json.dumps(body).encode(), {"Content-Type": "application/json", "User-Agent": "gbmrafli-base-reads/1.0"})
    try: return json.loads(urllib.request.urlopen(r, timeout=40).read())
    except urllib.error.HTTPError as e: return json.loads(e.read() or b"{}")
b64 = lambda o: base64.b64encode(json.dumps(o).encode()).decode()
import hmac
EXPORT_FILES = ("executions.jsonl", "outcomes.jsonl", "observations.jsonl", "costs.jsonl")
def export(auth, q):
    """Bearer-protected read-only export of the sales log. Rows include the PayAI settlement tx hash
    from PAYMENT-RESPONSE / X-PAYMENT-RESPONSE, which the external collector matches against on-chain Transfer logs."""
    tok = os.environ.get("EXPORT_TOKEN", "")
    given = auth[7:] if auth.startswith("Bearer ") else ""
    if len(tok) < 32 or not hmac.compare_digest(given.encode(), tok.encode()): return 401, {"error": "unauthorized"}
    since = urllib.parse.unquote(q.get("since", ""))
    out = {n.split(".")[0]: [r for r in MS.rows(n) if not since or (r.get("startedAt") or r.get("verifiedAt") or r.get("observedAt") or r.get("incurredAt") or "") >= since] for n in EXPORT_FILES}
    return 200, {"payTo": PAY_TO, "network": NETWORK, "asset": USDC, "exportedAt": MS.iso(), "records": out}
class handler(BaseHTTPRequestHandler):
    def log_message(s, f, *a): pass
    def do_GET(s):
        path, _, qs = s.path.partition("?"); q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x)
        if path in ("/", "/index.json"):
            return s._send(200, {"service": "GBMRAFLI Base Reads", "network": NETWORK, "protocol": "x402 v2", "routes": {k: {"price_usdc": v[0] / 1e6, "description": v[1]} for k, v in ROUTES.items()}})
        if path == "/internal/export":
            code, obj = export(s.headers.get("Authorization", ""), q); return s._send(code, obj)
        if path == "/x402/preflight/pubkey":
            try: return s._send(200, PF.public_key_info())
            except RuntimeError: return s._send(503, {"error": "signing key unavailable"})
        if path not in ROUTES: return s._send(404, {"error": "not found"})
        if path == "/x402/preflight" and not ADDR.match(PAY_TO): return s._send(503, {"error": "payee not configured"})
        t_req = iso(time.time())
        sig = s.headers.get("PAYMENT-SIGNATURE") or s.headers.get("X-PAYMENT")
        if not sig: pr = required(path, s.headers.get("Host", "")); return s._send(402, pr, {"PAYMENT-REQUIRED": b64(pr)})
        # validate input before charging
        try: payload = json.loads(base64.b64decode(sig))
        except Exception: return s._send(400, {"error": "bad payment header"})
        r = req_for(path); body = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": r}
        v = fac("/verify", body); t_ver = iso(time.time())
        if not v.get("isValid"): return s._send(402, {"error": v.get("invalidReason", "invalid")}, {"PAYMENT-RESPONSE": b64({"success": False, "errorReason": v.get("invalidReason"), "network": NETWORK})})
        try: code, out = handle(path, q)
        except RuntimeError: return s._send(503, {"error": "signing unavailable, not charged"})
        except Exception as e: return s._send(502, {"error": "upstream error, not charged"})
        if code != 200: return s._send(code, out)  # bad input: not settled, not charged
        st = fac("/settle", body)
        if not st.get("success"): return s._send(402, {"error": st.get("errorReason", "settle failed")}, {"PAYMENT-RESPONSE": b64(st)})
        t_set = iso(time.time()); s._send(200, out, {"PAYMENT-RESPONSE": b64(st)})  # deliver first, then verify on-chain
        try:
            oc = MS.verify_onchain(rpc, st.get("transaction"), r["asset"], r["payTo"], r["amount"], st.get("payer"), NETWORK)
            MS.record_sale(path, r, st, (t_req, t_ver, t_set), oc)
            MS.record_observation(path, __import__("hashlib").sha256(qs.encode()).hexdigest()[:16], 200, None)
        except Exception as e: print("sales log write failed:", type(e).__name__, flush=True)
    def _send(s, code, obj, hd={}):
        b = json.dumps(obj).encode()
        try:
            s.send_response(code); s.send_header("Content-Type", "application/json"); s.send_header("Content-Length", str(len(b)))
            s.send_header("Access-Control-Allow-Origin", "*"); s.send_header("Access-Control-Expose-Headers", "PAYMENT-REQUIRED, PAYMENT-RESPONSE")
            for k, v in hd.items(): s.send_header(k, v)
            s.end_headers(); s.wfile.write(b)
        except BrokenPipeError: pass
def next_run_delay(now, hh=0, mm=15):
    """Seconds until the next hh:mm UTC."""
    t = time.gmtime(now); target = now - (t.tm_hour * 3600 + t.tm_min * 60 + t.tm_sec) + hh * 3600 + mm * 60
    return target - now if target > now else target + 86400 - now
def snapshot_loop(run_once=None, sleep=time.sleep, now=time.time, stop=lambda: False):
    """In-process daily Bazaar snapshot. Runs at startup if today's snapshot is missing, then daily at 00:15 UTC."""
    if run_once is None:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")); import bazaar_snapshot as BS
        run_once = lambda: BS.write(BS.crawl())
    if time.strftime("%Y-%m-%d", time.gmtime(now())) not in PF.snapshot_dates():
        try: run_once()
        except Exception as e: print("snapshot failed:", type(e).__name__, flush=True)
    while not stop():
        sleep(next_run_delay(now()))
        try: run_once()
        except Exception as e: print("snapshot failed:", type(e).__name__, flush=True)
if __name__ == "__main__":
    if os.environ.get("SNAPSHOT_SCHEDULER", "1") == "1":
        import threading; threading.Thread(target=snapshot_loop, daemon=True, name="bazaar-snapshot").start()
    ThreadingHTTPServer((os.environ.get("HOST", "127.0.0.1"), PORT), handler).serve_forever()
