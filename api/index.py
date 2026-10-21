"""Base Reads: receive-only x402 v2 seller on Base mainnet. Never signs or sends funds.
Zero-LLM: every route is 100% deterministic code (JSON-RPC reads only)."""
import calendar, json, os, re, base64, time, urllib.request, urllib.parse, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import preflight as PF, attestation as AT
import sales_log as MS, cdp_auth, settle_guard as SG
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
 "/base/usdc-balance": (1000, "Live Base mainnet USDC and ETH balance for one address, read with eth_call at the latest block; returns decimal and raw values plus the block number. Use it to check a wallet can cover a payment or that funds arrived before acting. Simpler than running an RPC client and decoding ERC-20 calls yourself, and the block number makes each reading reproducible. Query: ?address=0x...", {"address": "0x4200000000000000000000000000000000000016"}),
 "/base/tx-status": (2000, "Base mainnet transaction status: success, failed or pending, with block, confirmations, gas used, effective gas price, from/to and log count. Use it after sending or receiving a payment to confirm it landed and how deep it is. One normalized JSON answer instead of combining receipt and block calls and computing confirmations yourself. Query: ?hash=0x...", {"hash": "0x" + "0"*64}),
 "/base/basename": (3000, "Resolve a Basename (name.base.eth) to its Base address, or an address to its primary Basename, checked both ways so a reverse name is only returned when it resolves back. Use it to turn a human name into a payout address or to label an address. Avoids hand-written ENS-style namehash and resolver calls. Query: ?name=jesse.base.eth or ?address=0x...", {"name": "jesse.base.eth"}),
 "/base/address-intel": (10000, "One call for an address on Base: USDC balance, ETH balance, verified primary Basename, transaction count (nonce) and whether it is a contract. Use it to profile a counterparty or payout wallet before interacting. Replaces four or five separate reads with a single priced request. Query: ?address=0x...", {"address": "0x2211d1d0020daea8039e46cf1367962070d77da9"}),
 "/x402/preflight": (10000, "Pre-pay Check: Ed25519-signed, deterministic facts about another x402 endpoint before you pay it: challenge validity, reachability and latency, host listing count, payout wallet reuse across hosts, last-called and payer trend from daily Bazaar snapshots. Use it when choosing between paid endpoints. Signed facts you can verify against the published key, not ratings; facts only, no advice. Query: ?url=https://...", {"url": "https://x402.org/protected"}),
 "/base/network": (1000, "Base mainnet head: latest block number, block age in seconds, base fee and gas price in gwei. Use it to check the chain is advancing and to estimate fees before sending a transaction. One small JSON read instead of several raw RPC calls and unit conversions.", {}),
}
def rpc(m, p):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(), {"Content-Type": "application/json", "User-Agent": "base-reads/1.0"})
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
        t = os.environ.get("ATTESTATION_TTL_S", ""); ttl = int(t) if re.fullmatch(r"[0-9]{1,6}", t) else None  # int >= 1 else 900
        base = os.environ.get("PUBLIC_URL", "").rstrip("/")
        return PF.preflight(u, rpc=rpc, ttl_s=ttl, issuer_url=base + "/.well-known/issuer.json" if base else None)
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
        return 200, {"chain": "base", "address": a, "usdc": raw / 1e6, "usdc_raw": str(raw), "eth": eth / 1e18, "eth_wei": str(eth), "block": int(rpc("eth_blockNumber", []), 16), "related_routes": related(path)}
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
        return 200, {"chain": "base", "chain_id": 8453, "block": int(b["number"], 16), "block_age_s": max(0, int(time.time()) - int(b["timestamp"], 16)), "base_fee_gwei": int(b.get("baseFeePerGas", "0x0"), 16) / 1e9, "gas_price_gwei": int(rpc("eth_gasPrice", []), 16) / 1e9, "related_routes": related(path)}
RELATED = {"/base/network": ["/base/tx-status", "/x402/preflight"], "/base/usdc-balance": ["/base/address-intel", "/x402/preflight"]}
def related(path):
    """Neutral follow-up list (path and price only) for a response."""
    return [{"path": p, "price_usdc": f"{ROUTES[p][0] / 1e6:.3f}"} for p in RELATED[path]]
def req_for(path):
    return {"scheme": "exact", "network": NETWORK, "amount": str(ROUTES[path][0]), "asset": USDC, "payTo": PAY_TO, "maxTimeoutSeconds": 120, "extra": {"name": "USD Coin" if NETWORK == "eip155:8453" else "USDC", "version": "2"}}
DISCOVERY = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "discovery.json")))
def bazaar(path):
    """extensions.bazaar in the declareDiscoveryExtension format (info + JSON schema), method already set to GET
    as the official resource-server extension does. Field descriptions and output examples: api/discovery.json."""
    ex, d = ROUTES[path][2], DISCOVERY[path]
    inp = {"type": "http", "method": "GET"}; inp_s = {"type": {"type": "string", "const": "http"}, "method": {"type": "string", "enum": ["GET", "HEAD", "DELETE"]}}
    if d["params"]:
        inp["queryParams"] = ex
        inp_s["queryParams"] = {"type": "object", "properties": d["params"], "required": d["required"]}
    else:  # no inputs: still declare an (empty) input schema so discovery tools do not flag "input schema missing"
        inp_s["queryParams"] = {"type": "object", "properties": {}, "additionalProperties": False}
    return {"info": {"input": inp, "output": {"type": "json", "example": d["output"]}},
            "schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                       "properties": {"input": {"type": "object", "properties": inp_s, "required": ["type", "method"], "additionalProperties": False},
                                      "output": {"type": "object", "properties": {"type": {"type": "string"}, "example": {"type": "object"}}, "required": ["type"]}},
                       "required": ["input"]}}
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$")
def safe_host(h):
    """The Host header is client-controlled; only a plain hostname[:port] may appear in the challenge's resource URL."""
    return h if HOST_RE.match(h or "") else "invalid-host"
def required(path, host=""):
    price, desc, ex = ROUTES[path]
    return {"x402Version": 2, "error": "PAYMENT-SIGNATURE header is required", "resource": {"url": (PUBLIC or ("https://" + safe_host(host))) + path, "description": desc, "mimeType": "application/json"},
            "accepts": [req_for(path)], "extensions": {"bazaar": bazaar(path)}}
def fac(p, body):
    r = urllib.request.Request(FAC + p, json.dumps(body).encode(), {"Content-Type": "application/json", "User-Agent": "base-reads/1.0", **cdp_auth.headers(FAC, p)})
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
REPO_URL = os.environ.get("REPO_URL", "https://github.com/GBMRAFLI/base-reads-api")
def root():
    return {"service": "Base Reads", "network": NETWORK, "protocol": "x402 v2", "facilitator": facilitator_info(),
            "free": ["/llms.txt", "/openapi.json", "/.well-known/402index-verify.txt", "/.well-known/x402-preflight", "/.well-known/x402-preflight-key-history.json", "/.well-known/issuer.json", "/.well-known/prepay-check-attestation-v1.schema.json", "/.well-known/bazaar-snapshot.json", "/x402/preflight/pubkey", "/bazaar/snapshots"],
            "routes": {k: {"price_usdc": v[0] / 1e6, "description": v[1]} for k, v in ROUTES.items()}}
REF_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
def clean_ref(qs):
    """Optional ?ref= attribution tag: logged with paid calls only, never part of the price, challenge or requirements.
    Self-reported and unverified. If ref appears more than once, the first occurrence wins (same as Deno cleanRef)."""
    for x in qs.split("&"):
        if x.startswith("ref="): v = urllib.parse.unquote(x[4:]); return v if REF_RE.fullmatch(v) else None
    return None
def strip_ref(qs):
    """Query string without ref params, so the logged input hash does not depend on attribution."""
    return "&".join(x for x in qs.split("&") if x and not x.startswith("ref=") and x != "ref")
def llms_txt():
    net = "Base mainnet" if NETWORK == "eip155:8453" else "Base Sepolia" if NETWORK == "eip155:84532" else NETWORK
    L = ["# Base Reads", "", f"> Pay-per-call read API for {net} over x402 v2. Each paid route answers GET without payment with HTTP 402 and a PAYMENT-REQUIRED challenge; retry with a PAYMENT-SIGNATURE header to get JSON.", "",
         "## Payment", "", "- Protocol: x402 v2, scheme exact", f"- Network: {NETWORK} ({net})", f"- Asset: USDC {USDC}", "- Authorization: EIP-3009 transferWithAuthorization only (Permit2 is rejected)",
         "- Responses are served only after the transfer is confirmed on-chain", "- Optional ?ref=<tag> (A-Z a-z 0-9 . _ -, max 64) is recorded for attribution and never changes price or challenge", "",
         "## Paid routes (GET, JSON)", ""]
    L += [f"- {k} ({v[0] / 1e6:.3f} USDC): {v[1]}" for k, v in ROUTES.items()]
    L += ["", "## What the responses are", "", "- Verifiable facts only: /base/network, /base/usdc-balance, /base/address-intel and /base/tx-status (once mined) include the Base block number they refer to, so those readings can be reproduced against any Base RPC node",
          "- No verdicts, opinions, scores or predictions, no buy/sell advice, and no language model in the response path",
          "- Compared with a free RPC endpoint: values are normalized (decimal and raw units, gwei, confirmations), pinned to a block number, and several reads are combined into one call",
          "", "## Usage pattern", "", f"- To get signed facts about an x402 endpoint before paying it, you can call /x402/preflight?url=<endpoint> ({ROUTES['/x402/preflight'][0] / 1e6:.3f} USDC). Facts only, no guarantee.",
          "- /base/network and /base/usdc-balance responses list related_routes (path and price) for follow-up reads"]
    L += ["", "## Discovery (free)", "", "- / : service index with routes and prices", "- /openapi.json : OpenAPI 3.1 description of the paid routes with prices", "- /bazaar/snapshots : daily Bazaar snapshot summary",
          "- /.well-known/bazaar-snapshot.json : signed snapshot series metadata", "- /.well-known/x402-preflight : Pre-pay Check schema and signing key",
          "- /.well-known/x402-preflight-key-history.json : signing key history",
          "- /.well-known/issuer.json : attestation issuer, contact and signing keys (active and retired), plus machine-readable signing rules and verify steps. v1.0 attestation: Ed25519 (RFC 8032) over UTF-8 of \"prepay-check-attestation/v1\" + LF followed by RFC 8785 (JCS) of the attestation without its signature member; snapshot meta uses the prefix \"bazaar-snapshot-meta/v1\" + LF", "- /.well-known/prepay-check-attestation-v1.schema.json : JSON Schema of the signed attestation (CC0)", "- /x402/preflight/pubkey : Ed25519 public key for verifying signed facts",
          "- Each 402 challenge carries extensions.bazaar (input schema and output example) for x402 Bazaar listing", "", "Facts only, no investment advice.", ""]
    return "\n".join(L)
VERIFY_402INDEX_DEFAULT = "be918d4df21371f971ccaa589e4ed1adbe9a077a824950b1db21cebfbbf5ae3c"
def verify_token():
    """402index ownership token: INDEX_VERIFY_TOKEN if set, else the built-in constant. Served with no trailing newline."""
    return os.environ.get("INDEX_VERIFY_TOKEN") or VERIFY_402INDEX_DEFAULT
FAVICON_B64 = "AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0lIA/9JSAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP8AAAAAAAAAAAAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/AAAAAAAAAADSUgD/0lIA/9JSAP/SUgD/0lIA///////////////////////SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAA0lIA/9JSAP/SUgD/0lIA/9JSAP//////0lIA/9JSAP/SUgD//////9JSAP/SUgD/0lIA/9JSAP8AAAAA0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD//////9JSAP/SUgD/0lIA///////SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA///////////////////////SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP8AAAAA0lIA/9JSAP/SUgD/0lIA/9JSAP//////0lIA/9JSAP/SUgD//////9JSAP/SUgD/0lIA/9JSAP8AAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD//////9JSAP/SUgD/0lIA///////SUgD/0lIA/9JSAP/SUgD/AAAAAAAAAADSUgD/0lIA/9JSAP/SUgD/0lIA///////////////////////SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAANJSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAAAAAAAAAAAAA0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADSUgD/0lIA/9JSAP/SUgD/0lIA/9JSAP/SUgD/0lIA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0lIA/9JSAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="  # 16x16 ICO from scripts/gen_favicon.py
FREE_PATHS = ("/", "/index.json", "/favicon.ico", "/llms.txt", "/openapi.json", "/.well-known/402index-verify.txt", "/.well-known/x402-preflight", "/.well-known/x402-preflight-key-history.json", "/.well-known/issuer.json", "/.well-known/prepay-check-attestation-v1.schema.json", "/.well-known/bazaar-snapshot.json", "/x402/preflight/pubkey", "/bazaar/snapshots")
def openapi():
    """OpenAPI 3.1 for the paid routes, generated from ROUTES + discovery.json so prices cannot drift from the 402 challenge."""
    paths = {}
    for k, (price, desc, ex) in ROUTES.items():
        d = DISCOVERY[k]
        params = [{"name": n, "in": "query", "required": n in d["required"], "description": sch.get("description", ""), "schema": {kk: vv for kk, vv in sch.items() if kk != "description"}} for n, sch in d["params"].items()]
        paths[k] = {"get": {"operationId": k.strip("/").replace("/", "_").replace("-", "_"), "summary": desc.split(". ")[0][:120], "description": desc, "parameters": params,
            "responses": {"200": {"description": "Result (served after the payment is confirmed on-chain)", "content": {"application/json": {"example": d["output"]}}},
                          "402": {"description": "Payment required: x402 v2 challenge in the PAYMENT-REQUIRED header and body"}},
            "x-payment-info": {"protocols": ["x402"], "pricingMode": "fixed", "price": f"{price / 1e6:.3f}", "amount": str(price), "currency": "USDC", "asset": USDC, "network": NETWORK, "payTo": PAY_TO}}}
    return {"openapi": "3.1.0", "info": {"title": "Base Reads", "version": "1.0.0", "contact": {"email": "gbmrafli@agentmail.to"},
            "description": "Pay-per-call read API for Base over x402 v2. Deterministic data, no advice.",
            "x-guidance": "Call any path with GET. Without payment you get HTTP 402 and a PAYMENT-REQUIRED challenge (x402 v2, exact scheme, USDC on Base). Sign an EIP-3009 transferWithAuthorization for the stated amount and retry with the PAYMENT-SIGNATURE header; the JSON is returned once the transfer is confirmed on-chain."},
            "paths": paths}
def facilitator_info():
    """Which facilitator verifies/settles payments, derived from FACILITATOR (never hardcoded in responses)."""
    h = (urllib.parse.urlsplit(FAC).hostname or "").lower()
    name = "CDP" if h == cdp_auth.CDP_HOST else "PayAI" if h == "payai.network" or h.endswith(".payai.network") else h
    return {"name": name, "url": FAC, "auth": "cdp_jwt" if cdp_auth.enabled(FAC) else "none"}
def well_known():
    pub = PF.public_key_info()
    return {"service": "Base Reads", "schema": PF.SCHEMA, "alg": "Ed25519", "key_id": pub["key_id"], "public_key_b64": pub["public_key_b64"],
            "fingerprint": pub["fingerprint"], "fingerprint_short": pub["fingerprint_short"], "created_at": pub["created_at"],
            "attestation": {"spec": AT.SPEC, "version": AT.VERSION, "canonicalization": AT.CANON, "issuer": "/.well-known/issuer.json", "schema": "/.well-known/prepay-check-attestation-v1.schema.json"},
            "verify": ["Take the paid /x402/preflight response body: {facts, signature} (legacy form; the v1.0 envelope is in \"attestation\", see /.well-known/issuer.json).",
                       "Serialize facts as canonical JSON: keys sorted, separators (',', ':'), ASCII-only escapes (Python json.dumps(facts, sort_keys=True, separators=(',', ':'))).",
                       "Verify signature.value_b64 (base64) over those bytes with Ed25519 (RFC 8032) and public_key_b64 (32-byte raw key).",
                       "Check signature.key_id matches key_id here; key_id = first 16 hex chars of sha256(raw public key)."],
            "facilitator": facilitator_info(), "repo": REPO_URL, "routes": {"pubkey": "/x402/preflight/pubkey", "key_history": "/.well-known/x402-preflight-key-history.json", "paid_check": "/x402/preflight", "snapshots": "/bazaar/snapshots", "snapshot_meta": "/.well-known/bazaar-snapshot.json"}}
def snapshot_meta():
    """Free, signed metadata about the daily Bazaar snapshot series (no snapshot contents)."""
    dates = PF.snapshot_dates(); last = dates[-1] if dates else None
    meta = {"version": 1, "started_at": dates[0] if dates else None, "last_updated": last, "total_snapshots": len(dates),
            "covered_listings": len(PF.load_index(last).get("resources", {})) if last else 0}
    return {"metadata": meta, "signature": PF.sign_jcs(meta), "pubkey_url": "/x402/preflight/pubkey"}
ATT_SCHEMA = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "prepay-check-attestation-v1.schema.json")))
def signing_spec():
    """Machine-readable signing rules in issuer.json, built from the signer's own constants (same as Deno signingSpec)."""
    dom = lambda p, src, payload, loc: {"signing_prefix": p, "signing_prefix_hex": p.encode().hex(), "source": src, "payload": payload, "signature_location": loc}
    return {"algorithm": "Ed25519", "algorithm_ref": "RFC 8032 (pure Ed25519, no pre-hash)",
            "canonicalization": AT.CANON, "canonicalization_ref": "RFC 8785", "text_encoding": "UTF-8",
            "message": "signing_prefix || JCS(payload)",
            "public_key_encoding": "keys[].public_key_b64: standard base64 (RFC 4648, padded) of the raw 32-byte Ed25519 public key",
            "signature_encoding": "signature.value_b64: standard base64 (RFC 4648, padded) of the 64-byte Ed25519 signature",
            "key_id_derivation": "first 16 lowercase hex chars of sha256(raw 32-byte public key)",
            "domains": {"attestation": dom(AT.DOMAIN_ATTESTATION, "/x402/preflight response, member \"attestation\"", "the attestation object with its \"signature\" member removed (every other member is signed)", "attestation.signature"),
                        "snapshot_meta": dom(AT.DOMAIN_SNAPSHOT_META, "/.well-known/bazaar-snapshot.json", "the \"metadata\" member", "signature")}}
VERIFY_STEPS = (
    "Pick the domain in signing.domains (attestation for /x402/preflight \"attestation\", snapshot_meta for /.well-known/bazaar-snapshot.json).",
    "Build the payload: for an attestation, remove the \"signature\" member (all other members are signed); for snapshot meta, take \"metadata\".",
    "Serialize the payload with RFC 8785 JSON Canonicalization Scheme (JCS) and encode it as UTF-8.",
    "Prepend the UTF-8 bytes of signing_prefix (attestation: \"prepay-check-attestation/v1\" + LF, hex 7072657061792d636865636b2d6174746573746174696f6e2f76310a; snapshot meta: \"bazaar-snapshot-meta/v1\" + LF). Message = signing_prefix || JCS(payload). Without the prefix the signature does not verify.",
    "Find the key in keys[] whose key_id equals signature.key_id; key_id = first 16 lowercase hex chars of sha256(raw 32-byte public key); public_key_b64 is standard base64 of that raw key.",
    "Verify signature.value_b64 (standard base64, 64 bytes) over the message with Ed25519 (RFC 8032).",
    "Reject if now > expires_at, if issued_at is more than 60 s in the future, or if the key was retired before issued_at.")
def issuer_doc():
    """Attestation issuer document: identity, contact and every signing key (active + retired)."""
    h = PF.key_history(); base = os.environ.get("PUBLIC_URL", "").rstrip("/")
    return {"spec": AT.SPEC, "version": AT.VERSION, "issuer": {"name": AT.ISSUER_NAME, "contact": AT.CONTACT, "issuer_url": base + "/.well-known/issuer.json" if base else None},
            "canonicalization": AT.CANON, "signature_alg": "Ed25519", "keys": [h["current"]] + h["retired"],
            "schema": "/.well-known/prepay-check-attestation-v1.schema.json",
            "key_policy": "Signing keys are generated and held only in the production server environment and are never published or exported. Rotation adds the new key as active and keeps old keys listed as retired with retired_at.",
            "signing": signing_spec(), "verify": list(VERIFY_STEPS)}
_SNAP_SUM = {}
def snapshot_summary(limit=30):
    """Free: daily Bazaar snapshot history (counts only), newest first."""
    out = []
    for d in reversed(PF.snapshot_dates()[-limit:]):
        if d not in _SNAP_SUM:
            idx = PF.load_index(d); res = idx.get("resources", {})
            _SNAP_SUM[d] = {"date": d, "status": idx.get("status") or (idx.get("coverage") or {}).get("status"), "resources": len(res), "hosts": len(idx.get("hosts", {})), "payout_wallets": len(idx.get("wallet_hosts", {})),
                            "calls30d_total": sum((r.get("calls30d") or 0) for r in res.values()), "payers30d_total": sum((r.get("payers30d") or 0) for r in res.values())}
        out.append(_SNAP_SUM[d])
    return {"source": "x402 Bazaar discovery API, crawled daily at 00:15 UTC", "latest": latest_of(out), "snapshots": out}
def latest_of(out, now=None):
    """Freshness and completeness of the newest snapshot: date, status (complete | partial | failed | None), listing count, age in days."""
    if not out: return {"date": None, "status": None, "listings": 0, "age_days": None, "fresh": False}
    s = out[0]; now = time.time() if now is None else now
    age = int((now - calendar.timegm(time.strptime(s["date"], "%Y-%m-%d"))) // 86400)
    return {"date": s["date"], "status": s.get("status"), "listings": s.get("resources", 0), "age_days": max(0, age), "fresh": max(0, age) <= 3}
REPLAY, FAILS, SLOTS = SG.Replay(), SG.FailLimiter(), SG.Slots()
ONCHAIN_CHECK = os.environ.get("ONCHAIN_CHECK", "block")   # block: serve only after the nonce-bound USDC Transfer is confirmed on Base; log: serve on facilitator success (testnets only)
MAINNET = "eip155:8453"
def onchain_mode(mode=None, network=None):
    """ONCHAIN_CHECK=log is refused on Base mainnet: block is forced there."""
    mode, network = mode or ONCHAIN_CHECK, network or NETWORK
    return "log" if mode == "log" and network != MAINNET else "block"
def assert_onchain_mode(mode=None, network=None):
    if (mode or ONCHAIN_CHECK) == "log" and (network or NETWORK) == MAINNET: raise SystemExit("ONCHAIN_CHECK=log is not allowed on Base mainnet")
FAC_ERRORS = frozenset({"insufficient_funds", "invalid_exact_evm_payload_authorization_valid_after",
    "invalid_exact_evm_payload_authorization_valid_before", "invalid_exact_evm_payload_authorization_value",
    "invalid_exact_evm_payload_signature", "invalid_exact_evm_payload_recipient_mismatch", "invalid_network", "invalid_payload",
    "invalid_payment_requirements", "invalid_scheme", "unsupported_scheme", "invalid_x402_version", "invalid_transaction_state",
    "settle_exact_svm_block_height_exceeded", "unexpected_verify_error", "unexpected_settle_error", "payment_expired"})
def fac_err(x): return x if isinstance(x, str) and x in FAC_ERRORS else "facilitator_error"
def pay_resp(ok, tx, payer, why=None):
    """PAYMENT-RESPONSE is always rebuilt from validated fields; facilitator bodies are never echoed."""
    o = {"success": True, "transaction": tx, "network": NETWORK, "payer": payer} if ok else \
        {"success": False, "errorReason": why, "transaction": tx or "", "network": NETWORK, "payer": payer}
    return {"PAYMENT-RESPONSE": b64(o)}
import threading
_TX_LOCK, _TX_SEEN = threading.Lock(), set()
def tx_already_used(tx):
    """Atomically claim a settlement tx for one served sale (in-process set + durable check against the sales log)."""
    t = tx.lower()
    with _TX_LOCK:
        if t in _TX_SEEN or any((r.get("tx") or "").lower() == t for r in MS.rows("executions.jsonl")): return True
        _TX_SEEN.add(t); return False
def no_pay(st): return pay_resp(False, None, None, str(st))
def paid(path, q, qs, sig, t_req, check=None, ip=None):
    """precheck -> limits -> replay claim -> verify -> handler -> settle -> independent on-chain check -> serve. Returns (code, body, headers).
    block (default): the resource is returned ONLY when Base shows a successful tx with USDC Transfer(payer -> payTo, >= amount)
    and AuthorizationUsed(payer, nonce) in the same receipt. Facilitator success alone never serves. The payer is always the
    signed authorization's `from`. If the receipt is not visible yet: 202 + the payment is parked; a retry serves it once confirmed.
    log (testnets only; refused on Base mainnet): serve on facilitator success and record any on-chain mismatch."""
    payload, err = SG.parse_payment(sig)
    if err: return 400, {"error": err}, {}
    r = req_for(path)
    bad = SG.precheck(payload, r)   # before the claim: malformed/foreign payloads never consume a nonce slot
    if bad: return 402, {"error": bad}, no_pay(bad)
    who, nonce = SG.payer_of(payload), SG.nonce_of(payload); ids = {"ip": ip, "payer": who}
    check = check or (lambda tx, rq, payer: MS.verify_onchain(rpc, tx, rq["asset"], rq["payTo"], rq["amount"], payer, NETWORK, attempts=3, wait=1.0, nonce=nonce))
    release = SLOTS.acquire({"ip": ip})   # per-IP slot now; per-payer slot only after verify (L1)
    if release is None: return BUSY
    held = []
    try: return _paid_locked(path, q, qs, payload, r, who, ids, check, t_req, held)
    finally:
        for h in held: h()
        release()
BUSY = (429, {"error": "too many concurrent payments, retry shortly", "scope": "concurrency"}, {})
def _paid_locked(path, q, qs, payload, r, who, ids, check, t_req, held):
    ip = ids["ip"]
    lim = FAILS.blocked(ids)   # checked while holding a slot: bursts cannot overshoot by more than the slot count
    if lim: return 429, {"error": "too many failed payments, retry later", "scope": lim}, {}
    key = SG.replay_key(payload)
    if not REPLAY.claim(key, SG.expiry(payload)):
        pend = REPLAY.take_pending(key)
        if pend and pend["path"] == path: return deliver_pending(key, pend, path, q, qs, r, check, who)
        if pend: REPLAY.set_pending(key, pend)
        return 409, {"error": "payment authorization already used or in flight"}, no_pay("replay")
    sale = lambda tx: {"success": True, "transaction": tx, "payer": who, "network": NETWORK}
    body = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": r}
    v = fac("/verify", body); t_ver = iso(time.time())
    if not v.get("isValid"):
        why = fac_err(v.get("invalidReason")); FAILS.fail({"ip": ip}, "verify"); return 402, {"error": why}, no_pay(why)
    rp = SLOTS.acquire({"payer": who})   # L1: a forged `from` never reaches this line
    if rp is None: REPLAY.unclaim(key); return BUSY
    held.append(rp)
    if FAILS.blocked({"payer": who}): REPLAY.unclaim(key); return 429, {"error": "too many failed payments, retry later", "scope": "payer"}, {}
    try: code, out = handle(path, q)
    except RuntimeError: return 503, {"error": "signing unavailable, not charged"}, {}
    except Exception: return 502, {"error": "upstream error, not charged"}, {}
    if code != 200: return code, out, {}  # bad input: not settled, not charged
    st = fac("/settle", body); t_set = iso(time.time())
    tx = st.get("transaction").lower() if isinstance(st.get("transaction"), str) and SG.TX_RE.match(st.get("transaction")) else None
    if isinstance(st.get("payer"), str) and st["payer"].lower() != who: log_mismatch(path, "facilitator_payer_differs_from_signed_from")
    times = (t_req, t_ver, t_set)
    if not st.get("success"):
        oc = check(tx, r, who) if tx else {"settled": False, "reason": "no_tx_hash"}
        if oc.get("settled") is True and not tx_already_used(tx):   # facilitator said failed, chain says paid: honor it
            log_sale(path, r, sale(tx), times, dict(oc, note="settle_reported_failure_but_confirmed_onchain"), qs, True)
            return 200, out, pay_resp(True, tx, who)
        why = fac_err(st.get("errorReason")); FAILS.fail(ids, "settle")
        return 402, {"error": why}, pay_resp(False, tx, who, why)
    if not tx: log_mismatch(path, "settle_success_without_valid_tx_hash"); return 502, {"error": "settlement response invalid, contact support with your payment"}, {}
    if tx_already_used(tx): log_mismatch(path, "settlement_tx_reused"); return 409, {"error": "settlement transaction already used"}, no_pay("replay")
    oc = check(tx, r, who)
    if onchain_mode() == "log":
        log_sale(path, r, sale(tx), times, oc, qs, True)
        if oc.get("settled") is not True: log_mismatch(path, "onchain_" + str(oc.get("reason")))
        return 200, out, pay_resp(True, tx, who)
    if oc.get("settled") is True: log_sale(path, r, sale(tx), times, oc, qs, True); return 200, out, pay_resp(True, tx, who)
    if oc.get("settled") is None:
        REPLAY.set_pending(key, {"path": path, "tx": tx, "times": times})
        return 202, {"status": "settled_pending_onchain_confirmation", "transaction": tx,
                     "retry": "repeat the same request with the same payment header; it is served once the transfer is confirmed on Base"}, pay_resp(True, tx, who)
    log_sale(path, r, sale(tx), times, oc, qs, False)
    return 402, {"error": "settlement not confirmed on-chain: " + str(oc.get("reason"))}, pay_resp(False, tx, who, "not_confirmed_onchain")
def deliver_pending(key, pend, path, q, qs, r, check, who):
    st = {"success": True, "transaction": pend["tx"], "payer": who, "network": NETWORK}
    oc = check(pend["tx"], r, who)
    if oc.get("settled") is None: REPLAY.set_pending(key, pend); return 202, {"status": "settled_pending_onchain_confirmation", "transaction": pend["tx"]}, pay_resp(True, pend["tx"], who)
    if oc.get("settled") is False: log_sale(path, r, st, pend["times"], oc, qs, False); return 402, {"error": "settlement not confirmed on-chain: " + str(oc.get("reason"))}, {}
    try: code, out = handle(path, q)
    except Exception: REPLAY.set_pending(key, pend); return 502, {"error": "upstream error, retry the same request"}, {}
    if code != 200: REPLAY.set_pending(key, pend); return code, out, {}
    log_sale(path, r, st, pend["times"], oc, qs, True)
    return 200, out, pay_resp(True, pend["tx"], who)
def log_sale(path, r, st, times, oc, qs, served):
    try:
        MS.record_sale(path, r, st, times, oc, served, ref=clean_ref(qs))
        MS.record_observation(path, __import__("hashlib").sha256(strip_ref(qs).encode()).hexdigest()[:16], 200 if served else 402, None)
    except Exception as e: print("sales log write failed:", type(e).__name__, flush=True)
def log_mismatch(path, why):
    try: MS.record_observation(path, "settle-mismatch", 502, None, note=why)
    except Exception as e: print("sales log write failed:", type(e).__name__, flush=True)
class handler(BaseHTTPRequestHandler):
    def log_message(s, f, *a): pass
    head = False
    def do_HEAD(s):
        """HEAD on free routes: same status and headers as GET, no body. Paid routes keep their previous behaviour (501)."""
        if s.path.partition("?")[0] not in FREE_PATHS: return s.send_error(501, "Unsupported method ('HEAD')")
        s.head = True
        try: s.do_GET()
        finally: s.head = False
    def do_GET(s):
        path, _, qs = s.path.partition("?"); q = dict(x.split("=", 1) for x in qs.split("&") if "=" in x)
        if path in ("/", "/index.json"):
            return s._send(200, root())
        if path == "/llms.txt": return s._send(200, llms_txt(), {"Cache-Control": "public, max-age=3600"}, ctype="text/plain; charset=utf-8")
        if path == "/openapi.json": return s._send(200, openapi(), {"Cache-Control": "public, max-age=3600"})
        if path == "/.well-known/402index-verify.txt": return s._send(200, verify_token(), ctype="text/plain; charset=utf-8")
        if path == "/favicon.ico": return s._send(200, base64.b64decode(FAVICON_B64), {"Cache-Control": "public, max-age=86400"}, ctype="image/x-icon")
        if path == "/.well-known/x402-preflight":
            try: return s._send(200, well_known())
            except RuntimeError: return s._send(503, {"error": "signing key unavailable"})
        if path == "/bazaar/snapshots": return s._send(200, snapshot_summary())
        if path == "/.well-known/prepay-check-attestation-v1.schema.json": return s._send(200, ATT_SCHEMA)
        if path == "/.well-known/issuer.json":
            try: return s._send(200, issuer_doc())
            except RuntimeError: return s._send(503, {"error": "signing key unavailable"})
        if path in ("/.well-known/bazaar-snapshot.json", "/.well-known/x402-preflight-key-history.json"):
            try: return s._send(200, snapshot_meta() if "bazaar" in path else PF.key_history())
            except RuntimeError: return s._send(503, {"error": "signing key unavailable"})
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
        code, out, hd = paid(path, q, qs, sig, t_req, ip=s.client_address[0])
        return s._send(code, out, hd)
    def _send(s, code, obj, hd={}, ctype="application/json"):
        b = obj if isinstance(obj, bytes) else obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
        try:
            s.send_response(code); s.send_header("Content-Type", ctype); s.send_header("Content-Length", str(len(b))); s.send_header("X-Content-Type-Options", "nosniff")
            s.send_header("Access-Control-Allow-Origin", "*"); s.send_header("Access-Control-Expose-Headers", "PAYMENT-REQUIRED, PAYMENT-RESPONSE")
            for k, v in hd.items(): s.send_header(k, v)
            s.end_headers()
            if not s.head: s.wfile.write(b)  # HEAD: same headers (incl. Content-Length), no body
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
    for w in PF.startup_warnings(): print("WARNING:", w, flush=True)
    assert_onchain_mode()
    if os.environ.get("SNAPSHOT_SCHEDULER", "1") == "1":
        import threading; threading.Thread(target=snapshot_loop, daemon=True, name="bazaar-snapshot").start()
    ThreadingHTTPServer((os.environ.get("HOST", "127.0.0.1"), PORT), handler).serve_forever()
