import base64, json, os, sys, tempfile, threading, time, unittest, urllib.request, urllib.error
T = tempfile.mkdtemp()
os.environ.update(SNAPSHOT_DIR=os.path.join(T, "snap"), SIGNING_KEY_PATH=os.path.join(T, "k.pem"), DATA_STORE=os.path.join(T, "merc"), SELF_WALLETS="0x" + "77" * 20, EXPORT_TOKEN="t" * 40,
                  SIGNING_KEY_PASSPHRASE="test-passphrase-0123456789", PORT="18766")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api")); sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import preflight as PF, index as IX, bazaar_snapshot as BS
W1, W2 = "0x" + "11" * 20, "0x" + "22" * 20
ACC = {"scheme": "exact", "network": "eip155:8453", "amount": "1000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": W1, "maxTimeoutSeconds": 60}
def item(u, w, p): return {"resource": u, "accepts": [dict(ACC, payTo=w)], "quality": {"l30DaysUniquePayers": p, "l30DaysTotalCalls": p * 3, "lastCalledAt": "2026-10-13T00:00:00Z"}}

class T1(unittest.TestCase):
    @classmethod
    def setUpClass(c):
        BS.write([item("https://a.example/x", W1, 2), item("https://a.example/y", W1, 1), item("https://b.example/z", W1, 5)], "2026-10-12")
        BS.write([item("https://a.example/x", W1, 4), item("https://b.example/z", W2, 5)], "2026-10-13")
    def test_challenge_valid(self):
        ok, p, a = PF.validate_challenge({"x402Version": 2, "accepts": [ACC]}); self.assertTrue(ok); self.assertEqual(p, []); self.assertEqual(a[0]["payTo"], W1)
    def test_challenge_invalid(self):
        self.assertEqual(PF.validate_challenge(None)[1], ["no_402_challenge"])
        ok, p, _ = PF.validate_challenge({"x402Version": 2, "accepts": [dict(ACC, payTo="0xbad", amount="1.5")]})
        self.assertFalse(ok); self.assertIn("accepts[0].payTo_invalid", p); self.assertIn("accepts[0].amount_invalid", p)
        self.assertIn("accepts_missing_or_empty", PF.validate_challenge({"x402Version": 2, "accepts": []})[1])
    def test_sign_verify_and_tamper(self):
        env = PF.sign({"a": 1}); self.assertTrue(PF.verify(env)); env["facts"]["a"] = 2; self.assertFalse(PF.verify(env))
    def test_key_encrypted_at_rest(self):
        PF.public_key_info(); pem = open(os.environ["SIGNING_KEY_PATH"]).read()
        self.assertIn("ENCRYPTED", pem); self.assertEqual(oct(os.stat(os.environ["SIGNING_KEY_PATH"]).st_mode & 0o777), "0o600")
    def test_bazaar_facts(self):
        f = PF.bazaar_facts("https://a.example/x?q=1", [W1])
        self.assertEqual(f["snapshot_date"], "2026-10-13"); self.assertEqual(f["host_listing_count"], 1)
        self.assertEqual(f["payout_wallet_reuse"][W1]["hosts_using_wallet"], 1)
        self.assertEqual([t["payers30d"] for t in f["payer_trend"]], [2, 4]); self.assertEqual(f["last_called_at"], "2026-10-13T00:00:00Z")
    def test_ssrf_blocked(self):
        for u in ("http://example.com", "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://10.0.0.1/", "file:///etc/passwd"):
            self.assertEqual(PF.preflight(u)[0], 400, u)
    def test_preflight_end_to_end_signed(self):
        orig_c, orig_p = PF.check_url, PF.probe
        PF.check_url = lambda u: (object(), "93.184.216.34", None); PF.probe = lambda u, ip: ({"reachable": True, "http_status": 402, "latency_ms": 42}, {"x402Version": 2, "accepts": [ACC]})
        try: code, env = PF.preflight("https://a.example/x")
        finally: PF.check_url, PF.probe = orig_c, orig_p
        self.assertEqual(code, 200); self.assertTrue(PF.verify(env)); f = env["facts"]
        self.assertTrue(f["challenge"]["valid"]); self.assertEqual(f["reachability"]["latency_ms"], 42); self.assertIn("Not advice", f["disclaimer"])
    def test_no_secret_in_output(self):
        env = PF.sign({"x": 1}); s = json.dumps(env) + json.dumps(PF.public_key_info())
        self.assertNotIn(os.environ["SIGNING_KEY_PASSPHRASE"], s); self.assertNotIn("PRIVATE", s)
    def _rc(self, frm, to, val, status="0x1"):
        pad = lambda a: "0x" + "0" * 24 + a[2:]
        return {"status": status, "blockNumber": "0x10", "logs": [{"address": ACC["asset"], "topics": [IX.MS.TRANSFER, pad(frm), pad(to)], "data": hex(val)}]}
    def test_onchain_and_outcome(self):
        MS = IX.MS; req = IX.req_for("/x402/preflight"); tx = "0x" + "cd" * 32
        rpc = lambda m, p: self._rc(W2, req["payTo"], 1000)
        oc = MS.verify_onchain(rpc, tx, req["asset"], req["payTo"], "1000", W2, sleep=lambda x: None); self.assertTrue(oc["settled"])
        out = MS.record_sale("/x402/preflight", req, {"success": True, "payer": W2, "transaction": tx}, ("a", "b", "c"), oc)
        self.assertEqual((out["status"], out["category"], out["externalPayer"]), ("verified_success", "endpoint_check", True))
        self.assertEqual(MS.rows("executions.jsonl")[-1]["receipt"], "payment_received"); self.assertEqual(MS.rows("costs.jsonl")[-1]["revenue"], 0.001)
    def test_self_payer_excluded(self):
        MS = IX.MS; req = IX.req_for("/base/network"); me = "0x" + "77" * 20
        oc = MS.verify_onchain(lambda m, p: self._rc(me, req["payTo"], 1000), "0x" + "ee" * 32, req["asset"], req["payTo"], "1000", me)
        out = MS.record_sale("/base/network", req, {"success": True, "payer": me, "transaction": "0x" + "ee" * 32}, ("a", "b", "c"), oc)
        self.assertEqual((out["status"], out["reason"], out["category"]), ("excluded", "self_payer", "chain_reads"))
    def test_onchain_failures(self):
        MS = IX.MS; req = IX.req_for("/base/network"); f = lambda r: MS.verify_onchain(lambda m, p: r, "0x" + "ab" * 32, req["asset"], req["payTo"], "1000", W2, sleep=lambda x: None)
        self.assertEqual(f(self._rc(W2, req["payTo"], 999))["reason"], "no_matching_usdc_transfer")
        self.assertEqual(f(self._rc(W2, W1, 1000))["reason"], "no_matching_usdc_transfer")
        self.assertEqual(f(self._rc(W2, req["payTo"], 1000, "0x0"))["reason"], "tx_reverted")
        self.assertIsNone(f(None)["settled"])
        out = MS.record_sale("/base/network", req, {"success": True, "payer": W2, "transaction": "0x" + "ab" * 32}, ("a", "b", "c"), f(None))
        self.assertEqual(out["status"], "inconclusive")
    def test_server_402_and_pubkey(self):
        srv = IX.ThreadingHTTPServer(("127.0.0.1", 18766), IX.handler); threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            try: urllib.request.urlopen("http://127.0.0.1:18766/x402/preflight?url=https://a.example/x"); self.fail()
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 402); pr = json.loads(base64.b64decode(e.headers["PAYMENT-REQUIRED"]))
                a = pr["accepts"][0]; self.assertEqual((a["amount"], a["network"], a["payTo"]), ("1000", "eip155:8453", IX.PAY_TO))
            pk = json.loads(urllib.request.urlopen("http://127.0.0.1:18766/x402/preflight/pubkey").read()); self.assertEqual(pk["alg"], "Ed25519")
            idx = json.loads(urllib.request.urlopen("http://127.0.0.1:18766/").read()); self.assertEqual(idx["routes"]["/x402/preflight"]["price_usdc"], 0.001)
        finally: srv.shutdown()
    def test_llms_txt_and_ref_never_changes_402(self):
        srv = IX.ThreadingHTTPServer(("127.0.0.1", 18767), IX.handler); threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = urllib.request.urlopen("http://127.0.0.1:18767/llms.txt"); t = r.read().decode()
            self.assertTrue(r.headers["Content-Type"].startswith("text/plain")); self.assertEqual(r.headers["Cache-Control"], "public, max-age=3600")
            for k, v in IX.ROUTES.items(): self.assertIn(f"- {k} ({v[0] / 1e6:.3f} USDC)", t)
            for w in ("x402 v2", "EIP-3009", "/.well-known/bazaar-snapshot.json", "/x402/preflight/pubkey", IX.USDC): self.assertIn(w, t)
            for k, ex in IX.ROUTES.items():
                qs = "&".join(f"{a}={b}" for a, b in ex[2].items())
                got = []
                for extra in ("", "ref=agent-7", "ref=" + "z" * 200, "ref=%3Cx%3E"):
                    u = f"http://127.0.0.1:18767{k}?" + "&".join(x for x in (qs, extra) if x)
                    try: urllib.request.urlopen(u); self.fail(u)
                    except urllib.error.HTTPError as e: self.assertEqual(e.code, 402); got.append((e.read(), e.headers["PAYMENT-REQUIRED"]))
                self.assertEqual(len(set(got)), 1, k)
        finally: srv.shutdown()
    def test_openapi_prices_match_402_and_verify_file(self):
        srv = IX.ThreadingHTTPServer(("127.0.0.1", 18768), IX.handler); threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            o = json.loads(urllib.request.urlopen("http://127.0.0.1:18768/openapi.json").read())
            self.assertEqual((o["openapi"], o["info"]["title"]), ("3.1.0", "Base Reads")); self.assertNotIn("contact", o["info"])
            self.assertEqual(list(o["paths"]), list(IX.ROUTES))
            for k in IX.ROUTES:
                try: urllib.request.urlopen("http://127.0.0.1:18768" + k); self.fail(k)
                except urllib.error.HTTPError as e: self.assertEqual(e.code, 402); amt = json.loads(e.read())["accepts"][0]["amount"]
                pi = o["paths"][k]["get"]["x-payment-info"]
                self.assertEqual(pi["amount"], amt); self.assertEqual(round(float(pi["price"]) * 1e6), int(amt))
                self.assertEqual((pi["protocols"], pi["currency"]), (["x402"], "USDC")); self.assertIn("402", o["paths"][k]["get"]["responses"])
            r = urllib.request.urlopen("http://127.0.0.1:18768/.well-known/402index-verify.txt")
            self.assertTrue(r.headers["Content-Type"].startswith("text/plain")); self.assertEqual(r.read(), b"be918d4df21371f971ccaa589e4ed1adbe9a077a824950b1db21cebfbbf5ae3c")
        finally: srv.shutdown()
    def test_ref_newline_rejected_first_wins_and_hash_ignores_ref(self):
        self.assertIsNone(IX.clean_ref("ref=abc%0A")); self.assertIsNone(IX.clean_ref("ref=abc%0D%0A"))
        self.assertEqual(IX.clean_ref("ref=first&ref=second"), "first")
        req = IX.req_for("/base/network"); hs = []
        for qs in ("address=0x1", "address=0x1&ref=agent-7", "ref=x&address=0x1"):
            IX.log_sale("/base/network", req, {"success": True, "payer": "0x" + "02" * 20, "transaction": "0x" + os.urandom(32).hex()}, ("a", "b", "c"), {"settled": None}, qs, True)
            hs.append(MS.rows("observations.jsonl")[-1]["inputHash"])
        self.assertEqual(len(set(hs)), 1)
    def test_ref_logged_with_sale_and_exported(self):
        req = IX.req_for("/base/network"); tx = "0x" + "ef" * 32
        IX.log_sale("/base/network", req, {"success": True, "payer": "0x" + "02" * 20, "transaction": tx}, ("a", "b", "c"), {"settled": None}, "ref=agent.x_1", True)
        ex = [r for r in MS.rows("executions.jsonl") if r.get("tx") == tx][-1]; self.assertEqual(ex["ref"], "agent.x_1")
        IX.log_sale("/base/network", req, {"success": True, "payer": "0x" + "02" * 20, "transaction": "0x" + "ee" * 32}, ("a", "b", "c"), {"settled": None}, "ref=" + "a" * 65, True)
        self.assertNotIn("ref", MS.rows("executions.jsonl")[-1])
        old = os.environ.get("EXPORT_TOKEN"); os.environ["EXPORT_TOKEN"] = "t" * 40
        try: code, out = IX.export("Bearer " + "t" * 40, {})
        finally:
            if old is None: os.environ.pop("EXPORT_TOKEN")
            else: os.environ["EXPORT_TOKEN"] = old
        self.assertEqual(code, 200); self.assertIn("agent.x_1", [r.get("ref") for r in out["records"]["executions"]])
class T2(unittest.TestCase):
    def fake(self, *ips): return lambda h, p, *a: [(2, 1, 6, "", (ip, p)) for ip in ips]
    def test_pins_public_ip(self):
        u, ip, err = PF.check_url("https://good.example/x", resolver=self.fake("93.184.216.34"))
        self.assertEqual((ip, err), ("93.184.216.34", None))
    def test_rejects_any_private_answer(self):
        for bad in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.1", "::1", "fe80::1", "0.0.0.0", "240.0.0.1"):
            self.assertEqual(PF.check_url("https://evil.example/", resolver=self.fake("93.184.216.34", bad))[2], "target resolves to a non-public address", bad)
    def test_resolve_once_then_connect_to_pinned_ip(self):
        calls = []
        def resolver(h, p, *a):
            calls.append(h); return [(2, 1, 6, "", ("93.184.216.34" if len(calls) == 1 else "127.0.0.1", p))]  # rebinding attempt
        u, ip, _ = PF.check_url("https://rebind.example/p?q=1", resolver=resolver)
        seen = {}
        class Fake:
            def __init__(s, host, pinned, port, timeout): seen.update(host=host, pinned=pinned, port=port)
            def request(s, m, path, headers): seen.update(path=path)
            def getresponse(s):
                class R: status = 402; getheaders = lambda self: [("PAYMENT-REQUIRED", base64.b64encode(json.dumps({"x402Version": 2, "accepts": [ACC]}).encode()).decode())]; read = lambda self, n: b""
                return R()
            def close(s): pass
        reach, ch = PF.probe(u, ip, conn_cls=Fake)
        self.assertEqual(len(calls), 1); self.assertEqual(seen, {"host": "rebind.example", "pinned": "93.184.216.34", "port": 443, "path": "/p?q=1"})
        self.assertTrue(PF.validate_challenge(ch)[0]); self.assertEqual(reach["http_status"], 402)
    def test_pinned_connection_uses_sni_hostname(self):
        import socket as S
        wrapped = {}
        class Ctx:
            def wrap_socket(s, sock, server_hostname): wrapped["sni"] = server_hostname; return sock
        orig = S.create_connection; S.create_connection = lambda addr, t: wrapped.setdefault("addr", addr) and "sock"
        try: c = PF.PinnedHTTPSConnection("host.example", "93.184.216.34", 443, context=Ctx()); c.connect()
        finally: S.create_connection = orig
        self.assertEqual(wrapped, {"addr": ("93.184.216.34", 443), "sni": "host.example"})
    def test_payto_default(self):
        self.assertTrue(IX.ADDR.match(IX.PAY_TO_DEFAULT)); self.assertEqual(IX.PAY_TO, os.environ.get("PAY_TO_ADDRESS") or IX.PAY_TO_DEFAULT)
    def test_scheduler(self):
        runs, sleeps = [], []
        n = iter([False, False, True])
        IX.snapshot_loop(run_once=lambda: runs.append(1), sleep=sleeps.append, now=lambda: 1760400000.0, stop=lambda: next(n))
        self.assertEqual(len(runs), 3); self.assertTrue(all(0 < x <= 86400 for x in sleeps))
        self.assertEqual(IX.next_run_delay(86400 * 10), 900); self.assertEqual(IX.next_run_delay(86400 * 10 + 900), 86400)
class T3(unittest.TestCase):
    def test_export_auth(self):
        self.assertEqual(IX.export("", {})[0], 401); self.assertEqual(IX.export("Bearer wrong", {})[0], 401)
        self.assertEqual(IX.export("t" * 40, {})[0], 401)
        IX.MS.append("executions.jsonl", {"id": "exec-z", "tx": "0x" + "12" * 32, "startedAt": "2026-10-14T00:00:00Z"})
        code, o = IX.export("Bearer " + "t" * 40, {}); self.assertEqual(code, 200)
        self.assertIn("exec-z", [r["id"] for r in o["records"]["executions"]]); self.assertEqual(o["payTo"], IX.PAY_TO)
        self.assertNotIn("exec-z", [r["id"] for r in IX.export("Bearer " + "t" * 40, {"since": "2026-10-15"})[1]["records"]["executions"]])
    def test_export_refuses_weak_or_missing_token(self):
        old = os.environ["EXPORT_TOKEN"]; os.environ["EXPORT_TOKEN"] = "short"
        try: self.assertEqual(IX.export("Bearer short", {})[0], 401)
        finally: os.environ["EXPORT_TOKEN"] = old
    def test_render_free_no_disk(self):
        r = open(os.path.join(os.path.dirname(__file__), "..", "render.yaml")).read()
        self.assertIn("plan: free", r); self.assertNotIn("disk:", r); self.assertNotIn("/var/data", r)
        for k in ("EXPORT_TOKEN", "SIGNING_KEY_PASSPHRASE", "SIGNING_KEY_ENC_B64"):
            self.assertRegex(r, k + r"[^\n]*\n\s*sync: false")
    def test_signing_key_from_env(self):
        from Crypto.PublicKey import ECC
        k = ECC.generate(curve="ed25519"); pem = k.export_key(format="PEM", passphrase=os.environ["SIGNING_KEY_PASSPHRASE"], protection="scryptAndAES256-CBC")
        os.environ["SIGNING_KEY_ENC_B64"] = base64.b64encode(pem.encode()).decode(); old = PF._key; PF._key = None
        try:
            self.assertEqual(base64.b64decode(PF.public_key_info()["public_key_b64"]), k.public_key().export_key(format="raw"))
        finally: del os.environ["SIGNING_KEY_ENC_B64"]; PF._key = old
class T4(unittest.TestCase):
    R = os.path.join(os.path.dirname(__file__), "..")
    def test_dockerfile(self):
        d = open(os.path.join(self.R, "Dockerfile")).read()
        for k in ("PORT=7860", "EXPOSE 7860", "HOST=0.0.0.0", "SNAPSHOT_DIR=/tmp", "DATA_STORE=/tmp", "USER user"): self.assertIn(k, d)
        for s in ("SIGNING_KEY_PASSPHRASE=", "EXPORT_TOKEN=", "SIGNING_KEY_ENC_B64="): self.assertNotIn(s, d)
    def test_spaces_frontmatter(self):
        r = open(os.path.join(self.R, "README.md")).read()
        self.assertTrue(r.startswith("---\n")); fm = r.split("---")[1]
        self.assertIn("sdk: docker", fm); self.assertIn("app_port: 7860", fm)
class T5(unittest.TestCase):
    def test_deno_contract_fixture_is_current(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts")); import gen_contract_fixture as G
        f = json.load(open(os.path.join(os.path.dirname(__file__), "..", "deno", "tests", "fixtures", "contract.json")))
        self.assertEqual(json.loads(json.dumps(G.build(), sort_keys=True)), f, "run scripts/gen_contract_fixture.py")
class T6(unittest.TestCase):
    R = os.path.join(os.path.dirname(__file__), "..")
    def test_bazaar_block_every_route(self):
        self.assertEqual(open(os.path.join(self.R, "api", "discovery.json")).read(), open(os.path.join(self.R, "deno", "lib", "discovery.json")).read())
        for path in IX.ROUTES:
            b = IX.required(path, "h.example")["extensions"]["bazaar"]
            self.assertEqual(set(b), {"info", "schema"}); inp = b["info"]["input"]
            self.assertEqual((inp["type"], inp["method"]), ("http", "GET"))
            self.assertEqual(b["info"]["output"]["type"], "json"); self.assertIsInstance(b["info"]["output"]["example"], dict); self.assertTrue(b["info"]["output"]["example"])
            si = b["schema"]["properties"]["input"]; self.assertEqual(si["required"], ["type", "method"]); self.assertFalse(si["additionalProperties"])
            params = IX.DISCOVERY[path]["params"]
            ex = inp.get("queryParams", {}); self.assertEqual(bool(ex), bool(params))
            self.assertLessEqual(set(ex), set(params)); self.assertLessEqual(set(IX.DISCOVERY[path]["required"]), set(ex))
            for name, sch in params.items():
                self.assertGreater(len(sch.get("description", "")), 15, (path, name)); self.assertEqual(sch["type"], "string")
                if "pattern" in sch and name in ex: self.assertRegex(ex[name], sch["pattern"])
            self.assertNotIn("example.com", json.dumps(b))
            try: import jsonschema
            except ImportError: continue
            jsonschema.validate(b["info"], b["schema"])
    def test_cdp_jwt_claims_and_signature(self):
        import cdp_auth; from Crypto.PublicKey import ECC; from Crypto.Signature import eddsa
        seed = bytes(range(32)); pub = ECC.construct(curve="ed25519", seed=seed).public_key()
        sec = base64.b64encode(seed + pub.export_key(format="raw")).decode()
        tok = cdp_auth.jwt("kid-1", sec, "POST", "api.cdp.coinbase.com", "/platform/v2/x402/settle", now=1000)
        h, c, sg = tok.split("."); dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))
        hd, cl = dec(h), dec(c)
        self.assertEqual((hd["alg"], hd["kid"], hd["typ"]), ("EdDSA", "kid-1", "JWT")); self.assertRegex(hd["nonce"], r"^[0-9]{16}$")
        self.assertEqual(cl, {"sub": "kid-1", "iss": "cdp", "nbf": 1000, "exp": 1120, "uris": ["POST api.cdp.coinbase.com/platform/v2/x402/settle"]})
        eddsa.new(pub, "rfc8032").verify((h + "." + c).encode(), base64.urlsafe_b64decode(sg + "=" * (-len(sg) % 4)))
        self.assertNotEqual(cdp_auth.jwt("kid-1", sec, "POST", "a", "/b"), cdp_auth.jwt("kid-1", sec, "POST", "a", "/b"))  # fresh nonce per request
        with self.assertRaises(ValueError): cdp_auth.jwt("k", base64.b64encode(b"x" * 32).decode(), "POST", "a", "/b")
    def test_cdp_only_when_cdp_url_and_keys(self):
        import cdp_auth
        sec = base64.b64encode(bytes(range(32)) + bytes(32)).decode()
        keys = {"CDP_API_KEY_ID": "k", "CDP_API_KEY_SECRET": sec}; cdp = "https://api.cdp.coinbase.com/platform/v2/x402"
        self.assertEqual(cdp_auth.headers("https://facilitator.payai.network", "/settle", keys), {})
        self.assertEqual(cdp_auth.headers(cdp, "/settle", {}), {})
        self.assertEqual(cdp_auth.headers(cdp, "/settle", {"CDP_API_KEY_ID": "k"}), {})
        self.assertEqual(cdp_auth.headers("https://api.cdp.coinbase.com.evil.example/x", "/settle", keys), {})
        a = cdp_auth.headers(cdp, "/settle", keys)["Authorization"]; self.assertTrue(a.startswith("Bearer "))
        cl = json.loads(base64.urlsafe_b64decode(a.split(".")[1] + "=="))
        self.assertEqual(cl["uris"], ["POST api.cdp.coinbase.com/platform/v2/x402/settle"])
    def test_fac_payai_default_unchanged(self):
        self.assertEqual(IX.FAC, os.environ.get("FACILITATOR", "https://facilitator.payai.network"))
        seen = {}
        class R:
            def read(self): return b'{"success": true, "transaction": "0x' + b"ab" * 32 + b'", "payer": "0x1", "network": "eip155:8453"}'
        old = IX.urllib.request.urlopen
        IX.urllib.request.urlopen = lambda req, timeout: (seen.update(h=dict(req.header_items()), u=req.full_url), R())[1]
        try: st = IX.fac("/settle", {"x": 1})
        finally: IX.urllib.request.urlopen = old
        self.assertNotIn("Authorization", seen["h"]); self.assertEqual(seen["u"], "https://facilitator.payai.network/settle")
        self.assertTrue(st["success"]); self.assertEqual(st["transaction"], "0x" + "ab" * 32)  # CDP settle response uses the same fields
MS = IX.MS
class T7(unittest.TestCase):
    """Seller verify/settle hardening (SECURITY.md)."""
    PAYER = "0x" + "a1" * 20
    def pay(self, path="/base/network", nonce=None, **over):
        r = IX.req_for(path); now = int(time.time())
        a = {"from": self.PAYER, "to": r["payTo"], "value": r["amount"], "validAfter": str(now - 5), "validBefore": str(now + 300), "nonce": nonce or "0x" + os.urandom(32).hex()}
        a.update(over); return base64.b64encode(json.dumps({"x402Version": 2, "accepted": r, "payload": {"authorization": a, "signature": "0x" + "11" * 65}}).encode()).decode()
    def setUp(self):
        self.calls = []; self.tx = "0x" + os.urandom(32).hex(); self.settle = lambda: {"success": True, "transaction": self.tx, "payer": self.PAYER, "network": IX.NETWORK}
        def fac(p, body): self.calls.append(p); return {"isValid": True, "payer": self.PAYER} if p == "/verify" else self.settle()
        self.old = (IX.fac, IX.handle); IX.fac = fac; IX.handle = lambda path, q: (200, {"ok": True})
        IX.REPLAY, IX.FAILS, IX.SLOTS = IX.SG.Replay(), IX.SG.FailLimiter(), IX.SG.Slots()
        self.chain = {"settled": True, "block": 1}; self.check = lambda tx, r, payer: dict(self.chain)
    def tearDown(self): IX.fac, IX.handle = self.old
    def run_paid(self, sig, path="/base/network"): return IX.paid(path, {}, "", sig, "t", check=self.check)
    def test_serves_only_after_settle_and_onchain_confirmation(self):
        c, out, hd = self.run_paid(self.pay()); self.assertEqual((c, out), (200, {"ok": True})); self.assertEqual(self.calls, ["/verify", "/settle"])
        self.assertTrue(json.loads(base64.b64decode(hd["PAYMENT-RESPONSE"]))["success"])
    def test_onchain_mismatch_blocks_serving(self):
        self.chain = {"settled": False, "reason": "no_matching_usdc_transfer"}
        c, out, _ = self.run_paid(self.pay()); self.assertEqual(c, 402); self.assertIn("not confirmed on-chain", out["error"])
        o = MS.rows("outcomes.jsonl")[-1]; self.assertEqual((o["outcome"], o["status"]), ("not_delivered", "verified_failure"))
    def test_onchain_pending_parks_then_serves_once_on_retry(self):
        self.chain = {"settled": None, "reason": "receipt_not_found_yet"}; sig = self.pay()
        c, out, _ = self.run_paid(sig); self.assertEqual((c, out["status"]), (202, "settled_pending_onchain_confirmation"))
        self.assertEqual(self.run_paid(sig)[0], 202)                               # still pending: still not served
        self.chain = {"settled": True, "block": 2}
        self.assertEqual(self.run_paid(sig)[:2], (200, {"ok": True}))             # confirmed: served exactly once
        self.assertEqual(self.run_paid(sig)[0], 409); self.assertEqual(self.calls.count("/settle"), 1)
    def test_facilitator_success_alone_never_serves(self):
        for chain in ({"settled": None}, {"settled": False, "reason": "nonce_not_in_settlement_tx"}):
            self.chain = chain; self.assertNotEqual(self.run_paid(self.pay())[0], 200)
    def test_concurrent_duplicate_signature_only_one_wins(self):
        import concurrent.futures as cf
        gate = threading.Event(); orig = IX.fac
        def slow(p, body): gate.wait(1); return orig(p, body)
        IX.fac = slow; sig = self.pay()
        with cf.ThreadPoolExecutor(8) as ex:
            futs = [ex.submit(self.run_paid, sig) for _ in range(8)]; time.sleep(0.2); gate.set()
            codes = sorted(f.result()[0] for f in futs)
        self.assertEqual(codes, [200] + [409] * 7); self.assertEqual(self.calls.count("/settle"), 1)
    def test_onchain_check_binds_nonce(self):
        r = IX.req_for("/base/network"); P = self.PAYER; n = "0x" + "4e" * 32
        def rc(nonce_topic):
            logs = [{"address": r["asset"], "topics": [MS.TRANSFER, "0x" + "0" * 24 + P[2:], "0x" + "0" * 24 + r["payTo"][2:].lower()], "data": hex(1000)}]
            if nonce_topic: logs.append({"address": r["asset"], "topics": [MS.AUTH_USED, "0x" + "0" * 24 + P[2:], nonce_topic], "data": "0x"})
            return {"status": "0x1", "blockNumber": "0x5", "logs": logs}
        f = lambda rec, nonce: MS.verify_onchain(lambda m, p: rec, "0x" + "ab" * 32, r["asset"], r["payTo"], r["amount"], P, nonce=nonce, sleep=lambda x: None)
        self.assertTrue(f(rc(n), n)["settled"]); self.assertTrue(f(rc(n), n)["nonceBound"])
        self.assertEqual(f(rc("0x" + "11" * 32), n)["reason"], "nonce_not_in_settlement_tx")
        self.assertEqual(f(rc(None), n)["reason"], "nonce_not_in_settlement_tx")
        self.assertTrue(f(rc(None), None)["settled"])  # non-EIP-3009 schemes: Transfer-only check
    def test_nonce_kept_until_valid_before(self):
        g = IX.SG.Replay(ttl=1); now = 1000
        self.assertTrue(g.claim("k", expires_at=now + 500, now=now)); self.assertFalse(g.claim("k", now=now + 499)); self.assertTrue(g.claim("k", now=now + 501))
    def test_replay_same_authorization_rejected(self):
        sig = self.pay(nonce="0x" + "05" * 32); self.assertEqual(self.run_paid(sig)[0], 200)
        self.tx = "0x" + os.urandom(32).hex(); c, _, _ = self.run_paid(sig); self.assertEqual(c, 409); self.assertEqual(self.calls.count("/settle"), 1)
    def test_settle_tx_reuse_rejected(self):
        self.assertEqual(self.run_paid(self.pay())[0], 200)
        c, out, _ = self.run_paid(self.pay()); self.assertEqual((c, out["error"]), (409, "settlement transaction already used"))
    def test_window_payee_amount_and_accepted_prechecks(self):
        now = int(time.time())
        for over, why in (({"validBefore": str(now + 2)}, "authorization_expired_or_expiring"), ({"validAfter": str(now + 60)}, "authorization_not_yet_valid"),
                          ({"to": "0x" + "99" * 20}, "authorization_payee_mismatch"), ({"value": "1"}, "authorization_amount_mismatch")):
            c, out, _ = self.run_paid(self.pay(**over)); self.assertEqual((c, out["error"]), (402, why))
        self.assertEqual(self.calls, [])  # rejected before any facilitator call
        p = json.loads(base64.b64decode(self.pay())); p["accepted"]["amount"] = "1"
        self.assertEqual(self.run_paid(base64.b64encode(json.dumps(p).encode()).decode())[1]["error"], "accepted.amount_mismatch")
    def test_permit2_and_non_eip3009_rejected_before_facilitator(self):
        r = IX.req_for("/base/network")
        p2 = {"x402Version": 2, "accepted": r, "payload": {"permit2Authorization": {"from": self.PAYER, "nonce": "1"}, "signature": "0x"}}
        acc = dict(r, extra=dict(r["extra"], assetTransferMethod="permit2"))
        for body, why in ((p2, "permit2_not_supported"), ({"x402Version": 2, "accepted": acc, "payload": {"authorization": {}}}, "permit2_not_supported"),
                          ({"x402Version": 2, "accepted": r, "payload": {"signature": "0x"}}, "eip3009_authorization_required")):
            c, out, hd = self.run_paid(base64.b64encode(json.dumps(body).encode()).decode())
            self.assertEqual(c, 402); self.assertTrue(out["error"].startswith(why), out)
        self.assertEqual(self.calls, [])
    def test_bad_or_huge_header(self):
        self.assertEqual(self.run_paid("x" * 20000)[0], 400); self.assertEqual(self.run_paid("%%%")[0], 400)
    def test_failed_settle_burns_signature_then_cooldown(self):
        self.settle = lambda: {"success": False, "errorReason": "insufficient_funds"}
        sig = self.pay(); self.assertEqual(self.run_paid(sig)[0], 402); self.assertEqual(self.run_paid(sig)[0], 409)  # duplicates rejected consistently
        for _ in range(2): self.assertEqual(self.run_paid(self.pay())[0], 402)
        self.assertEqual(self.run_paid(self.pay())[0], 429)
    def test_settle_reported_failure_but_confirmed_onchain_is_honored(self):
        self.settle = lambda: {"success": False, "errorReason": "timeout", "transaction": self.tx}
        c, out, hd = self.run_paid(self.pay()); self.assertEqual(c, 200)
        self.assertEqual(MS.rows("executions.jsonl")[-1]["tx"], self.tx)
    def test_settle_success_without_tx_not_served(self):
        self.settle = lambda: {"success": True, "transaction": "nope"}
        self.assertEqual(self.run_paid(self.pay())[0], 502)
    def test_host_header_cannot_inject_resource_url(self):
        old = IX.PUBLIC; IX.PUBLIC = ""
        try:
            self.assertEqual(IX.required("/base/network", "evil.example/x?y")["resource"]["url"], "https://invalid-host/base/network")
            self.assertEqual(IX.required("/base/network", "h.example:8443")["resource"]["url"], "https://h.example:8443/base/network")
        finally: IX.PUBLIC = old
class T10(T7):
    """Auditor findings A1-A11 (Python mirror; see SECURITY.md)."""
    def mk(self, acc=None, **auth):
        r = IX.req_for("/base/network"); now = int(time.time())
        a = {"from": self.PAYER, "to": r["payTo"], "value": r["amount"], "validAfter": str(now - 5), "validBefore": str(now + 300), "nonce": "0x" + os.urandom(32).hex()}
        a.update(auth); return {"x402Version": 2, "accepted": r if acc is None else acc, "payload": {"signature": "0x", "authorization": a}}
    def test_a1_a4_a5_precheck_exact_accepted_nonce(self):
        r = IX.req_for("/base/network")
        self.assertIsNone(IX.SG.precheck(self.mk(), r))
        self.assertIsNone(IX.SG.precheck(self.mk(dict(r, payTo=r["payTo"].upper().replace("0X", "0x"))), r))
        p = self.mk(); p.pop("accepted"); self.assertEqual(IX.SG.precheck(p, r), "accepted_missing")
        for k in IX.SG.ACCEPTED_FIELDS:
            acc = dict(r); acc.pop(k); self.assertEqual(IX.SG.precheck(self.mk(acc), r), f"accepted.{k}_missing")
        self.assertEqual(IX.SG.precheck(self.mk(dict(r, scheme="EXACT")), r), "accepted.scheme_mismatch")
        self.assertEqual(IX.SG.precheck(self.mk(dict(r, network="eip155:84532")), r), "accepted.network_mismatch")
        for n in ("0x1", "0x" + "ab" * 31, "0x" + "zz" * 32, "ab" * 32, 7): self.assertEqual(IX.SG.precheck(self.mk(nonce=n), r), "authorization_bad_nonce")
        n = "0x" + os.urandom(32).hex()
        self.assertEqual(IX.SG.replay_key(self.mk(nonce=n.upper().replace("0X", "0x"))), IX.SG.replay_key(self.mk(nonce=n)))
    def test_a1_reencoded_same_authorization_is_replay(self):
        n = "0x" + os.urandom(32).hex(); self.assertEqual(self.run_paid(self.pay(nonce=n))[0], 200)
        p = json.loads(base64.b64decode(self.pay(nonce=n))); re_enc = base64.b64encode(json.dumps({"payload": p["payload"], "accepted": p["accepted"], "x402Version": 2}).encode()).decode()
        self.tx = "0x" + os.urandom(32).hex(); self.assertEqual(self.run_paid(re_enc)[0], 409)
    def test_a6_rejected_payload_does_not_burn_nonce(self):
        n = "0x" + os.urandom(32).hex()
        self.assertEqual(self.run_paid(self.pay(nonce=n, value="1"))[0], 402); self.assertEqual(self.run_paid(self.pay(nonce=n))[0], 200)
    def test_a2_payer_from_signed_authorization(self):
        seen = []; att = "0x" + "66" * 20
        self.settle = lambda: {"success": True, "transaction": self.tx, "payer": att, "network": IX.NETWORK, "extra": "<x>"}
        self.check = lambda tx, r, payer: (seen.append(payer), {"settled": True})[1]
        c, _, hd = self.run_paid(self.pay()); self.assertEqual(c, 200); self.assertEqual(seen, [self.PAYER])
        pr = json.loads(base64.b64decode(hd["PAYMENT-RESPONSE"]))
        self.assertEqual(sorted(pr), ["network", "payer", "success", "transaction"]); self.assertEqual(pr["payer"], self.PAYER)
    def test_a3_n1_limits_payer_ip_global_alert_only(self):
        L = IX.SG.FailLimiter({"payer": 3, "ip": 5}, 60, global_alert=4); now = 1_000_000
        for _ in range(3): L.fail({"payer": "p"}, "settle", now)
        self.assertEqual(L.blocked({"payer": "p"}, now), "payer"); self.assertIsNone(L.blocked({"payer": "q"}, now)); self.assertIsNone(L.blocked({"payer": "p"}, now + 121))
        for _ in range(5): L.fail({"ip": "1.2.3.4", "payer": "v"}, "verify", now)
        self.assertEqual(L.blocked({"ip": "1.2.3.4", "payer": "q"}, now), "ip"); self.assertEqual(L.count("payer", "v", now), 0)
        self.assertEqual(L.count("global", "*", now), 3)                                  # verify failures never count globally
        L.fail({}, "settle", now); L.fail({}, "settle", now)
        self.assertIsNone(L.blocked({"ip": "5.5.5.5", "payer": "q"}, now))                  # global never blocks
        self.assertEqual(len(L.alerts), 1); L.fail({}, "settle", now); self.assertEqual(len(L.alerts), 1)   # alert once per window
        for i in range(5): L.fail({"ip": f"2001:db8:1:2::{i + 1}"}, "verify", now)
        self.assertEqual(L.blocked({"ip": "2001:db8:1:2:ffff::9"}, now), "ip"); self.assertIsNone(L.blocked({"ip": "2001:db8:1:3::1"}, now))
        self.assertEqual([IX.SG.ip_key("2001:DB8:1:2::1"), IX.SG.ip_key("::ffff:1.2.3.4"), IX.SG.ip_key("1.2.3.4")], ["2001:db8:1:2::/64", "1.2.3.4", "1.2.3.4"])
        ths = [threading.Thread(target=L.fail, args=({"payer": "z"}, "settle", now)) for _ in range(50)]; [t.start() for t in ths]; [t.join() for t in ths]
        self.assertEqual(L.count("payer", "z", now), 50)
    def test_n1_junk_from_many_ips_never_locks_out_buyers(self):
        good = IX.fac; IX.fac = lambda p, body: {"isValid": False, "invalidReason": "invalid_exact_evm_payload_signature"}
        for ip in range(40):
            for _ in range(10): IX.paid("/base/network", {}, "", self.pay(), "t", check=self.check, ip=f"10.0.{ip}.1")
        IX.fac = good; self.assertEqual(self.run_paid(self.pay())[0], 200)
    def test_n3_parallel_burst_bounded_by_slots(self):
        self.settle = lambda: (time.sleep(0.02), {"success": False, "errorReason": "insufficient_funds"})[1]; self.chain = {"settled": False, "reason": "x"}
        out = []; ths = [threading.Thread(target=lambda: out.append(self.run_paid(self.pay())[0])) for _ in range(30)]
        [t.start() for t in ths]; [t.join() for t in ths]
        self.assertLessEqual(self.calls.count("/settle"), 3 - 1 + IX.SG.SLOTS["payer"]); self.assertIn(429, out)
        S = IX.SG.Slots({"payer": 1, "ip": 1}); rel = S.acquire({"payer": "p", "ip": "1.1.1.1"}); self.assertIsNotNone(rel)
        self.assertIsNone(S.acquire({"payer": "p"})); rel(); self.assertIsNotNone(S.acquire({"payer": "p"}))
    def test_l1_forged_from_never_holds_payer_slot(self):
        gate = threading.Event(); good = IX.fac
        def bad(p, body): gate.wait(2); return {"isValid": False, "invalidReason": "invalid_exact_evm_payload_signature"}
        IX.fac = bad; out = []
        ths = [threading.Thread(target=lambda i=i: out.append(IX.paid("/base/network", {}, "", self.pay(), "t", check=self.check, ip=f"10.9.{i}.1")[0])) for i in range(2 * IX.SG.SLOTS["payer"])]
        [t.start() for t in ths]; time.sleep(0.2)
        self.assertEqual(IX.SLOTS.m.get(("payer", self.PAYER), 0), 0)   # forged requests parked in /verify hold no payer slot
        gate.set(); [t.join() for t in ths]; self.assertEqual(sorted(set(out)), [402])
        IX.fac = good; self.assertEqual(self.run_paid(self.pay())[0], 200)
    def test_l1_payer_busy_after_verify_releases_authorization(self):
        held = [IX.SLOTS.acquire({"payer": self.PAYER}) for _ in range(IX.SG.SLOTS["payer"])]; sig = self.pay()
        c, out, _ = self.run_paid(sig); self.assertEqual((c, out["scope"]), (429, "concurrency")); self.assertNotIn("/settle", self.calls)
        for h in held: h()
        self.assertEqual(self.run_paid(sig)[0], 200)
    def test_n5_extra_cidrs_require_test_flag(self):
        self.assertEqual(PF._extra_cidrs({}), [])
        with self.assertRaises(SystemExit): PF._extra_cidrs({"PREFLIGHT_EXTRA_ALLOWED_CIDRS": "10.0.0.0/8"})
        self.assertEqual(PF._extra_cidrs({"PREFLIGHT_EXTRA_ALLOWED_CIDRS": "10.0.0.0/8", "PREFLIGHT_TEST_MODE": "1"}), [PF.ipaddress.ip_network("10.0.0.0/8")])
    def test_a10_startup_warnings(self):
        self.assertEqual(PF.startup_warnings({"SIGNING_KEY_CREATED_AT": "2026-10-14T12:00:21Z"}), []); self.assertEqual(PF.startup_warnings({}), [])
        self.assertEqual(len(PF.startup_warnings({"SIGNING_KEY_CREATED_AT": "2026-10-14"})), 1)
        self.assertEqual(PF.startup_warnings({"SIGNING_KEY_HISTORY": json.dumps([{"created_at": "yesterday", "retired_at": "2026-10-01T00:00:00Z"}])}),
                         ["SIGNING_KEY_HISTORY[0].created_at is not strict ISO-8601 UTC; published as null"])
        self.assertEqual(len(PF.startup_warnings({"SIGNING_KEY_HISTORY": "{"})), 1)
    def test_a3_verify_failures_count_per_ip_not_payer(self):
        IX.fac = lambda p, body: {"isValid": False, "invalidReason": "invalid_exact_evm_payload_signature"}
        for _ in range(10): self.assertEqual(IX.paid("/base/network", {}, "", self.pay(), "t", check=self.check, ip="9.9.9.9")[0], 402)
        c, out, _ = IX.paid("/base/network", {}, "", self.pay(), "t", check=self.check, ip="9.9.9.9"); self.assertEqual((c, out["scope"]), (429, "ip"))
        self.assertIsNone(IX.FAILS.blocked({"payer": self.PAYER.lower(), "ip": "8.8.8.8"}))
        self.assertEqual(IX.FAILS.count("global", "*"), 0)
    def test_a8_error_allowlist_and_rebuilt_payment_response(self):
        self.assertEqual(IX.fac_err("insufficient_funds"), "insufficient_funds"); self.assertEqual(IX.fac_err("<script>"), "facilitator_error")
        self.settle = lambda: {"success": False, "errorReason": "evil", "debug": "internal"}; self.chain = {"settled": False, "reason": "x"}
        c, out, hd = self.run_paid(self.pay()); self.assertEqual((c, out["error"]), (402, "facilitator_error"))
        self.assertEqual(json.loads(base64.b64decode(hd["PAYMENT-RESPONSE"])), {"success": False, "errorReason": "facilitator_error", "transaction": "", "network": IX.NETWORK, "payer": self.PAYER})
    def test_a7_log_mode_refused_on_mainnet(self):
        self.assertEqual(IX.onchain_mode("log", "eip155:8453"), "block"); self.assertEqual(IX.onchain_mode("log", "eip155:84532"), "log")
        with self.assertRaises(SystemExit): IX.assert_onchain_mode("log", "eip155:8453")
        old = IX.ONCHAIN_CHECK; IX.ONCHAIN_CHECK = "log"; self.chain = {"settled": False, "reason": "no_matching_usdc_transfer"}
        try: self.assertEqual(self.run_paid(self.pay())[0], 402)
        finally: IX.ONCHAIN_CHECK = old
    def test_a10_iso_validation(self):
        self.assertEqual(PF.iso_or_none("2026-10-14T12:00:21Z"), "2026-10-14T12:00:21Z")
        for bad in ("2026-10-14", "2026-02-30T00:00:00Z", "2026-10-14T12:00:21+07:00", "<b>", 5, None): self.assertIsNone(PF.iso_or_none(bad))
    def test_a11_pins(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        req = open(os.path.join(root, "requirements.txt")).read()
        self.assertRegex(req, r"(?m)^pycryptodome==\d+\.\d+\.\d+ \\$"); self.assertGreaterEqual(req.count("--hash=sha256:"), 1)
        for f in ("Dockerfile", ".github/workflows/test.yml"): self.assertIn("--require-hashes", open(os.path.join(root, f)).read(), f)
        self.assertRegex(open(os.path.join(root, "Dockerfile")).read(), r"(?m)^FROM python:[\w.-]+@sha256:[0-9a-f]{64}$")
    def test_ssrf_review(self):
        for ip in ("100.64.0.1", "::ffff:127.0.0.1", "::7f00:1", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001:0:4136:e378::1", "169.254.169.254", "fd00::1", "192.0.0.8"):
            self.assertFalse(PF.ip_allowed(ip), ip)
        self.assertTrue(PF.ip_allowed("8.8.8.8")); self.assertTrue(PF.ip_allowed("2606:4700::1111"))
        res = lambda h, p, *a: [(2, 1, 6, "", ("93.184.216.34", p))]
        self.assertEqual(PF.check_url("https://example.com:22/x", res)[2], "port not allowed (443, 8443)")
        self.assertEqual(PF.check_url("https://u:p@example.com/x", res)[2], "credentials in url not allowed")
        self.assertIsNone(PF.check_url("https://example.com:8443/x", res)[2])
        self.assertEqual(PF.check_url("https://100.64.0.1/x", lambda h, p, *a: [(2, 1, 6, "", ("100.64.0.1", p))])[2], "target resolves to a non-public address")
class T8(unittest.TestCase):
    def test_well_known_and_root_facilitator(self):
        w = IX.well_known(); self.assertEqual((w["alg"], w["key_id"]), ("Ed25519", PF.public_key_info()["key_id"]))
        self.assertEqual(w["facilitator"], IX.facilitator_info()); self.assertEqual(IX.root()["facilitator"]["name"], "PayAI")
        self.assertTrue(w["repo"].startswith("https://github.com/"))
        old = IX.FAC; IX.FAC = "https://api.cdp.coinbase.com/platform/v2/x402"
        try: self.assertEqual(IX.facilitator_info(), {"name": "CDP", "url": IX.FAC, "auth": "none"})
        finally: IX.FAC = old
        env = PF.sign({"z": 1, "a": "é"}); import hashlib
        from Crypto.Signature import eddsa
        pk = eddsa.import_public_key(base64.b64decode(w["public_key_b64"]))
        eddsa.new(pk, "rfc8032").verify(json.dumps(env["facts"], sort_keys=True, separators=(",", ":")).encode(), base64.b64decode(env["signature"]["value_b64"]))
        self.assertEqual(hashlib.sha256(base64.b64decode(w["public_key_b64"])).hexdigest()[:16], w["key_id"])
    def test_snapshot_summary(self):
        BS.write([{"resource": "https://a.example/x", "accepts": [{"payTo": "0x" + "ab" * 20}], "quality": {"l30DaysUniquePayers": 2, "l30DaysTotalCalls": 7}}], "2026-01-02")
        s = IX.snapshot_summary(); self.assertIn("snapshots", s)
        self.assertIn({"date": "2026-01-02", "resources": 1, "hosts": 1, "payout_wallets": 1, "calls30d_total": 7, "payers30d_total": 2}, s["snapshots"])
        for x in s["snapshots"]: self.assertEqual(set(x), {"date", "resources", "hosts", "payout_wallets", "calls30d_total", "payers30d_total"})
class T9(unittest.TestCase):
    def test_pubkey_fingerprints_and_history(self):
        import hashlib
        k = PF.public_key_info(); raw = base64.b64decode(k["public_key_b64"]); d = hashlib.sha256(raw).digest()
        self.assertEqual(k["fingerprint"], "SHA256:" + base64.b64encode(d).decode().rstrip("="))
        self.assertEqual(k["fingerprint_short"].replace(" ", ""), k["key_id"]); self.assertRegex(k["fingerprint_short"], r"^([0-9a-f]{4} ){3}[0-9a-f]{4}$")
        self.assertIn("created_at", k)
        os.environ["SIGNING_KEY_CREATED_AT"] = "2026-10-14T11:00:00Z"
        os.environ["SIGNING_KEY_HISTORY"] = json.dumps([{"public_key_b64": base64.b64encode(b"\x01" * 32).decode(), "created_at": "2026-10-01T00:00:00Z", "retired_at": "2026-10-14T00:00:00Z"}, {"public_key_b64": "bad"}])
        try:
            h = PF.key_history()
            self.assertEqual((h["current"]["status"], h["current"]["created_at"], h["current"]["key_id"]), ("active", "2026-10-14T11:00:00Z", k["key_id"]))
            self.assertEqual(len(h["retired"]), 1); self.assertEqual((h["retired"][0]["status"], h["retired"][0]["retired_at"]), ("retired", "2026-10-14T00:00:00Z"))
            self.assertNotIn("private", json.dumps(h).lower())
        finally: del os.environ["SIGNING_KEY_CREATED_AT"], os.environ["SIGNING_KEY_HISTORY"]
    def test_snapshot_meta_signed_metadata_only(self):
        BS.write([{"resource": "https://a.example/x", "accepts": [], "quality": {}}, {"resource": "https://b.example/y", "accepts": [], "quality": {}}], "2026-01-03")
        m = IX.snapshot_meta(); md = m["metadata"]
        self.assertEqual(set(md), {"version", "started_at", "last_updated", "total_snapshots", "covered_listings"})
        self.assertEqual(m["pubkey_url"], "/x402/preflight/pubkey"); self.assertTrue(PF.verify({"facts": md, "signature": m["signature"]}))
        self.assertGreaterEqual(md["total_snapshots"], 1); self.assertNotIn("resources", json.dumps(m))
        md["covered_listings"] += 1; self.assertFalse(PF.verify({"facts": md, "signature": m["signature"]}))
if __name__ == "__main__": unittest.main(verbosity=2)
