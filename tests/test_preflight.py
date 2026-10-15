import base64, json, os, sys, tempfile, threading, unittest, urllib.request, urllib.error
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
if __name__ == "__main__": unittest.main(verbosity=2)
