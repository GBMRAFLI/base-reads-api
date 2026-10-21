"""Pre-pay Check Attestation v1.0 (Python). Keys are ephemeral, generated in memory per test."""
import base64, hashlib, json, os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_preflight  # noqa: F401  shared test env (temp dirs, throwaway key) set before api modules load
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(R, "api")); sys.path.insert(0, os.path.join(R, "scripts"))
import attestation as AT, preflight as PF, index as IX, verify_attestation as VA
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
V = json.load(open(os.path.join(R, "spec", "test-vectors.json"), encoding="utf-8"))
SCHEMA = json.load(open(os.path.join(R, "spec", "prepay-check-attestation-v1.schema.json")))
ACC = {"scheme": "exact", "network": "eip155:8453", "amount": "10000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x" + "22" * 20}
NOW = 1792558800  # 2026-10-21T05:00:00Z
def facts(**o):
    f = {"schema": "prepay-check/v1", "target": "https://a.example/x", "checked_at": "2026-10-21T05:00:00Z", "disclaimer": "d",
         "reachability": {"reachable": True, "http_status": 402, "latency_ms": 5}, "challenge": {"valid": True, "problems": [], "accepts": [ACC]},
         "bazaar": {"available": True, "snapshot_date": "2026-10-20", "listed": True}}
    f.update(o); return f
def ephemeral():
    k = ECC.generate(curve="ed25519"); raw = k.public_key().export_key(format="raw"); kid = hashlib.sha256(raw).hexdigest()[:16]
    pub = base64.b64encode(raw).decode()
    return (kid, lambda m: eddsa.new(k, "rfc8032").sign(m)), pub, {"keys": [{"alg": "Ed25519", "key_id": kid, "public_key_b64": pub, "status": "active"}]}

class TA(unittest.TestCase):
    def test_jcs_vectors(self):
        for c in V["jcs"]: self.assertEqual(AT.jcs(c["input"]).decode(), c["canonical"])
        self.assertEqual(AT.signing_bytes(V["signed"]["attestation"]).decode(), V["signed"]["signing_bytes_utf8"])
        ok, why = VA.verify(V["signed"]["attestation"], V["signed"]["issuer"], now=NOW); self.assertTrue(ok, why)
        self.assertEqual(VA.verify(V["signed"]["attestation"], V["signed"]["issuer"], now=NOW + 3600), (False, "expired at 2026-10-21T05:15:00Z"))
    def test_envelope_sign_verify_tamper(self):
        s, pub, iss = ephemeral()
        e = AT.attest(facts(), s, rpc=lambda m, p: "0x", now=NOW, ttl_s=600, issuer_url="https://i.example/.well-known/issuer.json")
        self.assertEqual(sorted(e), ["attestation_id", "canonicalization", "claims", "expires_at", "issued_at", "issuer", "signature", "spec", "subject", "version"])
        self.assertEqual((e["issued_at"], e["expires_at"], e["issuer"]["contact"]), ("2026-10-21T05:00:00Z", "2026-10-21T05:10:00Z", "gbmrafli@agentmail.to"))
        self.assertEqual(AT.verify(e, pub, now=NOW), (True, None)); self.assertEqual(AT.verify(e, pub, now=NOW + 601), (False, "expired"))
        t = json.loads(json.dumps(e)); t["claims"]["facts"]["target"] = "https://x.example/"; self.assertEqual(AT.verify(t, pub, now=NOW), (False, "bad_signature"))
        self.assertTrue(VA.verify(e, iss, now=NOW)[0])
        retired = {"keys": [dict(iss["keys"][0], status="retired", retired_at="2026-10-01T00:00:00Z")]}
        self.assertEqual(VA.verify(e, retired, now=NOW), (False, "issued after key was retired"))
        self.assertEqual(VA.verify(e, {"keys": []}, now=NOW), (False, "signature.key_id not listed by issuer"))
        try: import jsonschema
        except ImportError: jsonschema = None
        if jsonschema: jsonschema.validate(e, SCHEMA)
        low = json.dumps(e).lower()
        for w in ("verdict", "score", "recommend", "safe", "trust"): self.assertNotIn(w, low)
    def test_checks(self):
        st = lambda f, c: {x["id"]: x["status"] for x in AT.build_checks(f, c)}
        self.assertEqual(set(st(facts(), [{"address": ACC["payTo"], "kind": "eoa", "code_bytes": 0}]).values()), {"pass"})
        bad = facts(challenge={"valid": True, "problems": [], "accepts": [dict(ACC, network="eip155:1", asset="0x" + "11" * 20)]})
        e = AT.attest(bad, ephemeral()[0], rpc=lambda m, p: "0x6080", now=NOW)
        self.assertEqual(e["claims"]["checks_failed"], ["network_is_base", "asset_is_base_usdc", "payto_is_eoa"])
        self.assertEqual(e["claims"]["payto_code"], [{"address": "0x" + "22" * 20, "kind": "contract", "code_bytes": 2}])
        down = facts(reachability={"reachable": False, "error_class": "TimeoutError"}, challenge={"valid": False, "problems": ["no_402_challenge"], "accepts": []}, bazaar={"available": False, "reason": "no_snapshot"})
        self.assertEqual(st(down, []), {"endpoint_reachable": "fail", "http_402_returned": "not_applicable", "challenge_well_formed": "fail", "network_is_base": "not_applicable",
                                        "asset_is_base_usdc": "not_applicable", "payto_is_eoa": "not_applicable", "bazaar_snapshot_available": "fail", "listed_in_bazaar": "not_applicable"})
        def boom(m, p): raise OSError("x")
        self.assertEqual(AT.payto_code(["0x" + "22" * 20, "0x" + "22" * 20, "bad"], boom), [{"address": "0x" + "22" * 20, "kind": None, "code_bytes": None}])
        self.assertEqual(len(AT.payto_code(["0x%040x" % i for i in range(1, 9)], lambda m, p: "0x")), 4)
    def test_python_signed_verifies_with_deno_script(self):
        s, pub, iss = ephemeral(); e = AT.attest(facts(), s, rpc=lambda m, p: "0x")
        d = tempfile.mkdtemp(); json.dump({"attestation": e}, open(d + "/a.json", "w")); json.dump(iss, open(d + "/i.json", "w"))
        try: r = subprocess.run(["deno", "run", "--allow-read", "--config", os.path.join(R, "deno", "deno.json"), os.path.join(R, "scripts", "verify_attestation.ts"), d + "/a.json", "--issuer", d + "/i.json"], capture_output=True, timeout=120)
        except OSError: self.skipTest("deno not installed")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
    def test_service_endpoints(self):
        iss = IX.issuer_doc(); self.assertEqual((iss["canonicalization"], iss["keys"][0]["status"], iss["issuer"]["contact"]), ("JCS", "active", "gbmrafli@agentmail.to"))
        self.assertNotIn("private", json.dumps(iss).lower())
        self.assertEqual(IX.ATT_SCHEMA, SCHEMA)
        m = IX.snapshot_meta(); self.assertEqual(m["signature"]["canonicalization"], "JCS")
        eddsa.new(eddsa.import_public_key(base64.b64decode(m["signature"]["public_key_b64"])), "rfc8032").verify(AT.jcs(m["metadata"]), base64.b64decode(m["signature"]["value_b64"]))
        self.assertIn("/.well-known/issuer.json", IX.FREE_PATHS); self.assertIn("/.well-known/issuer.json", IX.llms_txt())
if __name__ == "__main__": unittest.main()
