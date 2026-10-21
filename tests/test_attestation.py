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
         "bazaar": {"available": True, "snapshot_date": "2026-10-20", "listed": True, "listed_payTo": [ACC["payTo"]]}}
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
        self.assertEqual(VA.verify(e, {"keys": []}, now=NOW), (False, "signature.key_id not listed exactly once by issuer"))
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
        self.assertIs(e["claims"]["pay_to_matches_snapshot"], True)
        self.assertEqual(e["claims"]["payto_code"], [{"address": "0x" + "22" * 20, "kind": "contract", "code_bytes": 2}])
        down = facts(reachability={"reachable": False, "error_class": "TimeoutError"}, challenge={"valid": False, "problems": ["no_402_challenge"], "accepts": []}, bazaar={"available": False, "reason": "no_snapshot"})
        self.assertEqual(st(down, []), {"endpoint_reachable": "fail", "http_402_returned": "not_applicable", "challenge_well_formed": "fail", "network_is_base": "not_applicable",
                                        "asset_is_base_usdc": "not_applicable", "payto_is_eoa": "not_applicable", "bazaar_snapshot_available": "fail", "listed_in_bazaar": "not_applicable",
                                        "responds_within_5000ms": "fail", "pay_to_matches_snapshot": "not_applicable"})
        def boom(m, p): raise OSError("x")
        self.assertEqual(AT.payto_code(["0x" + "22" * 20, "0x" + "22" * 20, "bad"], boom), [{"address": "0x" + "22" * 20, "kind": None, "code_bytes": None}])
        self.assertEqual(len(AT.payto_code(["0x%040x" % i for i in range(1, 9)], lambda m, p: "0x")), 4)
        d = "0x" + "ab" * 20
        self.assertEqual(AT.payto_code([ACC["payTo"]], lambda m, p: "0xef0100" + d[2:]), [{"address": ACC["payTo"], "kind": "eip7702_delegated", "code_bytes": 23, "delegate": d}])
        self.assertEqual([c for c in AT.build_checks(facts(), [{"address": ACC["payTo"], "kind": "eip7702_delegated", "code_bytes": 23, "delegate": d}]) if c["id"] == "payto_is_eoa"],
                         [{"id": "payto_is_eoa", "status": "fail", "observed": [{"address": ACC["payTo"], "kind": "eip7702_delegated", "delegate": d}]}])  # M2
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
        eddsa.new(eddsa.import_public_key(base64.b64decode(m["signature"]["public_key_b64"])), "rfc8032").verify(AT.domain_bytes(AT.DOMAIN_SNAPSHOT_META, m["metadata"]), base64.b64decode(m["signature"]["value_b64"]))
        self.assertIn("/.well-known/issuer.json", IX.FREE_PATHS); self.assertIn("/.well-known/issuer.json", IX.llms_txt())
class TFix(unittest.TestCase):
    def test_m1_domain_separation(self):
        k = ECC.generate(curve="ed25519"); raw = k.public_key().export_key(format="raw"); kid = hashlib.sha256(raw).hexdigest()[:16]; pub = base64.b64encode(raw).decode()
        sg = lambda m: eddsa.new(k, "rfc8032").sign(m)
        e = AT.attest(facts(), (kid, sg), now=NOW); body = {x: v for x, v in e.items() if x != "signature"}
        self.assertTrue(AT.signing_bytes(e).startswith(b"prepay-check-attestation/v1\n"))
        ver = lambda sig, msg: eddsa.new(eddsa.import_public_key(raw), "rfc8032").verify(msg, sig)
        a_sig = base64.b64decode(e["signature"]["value_b64"])
        for msg in (AT.domain_bytes(AT.DOMAIN_SNAPSHOT_META, body), AT.jcs(body), PF.canonical(body)): self.assertRaises(ValueError, ver, a_sig, msg)
        meta_sig = sg(AT.domain_bytes(AT.DOMAIN_SNAPSHOT_META, body)); legacy_sig = sg(PF.canonical(body))
        for s_ in (meta_sig, legacy_sig):
            forged = dict(body, signature=dict(e["signature"], value_b64=base64.b64encode(s_).decode()))
            self.assertEqual(AT.verify(forged, pub, now=NOW), (False, "bad_signature"))
            self.assertEqual(VA.verify(forged, {"keys": [{"key_id": kid, "public_key_b64": pub, "status": "active"}]}, now=NOW), (False, "bad signature"))
        self.assertRaises(ValueError, ver, legacy_sig, AT.domain_bytes(AT.DOMAIN_SNAPSHOT_META, body))
    def test_l2_pinning_and_dates(self):
        s, pub, iss = ephemeral(); _, pub2, _ = ephemeral(); kid, sg = s
        e = AT.attest(facts(), s, now=NOW)
        self.assertEqual(AT.verify(e, pub2, now=NOW), (False, "key_id_mismatch")); self.assertEqual(AT.verify(e, pub, now=NOW, expected_key_id="0" * 16), (False, "key_id_mismatch"))
        self.assertFalse(VA.verify(e, iss, now=NOW, expected_key_id="0" * 16)[0]); self.assertFalse(VA.verify(e, {"keys": iss["keys"] * 2}, now=NOW)[0])
        def resign(**p):
            o = json.loads(json.dumps(e)); o.update(p); o["signature"]["value_b64"] = base64.b64encode(sg(AT.signing_bytes(o))).decode(); return o
        for p_, why in (({"issued_at": "nan"}, "bad_dates"), ({"expires_at": "2026-02-30T00:00:00Z"}, "bad_dates"),
                        ({"expires_at": "2026-10-23T05:00:01Z"}, "bad_validity_window"), ({"expires_at": "2026-10-21T04:59:59Z"}, "bad_validity_window")):
            o = resign(**p_); self.assertEqual(AT.verify(o, pub, now=NOW), (False, why)); self.assertFalse(VA.verify(o, iss, now=NOW)[0])
        fut = resign(issued_at="2026-10-21T05:02:00Z", expires_at="2026-10-21T05:10:00Z")
        self.assertEqual(AT.verify(fut, pub, now=NOW), (False, "issued_in_future")); self.assertEqual(VA.verify(fut, iss, now=NOW)[1], "issued_at is in the future")
        self.assertTrue(AT.verify(resign(issued_at="2026-10-21T05:00:59Z", expires_at="2026-10-21T05:10:00Z"), pub, now=NOW)[0])
    def test_l3_ttl(self):
        self.assertEqual([AT.norm_ttl(x) for x in (1, 600, 10 ** 9, 0, -5, 1.5, float("nan"), "600", None, True)], [1, 600, 86400, 900, 900, 900, 900, 900, 900, 900])
    def test_l4_strict_json_and_schema(self):
        self.assertEqual(VA.strict_loads('{"a":[{"b":1}]}'), {"a": [{"b": 1}]})
        for bad in ('{"a":1,"a":2}', '{"x":{"spec":1,"spec":2}}', '{"a":NaN}', '{"a":Infinity}'): self.assertRaises(ValueError, VA.strict_loads, bad)
        self.assertEqual(SCHEMA["properties"]["claims"]["properties"]["checks_passed"]["items"], {"$ref": "#/$defs/check_id"})
        import jsonschema
        e = AT.attest(facts(), ephemeral()[0], now=NOW); e["claims"]["checks_failed"] = ["made_up"]
        self.assertRaises(jsonschema.ValidationError, jsonschema.validate, e, SCHEMA)
    def test_l1_huge_int_network(self):
        ch = {"x402Version": 2, "accepts": [dict(ACC, network=10 ** 400, asset=10 ** 30)]}
        ok, probs, acc = PF.validate_challenge(ch); self.assertEqual((acc[0]["network"], acc[0]["asset"]), (None, None))
        f = facts(challenge={"valid": ok, "problems": probs, "accepts": acc})
        s, pub, _ = ephemeral(); e = AT.attest(f, s, now=NOW); self.assertTrue(AT.verify(e, pub, now=NOW)[0])
        import unittest.mock as M
        with M.patch.object(PF, "probe", lambda u, ip, *a, **k: ({"reachable": True, "http_status": 402, "latency_ms": 1}, ch)), \
             M.patch.object(PF, "check_url", lambda u, *a: (u, "93.184.216.34", None)), M.patch.object(AT, "attest", side_effect=OverflowError("x")):
            code, body = PF.preflight("https://a.example/x")
        self.assertEqual((code, body["attestation"], body["attestation_error"]), (200, None, "attestation_unavailable")); self.assertTrue(body["signature"]["value_b64"])
class TAttack(unittest.TestCase):
    def test_a9_a10_checks_parity(self):
        slow = facts(reachability={"reachable": False, "error_class": "TimeoutError"})
        e = AT.attest(slow, ephemeral()[0], now=NOW); self.assertIn("responds_within_5000ms", e["claims"]["checks_failed"])
        other = facts(bazaar={"available": True, "snapshot_date": "2026-10-20", "listed": True, "listed_payTo": ["0x" + "33" * 20]})
        e2 = AT.attest(other, ephemeral()[0], now=NOW); self.assertIs(e2["claims"]["pay_to_matches_snapshot"], False)
        self.assertIn("pay_to_matches_snapshot", e2["claims"]["checks_failed"])
        self.assertIsNone(AT.pay_to_matches_snapshot(facts(bazaar={"available": False})))
        self.assertEqual(PF.probe.__defaults__[0], 5)
    def test_a11_a12_python_verifier(self):
        s, pub, iss = ephemeral()
        e = AT.attest(facts(bazaar={"available": True, "snapshot_date": "2026-10-20", "listed": True, "listed_payTo": [ACC["payTo"]], "snapshot_sha256": "a" * 64}), s, now=NOW)
        self.assertEqual(VA.verify_snapshot_binding(e, {"snapshots": [{"date": "2026-10-20", "sha256": "a" * 64}]})[0], True)
        self.assertEqual(VA.verify_snapshot_binding(e, {"snapshots": [{"date": "2026-10-20", "sha256": "b" * 64}]}), (False, "snapshot hash does not match the published snapshot"))
        self.assertFalse(VA.verify_snapshot_binding(e, {"snapshots": []})[0])
        y = AT.attest(facts(), s, now=NOW - 86400)
        self.assertEqual(VA.verify(y, iss, now=NOW)[1], "expired at 2026-10-20T05:15:00Z"); self.assertEqual(AT.verify(y, pub, now=NOW), (False, "expired"))
class TIssuerDocDrift(unittest.TestCase):
    """Verify a real attestation and real snapshot meta using ONLY the rules read from the served issuer.json."""
    def _verify(self, iss, domain, payload, sig, use_prefix=True):
        s = iss["signing"]; d = s["domains"][domain]
        self.assertEqual((s["algorithm"], s["canonicalization"], s["canonicalization_ref"], s["text_encoding"], s["message"]), ("Ed25519", "JCS", "RFC 8785", "UTF-8", "signing_prefix || JCS(payload)"))
        self.assertEqual(d["signing_prefix"].encode().hex(), d["signing_prefix_hex"])
        key = [k for k in iss["keys"] if k["key_id"] == sig["key_id"]]; self.assertEqual(len(key), 1)
        raw = base64.b64decode(key[0]["public_key_b64"]); self.assertEqual(len(raw), 32)
        self.assertEqual(hashlib.sha256(raw).hexdigest()[:16], key[0]["key_id"])
        import rfc8785
        msg = (d["signing_prefix"].encode("utf-8") if use_prefix else b"") + rfc8785.dumps(payload)
        try: eddsa.new(eddsa.import_public_key(raw), "rfc8032").verify(msg, base64.b64decode(sig["value_b64"])); return True
        except ValueError: return False
    def test_issuer_doc_rules_verify(self):
        iss = json.loads(json.dumps(IX.issuer_doc()))  # as served (JSON round trip)
        self.assertEqual(iss["signing"]["domains"]["attestation"]["signing_prefix"], "prepay-check-attestation/v1\n")
        self.assertEqual(iss["signing"]["domains"]["snapshot_meta"]["signing_prefix"], "bazaar-snapshot-meta/v1\n")
        k = PF.load_or_create_key(); kid = PF.public_key_info()["key_id"]
        e = json.loads(json.dumps(AT.attest(facts(), (kid, lambda m: eddsa.new(k, "rfc8032").sign(m)), rpc=lambda m, p: "0x", now=NOW)))
        payload = {x: v for x, v in e.items() if x != "signature"}
        self.assertTrue(self._verify(iss, "attestation", payload, e["signature"]))
        self.assertFalse(self._verify(iss, "attestation", payload, e["signature"], use_prefix=False))
        self.assertFalse(self._verify(iss, "snapshot_meta", payload, e["signature"]))
        m = json.loads(json.dumps(IX.snapshot_meta()))
        self.assertTrue(self._verify(iss, "snapshot_meta", m["metadata"], m["signature"]))
        self.assertFalse(self._verify(iss, "snapshot_meta", m["metadata"], m["signature"], use_prefix=False))

if __name__ == "__main__": unittest.main()
