"""Pre-pay Check Attestation v1.0 (Python). Keys are ephemeral, generated in memory per test."""
import base64, hashlib, json, os, subprocess, sys, tempfile, time, unittest
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
        try: r = subprocess.run(["deno", "run", "--allow-read", "--config", os.path.join(R, "deno", "deno.json"), os.path.join(R, "scripts", "verify_attestation.ts"), d + "/a.json", "--issuer", d + "/i.json", "--key-id", s[0]], capture_output=True, timeout=120)
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
    """Verify real attestations and real snapshot meta using ONLY the rules read from the served issuer.json."""
    @staticmethod
    def _ts(x):
        import re, calendar
        if not isinstance(x, str) or not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", x): return None
        return calendar.timegm(time.strptime(x, "%Y-%m-%dT%H:%M:%SZ"))
    def _verify(self, iss, a, now, pinned=None, prefix=True):
        """One function per name in signing.check_order; returns the first failing check name, or "valid"."""
        import rfc8785
        s = iss["signing"]; d = s["domains"]["attestation"]; st = {}; T = self._ts
        def lookup():
            k = [k for k in iss["keys"] if k["key_id"] == a["signature"]["key_id"]]; st["k"] = k[0] if k else None; return len(k) == 1
        def integrity():
            raw = base64.b64decode(st["k"]["public_key_b64"]); return len(raw) == 32 and hashlib.sha256(raw).hexdigest()[:16] == st["k"]["key_id"]
        def window():
            i, e = T(a.get("issued_at")), T(a.get("expires_at")); return i is not None and e is not None and 0 <= e - i <= 86400
        def retired():
            k = st["k"]
            if k["status"] == "active": return "retired_at" not in k
            return k["status"] == "retired" and T(k.get("retired_at")) is not None and T(a["issued_at"]) <= T(k["retired_at"])
        def sig():
            msg = (d["signing_prefix"].encode("utf-8") if prefix else b"") + rfc8785.dumps({x: v for x, v in a.items() if x != "signature"})
            try: eddsa.new(eddsa.import_public_key(base64.b64decode(st["k"]["public_key_b64"])), "rfc8032").verify(msg, base64.b64decode(a["signature"]["value_b64"])); return True
            except ValueError: return False
        checks = {"spec_version_canonicalization": lambda: (a.get("spec"), a.get("version"), a.get("canonicalization")) == ("prepay-check-attestation", "1.0", s["canonicalization"]),
                  "signature_block": lambda: isinstance(a.get("signature"), dict) and a["signature"].get("alg") == s["algorithm"] and isinstance(a["signature"].get("value_b64"), str),
                  "pinned_key_id": lambda: isinstance(pinned, str) and a["signature"]["key_id"] == pinned,  # mandatory
                  "issuer_key_id_match": lambda: (a.get("issuer") or {}).get("key_id") == a["signature"]["key_id"],
                  "key_lookup": lookup, "key_integrity": integrity, "validity_window": window, "key_not_retired": retired, "signature": sig,
                  "not_future": lambda: T(a["issued_at"]) <= now + 60, "not_expired": lambda: now <= T(a["expires_at"])}
        self.assertEqual(list(checks), s["check_order"])
        for n in s["check_order"]:
            if not checks[n](): return n
        return "valid"
    def _meta(self, iss, m, prefix=True):
        import rfc8785
        k = [k for k in iss["keys"] if k["key_id"] == m["signature"]["key_id"]][0]
        msg = (iss["signing"]["domains"]["snapshot_meta"]["signing_prefix"].encode() if prefix else b"") + rfc8785.dumps(m["metadata"])
        try: eddsa.new(eddsa.import_public_key(base64.b64decode(k["public_key_b64"])), "rfc8032").verify(msg, base64.b64decode(m["signature"]["value_b64"])); return True
        except ValueError: return False
    def test_issuer_doc_rules_verify(self):
        iss = json.loads(json.dumps(IX.issuer_doc()))  # as served (JSON round trip)
        s = iss["signing"]
        self.assertEqual(s["domains"]["attestation"]["signing_prefix"], "prepay-check-attestation/v1\n")
        self.assertEqual(s["domains"]["snapshot_meta"]["signing_prefix"], "bazaar-snapshot-meta/v1\n")
        for d in s["domains"].values(): self.assertEqual(d["signing_prefix"].encode().hex(), d["signing_prefix_hex"])
        self.assertEqual(len(iss["verify"]), len(s["check_order"]) + 1)
        for i, n in enumerate(s["check_order"]): self.assertTrue(iss["verify"][i + 1].startswith("%d %s:" % (i + 1, n)), n)
        k = PF.load_or_create_key(); kid = PF.public_key_info()["key_id"]
        e = json.loads(json.dumps(AT.attest(facts(), (kid, lambda m: eddsa.new(k, "rfc8032").sign(m)), rpc=lambda m, p: "0x", now=NOW)))
        V = lambda att=e, i=iss, **kw: self._verify(i, att, kw.pop("now", NOW), **dict({"pinned": kid}, **kw))
        with self.subTest("01 expect valid"): self.assertEqual(V(pinned=kid), "valid")
        with self.subTest("02 expect valid"): self.assertEqual(V(dict(e, signature=dict(e["signature"], public_key_b64="AAAA"))), "valid")  # informational only
        with self.subTest("03 expect spec_version_canonicalization"): self.assertEqual(V(dict(e, version="2.0")), "spec_version_canonicalization")
        with self.subTest("04 expect signature_block"): self.assertEqual(V(dict(e, signature=dict(e["signature"], alg="RS256"))), "signature_block")
        with self.subTest("05b expect pinned_key_id (no pin given)"): self.assertEqual(V(pinned=None), "pinned_key_id")
        with self.subTest("05 expect pinned_key_id"): self.assertEqual(V(pinned="0" * 16), "pinned_key_id")
        with self.subTest("06 expect issuer_key_id_match"): self.assertEqual(V(dict(e, issuer=dict(e["issuer"], key_id="0" * 16))), "issuer_key_id_match")
        with self.subTest("07 expect key_lookup"): self.assertEqual(V(i=dict(iss, keys=[])), "key_lookup")
        with self.subTest("08 expect key_integrity"): self.assertEqual(V(i=dict(iss, keys=[dict(iss["keys"][0], public_key_b64=base64.b64encode(b"x" * 32).decode())])), "key_integrity")
        with self.subTest("09 expect validity_window"): self.assertEqual(V(dict(e, expires_at="2026-10-23T05:00:00Z")), "validity_window")
        def ret(at):
            kk = dict(iss["keys"][0], status="retired")
            if at is not None: kk["retired_at"] = at
            return dict(iss, keys=[kk])
        with self.subTest("10 expect key_not_retired"): self.assertEqual(V(i=ret("2026-10-21T04:59:59Z")), "key_not_retired")
        with self.subTest("11 expect key_not_retired"): self.assertEqual(V(i=ret(None)), "key_not_retired")
        with self.subTest("12 expect valid"): self.assertEqual(V(i=ret(e["issued_at"])), "valid")  # issued_at == retired_at is accepted
        with self.subTest("13 expect signature"): self.assertEqual(V(prefix=False), "signature")  # no prefix -> fail
        with self.subTest("14 expect signature"): self.assertEqual(V(dict(e, subject=dict(e["subject"], url="https://evil.example/"))), "signature")
        with self.subTest("15 expect not_future"): self.assertEqual(V(now=NOW - 120), "not_future")
        with self.subTest("16 expect not_expired"): self.assertEqual(V(now=NOW + 901), "not_expired")
        # official verifier agrees on the retired boundary and the key_id mismatch
        self.assertTrue(VA.verify(e, ret(e["issued_at"]), now=NOW)[0])
        self.assertFalse(VA.verify(e, ret("2026-10-21T04:59:59Z"), now=NOW)[0])
        self.assertFalse(VA.verify(dict(e, issuer=dict(e["issuer"], key_id="0" * 16)), iss, now=NOW)[0])
        m = json.loads(json.dumps(IX.snapshot_meta()))
        self.assertTrue(self._meta(iss, m)); self.assertFalse(self._meta(iss, m, prefix=False))

    def test_l1_official_verifier_key_status(self):
        k = PF.load_or_create_key(); cur = PF.key_history()["current"]
        e = json.loads(json.dumps(AT.attest(facts(), (cur["key_id"], lambda m: eddsa.new(k, "rfc8032").sign(m)), rpc=lambda m, p: "0x", now=NOW)))
        self.assertTrue(VA.verify(e, {"keys": [cur]}, now=NOW)[0])
        self.assertEqual(VA.verify(e, {"keys": [dict(cur, status="revoked")]}, now=NOW), (False, "unknown key status"))
        self.assertEqual(VA.verify(e, {"keys": [dict(cur, retired_at="2026-10-22T00:00:00Z")]}, now=NOW), (False, "active key must not carry retired_at"))
    def test_l2_key_timestamps_second_precision(self):
        self.assertEqual(PF.iso_or_none("2026-10-14T12:00:21.251Z"), "2026-10-14T12:00:21Z")
        k = PF.load_or_create_key(); cur = PF.key_history()["current"]
        old = os.environ.get("SIGNING_KEY_HISTORY")
        os.environ["SIGNING_KEY_HISTORY"] = json.dumps([{"public_key_b64": cur["public_key_b64"], "created_at": "2026-01-01T00:00:00.5Z", "retired_at": "2026-10-21T05:00:00.999Z"}])
        try: r = PF.key_history()["retired"][0]
        finally:
            if old is None: os.environ.pop("SIGNING_KEY_HISTORY")
            else: os.environ["SIGNING_KEY_HISTORY"] = old
        self.assertEqual((r["created_at"], r["retired_at"]), ("2026-01-01T00:00:00Z", "2026-10-21T05:00:00Z"))
        e = json.loads(json.dumps(AT.attest(facts(), (cur["key_id"], lambda m: eddsa.new(k, "rfc8032").sign(m)), rpc=lambda m, p: "0x", now=NOW)))
        self.assertTrue(VA.verify(e, {"keys": [r]}, now=NOW)[0])  # issued_at == normalized retired_at

    def test_medium_attacker_issuer_rejected(self):
        """Attacker-hosted issuer + attestation signed with the attacker's key (issuer_url points at the attacker) -> rejected."""
        legit_kid = PF.key_history()["current"]["key_id"]
        s, pub, evil = ephemeral(); d = tempfile.mkdtemp()
        json.dump(evil, open(d + "/evil_issuer.json", "w"))
        e = AT.attest(facts(), s, rpc=lambda m, p: "0x", issuer_url=d + "/evil_issuer.json")
        json.dump({"attestation": e}, open(d + "/a.json", "w"))
        import io, contextlib
        def run(*a):
            with contextlib.redirect_stdout(io.StringIO()): return VA.main([d + "/a.json", *a])
        self.assertEqual(run(), 2)  # no --issuer: issuer_url from the attestation is never used
        self.assertEqual(run("--issuer", d + "/evil_issuer.json"), 2)  # no --key-id: pin is mandatory
        self.assertEqual(run("--issuer", d + "/evil_issuer.json", "--key-id", legit_kid), 1)
        self.assertFalse(VA.verify(e, json.loads(json.dumps(IX.issuer_doc())), now=time.time(), expected_key_id=legit_kid)[0])

if __name__ == "__main__": unittest.main()
