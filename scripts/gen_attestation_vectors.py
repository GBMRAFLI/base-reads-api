"""Writes spec/test-vectors.json: JCS (RFC 8785) canonicalization cases and one signed attestation.
The signing key is a THROWAWAY Ed25519 key generated in memory for this run and discarded; only its public key is written."""
import base64, json, os, sys
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(R, "api")); import attestation as AT
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
CASES = [{"b": 1, "a": 2}, {"u": "é\u2028😀\"\\\n\t\x01", "\u20ac": 1, "\U0001f600": 2, "a": 3}, [1, -0, 10, 1e21, 0.5, 123456789012, None, True, False],
         {"nested": {"z": [], "a": {}}, "": ""}, {"amount": "1000", "network": "eip155:8453"}]
def build():
    k = ECC.generate(curve="ed25519"); pub = k.public_key().export_key(format="raw"); kid = __import__("hashlib").sha256(pub).hexdigest()[:16]
    facts = {"schema": "prepay-check/v1", "target": "https://a.example/x", "checked_at": "2026-10-21T05:00:00Z", "disclaimer": "Deterministic observations only. Not advice to pay, buy or sell.",
             "reachability": {"reachable": True, "http_status": 402, "latency_ms": 120},
             "challenge": {"valid": True, "problems": [], "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "10000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0x" + "22" * 20}]},
             "bazaar": {"available": False, "reason": "no_snapshot"}}
    att = AT.attest(facts, (kid, lambda m: eddsa.new(k, "rfc8032").sign(m)), rpc=lambda m, p: "0x", now=1792558800, ttl_s=900, issuer_url="https://issuer.example/.well-known/issuer.json")
    att["attestation_id"] = "00000000-0000-4000-8000-000000000001"  # fixed id, then re-sign
    att["signature"]["value_b64"] = base64.b64encode(eddsa.new(k, "rfc8032").sign(AT.signing_bytes(att))).decode()
    return {"license": "CC0-1.0", "jcs": [{"input": c, "canonical": AT.jcs(c).decode()} for c in CASES],
            "signed": {"public_key_b64": base64.b64encode(pub).decode(), "key_id": kid, "signing_bytes_utf8": AT.signing_bytes(att).decode(), "attestation": att,
                       "issuer": {"keys": [{"alg": "Ed25519", "key_id": kid, "public_key_b64": base64.b64encode(pub).decode(), "status": "active"}]}}}
if __name__ == "__main__":
    json.dump(build(), open(os.path.join(R, "spec", "test-vectors.json"), "w"), indent=1, ensure_ascii=False); print("ok")
