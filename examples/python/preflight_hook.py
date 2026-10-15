"""Pre-pay Check hook for the official x402 Python client (pip install x402).
Before any payment is created, fetch signed facts about the target and abort on hard failures.
The $0.001 preflight is paid by a SEPARATE client (no hook recursion)."""
from urllib.parse import quote
from x402 import x402Client, AbortResult

PREFLIGHT = "https://<your-deploy-host>/x402/preflight?url="
MAX_LATENCY_MS = 3000


def make_prepay_hook(paid_get, resource_url, preflight_base=PREFLIGHT):
    """paid_get(url) -> dict: an x402-enabled HTTP GET from a separate client. resource_url() -> target URL."""
    async def before_payment(ctx):
        try:
            env = await paid_get(preflight_base + quote(resource_url(), safe=""))
        except Exception as e:
            return AbortResult(reason=f"preflight unavailable: {type(e).__name__}")
        f, req = env["facts"], ctx.selected_requirements  # verify env["signature"] with the published key if needed
        if not f["challenge"]["valid"]:
            return AbortResult(reason="challenge invalid: " + ",".join(f["challenge"]["problems"]))
        if not any((a.get("payTo") or "").lower() == req.pay_to.lower() for a in f["challenge"]["accepts"]):
            return AbortResult(reason="payTo differs from the challenge observed by preflight")
        if f["reachability"].get("latency_ms", 0) > MAX_LATENCY_MS:
            return AbortResult(reason="slow endpoint")
        reuse = (f.get("bazaar") or {}).get("payout_wallet_reuse", {}).get(req.pay_to.lower())
        if reuse and reuse["hosts_using_wallet"] > 20:
            return AbortResult(reason="payout wallet shared by many hosts")
        return None  # thresholds are YOUR policy; the service only reports facts
    return before_payment


# client = x402Client(); client.on_before_payment_creation(make_prepay_hook(paid_get, lambda: TARGET))
