"""Sales log. Both paid endpoints write ONLY through this module, using one record schema and file set
(observations / executions / outcomes / costs .jsonl). An external collector ingests this directory.
Zero LLM, no secrets recorded."""
import hashlib, json, os, time
STORE = os.environ.get("DATA_STORE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "records"))
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
AUTH_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"  # EIP-3009 AuthorizationUsed(address,bytes32)
CATEGORY = {"/x402/preflight": "endpoint_check"}  # every /base/* route = chain_reads
def category(route): return CATEGORY.get(route, "chain_reads")
def iso(t=None): t = time.time() if t is None else t; return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)
def rid(prefix, *parts): return prefix + "-" + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:12]
def append(name, rec):
    os.makedirs(STORE, exist_ok=True)
    with open(os.path.join(STORE, name), "a") as f: f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec
def rows(name):
    p = os.path.join(STORE, name)
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []
def self_wallets(pay_to):
    """Our own wallets: payTo + PAY_TO_ADDRESS + SELF_WALLETS (comma list). Payments from these never count."""
    w = {pay_to.lower()}
    for k in ("PAY_TO_ADDRESS",):
        if os.environ.get(k): w.add(os.environ[k].strip().lower())
    w |= {x.strip().lower() for x in os.environ.get("SELF_WALLETS", "").split(",") if x.strip()}
    return w

def verify_onchain(rpc, tx, asset, pay_to, amount, payer, network="eip155:8453", attempts=4, wait=2.0, sleep=time.sleep, nonce=None):
    """Read-only Base check: receipt status=1 and a USDC Transfer(payer -> pay_to, value >= amount) in the tx logs.
    With nonce (EIP-3009): the same receipt must also carry USDC AuthorizationUsed(payer, nonce), binding the tx to THIS payment."""
    if not tx: return {"settled": False, "reason": "no_tx_hash"}
    for i in range(attempts):
        try: rc = rpc("eth_getTransactionReceipt", [tx])
        except Exception as e: rc = None; err = type(e).__name__
        if rc: break
        if i < attempts - 1: sleep(wait)
    else: return {"settled": None, "reason": "receipt_not_found_yet"}
    if rc.get("status") != "0x1": return {"settled": False, "reason": "tx_reverted", "block": int(rc["blockNumber"], 16)}
    for lg in rc.get("logs", []):
        t = lg.get("topics", [])
        if lg.get("address", "").lower() == asset.lower() and len(t) == 3 and t[0] == TRANSFER:
            frm, to, val = "0x" + t[1][-40:], "0x" + t[2][-40:], int(lg.get("data", "0x0"), 16)
            if to.lower() == pay_to.lower() and (payer is None or frm.lower() == payer.lower()) and val >= int(amount):
                if nonce is not None and not _auth_used(rc, asset, frm, nonce): return {"settled": False, "reason": "nonce_not_in_settlement_tx"}
                return {"settled": True, "network": network, "block": int(rc["blockNumber"], 16), "from": frm, "to": to, "value": val, "nonceBound": nonce is not None}
    return {"settled": False, "reason": "no_matching_usdc_transfer"}
def _auth_used(rc, asset, frm, nonce):
    n = nonce.lower(); n = "0x" + n[2:].rjust(64, "0") if n.startswith("0x") else n
    for lg in rc.get("logs", []):
        t = [x.lower() for x in lg.get("topics", [])]
        if lg.get("address", "").lower() == asset.lower() and len(t) == 3 and t[0] == AUTH_USED and t[1][-40:] == frm.lower()[2:] and t[2] == n: return True
    return False

def record_sale(route, req, st, times, onchain, served_ok=True, ref=None):
    """ExecutionRecord (receipt = payment received) + OutcomeRecord (outcome = resource delivered, on-chain verified,
    external payer) + CostEntry. verified_success ONLY if settled on Base AND payer is external AND resource delivered."""
    tx, payer = st.get("transaction"), (st.get("payer") or "").lower() or None
    cand = rid("cand", "v1", category(route), route)
    ex = append("executions.jsonl", {"id": rid("exec", tx, route), "candidateRef": cand, "category": category(route), "protocolType": "x402",
        "role": "seller", "adapter": "x402-seller", "route": route, "amount": req["amount"], "asset": req["asset"], "network": req["network"],
        "payTo": req["payTo"], "payer": payer, "tx": tx, "status": "succeeded" if st.get("success") else "failed",
        "startedAt": times[0], "verifiedAt": times[1], "settledAt": times[2], "receipt": "payment_received", **({"ref": ref} if ref else {})})
    is_self = payer in self_wallets(req["payTo"]) if payer else None
    if onchain.get("settled") is True and is_self is False and served_ok: status, why = "verified_success", None
    elif onchain.get("settled") is None: status, why = "inconclusive", "deferred_onchain_check"
    elif is_self: status, why = "excluded", "self_payer"
    else: status, why = "verified_failure", onchain.get("reason") or "resource_not_delivered"
    out = append("outcomes.jsonl", {"id": rid("out", tx, route), "candidateRef": cand, "executionRef": ex["id"], "category": category(route),
        "status": status, "reason": why, "externalPayer": is_self is False, "payer": payer, "onchain": onchain,
        "outcome": "resource_delivered" if served_ok else "not_delivered", "verifiedAt": iso()})
    append("costs.jsonl", {"id": rid("cost", tx, route), "candidateRef": cand, "executionRef": ex["id"], "category": "settlement",
        "amount": 0.0, "currency": "USD", "incurredAt": iso(), "evidenceRef": f"tx:{tx}", "measured": True,
        "allocationMethod": "direct; facilitator pays gas, seller cost 0", "revenue": int(req["amount"]) / 1e6 if status == "verified_success" else 0.0})
    return out

def record_observation(route, query_hash, code, latency_ms, note=None):
    rec = {"id": rid("obs", route, query_hash, iso()), "category": category(route), "route": route,
        "inputHash": query_hash, "httpStatus": code, "latencyMs": latency_ms, "observedAt": iso(), "method": "deterministic_code"}
    if note: rec["note"] = note
    return append("observations.jsonl", rec)
