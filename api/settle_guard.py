"""Seller-side defenses around facilitator verify/settle (see SECURITY.md). Deterministic, no network calls.
- parse_payment: size cap + strict base64/JSON parsing of PAYMENT-SIGNATURE / X-PAYMENT.
- precheck: local EIP-3009 authorization checks (payee, amount, validAfter/validBefore window) before any facilitator call.
- Replay: one in-flight/used claim per authorization (from+nonce) and per settlement tx hash; durable tx check via the sales log.
- FailLimiter: payers whose settles keep failing are cooled down (limits free-work griefing on paid handlers)."""
import base64, hashlib, json, re, threading, time
MAX_HEADER = 16384
MIN_VALID_WINDOW = 6          # seconds a signed authorization must still be valid when we receive it
TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$"); ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
def parse_payment(sig):
    if not sig or len(sig) > MAX_HEADER: return None, "payment header missing or too large"
    try:
        p = json.loads(base64.b64decode(sig, validate=True))
        if not isinstance(p, dict): raise ValueError
        return p, None
    except Exception: return None, "bad payment header"
def authorization(payload):
    a = (payload.get("payload") or {}).get("authorization") if isinstance(payload.get("payload"), dict) else None
    return a if isinstance(a, dict) else None
def precheck(payload, req, now=None):
    """None if acceptable, else a reason string. Only EIP-3009 (exact, transferWithAuthorization) payments are accepted; Permit2 is rejected."""
    now = int(now if now is not None else time.time())
    acc = payload.get("accepted")
    if isinstance(acc, dict):
        for k in ("scheme", "network", "asset", "payTo", "amount"):
            if k in acc and str(acc[k]).lower() != str(req[k]).lower(): return f"accepted.{k}_mismatch"
    if is_permit2(payload): return "permit2_not_supported: pay with an EIP-3009 transferWithAuthorization (exact scheme)"
    a = authorization(payload)
    if a is None: return "eip3009_authorization_required"
    try:
        if str(a.get("to", "")).lower() != req["payTo"].lower(): return "authorization_payee_mismatch"
        if int(a.get("value", -1)) != int(req["amount"]): return "authorization_amount_mismatch"
        if int(a.get("validAfter", 0)) > now: return "authorization_not_yet_valid"
        if int(a.get("validBefore", 0)) < now + MIN_VALID_WINDOW: return "authorization_expired_or_expiring"
        if not ADDR_RE.match(str(a.get("from", ""))): return "authorization_bad_from"
    except (TypeError, ValueError): return "authorization_malformed"
    return None
def is_permit2(payload):
    """Permit2 payloads carry no EIP-3009 nonce event, so the on-chain check could not bind the tx to this payment."""
    inner = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
    acc = payload.get("accepted") if isinstance(payload.get("accepted"), dict) else {}
    extra = acc.get("extra") if isinstance(acc.get("extra"), dict) else {}
    return any("permit2" in str(k).lower() for k in inner) or str(extra.get("assetTransferMethod", "")).lower() == "permit2"
def replay_key(payload, sig):
    a = authorization(payload)
    if a and a.get("nonce") and a.get("from"): return "auth:" + str(a["from"]).lower() + ":" + str(a["nonce"]).lower()
    return "sig:" + hashlib.sha256(sig.encode()).hexdigest()
class Replay:
    """Used payment authorizations, kept until their validBefore (+margin) or the TTL. claim() is an atomic check-and-set
    under a lock, so concurrent duplicates cannot race. Claims are never released: a signature is spent once it is seen."""
    def __init__(s, ttl=3600): s.ttl, s.m, s.pending, s.lock = ttl, {}, {}, threading.Lock()
    def claim(s, key, expires_at=None, now=None):
        now = now or time.time()
        with s.lock:
            for k in [k for k, t in s.m.items() if t < now]: s.m.pop(k, None); s.pending.pop(k, None)
            if key in s.m: return False
            s.m[key] = max(expires_at or 0, now + s.ttl); return True
    def set_pending(s, key, rec):
        with s.lock: s.pending[key] = rec
    def take_pending(s, key):
        """Atomically remove and return a pending delivery (so two retries cannot both be served)."""
        with s.lock: return s.pending.pop(key, None)
def expiry(payload, margin=60):
    a = authorization(payload)
    try: return int(a["validBefore"]) + margin if a else None
    except (KeyError, TypeError, ValueError): return None
def nonce_of(payload):
    n = str((authorization(payload) or {}).get("nonce", ""))
    return n if re.match(r"^0x[0-9a-fA-F]{1,64}$", n) else None
class FailLimiter:
    """Single-process, in-memory cooldown. Fine for one Python instance (tests, a single container); NOT for production
    behind several instances, where each would keep its own counts. The Deno server keeps this state in KV."""
    def __init__(s, limit=3, window=600): s.limit, s.window, s.m, s.lock = limit, window, {}, threading.Lock()
    def blocked(s, who, now=None):
        now = now or time.time()
        with s.lock: return who is not None and len([t for t in s.m.get(who, []) if t > now - s.window]) >= s.limit
    def fail(s, who, now=None):
        if who is None: return
        now = now or time.time()
        with s.lock: s.m[who] = [t for t in s.m.get(who, []) if t > now - s.window] + [now]
def payer_of(payload):
    a = authorization(payload); f = str((a or {}).get("from", "")).lower()
    return f if ADDR_RE.match(f) else None
