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
NONCE_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
ACCEPTED_FIELDS = ("scheme", "network", "asset", "payTo", "amount")
def precheck(payload, req, now=None):
    """None if acceptable, else a reason string. Only `exact` EIP-3009 transferWithAuthorization is accepted (Permit2 and anything
    else rejected). `accepted` must carry all 5 fields equal to ours (addresses case-insensitive, the rest exact). Runs before the claim."""
    now = int(now if now is not None else time.time())
    if is_permit2(payload): return "permit2_not_supported: pay with an EIP-3009 transferWithAuthorization (exact scheme)"
    acc = payload.get("accepted")
    if not isinstance(acc, dict): return "accepted_missing"
    for k in ACCEPTED_FIELDS:
        if acc.get(k) is None: return f"accepted.{k}_missing"
        a, b = str(acc[k]), str(req[k])
        if (a.lower() != b.lower()) if k in ("asset", "payTo") else (a != b): return f"accepted.{k}_mismatch"
    if req["scheme"] != "exact": return "scheme_not_supported"
    a = authorization(payload)
    if a is None: return "eip3009_authorization_required"
    try:
        if not ADDR_RE.match(str(a.get("from", ""))): return "authorization_bad_from"
        if not NONCE_RE.match(str(a.get("nonce", ""))): return "authorization_bad_nonce"
        if str(a.get("to", "")).lower() != req["payTo"].lower(): return "authorization_payee_mismatch"
        if _int(a.get("value", -1)) != int(req["amount"]): return "authorization_amount_mismatch"
        if _int(a.get("validAfter", 0)) > now: return "authorization_not_yet_valid"
        if _int(a.get("validBefore", 0)) < now + MIN_VALID_WINDOW: return "authorization_expired_or_expiring"
    except (TypeError, ValueError): return "authorization_malformed"
    return None
def _int(x):
    if isinstance(x, bool) or not re.match(r"^-?\d+$", str(x)): raise ValueError("malformed")
    return int(str(x))
def is_permit2(payload):
    """Permit2 payloads carry no EIP-3009 nonce event, so the on-chain check could not bind the tx to this payment."""
    inner = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
    acc = payload.get("accepted") if isinstance(payload.get("accepted"), dict) else {}
    extra = acc.get("extra") if isinstance(acc.get("extra"), dict) else {}
    return any("permit2" in str(k).lower() for k in inner) or str(extra.get("assetTransferMethod", "")).lower() == "permit2"
def replay_key(payload):
    """(from, 32-byte nonce), lower-cased: the on-chain uniqueness unit of EIP-3009. Only called after precheck() passed."""
    a = authorization(payload)
    return "auth:" + str(a["from"]).lower() + ":" + str(a["nonce"]).lower()
def payload_hash(payload):
    """sha256 of the canonical payload, stored with the claim for audit."""
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
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
    return n.lower() if NONCE_RE.match(n) else None
import ipaddress
def ip_key(ip):
    """Per-IP limit key: IPv4 as-is, IPv6 collapsed to its /64 (IPv4-mapped IPv6 -> the IPv4)."""
    if not ip: return None
    try: a = ipaddress.ip_address(str(ip).strip("[]").split("%")[0])
    except ValueError: return str(ip)
    if a.version == 6 and a.ipv4_mapped: return str(a.ipv4_mapped)
    if a.version == 4: return str(a)
    n = ipaddress.ip_network(f"{a}/64", strict=False); return str(n)
FAIL_LIMITS = {"payer": 3, "ip": 10}
GLOBAL_ALERT = 1000
class FailLimiter:
    """Failure cooldowns (same rules as the Deno KV version). BLOCKING scopes: payer (settle failures of the verified signer),
    ip (verify + settle failures; IPv6 keyed on /64). global: settle failures only, ALERT-ONLY (logged once per window,
    never blocks), so junk verify failures from a few IPs cannot lock out every buyer.
    Single-process, in-memory: fine for one Python instance (tests, a single container); NOT for production behind
    several instances, where each would keep its own counts. The Deno server keeps these counters in KV."""
    def __init__(s, limits=None, window=600, global_alert=GLOBAL_ALERT):
        s.limits, s.window, s.global_alert, s.m, s.lock, s.alerts, s._alerted = dict(limits or FAIL_LIMITS), window, global_alert, {}, threading.Lock(), [], set()
    def _b(s, now): return int(now // s.window)
    def count(s, scope, who, now=None):
        now = time.time() if now is None else now; b = s._b(now)
        with s.lock: return s.m.get((scope, who, b), 0) + s.m.get((scope, who, b - 1), 0)
    def blocked(s, ids, now=None):
        for sc in ("ip", "payer"):
            who = ip_key(ids.get("ip")) if sc == "ip" else ids.get("payer")
            if who and s.count(sc, who, now) >= s.limits[sc]: return sc
        return None
    def fail(s, ids, kind, now=None):
        """kind "verify": per-IP only (payer not proven yet). kind "settle": payer + IP + global (alert-only)."""
        now = time.time() if now is None else now; b = s._b(now)
        keys = []
        if ip_key(ids.get("ip")): keys.append(("ip", ip_key(ids.get("ip"))))
        if kind == "settle":
            if ids.get("payer"): keys.append(("payer", ids["payer"]))
            keys.append(("global", "*"))
        with s.lock:
            for k in [k for k in s.m if k[2] < b - 1]: s.m.pop(k)
            for sc, who in keys: s.m[(sc, who, b)] = s.m.get((sc, who, b), 0) + 1
            g = s.m.get(("global", "*", b), 0) + s.m.get(("global", "*", b - 1), 0)
            if kind == "settle" and g >= s.global_alert and b not in s._alerted:
                s._alerted.add(b); msg = f"ALERT: {s.global_alert}+ settle failures in the last window (global, alert-only, nothing blocked)"
                s.alerts.append(msg); print(msg, flush=True)
    def clear(s):
        with s.lock: s.m.clear(); s._alerted.clear()
SLOTS = {"payer": 4, "ip": 8}
class Slots:
    """Concurrency slots (same as Deno acquireSlots): at most SLOTS in-flight paid requests per payer and per IP (/64), so a
    parallel burst cannot slip past blocked() before its failures are counted. acquire() returns a release callable or None."""
    def __init__(s, slots=None): s.slots, s.m, s.lock = dict(slots or SLOTS), {}, threading.Lock()
    def acquire(s, ids):
        keys = [(sc, w) for sc, w in (("payer", ids.get("payer")), ("ip", ip_key(ids.get("ip")))) if w]
        with s.lock:
            if any(s.m.get(k, 0) >= s.slots[k[0]] for k in keys): return None
            for k in keys: s.m[k] = s.m.get(k, 0) + 1
        def release():
            with s.lock:
                for k in keys:
                    s.m[k] -= 1
                    if s.m[k] <= 0: s.m.pop(k)
        return release
def payer_of(payload):
    a = authorization(payload); f = str((a or {}).get("from", "")).lower()
    return f if ADDR_RE.match(f) else None
