"""Pre-pay Check: deterministic, signed facts about an x402 endpoint BEFORE a buyer pays it.
Zero LLM. No buy/sell advice: facts only. Receive-only service; the signing key holds no funds."""
import base64, gzip, hashlib, ipaddress, json, os, re, socket, time, urllib.error, urllib.parse, urllib.request
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
SNAP_DIR = os.environ.get("SNAPSHOT_DIR", os.path.join(os.path.dirname(__file__), "..", "data", "snapshots"))
KEY_PATH = os.environ.get("SIGNING_KEY_PATH", os.path.join(os.path.dirname(__file__), "..", "data", "signing_key.enc.pem"))
UA = "base-reads-prepay-check/1.0"
SCHEMA = "prepay-check/v1"

# ---------- signing key (Ed25519, encrypted at rest, never printed) ----------
_key = None
def _passphrase():
    p = os.environ.get("SIGNING_KEY_PASSPHRASE", "")
    if len(p) < 16: raise RuntimeError("SIGNING_KEY_PASSPHRASE missing or too short")
    return p
def load_or_create_key():
    global _key
    if _key: return _key
    pw = _passphrase()
    env_pem = os.environ.get("SIGNING_KEY_ENC_B64")  # encrypted PEM (base64) so the key survives free-tier restarts
    if env_pem:
        _key = ECC.import_key(base64.b64decode(env_pem).decode(), passphrase=pw); return _key
    if os.path.exists(KEY_PATH):
        _key = ECC.import_key(open(KEY_PATH).read(), passphrase=pw)
    else:
        _key = ECC.generate(curve="ed25519")
        os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f: f.write(_key.export_key(format="PEM", passphrase=pw, protection="scryptAndAES256-CBC"))
    return _key
def key_meta(raw, created_at=None):
    """Identity of a raw 32-byte Ed25519 public key: key_id, SSH-style fingerprint and a grouped short form."""
    d = hashlib.sha256(raw).digest(); kid = d.hex()[:16]
    return {"alg": "Ed25519", "public_key_b64": base64.b64encode(raw).decode(), "key_id": kid,
            "fingerprint": "SHA256:" + base64.b64encode(d).decode().rstrip("="), "fingerprint_short": " ".join(kid[i:i + 4] for i in range(0, 16, 4)),
            "created_at": created_at}
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
def iso_or_none(x):
    """Strict ISO-8601 UTC (YYYY-MM-DDTHH:MM:SS[.fff]Z) that is a real date, else None."""
    if not isinstance(x, str) or not ISO_RE.match(x): return None
    try: time.strptime(x[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError: return None
    return x
def startup_warnings(env=os.environ):
    """Non-fatal configuration problems, logged once at startup."""
    w = []; ca = env.get("SIGNING_KEY_CREATED_AT")
    if ca and not iso_or_none(ca): w.append("SIGNING_KEY_CREATED_AT is not strict ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ); published as null")
    try:
        h = json.loads(env.get("SIGNING_KEY_HISTORY") or "[]")
        if not isinstance(h, list): w.append("SIGNING_KEY_HISTORY is not a JSON list; ignored")
        else:
            for i, k in enumerate(h):
                for f in ("created_at", "retired_at"):
                    if isinstance(k, dict) and k.get(f) is not None and not iso_or_none(k[f]): w.append(f"SIGNING_KEY_HISTORY[{i}].{f} is not strict ISO-8601 UTC; published as null")
    except ValueError: w.append("SIGNING_KEY_HISTORY is not valid JSON; ignored")
    return w
def _created_at():
    if os.environ.get("SIGNING_KEY_CREATED_AT"): return iso_or_none(os.environ["SIGNING_KEY_CREATED_AT"])
    if not os.environ.get("SIGNING_KEY_ENC_B64") and os.path.exists(KEY_PATH):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(KEY_PATH)))
    return None
def public_key_info():
    return key_meta(load_or_create_key().public_key().export_key(format="raw"), _created_at())
def key_history():
    """Current key plus retired keys from SIGNING_KEY_HISTORY (JSON list of {public_key_b64, created_at, retired_at}). Public data only."""
    try: retired = json.loads(os.environ.get("SIGNING_KEY_HISTORY") or "[]")
    except ValueError: retired = []
    out = []
    for k in retired if isinstance(retired, list) else []:
        try: raw = base64.b64decode(str(k["public_key_b64"]), validate=True)
        except Exception: continue
        if len(raw) == 32: out.append(dict(key_meta(raw, iso_or_none(k.get("created_at"))), retired_at=iso_or_none(k.get("retired_at")), status="retired"))
    return {"current": dict(public_key_info(), status="active"), "retired": out}
def canonical(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def sign(facts):
    k = load_or_create_key(); pub = public_key_info()
    sig = eddsa.new(k, "rfc8032").sign(canonical(facts))
    return {"facts": facts, "signature": {"alg": "Ed25519", "key_id": pub["key_id"], "public_key_b64": pub["public_key_b64"], "value_b64": base64.b64encode(sig).decode(), "signed_over": "canonical JSON of facts (sorted keys, no whitespace)"}}
def verify(envelope):
    s = envelope["signature"]; pk = eddsa.import_public_key(base64.b64decode(s["public_key_b64"]))
    try: eddsa.new(pk, "rfc8032").verify(canonical(envelope["facts"]), base64.b64decode(s["value_b64"])); return True
    except ValueError: return False

# ---------- target URL safety (no SSRF, no DNS rebinding) ----------
import http.client, ssl
def _extra_cidrs(env=os.environ):
    """PREFLIGHT_EXTRA_ALLOWED_CIDRS bypasses the address checks (local proxy tests only). Refuse to start with it
    unless PREFLIGHT_TEST_MODE=1 is also set, so it cannot be left on in production by accident."""
    raw = env.get("PREFLIGHT_EXTRA_ALLOWED_CIDRS", "")
    if not raw.strip(): return []
    if env.get("PREFLIGHT_TEST_MODE") != "1":
        raise SystemExit("PREFLIGHT_EXTRA_ALLOWED_CIDRS is set without PREFLIGHT_TEST_MODE=1: refusing to start (it disables SSRF address checks)")
    print("WARNING: PREFLIGHT_EXTRA_ALLOWED_CIDRS active (test mode): SSRF address checks relaxed for", raw, flush=True)
    return [ipaddress.ip_network(c.strip()) for c in raw.split(",") if c.strip()]
_EXTRA = _extra_cidrs()
_EMBED_V4 = [ipaddress.ip_network(n) for n in ("::ffff:0:0/96", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")]
def ip_allowed(ip):
    """Only globally routable unicast. is_global also excludes shared/CGNAT 100.64/10, which is_private does not.
    IPv6 forms that embed an IPv4 address (mapped, compatible, NAT64, 6to4, Teredo) are refused outright."""
    a = ipaddress.ip_address(ip)
    if any(a in n for n in _EXTRA): return True
    if a.version == 6 and any(a in n for n in _EMBED_V4): return False
    return a.is_global and not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified)
ALLOWED_PORTS = (443, 8443)
def resolve_pinned(host, port, resolver=socket.getaddrinfo):
    """Resolve ONCE. Reject if ANY answer is non-public; return the first IP to pin the connection to."""
    try: ips = [a[4][0] for a in resolver(host, port, 0, socket.SOCK_STREAM)]
    except socket.gaierror: return None, "dns_unresolvable"
    if not ips: return None, "dns_unresolvable"
    for ip in ips:
        if not ip_allowed(ip): return None, "target resolves to a non-public address"
    return ips[0], None
def check_url(url, resolver=socket.getaddrinfo):
    """-> (parts, pinned_ip, error)."""
    try: u = urllib.parse.urlsplit(url); port = u.port or 443
    except Exception: return None, None, "unparseable url"
    if any(c in url for c in "\r\n\t ") or "\\" in url: return None, None, "unparseable url"
    if u.scheme != "https" or not u.hostname: return None, None, "url must be https://host/..."
    if len(url) > 2048: return None, None, "url too long"
    if u.username is not None or u.password is not None: return None, None, "credentials in url not allowed"
    if port not in ALLOWED_PORTS: return None, None, "port not allowed (443, 8443)"
    ip, err = resolve_pinned(u.hostname, port, resolver)
    if err == "dns_unresolvable": return u, None, err
    if err: return None, None, err
    return u, ip, None

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TCP to the pre-validated IP; TLS SNI + certificate check + Host header use the original hostname."""
    def __init__(self, host, pinned_ip, port=443, timeout=8, context=None):
        super().__init__(host, port, timeout=timeout, context=context or ssl.create_default_context()); self.pinned_ip = pinned_ip
    def connect(self):
        sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

def probe(u, pinned_ip, timeout=8, conn_cls=PinnedHTTPSConnection):
    """One unpaid GET over the pinned IP. No redirects followed."""
    t0 = time.monotonic()
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    try:
        c = conn_cls(u.hostname, pinned_ip, u.port or 443, timeout=timeout)
        c.request("GET", path, headers={"User-Agent": UA, "Accept": "application/json"})  # Host header = hostname (http.client default)
        r = c.getresponse(); status, hdrs, body = r.status, dict(r.getheaders()), r.read(65536); c.close()
    except Exception as e:
        return {"reachable": False, "error_class": type(e).__name__, "latency_ms": round((time.monotonic() - t0) * 1000)}, None
    lat = round((time.monotonic() - t0) * 1000); ch = None
    h = {k.lower(): v for k, v in hdrs.items()}
    if "payment-required" in h:
        try: ch = json.loads(base64.b64decode(h["payment-required"]))
        except Exception: ch = {"_unparseable": "header"}
    elif status == 402:
        try: ch = json.loads(body)
        except Exception: ch = {"_unparseable": "body"}
    return {"reachable": True, "http_status": status, "latency_ms": lat}, ch

def validate_challenge(ch, now=None):
    """Deterministic structural validity of an x402 challenge. Returns (valid, problems, accepts_summary)."""
    if ch is None: return False, ["no_402_challenge"], []
    if "_unparseable" in ch: return False, ["challenge_" + ch["_unparseable"] + "_not_json"], []
    p = []
    ver = ch.get("x402Version")
    if ver not in (1, 2): p.append("unknown_x402Version")
    acc = ch.get("accepts")
    if not isinstance(acc, list) or not acc: return False, p + ["accepts_missing_or_empty"], []
    out = []
    for i, a in enumerate(acc):
        if not isinstance(a, dict): p.append(f"accepts[{i}]_not_object"); continue
        amt = a.get("amount", a.get("maxAmountRequired"))
        for f, ok in (("scheme", isinstance(a.get("scheme"), str)), ("network", isinstance(a.get("network"), str)),
                      ("amount", isinstance(amt, str) and amt.isdigit()), ("asset", isinstance(a.get("asset"), str) and bool(ADDR.match(a.get("asset", "")))),
                      ("payTo", isinstance(a.get("payTo"), str) and bool(ADDR.match(a.get("payTo", "")))),
                      ("maxTimeoutSeconds", isinstance(a.get("maxTimeoutSeconds"), int) and 0 < a.get("maxTimeoutSeconds", 0) <= 3600)):
            if not ok: p.append(f"accepts[{i}].{f}_invalid")
        out.append({"scheme": a.get("scheme"), "network": a.get("network"), "amount": amt, "asset": a.get("asset"), "payTo": a.get("payTo")})
    return not p, p, out

# ---------- Bazaar snapshots ----------
def host_of(url):
    try: return (urllib.parse.urlsplit(url).hostname or "").lower()
    except Exception: return ""
def build_index(items, date):
    hosts, wallets, res = {}, {}, {}
    for it in items:
        u = it.get("resource") or ""; h = host_of(u)
        if not h: continue
        hosts[h] = hosts.get(h, 0) + 1
        for a in it.get("accepts") or []:
            w = (a.get("payTo") or "").lower()
            if w: wallets.setdefault(w, set()).add(h)
        q = it.get("quality") or {}
        res[u.split("?")[0]] = {"payers30d": q.get("l30DaysUniquePayers"), "calls30d": q.get("l30DaysTotalCalls"), "lastCalledAt": q.get("lastCalledAt"),
                                 "payTo": sorted({(a.get("payTo") or "").lower() for a in it.get("accepts") or [] if a.get("payTo")})}
    return {"date": date, "listings": len(items), "hosts": hosts, "wallet_hosts": {w: sorted(s) for w, s in wallets.items()}, "resources": res}
def snapshot_dates():
    if not os.path.isdir(SNAP_DIR): return []
    return sorted(f[:10] for f in os.listdir(SNAP_DIR) if f.endswith(".index.json.gz"))
def load_index(date):
    with gzip.open(os.path.join(SNAP_DIR, date + ".index.json.gz"), "rt") as f: return json.load(f)

def bazaar_facts(url, payto_list, max_trend=14):
    dates = snapshot_dates()
    if not dates: return {"available": False, "reason": "no_snapshot"}
    idx = load_index(dates[-1]); h = host_of(url); key = url.split("?")[0]
    cur = idx["resources"].get(key); wl = {}
    listed_payto = (cur or {}).get("payTo", [])
    for w in {x.lower() for x in payto_list if x} | set(listed_payto):
        hs = idx["wallet_hosts"].get(w, [])
        wl[w] = {"hosts_using_wallet": len(hs), "other_hosts_sample": [x for x in hs if x != h][:10]}
    trend = []
    for d in dates[-max_trend:]:
        r = (idx if d == dates[-1] else load_index(d))["resources"].get(key)
        trend.append({"snapshot": d, "payers30d": r and r["payers30d"], "calls30d": r and r["calls30d"]})
    return {"available": True, "snapshot_date": dates[-1], "listed": cur is not None, "listed_payTo": listed_payto,
            "host_listing_count": idx["hosts"].get(h, 0), "payout_wallet_reuse": wl,
            "last_called_at": cur and cur["lastCalledAt"], "payer_trend": trend}

def preflight(url, now=None):
    now = now or time.time()
    u, ip, err = check_url(url)
    if u is None: return 400, {"error": err}
    base = {"schema": SCHEMA, "target": url, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "disclaimer": "Deterministic observations only. Not advice to pay, buy or sell."}
    if err == "dns_unresolvable":
        reach, ch = {"reachable": False, "error_class": "dns_unresolvable"}, None
    else:
        reach, ch = probe(u, ip)
    valid, problems, acc = validate_challenge(ch)
    facts = dict(base, reachability=reach, challenge={"valid": valid, "problems": problems, "accepts": acc},
                 bazaar=bazaar_facts(url, [a["payTo"] for a in acc if a.get("payTo")]))
    return 200, sign(facts)
