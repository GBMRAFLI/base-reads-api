"""RWA Exitability Check (reference implementation; same output as deno/lib/rwa.ts). Deterministic lookup over
spec/rwa-exitability-dataset.json. Values only with a cited source; otherwise "not_disclosed". Zero LLM."""
import json, os, re, time, urllib.parse
DATA = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "rwa-exitability-dataset.json")))
FIELDS = ["transfer_eligibility", "nav_freshness", "redemption_path", "redemption_timing", "instant_capacity", "pause_freeze"]
ND = "not_disclosed"
DISCLAIMER = "Reported facts from cited public sources at the stated retrieval times. Not a liquidity guarantee, not a redemption promise, and not investment advice. Fields marked not_disclosed had no cited source in this dataset revision."
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$")
CHAIN_RE = re.compile(r"^[a-z0-9-]{1,32}$"); ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SIG = r"[A-Za-z_][A-Za-z0-9_]{0,63}\([A-Za-z0-9_,\[\] ]{0,200}\)"
FN_RE = re.compile(r"^(%s(/%s){0,3}|0x[0-9a-fA-F]{8})$" % (_SIG, _SIG))
INTERNAL_PATH_RE = re.compile(r"/(workspace|home|root|opt|etc|var|tmp|srv|mnt|usr)(/|$)|file:|~/", re.I)
def has_internal_path(u):
    """Same rule as hasInternalPath in deno/lib/rwa_schema.ts."""
    cur = u
    for _ in range(5):
        if "\\" in cur or INTERNAL_PATH_RE.search(cur): return True
        try: nxt = urllib.parse.unquote(cur, errors="strict")
        except UnicodeDecodeError: return True
        if re.search(r"%(?![0-9A-Fa-f]{2})", cur): return True  # malformed escape, as decodeURIComponent rejects
        if nxt == cur: return False
        cur = nxt
    return True
def public_https(u):
    if not isinstance(u, str) or has_internal_path(u): return False
    x = urllib.parse.urlsplit(u)
    return x.scheme == "https" and bool(x.hostname) and x.username is None and x.password is None
EXPLORER_HOSTS = ("etherscan.io", "basescan.org")
def explorer_for(u, address):
    try: x = urllib.parse.urlsplit(u); host = (x.hostname or "").lower()
    except ValueError: return False
    if x.scheme != "https" or host not in EXPLORER_HOSTS: return False
    m = re.fullmatch(r"/address/(0x[0-9a-fA-F]{40})/?", x.path)
    return bool(m) and isinstance(address, str) and m.group(1).lower() == address.lower()
def onchain_errors(o):
    """Same rules as onchainErrors in deno/lib/rwa.ts (empty list = valid)."""
    if not isinstance(o, dict) or sorted(o) != ["address", "block", "chain", "function"]: return ["onchain must have exactly chain, address, function, block"]
    e = []
    if not isinstance(o["chain"], str) or not CHAIN_RE.match(o["chain"]): e.append("onchain.chain")
    if not isinstance(o["address"], str) or not ADDR_RE.match(o["address"]): e.append("onchain.address")
    if not isinstance(o["function"], str) or not FN_RE.match(o["function"]): e.append("onchain.function")
    b = o["block"]
    if not isinstance(b, int) or isinstance(b, bool) or b < 1 or b > 2**53 - 1: e.append("onchain.block")
    return e
def entry_errors(v):
    """Per-field rules of validateDataset in deno/lib/rwa.ts. An invalid entry is served as not_disclosed, never a 500."""
    if not isinstance(v, dict): return ["entry must be an object"]
    ks = sorted(v)
    if ks not in (["retrieved_at", "source_url", "value"], ["onchain", "retrieved_at", "source_url", "value"]): return ["entry keys"]
    e = []
    if v["value"] is None or v["value"] == "" or v["value"] == ND: e.append("empty value")
    u = v["source_url"]
    if not public_https(u): e.append("source_url")
    elif isinstance(v.get("onchain"), dict) and not explorer_for(u, v["onchain"].get("address")): e.append("onchain needs the explorer page of its address")
    if not isinstance(v["retrieved_at"], str) or not ISO.match(v["retrieved_at"]): e.append("retrieved_at")
    if "onchain" in v: e += onchain_errors(v["onchain"])
    return e
def resolve(s):
    t = s.strip().lower()
    return next((k for k in DATA["assets"] if k.lower() == t), None)
def unknown(): return "unknown asset; supported: " + ", ".join(DATA["assets"])
def input_error(q):
    a = q.get("asset", "")
    return None if a == "" or resolve(urllib.parse.unquote_plus(a)) else unknown()
def confidence(n):
    r = n / len(FIELDS)
    return {"level": "none" if n == 0 else "low" if r < 0.5 else "medium" if r < 1 else "high", "disclosed_fields": n, "total_fields": len(FIELDS),
            "basis": "share of fields with a cited public source; not a quality or risk rating"}
def handle(q, now=None):
    raw = urllib.parse.unquote_plus(q.get("asset", ""))
    if not raw: return 400, {"error": "give ?asset=<symbol>; supported: " + ", ".join(DATA["assets"])}
    sym = resolve(raw)
    if not sym: return 400, {"error": unknown()}
    f = DATA["assets"][sym]["fields"]; fields, sources, n = {}, {}, 0
    for k in FIELDS:
        v = f.get(k)
        if v is not None and entry_errors(v): v = None
        if v:
            fields[k] = v["value"]; n += 1
            sources[k] = {"url": v["source_url"], "retrieved_at": v["retrieved_at"]}
            o = v.get("onchain")
            if o: sources[k]["onchain"] = {"chain": o["chain"], "address": o["address"], "function": o["function"], "block": o["block"]}
        else: fields[k] = ND; sources[k] = ND
    return 200, {"schema": "rwa-exitability/v1", "asset": sym, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now or time.time())),
                 "dataset": {"version": DATA["version"], "revision": DATA["dataset_revision"], "generated_at": DATA["generated_at"]},
                 "fields": fields, "sources": sources, "confidence": confidence(n), "disclaimer": DISCLAIMER}
