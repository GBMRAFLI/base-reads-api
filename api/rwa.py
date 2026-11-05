"""RWA Exitability Check (reference implementation; same output as deno/lib/rwa.ts). Deterministic lookup over
spec/rwa-exitability-dataset.json. Values only with a cited source; otherwise "not_disclosed". Zero LLM."""
import json, os, time, urllib.parse
DATA = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "rwa-exitability-dataset.json")))
FIELDS = ["transfer_eligibility", "nav_freshness", "redemption_path", "redemption_timing", "instant_capacity", "pause_freeze"]
ND = "not_disclosed"
DISCLAIMER = "Reported facts from cited public sources at the stated retrieval times. Not a liquidity guarantee, not a redemption promise, and not investment advice. Fields marked not_disclosed had no cited source in this dataset revision."
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
        if v: fields[k] = v["value"]; sources[k] = {"url": v["source_url"], "retrieved_at": v["retrieved_at"]}; n += 1
        else: fields[k] = ND; sources[k] = ND
    return 200, {"schema": "rwa-exitability/v1", "asset": sym, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now or time.time())),
                 "dataset": {"version": DATA["version"], "revision": DATA["dataset_revision"], "generated_at": DATA["generated_at"]},
                 "fields": fields, "sources": sources, "confidence": confidence(n), "disclaimer": DISCLAIMER}
