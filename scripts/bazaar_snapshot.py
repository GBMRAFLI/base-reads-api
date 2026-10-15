"""Daily Bazaar snapshot job (cron once/day). Stores a compact gzip index per UTC date.
Usage: python scripts/bazaar_snapshot.py [--from-file bazaar.json]"""
import gzip, json, os, sys, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import preflight as pf
U = os.environ.get("BAZAAR_URL", "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources") + "?limit=1000&offset=%d"
def crawl(max_pages=80):
    out, off = [], 0
    for _ in range(max_pages):
        for attempt in range(3):
            try: d = json.loads(urllib.request.urlopen(urllib.request.Request(U % off, headers={"User-Agent": pf.UA}), timeout=40).read()); break
            except Exception:
                if attempt == 2: raise
                time.sleep(3)
        it = d.get("items", []); out += it
        if len(it) < 1000: return out
        off += len(it); time.sleep(0.5)
    return out
def write(items, date=None, keep=60):
    date = date or time.strftime("%Y-%m-%d", time.gmtime())
    os.makedirs(pf.SNAP_DIR, exist_ok=True)
    p = os.path.join(pf.SNAP_DIR, date + ".index.json.gz"); tmp = p + ".tmp"
    with gzip.open(tmp, "wt") as f: json.dump(pf.build_index(items, date), f)
    os.replace(tmp, p)
    for old in pf.snapshot_dates()[:-keep]: os.remove(os.path.join(pf.SNAP_DIR, old + ".index.json.gz"))
    return p
if __name__ == "__main__":
    items = json.load(open(sys.argv[2])) if len(sys.argv) > 2 and sys.argv[1] == "--from-file" else crawl()
    print(write(items), len(items), "listings")
