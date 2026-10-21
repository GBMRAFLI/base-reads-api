"""Free static report on the Python server: whitelist, content types, anchors, no 402, no traversal."""
import http.client, os, re, sys, threading, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_preflight  # noqa: F401  shared test env
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(R, "api")); sys.path.insert(0, os.path.join(R, "scripts"))
import index as IX, render_report as RR

class TReport(unittest.TestCase):
    @classmethod
    def setUpClass(c):
        c.srv = IX.ThreadingHTTPServer(("127.0.0.1", 18791), IX.handler); threading.Thread(target=c.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(c): c.srv.shutdown(); c.srv.server_close()
    def req(s, p, m="GET"):
        c = http.client.HTTPConnection("127.0.0.1", 18791); c.request(m, p); r = c.getresponse(); b = r.read(); c.close(); return r.status, dict(r.getheaders()), b
    def test_routes(self):
        want = {"/reports/state-of-x402-2026-10": "text/html", "/reports/state-of-x402-2026-10.md": "text/markdown",
                "/reports/data/aggregate_stats.csv": "text/csv", "/reports/data/liveness_sample_200.csv": "text/csv"}
        self.assertEqual(sorted(IX.REPORT_FILES), sorted(want))
        for p, ct in want.items():
            with self.subTest(p):
                st, hd, b = self.req(p); self.assertEqual(st, 200); self.assertTrue(hd["Content-Type"].startswith(ct + ";"))
                self.assertNotIn("PAYMENT-REQUIRED", hd); self.assertIn(p, IX.FREE_PATHS); self.assertNotIn(p, IX.ROUTES)
                self.assertIn("default-src 'none'", hd["Content-Security-Policy"]); self.assertEqual(b, IX.REPORT_BYTES[p])
    def test_anchors_and_links(self):
        h = self.req("/reports/state-of-x402-2026-10")[2].decode()
        ids = re.findall(r' id="([^"]+)"', h); self.assertEqual(len(ids), len(set(ids)))
        for a in ("method", "m1", "m2", "m3", "m4"): self.assertIn(a, ids)
        for u in re.findall(r'href="([^"]+)"', h):
            if u.startswith("#"): self.assertIn(u[1:], ids)
            else: self.assertIn(u, IX.FREE_PATHS)
    def test_404_and_traversal(self):
        for p in ("/reports/data/listings_summary.csv", "/reports/data/", "/reports/data/../../api/index.py", "/reports/data/%2e%2e/%2e%2e/api/index.py",
                  "/reports/data/..%2f..%2fapi%2findex.py", "/reports/_internal_raw/x.csv", "/reports/state-of-x402-2026-10.html", "/static/reports/data/aggregate_stats.csv"):
            with self.subTest(p): self.assertEqual(self.req(p)[0], 404)
    def test_html_is_current(self):
        md = open(os.path.join(R, "static", "reports", "state-of-x402-2026-10.md"), encoding="utf-8").read()
        self.assertEqual(RR.render(md).encode(), IX.REPORT_BYTES["/reports/state-of-x402-2026-10"])
        self.assertNotIn("[REPORT_URL]", md); self.assertNotIn("[DATA_URL]", md)
    def test_renderer_escapes(self):
        h = RR.render("# T\n\n<script>x</script> [a](javascript:x)".replace(" [a](javascript:x)", ""))
        self.assertNotIn("<script>", h); self.assertIn("&lt;script&gt;", h)
        with self.assertRaises(SystemExit): RR.render("# T\n\n[a](javascript:alert(1))")
        for bad in ("//evil.com", "//evil.com/x", "http://evil.com", "data:text/html,x"):
            with self.subTest(bad), self.assertRaises(SystemExit): RR.render("# T\n\n[a](%s)" % bad)
        self.assertIn('href="/reports/x"', RR.render("# T\n\n[a](/reports/x)"))

if __name__ == "__main__": unittest.main()
