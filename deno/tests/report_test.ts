// Free static report: exact whitelist, correct types, anchors, no 402, no traversal.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { FREE_PATHS, handler, REPORT_FILES } from "../main.ts";
import { ROUTES } from "../lib/routes.ts";
const P = JSON.parse(Deno.readTextFileSync(new URL("./fixtures/py_signed.json", import.meta.url)));
const E: Record<string, string> = { SIGNING_KEY_PASSPHRASE: P.passphrase, SIGNING_KEY_ENC_B64: P.enc_b64, PUBLIC_URL: "https://h.example/" };
const env = (x: string) => E[x];
const get = (p: string, method = "GET") => handler(new Request("http://h.example" + p, { method }), { env });

Deno.test("report routes: 200, content-type, free (no 402 / payment headers), CSP", async () => {
  const want: Record<string, string> = { "/reports/state-of-x402-2026-10": "text/html", "/reports/state-of-x402-2026-10.md": "text/markdown",
    "/reports/data/aggregate_stats.csv": "text/csv", "/reports/data/liveness_sample_200.csv": "text/csv" };
  assertEquals(Object.keys(REPORT_FILES).sort(), Object.keys(want).sort());
  for (const [p, ct] of Object.entries(want)) {
    const r = await get(p); await r.arrayBuffer();
    assertEquals(r.status, 200, p); assert(r.headers.get("Content-Type")!.startsWith(ct + ";"), p);
    assert(!r.headers.has("PAYMENT-REQUIRED"), p); assert(FREE_PATHS.has(p), p); assert(!(p in ROUTES), p);
    assert(r.headers.get("Content-Security-Policy")!.includes("default-src 'none'"), p);
  }
});
Deno.test("report HTML: anchors #method and #m1..#m4 exist and every in-page link resolves; data links point at served files", async () => {
  const h = await (await get("/reports/state-of-x402-2026-10")).text();
  const ids = new Set([...h.matchAll(/ id="([^"]+)"/g)].map((m) => m[1]));
  for (const a of ["method", "m1", "m2", "m3", "m4"]) assert(ids.has(a), a);
  assertEquals([...h.matchAll(/ id="([^"]+)"/g)].length, ids.size, "no duplicate ids");
  for (const m of h.matchAll(/href="([^"]+)"/g)) {
    const u = m[1];
    if (u.startsWith("#")) assert(ids.has(u.slice(1)), u);
    else { assert(u.startsWith("/"), u); assert(FREE_PATHS.has(u), u); }
  }
  assert(!h.includes("[REPORT_URL]") && !h.includes("[DATA_URL]") && !h.includes("<script"));
});
Deno.test("report: unknown files 404, traversal refused, other methods not served", async () => {
  for (const p of ["/reports/data/listings_summary.csv", "/reports/data/", "/reports/data/../../deno/main.ts", "/reports/data/%2e%2e/%2e%2e/deno/main.ts",
    "/reports/data/..%2f..%2fdeno%2fmain.ts", "/reports/_internal_raw/x.csv", "/reports/state-of-x402-2026-10.html", "/static/reports/data/aggregate_stats.csv", "/reports/data/aggregate_stats.csv/"]) {
    const r = await get(p); await r.body?.cancel(); assertEquals(r.status, 404, p);
  }
  const h = await get("/reports/data/aggregate_stats.csv", "HEAD"); assertEquals([h.status, h.body], [200, null]);
  const po = await get("/reports/data/aggregate_stats.csv", "POST"); await po.body?.cancel(); assertEquals(po.status, 501);
});
Deno.test("served report bytes equal the Python renderer output (HTML is generated from the .md)", async () => {
  const out = new Deno.Command("python3", { args: ["-c", "import sys;sys.path.insert(0,'../scripts');import render_report as R;sys.stdout.write(R.render(open('../static/reports/state-of-x402-2026-10.md',encoding='utf-8').read()))"], stdout: "piped" }).outputSync();
  assertEquals(new TextDecoder().decode(out.stdout), await (await get("/reports/state-of-x402-2026-10")).text());
});
