import { assert, assertEquals } from "jsr:@std/assert@1";
import { useKv } from "../lib/store.ts";
import { ROUTES, related } from "../lib/routes.ts";
import { Chain } from "../lib/chain.ts";
import { latestOf, llmsTxt, snapshotSummary } from "../main.ts";

useKv(await Deno.openKv(":memory:"));
const env = (_k: string) => undefined;
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const rpc = (async (m: string) => m === "eth_getBlockByNumber" ? { number: "0x10", timestamp: "0x" + Math.floor(Date.now() / 1000).toString(16), baseFeePerGas: "0x1" }
  : m === "eth_call" ? "0x" + "0".repeat(63) + "5" : "0x1") as any;

Deno.test("prices: address-intel and preflight 0.010 USDC, others unchanged", () => {
  assertEquals(Object.fromEntries(Object.entries(ROUTES).map(([k, v]) => [k, v[0]])),
    { "/base/usdc-balance": 1000, "/base/tx-status": 2000, "/base/basename": 3000, "/base/address-intel": 10000, "/x402/preflight": 10000, "/base/network": 1000 });
});
Deno.test("related_routes on /base/network and /base/usdc-balance only, path and price only", async () => {
  const c = new Chain(rpc, USDC);
  const [, n]: any = await c.handle("/base/network", {});
  assertEquals(n.related_routes, [{ path: "/base/tx-status", price_usdc: "0.002" }, { path: "/x402/preflight", price_usdc: "0.010" }]);
  const [, b]: any = await c.handle("/base/usdc-balance", { address: "0x" + "ab".repeat(20) });
  assertEquals(b.related_routes, related("/base/usdc-balance"));
  assertEquals(b.related_routes, [{ path: "/base/address-intel", price_usdc: "0.010" }, { path: "/x402/preflight", price_usdc: "0.010" }]);
  for (const r of [...n.related_routes, ...b.related_routes]) assertEquals(Object.keys(r).sort(), ["path", "price_usdc"]);
});
Deno.test("llms.txt: facts-only framing and preflight usage pattern, no advice wording", () => {
  const t = llmsTxt(env); assert(t.includes("before every x402 payment")); assert(t.includes("no language model")); assert(t.includes("pinned to a block number"));
  assert(t.includes("/x402/preflight (0.010 USDC)")); assert(t.includes("/base/address-intel (0.010 USDC)"));
  for (const bad of ["buy now", "recommend", "best ", "guarantee"]) assert(!t.toLowerCase().includes(bad), bad);
});
Deno.test("/bazaar/snapshots publishes latest date, status, listing count and age", async () => {
  const s: any = await snapshotSummary(); assertEquals(Object.keys(s.latest).sort(), ["age_days", "date", "listings", "status"]);
  assertEquals(latestOf([]), { date: null, status: null, listings: 0, age_days: null });
  const now = Date.parse("2026-10-21T01:00:00Z");
  assertEquals(latestOf([{ date: "2026-10-20", status: "complete", resources: 26364 }], now), { date: "2026-10-20", status: "complete", listings: 26364, age_days: 1 });
  assertEquals(latestOf([{ date: "2026-10-21", status: "partial", resources: 3 }], now).age_days, 0);
});
