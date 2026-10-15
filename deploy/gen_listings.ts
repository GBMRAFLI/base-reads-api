// Regenerates deploy/listings.json from the code (routes, prices, descriptions) while keeping the
// hand-maintained fields (base_url, directories, ref values). Run: deno run -A deploy/gen_listings.ts [base_url]
import { ROUTES } from "../deno/lib/routes.ts";
import DISCOVERY from "../deno/lib/discovery.json" with { type: "json" };

const FILE = new URL("./listings.json", import.meta.url);
export function buildRoutes() {
  return Object.entries(ROUTES).map(([path, [amount, description]]) => ({
    path, method: "GET", price_usdc: (amount / 1e6).toFixed(3), amount_atomic: String(amount),
    query_params: Object.keys((DISCOVERY as Record<string, { params: Record<string, unknown> }>)[path]?.params ?? {}),
    description,
  }));
}
if (import.meta.main) {
  const cur = JSON.parse(await Deno.readTextFile(FILE));
  if (Deno.args[0]) {
    const u = Deno.args[0].replace(/\/+$/, "");
    if (!/^https:\/\/[a-z0-9.-]+$/.test(u)) { console.error("base_url must be https://<hostname>"); Deno.exit(2); }
    cur.base_url = u;
  }
  cur.routes = buildRoutes();
  const tmp = new URL("./listings.json.tmp", import.meta.url);
  await Deno.writeTextFile(tmp, JSON.stringify(cur, null, 2) + "\n");
  await Deno.rename(tmp, FILE);
}
