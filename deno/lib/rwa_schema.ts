// RWA exitability dataset schema and validation (pure, no dataset import), shared by the server and scripts/rwa_dataset.ts,
// so the build tool still runs when the shipped dataset is invalid.
export const RWA_SCHEMA = "rwa-exitability/v1";
export const DATASET_VERSION = "rwa-exitability-dataset/1";
export const NOT_DISCLOSED = "not_disclosed";
/** Field order is part of the response contract. */
export const RWA_FIELDS = ["transfer_eligibility", "nav_freshness", "redemption_path", "redemption_timing", "instant_capacity", "pause_freeze"] as const;
export type RwaField = typeof RWA_FIELDS[number];
export const RWA_DISCLAIMER = "Reported facts from cited public sources at the stated retrieval times. Not a liquidity guarantee, not a redemption promise, and not investment advice. Fields marked not_disclosed had no cited source in this dataset revision.";

export type Onchain = { chain: string; address: string; function: string; block: number };
type Entry = { value: unknown; source_url: string; retrieved_at: string; onchain?: Onchain };
export type Dataset = { version: string; dataset_revision: number; generated_at: string; assets: Record<string, { fields: Partial<Record<RwaField, Entry>> }> };

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const SYM = /^[A-Za-z0-9]{1,16}$/;
export const CHAIN_RE = /^[a-z0-9-]{1,32}$/;
export const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
/** Function signature like "paused()", up to 4 signatures joined by "/" for a value read from several calls, or a 4-byte selector. */
const SIG = "[A-Za-z_][A-Za-z0-9_]{0,63}\\([A-Za-z0-9_,\\[\\] ]{0,200}\\)";
export const FN_RE = new RegExp(`^(${SIG}(/${SIG}){0,3}|0x[0-9a-fA-F]{8})$`);
/** Internal path fragments that must never appear in a shipped source URL. */
export const INTERNAL_PATH_RE = /\/(workspace|home|root|opt|etc|var|tmp|srv|mnt|usr)(\/|$)|file:|~\//i;
/** True when the URL has a backslash, does not percent-decode cleanly, or (after decoding until stable, max 5 rounds)
 * contains an internal path fragment. */
export function hasInternalPath(u: string): boolean {
  let cur = u;
  for (let i = 0; i < 5; i++) {
    if (cur.includes("\\") || INTERNAL_PATH_RE.test(cur)) return true;
    let next: string; try { next = decodeURIComponent(cur); } catch { return true; }
    if (next === cur) return false; cur = next;
  }
  return true; // still changing after 5 rounds: reject
}
/** https, no user:pass@ userinfo, no internal path fragment (also when percent-encoded), no backslash. */
export function publicHttps(u: unknown): boolean {
  if (typeof u !== "string" || hasInternalPath(u)) return false;
  try { const x = new URL(u); return x.protocol === "https:" && !x.username && !x.password && !!x.hostname; } catch { return false; }
}
/** Block explorers accepted for on-chain citations (exact hostname match). */
export const EXPLORER_HOSTS: readonly string[] = ["etherscan.io", "basescan.org"];
/** True when the URL is an https address page on an allowlisted explorer for exactly this contract. */
export function explorerFor(u: string, address: unknown): boolean {
  let x: URL; try { x = new URL(u); } catch { return false; }
  if (x.protocol !== "https:" || !EXPLORER_HOSTS.includes(x.hostname.toLowerCase())) return false;
  const m = /^\/address\/(0x[0-9a-fA-F]{40})\/?$/.exec(x.pathname);
  return !!m && typeof address === "string" && m[1].toLowerCase() === address.toLowerCase();
}
/** Problems with a sanitized on-chain citation (empty = valid). */
export function onchainErrors(o: any): string[] {
  if (!o || typeof o !== "object" || Array.isArray(o) || Object.keys(o).sort().join(",") !== "address,block,chain,function") return ["onchain must have exactly chain, address, function, block"];
  const e: string[] = [];
  if (typeof o.chain !== "string" || !CHAIN_RE.test(o.chain)) e.push("onchain.chain must be a lowercase chain name");
  if (typeof o.address !== "string" || !ADDR_RE.test(o.address)) e.push("onchain.address must be a 0x 20-byte address");
  if (typeof o.function !== "string" || !FN_RE.test(o.function)) e.push("onchain.function must be a signature or 4-byte selector");
  if (!Number.isSafeInteger(o.block) || o.block < 1) e.push("onchain.block must be a positive integer");
  return e;
}
/** Structural validation; returns a list of problems (empty = valid). Used by tests and scripts/rwa_dataset.ts. */
export function validateDataset(d: any): string[] {
  const e: string[] = [];
  if (!d || typeof d !== "object") return ["dataset is not an object"];
  const top = Object.keys(d).sort().join(",");
  if (top !== "assets,dataset_revision,generated_at,version") e.push("top-level keys must be version, dataset_revision, generated_at, assets");
  if (d.version !== DATASET_VERSION) e.push("version must be " + DATASET_VERSION);
  if (!Number.isInteger(d.dataset_revision) || d.dataset_revision < 1) e.push("dataset_revision must be a positive integer");
  if (typeof d.generated_at !== "string" || !ISO.test(d.generated_at)) e.push("generated_at must be ISO-8601 UTC");
  if (!d.assets || typeof d.assets !== "object" || Array.isArray(d.assets)) return [...e, "assets must be an object"];
  for (const [sym, a] of Object.entries<any>(d.assets)) {
    if (!SYM.test(sym)) e.push(`${sym}: symbol must be 1-16 letters or digits`);
    if (!a || typeof a !== "object" || Object.keys(a).join(",") !== "fields" || typeof a.fields !== "object" || Array.isArray(a.fields)) { e.push(`${sym}: must be { fields: {...} }`); continue; }
    for (const [f, v] of Object.entries<any>(a.fields)) {
      if (!(RWA_FIELDS as readonly string[]).includes(f)) { e.push(`${sym}.${f}: unknown field`); continue; }
      const ks = v && typeof v === "object" ? Object.keys(v).sort().join(",") : "";
      if (ks !== "retrieved_at,source_url,value" && ks !== "onchain,retrieved_at,source_url,value") { e.push(`${sym}.${f}: must have exactly value, source_url, retrieved_at and optionally onchain`); continue; }
      if ("onchain" in v) for (const m of onchainErrors(v.onchain)) e.push(`${sym}.${f}: ${m}`);
      if (v.value === null || v.value === undefined || v.value === "" || v.value === NOT_DISCLOSED) e.push(`${sym}.${f}: empty value (omit the field instead)`);
      if (!publicHttps(v.source_url)) e.push(`${sym}.${f}: source_url must be a public https URL (no userinfo, no internal path)`);
      else if (v.onchain && !explorerFor(v.source_url, v.onchain.address)) e.push(`${sym}.${f}: onchain needs source_url to be the explorer page of onchain.address`);
      if (typeof v.retrieved_at !== "string" || !ISO.test(v.retrieved_at)) e.push(`${sym}.${f}: retrieved_at must be ISO-8601 UTC`);
    }
  }
  const lower = Object.keys(d.assets).map((s) => s.toLowerCase());
  if (new Set(lower).size !== lower.length) e.push("asset symbols must be unique case-insensitively");
  return e;
}

