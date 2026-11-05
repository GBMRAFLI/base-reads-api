// RWA Exitability Check: deterministic lookup over a versioned, source-cited dataset (spec/rwa-exitability-dataset.json).
// Zero LLM. Values are served only when the dataset has them with a source URL and retrieval time; otherwise "not_disclosed".
import { unquote } from "./util.ts";
import DATA from "../../spec/rwa-exitability-dataset.json" with { type: "json" };

export const RWA_PATH = "/rwa/exitability";
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
      let ok = false; try { ok = new URL(v.source_url).protocol === "https:"; } catch { /* invalid */ }
      if (!ok) e.push(`${sym}.${f}: source_url must be an https URL`);
      if (typeof v.retrieved_at !== "string" || !ISO.test(v.retrieved_at)) e.push(`${sym}.${f}: retrieved_at must be ISO-8601 UTC`);
    }
  }
  const lower = Object.keys(d.assets).map((s) => s.toLowerCase());
  if (new Set(lower).size !== lower.length) e.push("asset symbols must be unique case-insensitively");
  return e;
}

let DS: Dataset = DATA as Dataset;
/** Test hook: swap the dataset (validated). */
export function useDataset(d: Dataset) { const e = validateDataset(d); if (e.length) throw new Error("invalid dataset: " + e.join("; ")); DS = d; }
export const dataset = () => DS;
export const knownAssets = () => Object.keys(DS.assets);
/** Case-insensitive symbol lookup; returns the canonical symbol or null. */
export function resolveAsset(s: string): string | null {
  const t = s.trim().toLowerCase(); return knownAssets().find((k) => k.toLowerCase() === t) ?? null;
}
/** Pre-payment input check (pure computation). Missing asset is allowed through to the 402 (discovery probes call without input). */
export function rwaInputError(q: Record<string, string>): string | null {
  const a = q.asset; if (a === undefined || a === "") return null;
  return resolveAsset(unquote(a.replace(/\+/g, " "))) ? null : unknownMsg();
}
const unknownMsg = () => "unknown asset; supported: " + knownAssets().join(", ");

/** Deterministic confidence from coverage: share of fields with a cited value. */
export function confidence(n: number) {
  const r = n / RWA_FIELDS.length;
  return { level: n === 0 ? "none" : r < 0.5 ? "low" : r < 1 ? "medium" : "high", disclosed_fields: n, total_fields: RWA_FIELDS.length,
    basis: "share of fields with a cited public source; not a quality or risk rating" };
}

export function rwaHandle(q: Record<string, string>, now: Date = new Date()): [number, unknown] {
  const raw = q.asset === undefined ? "" : unquote(q.asset.replace(/\+/g, " "));
  if (!raw) return [400, { error: "give ?asset=<symbol>; supported: " + knownAssets().join(", ") }];
  const sym = resolveAsset(raw); if (!sym) return [400, { error: unknownMsg() }];
  const f = DS.assets[sym].fields; const fields: Record<string, unknown> = {}, sources: Record<string, unknown> = {}; let n = 0;
  for (const k of RWA_FIELDS) {
    const v = f[k];
    if (v) {
      fields[k] = v.value; n++;
      const o = v.onchain;
      sources[k] = o ? { url: v.source_url, retrieved_at: v.retrieved_at, onchain: { chain: o.chain, address: o.address, function: o.function, block: o.block } }
        : { url: v.source_url, retrieved_at: v.retrieved_at };
    }
    else { fields[k] = NOT_DISCLOSED; sources[k] = NOT_DISCLOSED; }
  }
  return [200, { schema: RWA_SCHEMA, asset: sym, checked_at: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
    dataset: { version: DS.version, revision: DS.dataset_revision, generated_at: DS.generated_at },
    fields, sources, confidence: confidence(n), disclaimer: RWA_DISCLAIMER }];
}
