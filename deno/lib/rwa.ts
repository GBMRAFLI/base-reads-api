// RWA Exitability Check: deterministic lookup over a versioned, source-cited dataset (spec/rwa-exitability-dataset.json).
// Zero LLM. Values are served only when the dataset has them with a source URL and retrieval time; otherwise "not_disclosed".
import { unquote } from "./util.ts";
import DATA from "../../spec/rwa-exitability-dataset.json" with { type: "json" };

export const RWA_PATH = "/rwa/exitability";
export * from "./rwa_schema.ts";
import { NOT_DISCLOSED, RWA_DISCLAIMER, RWA_FIELDS, RWA_SCHEMA, validateDataset } from "./rwa_schema.ts";
import type { Dataset } from "./rwa_schema.ts";
/** Validate a dataset or throw. Called on the shipped file at module load, so an invalid dataset fails startup
 * (the process never listens, the deploy /healthz check fails and the release is rolled back). */
export function loadDataset(d: unknown): Dataset { const e = validateDataset(d); if (e.length) throw new Error("invalid dataset: " + e.join("; ")); return d as Dataset; }
let DS: Dataset = loadDataset(DATA);
/** Test hook: swap the dataset (validated). */
export function useDataset(d: Dataset) { DS = loadDataset(d); }
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
