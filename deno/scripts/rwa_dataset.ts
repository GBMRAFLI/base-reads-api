// RWA exitability dataset tool. Zero LLM, no network.
//   deno run -A scripts/rwa_dataset.ts validate [file]          check spec/rwa-exitability-dataset.json (exit 1 on problems)
//   deno run -A scripts/rwa_dataset.ts build <source_dir> [out] rebuild it from per-asset source files
// Source files: <source_dir>/<SYMBOL>.json, each { "asset", "fields": { "<field>": { "value", "source_url", "retrieved_at",
//   [confidence], [refresh_method], [onchain: { chain, address, function | selector, block, result }] } } }.
// value null = no public source: the field is dropped and served as not_disclosed. Only entries with a non-empty value, an
// https source_url and an ISO-8601 UTC retrieved_at are kept. An onchain citation is reduced to { chain, address, function,
// block }; if present but incomplete the entry is dropped. All other keys (per-field confidence, refresh_method, raw result,
// notes) are ignored and never shipped. Nothing is filled in or inferred.
import { DATASET_VERSION, NOT_DISCLOSED, onchainErrors, RWA_FIELDS, validateDataset } from "../lib/rwa.ts";
import type { Onchain } from "../lib/rwa.ts";

const DEFAULT = new URL("../../spec/rwa-exitability-dataset.json", import.meta.url).pathname;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
/** Reduce a source onchain object to the shipped citation keys; null if it does not form a valid citation. */
export function sanitizeOnchain(o: any): Onchain | null {
  if (!o || typeof o !== "object" || Array.isArray(o)) return null;
  const fn = o.function ?? o.selector; const b = typeof o.block === "string" && /^\d{1,15}$/.test(o.block) ? Number(o.block) : o.block;
  const c: Onchain = { chain: typeof o.chain === "string" ? o.chain.trim().toLowerCase() : o.chain, address: o.address, function: typeof fn === "string" ? fn.trim() : fn, block: b };
  return onchainErrors(c).length ? null : c;
}
const https = (u: unknown) => { try { return typeof u === "string" && new URL(u).protocol === "https:"; } catch { return false; } };

export function buildFrom(sources: { asset: string; fields?: Record<string, any> }[], prev: { dataset_revision?: number } | null, now: Date, symbols: string[]) {
  const assets: Record<string, { fields: Record<string, unknown> }> = {}; const dropped: string[] = [];
  for (const s of symbols) assets[s] = { fields: {} };
  for (const src of sources) {
    const sym = symbols.find((k) => k.toLowerCase() === String(src.asset ?? "").toLowerCase());
    if (!sym) { dropped.push(`${src.asset}: not in the supported asset list`); continue; }
    for (const [f, v] of Object.entries(src.fields ?? {})) {
      if (!(RWA_FIELDS as readonly string[]).includes(f)) { dropped.push(`${sym}.${f}: unknown field`); continue; }
      const ok = v && v.value !== undefined && v.value !== null && v.value !== "" && v.value !== NOT_DISCLOSED && https(v.source_url) && typeof v.retrieved_at === "string" && ISO.test(v.retrieved_at);
      if (v && v.value === null) { dropped.push(`${sym}.${f}: no public source (value null)`); continue; }
      if (!ok) { dropped.push(`${sym}.${f}: missing value, https source_url or retrieved_at`); continue; }
      const entry: Record<string, unknown> = { value: v.value, source_url: v.source_url, retrieved_at: v.retrieved_at };
      if (v.onchain !== undefined && v.onchain !== null) {
        const o = sanitizeOnchain(v.onchain);
        if (!o) { dropped.push(`${sym}.${f}: onchain citation needs chain, address, function or selector, block`); continue; }
        entry.onchain = o;
      }
      assets[sym].fields[f] = entry;
    }
  }
  const out = { version: DATASET_VERSION, dataset_revision: (prev?.dataset_revision ?? 0) + 1, generated_at: now.toISOString().replace(/\.\d{3}Z$/, "Z"), assets };
  return { out, dropped };
}

if (import.meta.main) {
  const [cmd, a1, a2] = Deno.args;
  if (cmd === "validate") {
    const e = validateDataset(JSON.parse(await Deno.readTextFile(a1 ?? DEFAULT)));
    if (e.length) { console.error(e.join("\n")); Deno.exit(1); } console.log("ok");
  } else if (cmd === "build" && a1) {
    const outFile = a2 ?? DEFAULT; let prev: any = null; try { prev = JSON.parse(await Deno.readTextFile(outFile)); } catch { /* first build */ }
    const symbols = prev ? Object.keys(prev.assets) : ["JAAA", "USYC", "mWIN"]; const srcs = [];
    for await (const f of Deno.readDir(a1)) if (f.isFile && f.name.endsWith(".json")) srcs.push(JSON.parse(await Deno.readTextFile(a1 + "/" + f.name)));
    const { out, dropped } = buildFrom(srcs, prev, new Date(), symbols);
    const e = validateDataset(out); if (e.length) { console.error(e.join("\n")); Deno.exit(1); }
    await Deno.writeTextFile(outFile, JSON.stringify(out, null, 1) + "\n");
    for (const d of dropped) console.log("dropped (served as not_disclosed): " + d);
    for (const [s, a] of Object.entries(out.assets)) console.log(`${s}: ${Object.keys(a.fields).length}/${RWA_FIELDS.length} fields with a source`);
  } else { console.error("usage: rwa_dataset.ts validate [file] | build <source_dir> [out]"); Deno.exit(2); }
}
