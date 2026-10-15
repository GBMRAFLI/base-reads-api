// Byte-exact port of Python json.dumps(o, sort_keys=True, separators=(",", ":")) with ensure_ascii=True.
// Used for Ed25519 signing so Python- and Deno-signed facts are interchangeable.
function esc(s: string): string {
  let o = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) o += '\\"';
    else if (c === 0x5c) o += "\\\\";
    else if (c === 0x0a) o += "\\n";
    else if (c === 0x0d) o += "\\r";
    else if (c === 0x09) o += "\\t";
    else if (c === 0x08) o += "\\b";
    else if (c === 0x0c) o += "\\f";
    else if (c < 0x20 || c > 0x7e) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += s[i];
  }
  return o + '"';
}
function pyCodepointKey(a: string, b: string): number { // Python sorts str keys by code point
  const A = Array.from(a), B = Array.from(b);
  for (let i = 0; i < Math.min(A.length, B.length); i++) {
    const d = A[i].codePointAt(0)! - B[i].codePointAt(0)!; if (d) return d;
  }
  return A.length - B.length;
}
export function pyNum(n: number): string {
  if (!Number.isFinite(n)) throw new Error("non-finite number not allowed");
  return String(n); // facts carry only ints; floats would differ from Python repr (1.0 vs 1)
}
export function canonical(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return pyNum(v);
  if (typeof v === "string") return esc(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).filter((k) => o[k] !== undefined).sort(pyCodepointKey).map((k) => esc(k) + ":" + canonical(o[k])).join(",") + "}";
  }
  throw new Error("unsupported type");
}
// Python json.dumps(o) default (", " / ": " separators, ensure_ascii, insertion order) for response-body parity
export function pyDumps(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : String(v);
  if (typeof v === "string") return esc(v);
  if (Array.isArray(v)) return "[" + v.map(pyDumps).join(", ") + "]";
  const o = v as Record<string, unknown>;
  return "{" + Object.keys(o).filter((k) => o[k] !== undefined).map((k) => esc(k) + ": " + pyDumps(o[k])).join(", ") + "}";
}
