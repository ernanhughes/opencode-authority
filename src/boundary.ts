import { createHash } from "node:crypto";

/** Hash JSON with sorted object keys, retaining array order and all values. */
export function requestHash(value: unknown): string {
  const stable = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(stable);
    if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, item]) => [k, stable(item)]));
    return v;
  };
  return createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
}
