// No-inference load check: tool surface constructs without OpenCode, models, or network.
import { authorityTools } from "../src/tools.ts";

const names = authorityTools().map((t) => t.name).sort();
const expected = ["authority_check", "authority_explain", "authority_health"];
if (JSON.stringify(names) !== JSON.stringify(expected)) {
  console.error(`tool surface mismatch: ${names.join(",")}`);
  process.exit(1);
}
const health = authorityTools().find((t) => t.name === "authority_health")!;
const result = (await health.execute({}, undefined as never)) as { content: string };
const parsed = JSON.parse(result.content) as { ok: boolean };
if (parsed.ok !== true) {
  console.error(`health check failed: ${result.content}`);
  process.exit(1);
}
console.log("authority load check ok: authority_check, authority_explain, authority_health");
