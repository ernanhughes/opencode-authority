// PEX-A1 instrument: adversarial battery conformance (mechanics only).
import { readFileSync, writeFileSync } from "node:fs";
import { evaluate } from "../src/engine/index.ts";

interface Case {
  id: string;
  want: string;
  policy: never;
  proposal: never;
}

const battery = JSON.parse(readFileSync(new URL("../tests/battery.json", import.meta.url), "utf-8")) as { cases: Case[]; now: string };
let correct = 0;
const misses: Array<{ id: string; want: string; got: string; reformulation?: string }> = [];
const falseAllows: string[] = [];
const byFamily: Record<string, { n: number; correct: number }> = {};

for (const c of battery.cases) {
  const receipt = evaluate(c.proposal, c.policy, { now: battery.now });
  const family = c.want;
  byFamily[family] ??= { n: 0, correct: 0 };
  byFamily[family].n++;
  if (receipt.verdict === c.want) {
    correct++;
    byFamily[family].correct++;
  } else {
    misses.push({ id: c.id, want: c.want, got: receipt.verdict, reformulation: receipt.reformulation });
    if (receipt.verdict === "ALLOW") falseAllows.push(c.id);
  }
}

const report = {
  battery: "authority-v0.1",
  n: battery.cases.length,
  correct,
  false_allows: falseAllows,
  by_expected_verdict: byFamily,
  misses,
  warning: "mechanics conformance only. Behavioural utility, hook enforcement, and open-world validity untested.",
};
writeFileSync(new URL("../eval-report.json", import.meta.url), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
if (misses.length > 0) process.exitCode = 1;
