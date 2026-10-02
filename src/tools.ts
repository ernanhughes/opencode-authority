import type { Info as ToolInfo } from "@opencode/plugin/promise/tool";
import { evaluate } from "./engine/index.ts";
import { AuthorityError, type AuthorityPolicy, type AuthorityProposal } from "./engine/types.ts";
import { checkSchema, explainSchema, healthSchema, nativeInput, validateInput } from "./validation.ts";
import { requestHash } from "./boundary.ts";

export function AuthorityCheck(): ToolInfo {
  return {
    name: "authority_check",
    options: { codemode: false },
    description: "Evaluate a strictly validated proposal and policy. Returns ALLOW/DENY/REQUIRE_APPROVAL/REFORMULATE with a minimised receipt; it does not execute the proposed action or grant host permission.",
    input: nativeInput(checkSchema),
    async execute(input) {
      try {
        const args = validateInput(checkSchema, input);
        const receipt = evaluate(args.proposal as AuthorityProposal, args.policy as AuthorityPolicy, args.now ? { now: args.now } : {});
        return {
          content: JSON.stringify({ receipt }, null, 2),
          metadata: { schema: "opencode.authority_boundary.v1", stage: "AUTHORITY_DECIDED", received_sha256: requestHash(input), policy_sha256: requestHash(args.policy), receipt_id: receipt.receipt_id },
        };
      } catch (error) {
        if (error instanceof AuthorityError) return { content: JSON.stringify({ error: error.code, message: error.message }) };
        throw error;
      }
    },
  };
}

export function AuthorityExplain(): ToolInfo {
  return {
    name: "authority_explain",
    options: { codemode: false },
    description: "Re-state why a prior authority receipt decided as it did, including reformulation guidance. Never re-evaluates or grants permission.",
    input: nativeInput(explainSchema),
    async execute(input) {
      const r = validateInput(explainSchema, input).receipt;
      return { content: JSON.stringify({
        verdict: r.verdict, reformulation: r.reformulation ?? null,
        approval_required_by: r.approval_required_by ?? [],
        failing_checks: r.data_receipts.flatMap((d) => d.reasons.filter((x) => x.code !== "PURPOSE_UNAUTHORISED" || d.result !== "allowed").map((x) => ({ source: d.source_id, operation: d.operation, code: x.code, detail: x.detail }))),
      }) };
    },
  };
}

export function AuthorityHealth(): ToolInfo {
  return {
    name: "authority_health",
    options: { codemode: false },
    description: "Report authority evaluator readiness without evaluating policy, requesting host permission or exercising enforcement.",
    input: nativeInput(healthSchema),
    async execute(input) {
      validateInput(healthSchema, input);
      return { content: JSON.stringify({ ok: true, version: "0.1.0", verdicts: ["ALLOW", "DENY", "REQUIRE_APPROVAL", "REFORMULATE"], operations: ["ACCESS", "PROCESS", "INFER", "RETAIN", "REUSE", "DISCLOSE"], external: ["ACT", "SPEAK", "DISCOVER"] }) };
    },
  };
}

export function authorityTools(): ToolInfo[] {
  return [AuthorityCheck(), AuthorityExplain(), AuthorityHealth()];
}
