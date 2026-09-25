import type { Info as ToolInfo } from "@opencode/plugin/promise/tool";
import { evaluate } from "./engine/index.ts";
import { AuthorityError, type AuthorityPolicy, type AuthorityProposal } from "./engine/types.ts";

const proposalSchema = {
  type: "object",
  properties: {
    proposal_id: { type: "string", minLength: 1 },
    purpose: { type: "string", minLength: 1 },
    external_operation: {
      type: "object",
      properties: {
        kind: { type: "string", enum: ["ACT", "SPEAK", "DISCOVER"] },
        action: { type: "string", minLength: 1 },
        target: { type: "string" },
        counterparty: { type: "string" },
        speech_act: { type: "string", enum: ["INFORM", "ASSERT", "REQUEST", "OFFER", "NEGOTIATE", "ACCEPT", "PROMISE"] },
        audience: { type: "string" },
        topics: { type: "array", items: { type: "string" } },
        predicate: { type: "string" },
      },
      required: ["kind", "action"],
      additionalProperties: false,
    },
    data_uses: {
      type: "array",
      items: {
        type: "object",
        properties: {
          source: {
            type: "object",
            properties: { id: { type: "string", minLength: 1 }, kind: { type: "string" } },
            required: ["id"],
            additionalProperties: false,
          },
          operation: { type: "string", enum: ["ACCESS", "PROCESS", "INFER", "RETAIN", "REUSE", "DISCLOSE"] },
          necessary: { type: "boolean" },
          recipient: { type: "string" },
          derivative: { type: "string" },
          third_party: { type: "boolean" },
        },
        required: ["source", "operation"],
        additionalProperties: false,
      },
    },
    required_inputs: { type: "array", items: { type: "string" } },
    irreversible_effects: { type: "array", items: { type: "string" } },
    requested_at: { type: "string" },
  },
  required: ["proposal_id", "purpose", "data_uses"],
  additionalProperties: false,
} as const;

const policySchema = {
  type: "object",
  properties: {
    version: { type: "string", minLength: 1 },
    data_use: { type: "array", items: { type: "object" } },
    actions: { type: "array", items: { type: "object" } },
    speech: { type: "array", items: { type: "object" } },
    discovery: { type: "array", items: { type: "object" } },
    revoked: { type: "array", items: { type: "object" } },
    forbidden_combinations: { type: "array", items: { type: "array", items: { type: "string" } } },
  },
  required: ["version", "data_use", "actions"],
  additionalProperties: false,
} as const;

export function AuthorityCheck(): ToolInfo {
  return {
    name: "authority_check",
    description: "Evaluate whether a proposed operation may proceed with the proposed information for the declared purpose. Returns ALLOW/DENY/REQUIRE_APPROVAL/REFORMULATE with a minimised receipt. Deterministic; confidence never grants.",
    input: {
      type: "object",
      properties: { proposal: proposalSchema, policy: policySchema, now: { type: "string" } },
      required: ["proposal", "policy"],
      additionalProperties: false,
    },
    async execute(input) {
      const args = input as { proposal: AuthorityProposal; policy: AuthorityPolicy; now?: string };
      try {
        const receipt = evaluate(args.proposal, args.policy, args.now ? { now: args.now } : {});
        return { content: JSON.stringify({ receipt }, null, 2) };
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
    description: "Re-state why a prior authority receipt decided as it did, including reformulation guidance. Never re-evaluates.",
    input: {
      type: "object",
      properties: { receipt: { type: "object" } },
      required: ["receipt"],
      additionalProperties: false,
    },
    async execute(input) {
      const args = input as {
        receipt: { verdict: string; reformulation?: string; approval_required_by?: string[]; data_receipts: Array<{ source_id: string; operation: string; result: string; reasons: Array<{ code: string; detail: string }> }> };
      };
      const r = args.receipt;
      return {
        content: JSON.stringify({
          verdict: r.verdict,
          reformulation: r.reformulation ?? null,
          approval_required_by: r.approval_required_by ?? [],
          failing_checks: r.data_receipts.flatMap((d) => d.reasons.filter((x) => x.code !== "PURPOSE_UNAUTHORISED" || d.result !== "allowed").map((x) => ({ source: d.source_id, operation: d.operation, code: x.code, detail: x.detail }))),
        }),
      };
    },
  };
}

export function AuthorityHealth(): ToolInfo {
  return {
    name: "authority_health",
    description: "Report authority readiness without evaluating anything.",
    input: { type: "object", properties: {}, additionalProperties: false },
    async execute() {
      return { content: JSON.stringify({ ok: true, version: "0.1.0", verdicts: ["ALLOW", "DENY", "REQUIRE_APPROVAL", "REFORMULATE"], operations: ["ACCESS", "PROCESS", "INFER", "RETAIN", "REUSE", "DISCLOSE"], external: ["ACT", "SPEAK", "DISCOVER"] }) };
    },
  };
}

export function authorityTools(): ToolInfo[] {
  return [AuthorityCheck(), AuthorityExplain(), AuthorityHealth()];
}
