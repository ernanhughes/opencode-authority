import { z } from "zod";
import { AuthorityError, type AuthorityFailureCode } from "./engine/types.ts";

const text = z.string().min(1);
const strings = z.array(z.string());
// The evaluator compares clocks lexically; ambiguous/noncanonical clocks fail closed.
export const clockSchema = z.iso.datetime({ precision: 3 });
const operations = z.enum(["ACCESS", "PROCESS", "INFER", "RETAIN", "REUSE", "DISCLOSE"]);
const verdicts = z.enum(["ALLOW", "DENY", "REQUIRE_APPROVAL", "REFORMULATE"]);
const speechActs = z.enum(["INFORM", "ASSERT", "REQUEST", "OFFER", "NEGOTIATE", "ACCEPT", "PROMISE"]);
const approval = z.enum(["none", "required"]);

export const proposalSchema = z.strictObject({
  proposal_id: text, purpose: text,
  external_operation: z.strictObject({
    kind: z.enum(["ACT", "SPEAK", "DISCOVER"]), action: text,
    target: z.string().optional(), counterparty: z.string().optional(),
    speech_act: speechActs.optional(), audience: z.string().optional(),
    topics: strings.optional(), predicate: z.string().optional(),
  }).optional(),
  data_uses: z.array(z.strictObject({
    source: z.strictObject({ id: text, kind: z.string().optional(), uri: z.string().optional(), scope: z.string().optional() }),
    operation: operations, necessary: z.boolean().optional(), recipient: z.string().optional(),
    derivative: z.string().optional(), third_party: z.boolean().optional(),
  })),
  required_inputs: strings.optional(), irreversible_effects: strings.optional(), requested_at: clockSchema.optional(),
});

const grant = { id: text, purpose: text, expires_at: clockSchema.optional() };
export const policySchema = z.strictObject({
  version: text,
  data_use: z.array(z.strictObject({
    ...grant, data_scope: strings, permitted_operations: z.array(operations), recipients: strings.optional(),
    retention: z.string().optional(), derivative_policy: z.string().optional(), third_party_allowed: z.boolean().optional(),
  })),
  actions: z.array(z.strictObject({
    ...grant, action_scope: strings, targets: strings.optional(), consequence_limit: z.string().optional(), approval,
  })),
  speech: z.array(z.strictObject({
    ...grant, audience_scope: strings.optional(), topic_scope: strings.optional(), permitted_acts: z.array(speechActs).optional(),
    disclosure_scope: strings.optional(), approval,
  })).optional(),
  discovery: z.array(z.strictObject({ ...grant, permitted_predicates: strings, approval })).optional(),
  revoked: z.array(z.strictObject({ id: text, revoked_at: clockSchema })).optional(),
  forbidden_combinations: z.array(strings).optional(),
});

export const checkSchema = z.strictObject({ proposal: proposalSchema, policy: policySchema, now: clockSchema.optional() });
export const canarySchema = z.strictObject({ marker: text, target: text, context_sources: strings.optional() });
export const healthSchema = z.strictObject({});

const checkResult = z.strictObject({ ok: z.boolean(), code: text, detail: z.string(), grant_id: text.optional() });
export const receiptSchema = z.strictObject({
  receipt_id: text, proposal_id: text, purpose: text, verdict: verdicts,
  data_receipts: z.array(z.strictObject({
    source_id: text, operation: operations, result: z.enum(["allowed", "denied", "approval_required"]), reasons: z.array(checkResult),
  })),
  action_result: checkResult.optional(), reformulation: z.string().optional(), approval_required_by: strings.optional(),
  revocation_active: z.boolean(), composed_scopes: strings, irreversible_effects: strings, policy_version: text,
});
export const explainSchema = z.strictObject({ receipt: receiptSchema });

/** Validate without coercion, projection or replacing the caller's representation. */
export function validateInput<S extends z.ZodType>(schema: S, input: unknown, code: AuthorityFailureCode = "PROPOSAL_INVALID"): z.output<S> {
  const result = schema.safeParse(input);
  if (!result.success) {
    const first = result.error.issues[0];
    const failureCode = first.path[0] === "policy" ? "POLICY_INVALID" : code;
    throw new AuthorityError(failureCode, `${first.path.join(".") || "input"}: ${first.message}`);
  }
  return input as z.output<S>;
}

/** Both native routes decode the catalog schema before this validator.
 * An untyped object transport preserves values for strict rejection here.
 * Tools also opt out of Code Mode, whose interpreter changes escaped strings. */
export function nativeInput<S extends z.ZodType>(schema: S) {
  const json = z.toJSONSchema(schema);
  const transport = { type: "object", additionalProperties: true };
  return Object.defineProperty(json, "~standard", {
    enumerable: false,
    value: {
      version: 1 as const, vendor: "opencode-authority",
      validate(value: unknown) {
        const result = schema.safeParse(value);
        return result.success ? { value } : { issues: result.error.issues };
      },
      jsonSchema: { input: () => transport, output: () => json },
    },
  });
}
