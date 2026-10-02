import { it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { AuthorityCheck, AuthorityExplain, AuthorityHealth } from "../src/tools.ts";
import { evaluate } from "../src/engine/index.ts";
import { checkSchema, nativeInput } from "../src/validation.ts";
import { AuthorityError } from "../src/engine/types.ts";

const policy = JSON.parse(readFileSync(new URL("../examples/policy.json", import.meta.url), "utf8"));
const proposal = {
  proposal_id: "strict-input", purpose: "book-travel",
  external_operation: { kind: "ACT", action: "search-flights" },
  data_uses: [{ source: { id: "calendar:travel-window", kind: "calendar" }, operation: "ACCESS", necessary: true }],
};
const valid = () => structuredClone({ proposal, policy, now: "2026-10-02T12:00:00.000Z" }) as any;
const malformed: Array<[string, (v: any) => void]> = [
  ["unexpected envelope field", (v) => { v.unexpected = true; }],
  ["Wave 1 metadata", (v) => { v.policy.example_expected_rule = "must-reject"; }],
  ["unexpected proposal field", (v) => { v.proposal.override = true; }],
  ["unexpected operation field", (v) => { v.proposal.external_operation.approved = true; }],
  ["unexpected source field", (v) => { v.proposal.data_uses[0].source.trusted = true; }],
  ["missing purpose", (v) => { delete v.proposal.purpose; }],
  ["invalid external kind", (v) => { v.proposal.external_operation.kind = "RUN"; }],
  ["invalid data operation", (v) => { v.proposal.data_uses[0].operation = "READ"; }],
  ["wrong necessity type", (v) => { v.proposal.data_uses[0].necessary = "false"; }],
  ["permissive wrong necessity type", (v) => { v.proposal.data_uses[0].necessary = "true"; }],
  ["wrong third-party type", (v) => { v.proposal.data_uses[0].third_party = "true"; }],
  ["null nested grant", (v) => { v.policy.actions[0] = null; }],
  ["missing nested scope", (v) => { delete v.policy.actions[0].action_scope; }],
  ["invalid approval", (v) => { v.policy.actions[0].approval = "auto"; }],
  ["wrong scope type", (v) => { v.policy.data_use[0].data_scope = "*"; }],
  ["unexpected grant field", (v) => { v.policy.actions[0].override = true; }],
  ["malformed speech grant", (v) => { v.policy.speech = [{ id: "s", purpose: "book-travel", approval: "auto" }]; }],
  ["malformed discovery grant", (v) => { v.policy.discovery = [{ id: "d", purpose: "book-travel", approval: "none", permitted_predicates: 1 }]; }],
  ["malformed revocation", (v) => { v.policy.revoked = [{ id: "s" }]; }],
  ["malformed combination", (v) => { v.policy.forbidden_combinations = [[true]]; }],
  ["ambiguous expiry", (v) => { v.policy.actions[0].expires_at = "tomorrow"; }],
  ["noncanonical clock", (v) => { v.now = "2026-10-02T13:00:00+01:00"; }],
];

for (const [name, change] of malformed) void it(`strict boundary rejects ${name} without a decision`, async () => {
  const input = valid(); change(input);
  const before = structuredClone(input);
  const tool = AuthorityCheck();
  const schema = tool.input as ReturnType<typeof nativeInput> & { "~standard": { validate: (v: unknown) => any } };
  let callbackEntered = false;
  const validation = schema["~standard"].validate(input);
  if (!validation.issues) { callbackEntered = true; await tool.execute(validation.value, undefined as never); }
  assert.ok(validation.issues?.length);
  assert.equal(callbackEntered, false);
  // Direct invocation bypasses host admission but must still emit no ALLOW/receipt.
  const direct = JSON.parse((await tool.execute(input, undefined as never)).content as string);
  assert.ok(["POLICY_INVALID", "PROPOSAL_INVALID"].includes(direct.error));
  assert.equal(direct.receipt, undefined);
  if (name !== "unexpected envelope field" && name !== "noncanonical clock") {
    assert.throws(() => evaluate(input.proposal, input.policy, { now: input.now }), AuthorityError);
  }
  assert.deepEqual(input, before);
});

void it("native transport preserves unknown values while canonical validation stays closed", () => {
  const input = valid();
  const schema = nativeInput(checkSchema) as any;
  assert.strictEqual(schema["~standard"].validate(input).value, input);
  assert.equal(schema.additionalProperties, false);
  const transport = schema["~standard"].jsonSchema.input({ target: "draft-2020-12" });
  assert.deepEqual(transport, { type: "object", additionalProperties: true });
  assert.equal(AuthorityCheck().options?.codemode, false);
  assert.equal(AuthorityExplain().options?.codemode, false);
  assert.equal(AuthorityHealth().options?.codemode, false);
  assert.strictEqual(schema["~standard"].jsonSchema.output({ target: "draft-2020-12" }), schema);
});

void it("unknown action is schema-valid and denied by policy, not a validation failure", async () => {
  const input = valid(); input.proposal.external_operation.action = "ungranted-action";
  const r = JSON.parse((await AuthorityCheck().execute(input, undefined as never)).content as string).receipt;
  assert.equal(r.verdict, "DENY");
  assert.equal(r.action_result.code, "ACTION_UNAUTHORISED");
});

void it("health and explain also reject malformed direct requests", async () => {
  await assert.rejects(() => AuthorityHealth().execute({ unknown: true }, undefined as never), AuthorityError);
  await assert.rejects(() => AuthorityExplain().execute({ receipt: { verdict: "ALLOW" } }, undefined as never), AuthorityError);
});
