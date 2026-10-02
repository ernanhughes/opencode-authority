import { it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { AuthorityCheck } from "../src/tools.ts";

void it("documented policy fits the closed registered schema and preserves search/purchase decisions", async () => {
  const tool = AuthorityCheck();
  const policy = JSON.parse(readFileSync(new URL("../examples/policy.json", import.meta.url), "utf8"));
  const schema = tool.input as { properties: { policy: { additionalProperties: boolean; properties: Record<string, unknown>; required: string[] } } };
  const policySchema = schema.properties.policy;
  assert.equal(policySchema.additionalProperties, false);
  for (const key of Object.keys(policy)) assert.ok(key in policySchema.properties, `unsupported policy field: ${key}`);
  for (const key of policySchema.required) assert.ok(key in policy, `missing policy field: ${key}`);
  const proposal = {
    proposal_id: "first-search", purpose: "book-travel",
    external_operation: { kind: "ACT", action: "search-flights" },
    data_uses: [{ source: { id: "calendar:travel-window", kind: "calendar" }, operation: "ACCESS", necessary: true }],
  };
  const search = await tool.execute({ proposal, policy }, undefined as never);
  assert.equal(JSON.parse(search.content as string).receipt.verdict, "ALLOW");
  const purchase = await tool.execute({ proposal: { ...proposal, external_operation: { kind: "ACT", action: "purchase-flight" } }, policy }, undefined as never);
  assert.equal(JSON.parse(purchase.content as string).receipt.verdict, "REQUIRE_APPROVAL");
});
