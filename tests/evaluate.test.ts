import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluate, revocationImpact, scopeMatches } from "../src/engine/index.ts";
import { AuthorityError, type AuthorityPolicy, type AuthorityProposal } from "../src/engine/types.ts";

const NOW = "2026-09-25T12:00:00.000Z";

const POLICY: AuthorityPolicy = {
  version: "t1",
  data_use: [{ id: "cal-travel", purpose: "book-travel", data_scope: ["calendar:travel-window"], permitted_operations: ["ACCESS", "PROCESS"] }],
  actions: [{ id: "search", purpose: "book-travel", action_scope: ["search-flights"], approval: "none" }],
};

function proposal(overrides: Partial<AuthorityProposal> = {}): AuthorityProposal {
  return {
    proposal_id: "p",
    purpose: "book-travel",
    external_operation: { kind: "ACT", action: "search-flights" },
    data_uses: [{ source: { id: "calendar:travel-window", kind: "calendar" }, operation: "ACCESS", necessary: true }],
    ...overrides,
  };
}

void describe("flagship split", () => {
  void it("allowed action + excessive information path → REFORMULATE, not ALLOW", () => {
    const receipt = evaluate(
      proposal({ data_uses: [
        { source: { id: "calendar:travel-window", kind: "calendar" }, operation: "ACCESS", necessary: true },
        { source: { id: "mailbox:all", kind: "mail" }, operation: "ACCESS", necessary: false },
      ] }),
      POLICY,
      { now: NOW },
    );
    assert.equal(receipt.verdict, "REFORMULATE");
    assert.ok((receipt.reformulation ?? "").includes("mailbox:all"));
  });
  void it("clean proposal → ALLOW", () => {
    const receipt = evaluate(proposal(), POLICY, { now: NOW });
    assert.equal(receipt.verdict, "ALLOW");
    assert.ok(receipt.receipt_id.length === 16);
  });
});

void describe("authority distinctions", () => {
  void it("purpose mismatch denies even with matching scopes", () => {
    const receipt = evaluate(proposal({ purpose: "marketing-profile" }), POLICY, { now: NOW });
    assert.equal(receipt.verdict, "DENY");
  });
  void it("revoked grants deny with REVOCATION_ACTIVE", () => {
    const revoked: AuthorityPolicy = { ...POLICY, revoked: [{ id: "search", revoked_at: "2026-09-24T00:00:00.000Z" }] };
    const receipt = evaluate(proposal(), revoked, { now: NOW });
    assert.equal(receipt.verdict, "DENY");
    assert.equal(receipt.action_result?.code, "REVOCATION_ACTIVE");
  });
  void it("expired grants deny with POLICY_EXPIRED", () => {
    const expired: AuthorityPolicy = {
      ...POLICY,
      data_use: [{ ...POLICY.data_use[0], expires_at: "2026-01-01T00:00:00.000Z" }],
    };
    const receipt = evaluate(proposal(), expired, { now: NOW });
    assert.equal(receipt.verdict, "DENY");
  });
  void it("approval-required actions do not execute silently", () => {
    const gated: AuthorityPolicy = {
      ...POLICY,
      actions: [{ id: "buy", purpose: "book-travel", action_scope: ["purchase-flight"], approval: "required" }],
    };
    const receipt = evaluate(
      proposal({ external_operation: { kind: "ACT", action: "purchase-flight" } }),
      gated,
      { now: NOW },
    );
    assert.equal(receipt.verdict, "REQUIRE_APPROVAL");
  });
  void it("same timestamp in, same verdict out (deterministic, explicit clock)", () => {
    const a = evaluate(proposal(), POLICY, { now: NOW });
    const b = evaluate(proposal(), POLICY, { now: NOW });
    assert.deepEqual(a, b);
  });
});

void describe("scope matching", () => {
  void it("exact and wildcard scopes match; nothing else does", () => {
    assert.equal(scopeMatches("calendar:*", "calendar:today"), true);
    assert.equal(scopeMatches("calendar:today", "calendar:today"), true);
    assert.equal(scopeMatches("calendar:today", "calendar:other"), false);
    assert.equal(scopeMatches("calendar:*", "mail:inbox"), false);
  });
});

void describe("revocation accounting", () => {
  void it("stops the future without claiming to reverse the past", () => {
    const impact = revocationImpact(
      ["cal-travel"],
      [{ id: "pref-1", derived_from: ["calendar:travel-window"], purpose: "book-travel", authority_source: ["cal-travel"], permitted_uses: ["triage"], expires_at: "2026-10-01T00:00:00.000Z" }],
      ["service X received attribute Y"],
      ["booking created"],
    );
    assert.ok(impact.future_operations_stopped.length === 1);
    assert.deepEqual(impact.retained_derivatives, ["pref-1"]);
    assert.deepEqual(impact.prior_disclosures, ["service X received attribute Y"]);
    assert.ok(impact.note.includes("does not reverse"));
  });
});

void describe("validation", () => {
  void it("rejects malformed policy and proposal", () => {
    assert.throws(() => evaluate({} as never, POLICY, { now: NOW }), (e) => e instanceof AuthorityError && e.code === "PROPOSAL_INVALID");
    assert.throws(() => evaluate(proposal(), { version: "", data_use: [], actions: [] }, { now: NOW }), (e) => e instanceof AuthorityError);
  });
});
