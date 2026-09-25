import { createHash } from "node:crypto";
import {
  AuthorityError,
  type AuthorityPolicy,
  type AuthorityProposal,
  type AuthorityReceipt,
  type CheckResult,
  type DataUse,
  type DataUseReceipt,
  type DerivedStateRef,
  type ReasonCode,
  type RevocationImpact,
  type Verdict,
} from "./types.ts";

export const AUTHORITY_VERSION = "0.1.0";

function stableId(parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 16);
}

/** Scope match: exact equality or `prefix:*` wildcard. No regex, no substrings. */
export function scopeMatches(scope: string, value: string): boolean {
  if (scope === value) return true;
  if (scope.endsWith(":*")) return value.startsWith(scope.slice(0, -1));
  if (scope.endsWith("*")) return value.startsWith(scope.slice(0, -1));
  return false;
}

function expired(expiresAt: string | undefined, now: string): boolean {
  if (!expiresAt) return false;
  return expiresAt < now;
}

function fail(code: ReasonCode, detail: string, grant_id?: string): CheckResult {
  return { ok: false, code, detail, ...(grant_id ? { grant_id } : {}) };
}

function pass(code: ReasonCode, detail: string, grant_id?: string): CheckResult {
  return { ok: true, code, detail, ...(grant_id ? { grant_id } : {}) };
}

export interface EvaluateOptions {
  now?: string;
  knownDerivatives?: DerivedStateRef[];
  priorDisclosures?: string[];
}

function validatePolicy(policy: AuthorityPolicy): void {
  if (!policy || typeof policy.version !== "string" || !Array.isArray(policy.data_use) || !Array.isArray(policy.actions)) {
    throw new AuthorityError("POLICY_INVALID", "policy must carry version, data_use[], and actions[]");
  }
  for (const g of [...policy.data_use, ...policy.actions, ...(policy.speech ?? []), ...(policy.discovery ?? [])]) {
    const grant = g as { id?: unknown; purpose?: unknown };
    if (typeof grant.id !== "string" || typeof grant.purpose !== "string") {
      throw new AuthorityError("POLICY_INVALID", "every grant needs string id and purpose");
    }
  }
}

function validateProposal(proposal: AuthorityProposal): void {
  if (!proposal || typeof proposal.proposal_id !== "string" || typeof proposal.purpose !== "string" || !Array.isArray(proposal.data_uses)) {
    throw new AuthorityError("PROPOSAL_INVALID", "proposal must carry proposal_id, purpose, and data_uses[]");
  }
}

function checkDataUse(use: DataUse, policy: AuthorityPolicy, purpose: string, now: string): CheckResult[] {
  const results: CheckResult[] = [];
  const grants = policy.data_use.filter((g) => g.purpose === purpose);
  if (grants.length === 0) {
    return [fail("PURPOSE_UNAUTHORISED", `no DataUseAuthority for purpose "${purpose}"`)];
  }
  const live = grants.filter((g) => !expired(g.expires_at, now) && !(policy.revoked ?? []).some((r) => r.id === g.id));
  if (live.length === 0) {
    const revokedHit = grants.some((g) => (policy.revoked ?? []).some((r) => r.id === g.id));
    return [fail(revokedHit ? "REVOCATION_ACTIVE" : "POLICY_EXPIRED", "all purpose-matching DataUseAuthority entries are revoked or expired")];
  }
  const scopeHit = live.filter((g) => g.data_scope.some((s) => scopeMatches(s, use.source.id)));
  if (scopeHit.length === 0) {
    return [fail("DATA_SCOPE_UNAUTHORISED", `source "${use.source.id}" outside authorised data scopes`)];
  }
  const opHit = scopeHit.filter((g) => g.permitted_operations.includes(use.operation));
  if (opHit.length === 0) {
    const code =
      use.operation === "INFER"
        ? "INFERENCE_UNAUTHORISED"
        : use.operation === "RETAIN"
          ? "RETENTION_UNAUTHORISED"
          : use.operation === "REUSE"
            ? "REUSE_UNAUTHORISED"
            : use.operation === "DISCLOSE"
              ? "DISCLOSURE_UNAUTHORISED"
              : "OPERATION_UNAUTHORISED";
    return [fail(code, `${use.operation} on "${use.source.id}" not permitted`, scopeHit[0].id)];
  }
  // Necessity: the use must be declared necessary for the purpose.
  if (use.necessary === false) {
    return [fail("UNNECESSARY_DATA_USE", `${use.operation} on "${use.source.id}" declared unnecessary for purpose`, opHit[0].id)];
  }
  // Third-party boundary: principal possession never implies reuse rights.
  if (use.third_party === true && !opHit.some((g) => g.third_party_allowed === true)) {
    return [fail("THIRD_PARTY_BOUNDARY", `third-party information in "${use.source.id}" needs explicit third_party_allowed`, opHit[0].id)];
  }
  // Disclosure needs a recipient inside an authorised recipient scope.
  if (use.operation === "DISCLOSE") {
    const withRecipients = opHit.filter((g) => g.recipients !== undefined);
    if (withRecipients.length === 0) {
      return [fail("DISCLOSURE_UNAUTHORISED", "DISCLOSE requires a grant with explicit recipients", opHit[0].id)];
    }
    if (!use.recipient || !withRecipients.some((g) => (g.recipients ?? []).some((r) => scopeMatches(r, use.recipient as string)))) {
      return [fail("DISCLOSURE_UNAUTHORISED", `recipient "${use.recipient ?? "(none)"}" outside authorised recipients`, withRecipients[0].id)];
    }
  }
  return [pass("PURPOSE_UNAUTHORISED", `allowed under ${opHit[0].id}`, opHit[0].id)];
}

function checkExternal(proposal: AuthorityProposal, policy: AuthorityPolicy, now: string): CheckResult | null {
  const op = proposal.external_operation;
  if (!op) return null;
  const revoked = (id: string): boolean => (policy.revoked ?? []).some((r) => r.id === id);
  if (op.kind === "ACT" || op.kind === "DISCOVER") {
    if (op.kind === "DISCOVER") {
      const grants = (policy.discovery ?? []).filter((g) => g.purpose === proposal.purpose && !expired(g.expires_at, now) && !revoked(g.id));
      if (grants.length === 0) {
        return fail("DISCOVERY_UNAUTHORISED", `no discovery grant for purpose "${proposal.purpose}" (private computation never implies legitimate purpose)`);
      }
      const predicate = op.action;
      if (!grants.some((g) => g.permitted_predicates.some((p) => scopeMatches(p, predicate)))) {
        return fail("DISCOVERY_UNAUTHORISED", `predicate "${predicate}" not listed in any discovery grant`, grants[0].id);
      }
      if (grants.some((g) => g.permitted_predicates.some((p) => scopeMatches(p, predicate)))) {
        const requiring = grants.filter((g) => g.approval === "required" && g.permitted_predicates.some((p) => scopeMatches(p, predicate)));
        if (requiring.length > 0) return fail("APPROVAL_REQUIRED", "discovery predicate requires approval", requiring[0].id);
      }
      return pass("DISCOVERY_UNAUTHORISED", `predicate authorised`, grants[0].id);
    }
    const purposeGrants = policy.actions.filter((g) => g.purpose === proposal.purpose);
    if (purposeGrants.length === 0) {
      return fail("ACTION_UNAUTHORISED", `no ActionGrant for purpose "${proposal.purpose}"`);
    }
    const livePurpose = purposeGrants.filter((g) => !expired(g.expires_at, now) && !revoked(g.id));
    if (livePurpose.length === 0) {
      const revokedHit = purposeGrants.some((g) => revoked(g.id));
      return fail(
        revokedHit ? "REVOCATION_ACTIVE" : "POLICY_EXPIRED",
        revokedHit ? `all ActionGrants for purpose "${proposal.purpose}" are revoked` : `all ActionGrants for purpose "${proposal.purpose}" are expired`,
      );
    }
    const grants = livePurpose;
    const scoped = grants.filter((g) => g.action_scope.some((s) => scopeMatches(s, op.action)));
    if (scoped.length === 0) {
      return fail("ACTION_UNAUTHORISED", `action "${op.action}" outside authorised action scopes`);
    }
    const requiring = scoped.filter((g) => g.approval === "required");
    if (requiring.length > 0) return fail("APPROVAL_REQUIRED", `action "${op.action}" requires approval`, requiring[0].id);
    return pass("ACTION_UNAUTHORISED", `action authorised`, scoped[0].id);
  }
  // SPEAK
  const speakPurpose = (policy.speech ?? []).filter((g) => g.purpose === proposal.purpose);
  if (speakPurpose.length === 0) {
    return fail("SPEECH_UNAUTHORISED", `no SpeechGrant for purpose "${proposal.purpose}"`);
  }
  const speakLive = speakPurpose.filter((g) => !expired(g.expires_at, now) && !revoked(g.id));
  if (speakLive.length === 0) {
    const revokedHit = speakPurpose.some((g) => revoked(g.id));
    return fail(
      revokedHit ? "REVOCATION_ACTIVE" : "POLICY_EXPIRED",
      revokedHit ? `all SpeechGrants for purpose "${proposal.purpose}" are revoked` : `all SpeechGrants for purpose "${proposal.purpose}" are expired`,
    );
  }
  const grants = speakLive;
  const act = op.action;
  const actOk = grants.filter((g) => !g.permitted_acts || g.permitted_acts.includes(act as never));
  if (actOk.length === 0) {
    return fail("SPEECH_UNAUTHORISED", `speech act "${act}" not permitted`);
  }
  if (op.audience && !actOk.some((g) => !g.audience_scope || g.audience_scope.some((s) => scopeMatches(s, op.audience as string)))) {
    return fail("SPEECH_UNAUTHORISED", `audience "${op.audience}" outside authorised audience scope`);
  }
  if (op.counterparty && !actOk.some((g) => !g.audience_scope || g.audience_scope.some((s) => scopeMatches(s, op.counterparty as string)))) {
    return fail("COUNTERPARTY_CONSTRAINT", `counterparty "${op.counterparty}" outside authorised audience scope`);
  }
  const requiring = actOk.filter((g) => g.approval === "required");
  if (requiring.length > 0) return fail("APPROVAL_REQUIRED", `speech act "${act}" requires approval`, requiring[0].id);
  return pass("SPEECH_UNAUTHORISED", "speech authorised", actOk[0].id);
}

export function evaluate(proposal: AuthorityProposal, policy: AuthorityPolicy, options: EvaluateOptions = {}): AuthorityReceipt {
  validatePolicy(policy);
  validateProposal(proposal);
  const now = options.now ?? new Date().toISOString();
  if (policy.version.trim().length === 0) throw new AuthorityError("POLICY_INVALID", "policy.version must be non-empty");

  const data_receipts: DataUseReceipt[] = proposal.data_uses.map((use) => {
    const reasons = checkDataUse(use, policy, proposal.purpose, now);
    const denied = reasons.some((r) => !r.ok && r.code !== "APPROVAL_REQUIRED");
    const approval = reasons.some((r) => !r.ok && r.code === "APPROVAL_REQUIRED");
    return {
      source_id: use.source.id,
      operation: use.operation,
      result: denied ? "denied" : approval ? "approval_required" : "allowed",
      reasons,
    };
  });

  // Composed privilege: union of accessed scopes vs forbidden combinations.
  const accessedScopes = proposal.data_uses.map((u) => u.source.id);
  const composedHits: string[][] = (policy.forbidden_combinations ?? []).filter((combo) =>
    combo.every((scope) => accessedScopes.some((a) => scopeMatches(scope, a))),
  );
  const composed_scopes = [...new Set(accessedScopes)];

  const action_result = checkExternal(proposal, policy, now);
  const dataDenied = data_receipts.some((r) => r.result === "denied");
  const dataApproval = data_receipts.some((r) => r.result === "approval_required");
  const actionDenied = action_result !== null && !action_result.ok && action_result.code !== "APPROVAL_REQUIRED";
  const actionApproval = action_result !== null && !action_result.ok && action_result.code === "APPROVAL_REQUIRED";
  const revocation_active = (policy.revoked ?? []).length > 0;

  let verdict: AuthorityReceipt["verdict"];
  let reformulation: string | undefined;
  const approval_required_by: string[] = [];
  if (actionDenied) {
    verdict = "DENY";
  } else if (composedHits.length > 0) {
    verdict = "DENY";
    reformulation = `composed privilege: scopes [${composedHits[0].join(" + ")}] must not combine for this purpose; drop at least one source`;
  } else if (dataDenied) {
    // Flagship split: acceptable action + unacceptable information path → REFORMULATE.
    // Two exceptions deny outright: dead authority (expired/revoked — nothing to
    // narrow toward) and proposals with no surviving lawful core.
    const deadAuthority = data_receipts.some((r) =>
      r.reasons.some((x) => !x.ok && (x.code === "POLICY_EXPIRED" || x.code === "REVOCATION_ACTIVE")),
    );
    const anythingAllowed =
      (action_result !== null && action_result.ok) || data_receipts.some((r) => r.result === "allowed");
    if (deadAuthority || !anythingAllowed) {
      verdict = "DENY";
    } else {
      verdict = "REFORMULATE";
      const bad = data_receipts.filter((r) => r.result === "denied").map((r) => `${r.operation}:${r.source_id}`);
      reformulation = `proceed without: ${bad.join(", ")}`;
    }
  } else if (actionApproval || dataApproval) {
    verdict = "REQUIRE_APPROVAL";
    for (const r of data_receipts) {
      for (const reason of r.reasons) if (!reason.ok && reason.grant_id) approval_required_by.push(reason.grant_id);
    }
    if (action_result && !action_result.ok && action_result.grant_id) approval_required_by.push(action_result.grant_id);
  } else {
    verdict = "ALLOW";
  }

  return {
    receipt_id: stableId(["authority", AUTHORITY_VERSION, policy.version, proposal.proposal_id, verdict]),
    proposal_id: proposal.proposal_id,
    purpose: proposal.purpose,
    verdict,
    data_receipts,
    ...(action_result ? { action_result } : {}),
    ...(reformulation ? { reformulation } : {}),
    approval_required_by,
    revocation_active,
    composed_scopes,
    irreversible_effects: proposal.irreversible_effects ?? [],
    policy_version: policy.version,
  };
}

/** Honest revocation accounting: stops the future, inventories the past. */
export function revocationImpact(
  revokedIds: string[],
  knownDerivatives: DerivedStateRef[] = [],
  priorDisclosures: string[] = [],
  irreversible: string[] = [],
): RevocationImpact {
  return {
    future_operations_stopped: revokedIds.map((id) => `all operations under grant ${id}`),
    retained_sources: [],
    retained_derivatives: knownDerivatives.filter((d) => d.authority_source.some((s) => revokedIds.includes(s))).map((d) => d.id),
    prior_disclosures: [...priorDisclosures],
    irreversible_effects: [...irreversible],
    note: "revocation stops future authority; it does not reverse prior disclosures, retained copies, or irreversible effects",
  };
}
