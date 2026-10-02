# OpenCode Authority

OpenCode Authority is a small OpenCode plugin for answering:

> **May this operation be performed, using this information, for this purpose?**

> **Capability is not authority. Access is not permission to use.**

## One job

```text
proposed operation
+ purpose
+ data inputs
+ grants/policy
+ counterparty constraints
        ↓
     AUTHORITY
        ↓
ALLOW | DENY | REQUIRE_APPROVAL | REFORMULATE
+ AuthorityReceipt
```

The final gate should be deterministic policy code wherever possible. An LLM may normalize an ambiguous proposal, but model confidence must not become permission.

## Authority dimensions

Data use: `ACCESS`, `PROCESS`, `INFER`, `RETAIN`, `REUSE`, `DISCLOSE`.

External effects: `ACT`, `SPEAK`, `DISCOVER`.

```text
ACCESS != PROCESS
PROCESS != INFER
INFER != RETAIN
RETAIN != REUSE
USE INTERNALLY != DISCLOSE
ACTION AUTHORITY != SPEECH AUTHORITY
```

## Proposed OpenCode tools

- `authority_check`
- `authority_explain`
- `authority_health`

Later versions may gate tool execution/communication, but v0.1 should earn the policy engine before broad interception.

## Core result

```ts
type AuthorityVerdict =
  | "ALLOW"
  | "DENY"
  | "REQUIRE_APPROVAL"
  | "REFORMULATE"

type AuthorityReceipt = {
  receipt_id: string
  proposal_id: string
  purpose: string
  operation: string
  data_operations: string[]
  data_sources: SourceRef[]
  target?: string
  counterparties?: string[]
  verdict: AuthorityVerdict
  reasons: string[]
  authority_sources: string[]
  policy_version: string
  irreversible_effects?: string[]
  retained_derivatives?: string[]
}
```

## Important rules

- A valid action can still fail because its information use was unauthorised.
- Processing does not imply retention/reuse.
- Revocation stops future authority; it does not reverse past disclosure.
- One principal cannot authorise every use of third-party information found in their account.
- Private computation can still serve an illegitimate purpose.
- Receipts themselves obey minimisation/retention.

## Composition

Authority does not decide relevance or representation. It receives a proposal from the orchestrator/main agent and evaluates permission. No direct dependency on Lens, Relate, or Radar.

## Status

**v0.1 implemented (pure evaluator + tools).** Deterministic engine (DataUseAuthority/ActionGrant/SpeechGrant/DiscoveryGrant, six data operations, four verdicts, necessity/minimisation, composed-privilege detection, third-party boundary, revocation accounting, minimised receipts), OpenCode tools (`authority_check`, `authority_explain`, `authority_health`), 15-case adversarial battery (15/15, zero false ALLOWs), unit tests, no-inference load check. No hook enforcement yet — that is Phase 8, explicitly unclaimed.

## Capability provider

- **Capability:** permission evaluation with minimised receipts and canary-scoped hook gates.
- **Interfaces:** OpenCode plugin: authority_check, authority_explain, authority_health and authority_canary_write; env-gated permission.evaluate and tool.execute.before hooks scoped to canaries; deterministic evaluator library.
- **Current maturity:** IMPLEMENTED+TESTED; canary-scoped hooks are implemented and mechanism-tested; broad interception and live smoke remain unproven.
- **Evidence:** 17 test declarations (10 evaluator + seven hooks); README records 15/15 adversarial cases with zero false ALLOWs. Mechanism checks were not rerun in this documentation pass.
- **Known limitations:** Permission does not establish competence or truth. No general enforcement or user-auth integration claim; the earlier “No hook enforcement yet” README statement is stale and remains separate documentation debt.
- **Used by:** No confirmed direct runtime consumer; explicit orchestrator proposals are a composition point. Work’s authority granter remains absent.
- **Registry:** Language `planning/capability-providers/` (Language-side availability index; this repository is the source of truth for itself).
- **Evidence snapshot:** Audited 2026-10-02 against commit 008e63e2.
  See repository history and current status for later changes.
