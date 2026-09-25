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

**Design seed only.** Validate the deterministic policy model and exact OpenCode enforcement surface before claiming broad gating.
