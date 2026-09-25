# OpenCode Authority — Design Contract

## Invariants

1. Capability != authority.
2. Access != permission to use.
3. Action authority != data-use authority.
4. Action authority != speech authority.
5. Prediction/confidence != consent.
6. Revocation != reversal of prior information flow.
7. Private computation != legitimate purpose.
8. One person's consent cannot erase another person's privacy/agency.
9. Least privilege applies to the composed workflow, not tools in isolation.
10. The LLM is not the final enforcement mechanism for consequential policy.
11. Auditability != retain everything forever.
12. No direct sibling-plugin calls.

## Seed policy

```ts
type DataUseAuthority = {
  id: string
  purpose: string
  data_scope: string[]
  permitted_operations: (
    | "ACCESS"
    | "PROCESS"
    | "INFER"
    | "RETAIN"
    | "REUSE"
    | "DISCLOSE"
  )[]
  recipients?: string[]
  expires_at?: string
  retention?: string
  derivative_policy?: string
}

type ActionGrant = {
  id: string
  action_scope: string[]
  targets?: string[]
  consequence_limit?: string
  approval?: "none" | "required"
  expires_at?: string
}
```

## Evaluation order

Purpose → required data operations → necessity/minimisation → DataUseAuthority → action/speech/discovery grant → counterparty constraints → irreversible effects → verdict + receipt.

## v0.1

- local versioned JSON policy;
- pure deterministic evaluator;
- four verdicts;
- data-operation decomposition;
- minimised receipts;
- adversarial fixtures;
- no automatic destructive action.

## Early adversarial fixtures

- task solvable from calendar, proposal reads mailbox;
- action allowed, evidence source forbidden;
- internal use allowed, disclosure forbidden;
- access revoked after derivative creation;
- third-party confidential data in principal account;
- narrow individual permissions create broad composed visibility;
- private predicate with unauthorised purpose.

## Enforcement split

```text
MODEL proposes
→ POLICY ENGINE checks
→ TOOL / COMMUNICATION BOUNDARY enforces
```

Do not claim enforcement until a real OpenCode hook blocks the operation in a smoke test.

## Acceptance test

The engine can deny/reformulate a proposal even when the final external action is itself allowed, because the proposed information path is excessive or unauthorised, and the receipt makes that distinction inspectable.
