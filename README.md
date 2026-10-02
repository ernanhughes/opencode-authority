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

## Install

Requires Git, Node.js **22.18 or newer** and npm. Use a source checkout; this
recipe does not assume the package is published to npm:

```powershell
git clone https://github.com/ernanhughes/opencode-authority.git C:\Projects\opencode-authority
Set-Location C:\Projects\opencode-authority
npm ci
npm run load-check
```

For an **OpenCode 2** host, merge this into the target project's `opencode.json`:

```json
{ "plugins": ["file:///C:/Projects/opencode-authority"] }
```

On Linux/WSL, clone into `/home/<user>/projects/opencode-authority`, run the same npm
commands, and use `file:///home/<user>/projects/opencode-authority`. The package entrypoint
is `src/index.ts`; root `index.ts` also exports the plugin for directory discovery.
This is a V2 `@opencode/plugin` definition. The V2 field is **`plugins`**;
see [OpenCode's plugin configuration](https://opencode.ai/v2/docs/plugins).
Restart the host after configuration changes. Host loading is a later integration
check; the offline load check only constructs the tool surface.

## Configure

`authority_check` requires a proposal and policy in its input; it does not read
the hook policy environment variable. No API key or model is required.

The **canary hooks** have these OPTIONAL environment settings, read at plugin setup:

| Variable | Default | Meaning |
|---|---|---|
| `AUTHORITY_ENABLED` | enabled unless `0` | Registers canary hooks; disabling them does not remove evaluator tools or the canary write tool. |
| `AUTHORITY_MANDATORY` | enabled unless `0` | Permission-hook policy/engine failures deny when mandatory. The tool hook also rejects malformed policy/target errors. |
| `AUTHORITY_POLICY_FILE` | unset | REQUIRED for successful gated canary execution; absolute path to a JSON policy with grants carrying `id` and `purpose`. Missing/invalid policy fails closed by default. |
| `AUTHORITY_CANARY_DIR` | `${TEMP}/authority-canary`, or `/tmp/authority-canary` without TEMP | Canary write target root; target must resolve inside it. |
| `AUTHORITY_TRACE_DIR` | `${TEMP}/authority-traces`, or `/tmp/authority-traces` | Appends `authority-gate.jsonl`; tracing failure does not weaken enforcement. |

## First use

After `npm ci`, run `node examples/first-use.mjs`. The complete example reads
`examples/policy.json`, creates a proposal for `book-travel`, ACCESS to
`calendar:travel-window` declared necessary, and ACT `search-flights`, then calls
the implemented `authority_check` tool. Expected: `{receipt}` containing generated
`receipt_id`, proposal/purpose, `verdict: "ALLOW"`, reasons, grant references and
policy version. The file prints the full proposal/policy and returned receipt,
and calls `authority_health` with `{}`. Use that same input with the host tool.

This evaluates the supplied policy. It does not search flights, write a canary,
grant general permission or establish live hook enforcement. No model or network
is used. Changing to `purchase-flight` requires approval under the example policy.

## Health check

Call `authority_health` with `{}`: expect `ok: true`, version, four verdicts,
six data operations and three external-operation kinds. Offline:
`npm run load-check`. Health reports the evaluator/tool surface; it **does not
load or validate `AUTHORITY_POLICY_FILE`**, exercise a hook or establish enforcement.

## Canary hook boundary

Implemented/mechanism-tested: `permission.evaluate` considers actions containing
`canary`, preserves an existing host deny, and maps policy verdicts to allow/ask/deny.
`tool.execute.before` gates only `authority_canary_write`, checks target containment
and rich data-use proposals, and blocks DENY, REFORMULATE and REQUIRE_APPROVAL.
The write tool refuses overwrite. This is a scoped mechanism, not general interception.
Permission and tool hooks use distinct cache keys; do not assume one shared evaluation
across those two boundaries. Direct offline calls to the write tool bypass host hooks.

Broad interception and live OpenCode allow/deny enforcement smoke remain **unproven**.
Do not interpret healthy tools as enforcement evidence. This documentation pass
does not run a live canary or enable hooks in any host.

## Troubleshooting

- Tool absent: check V2 `plugins`, checkout dependencies/path and restart; compare with `npm run load-check`.
- `POLICY_INVALID`: every grant needs `id` and `purpose`; use the complete example. For hooks, also check that `AUTHORITY_POLICY_FILE` is set/readable JSON.
- `authority fail-closed: POLICY_INVALID`: inspect the scoped policy/target; `authority_health` cannot diagnose the hook policy file.
- REQUIRE_APPROVAL/REFORMULATE/DENY is a policy outcome, not a successful action. The canary tool rejects targets outside its root and existing files.

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

## OpenCode tools

- `authority_check`
- `authority_explain`
- `authority_health`

Canary-scoped hook gates are implemented; broad tool execution/communication interception remains unproven.

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

**v0.1 implemented (pure evaluator + tools).** Deterministic engine (DataUseAuthority/ActionGrant/SpeechGrant/DiscoveryGrant, six data operations, four verdicts, necessity/minimisation, composed-privilege detection, third-party boundary, revocation accounting, minimised receipts), OpenCode tools (`authority_check`, `authority_explain`, `authority_health`), 15-case adversarial battery (15/15, zero false ALLOWs), unit tests, no-inference load check. Canary-scoped hook enforcement implemented and mechanism-tested — broad interception and live OpenCode enforcement smoke remain unproven.

## Capability provider

- **Capability:** permission evaluation with minimised receipts and canary-scoped hook gates.
- **Interfaces:** OpenCode plugin: authority_check, authority_explain, authority_health and authority_canary_write; env-gated permission.evaluate and tool.execute.before hooks scoped to canaries; deterministic evaluator library.
- **Current maturity:** IMPLEMENTED+TESTED; canary-scoped hooks are implemented and mechanism-tested; broad interception and live smoke remain unproven.
- **Evidence:** 17 test declarations (10 evaluator + seven hooks); README records 15/15 adversarial cases with zero false ALLOWs. Mechanism checks were not rerun in this documentation pass.
- **Known limitations:** Permission does not establish competence or truth. No general enforcement or user-auth integration claim; canary enforcement is scoped and mechanism-tested, with no live enforcement smoke claim.
- **Used by:** No confirmed direct runtime consumer; explicit orchestrator proposals are a composition point. Work’s authority granter remains absent.
- **Registry:** Language `planning/capability-providers/` (Language-side availability index; this repository is the source of truth for itself).
- **Evidence snapshot:** Audited 2026-10-02 against commit 008e63e2.
  See repository history and current status for later changes.
