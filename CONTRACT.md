# Authority request boundary — Pass A design (2026-10-02)

**Recovery correction:** `CONTRACT-RESUME.md` supersedes the final transport
design below. Direct invocation ALSO needs the untyped object transport; the
completed `native-final-01` run disproved closed direct discovery. See the
recovery evidence before treating any earlier validation result as acceptance.

Written before implementation. The engine and registered tools must use **strict
rejection**, because this repository requires malformed security policy to fail
closed and defines closed Authority inputs. Native OpenCode 2.0.22's plain JSON
Schema decoder instead projects unknown keys away, before the provider callback
and before its tool hook. That projection is not Authority validation.

- **Untrusted boundary:** the original argument object passed to a registered
  Authority tool, or the proposal/policy passed to the core evaluator. A local
  hook policy file is also untrusted input.
- **Canonical representation:** the existing proposal, policy, receipt and
  canary shapes, with all existing typed nested grants checked. No policy
  language or verdict is added. Unknown actions are valid proposals evaluated
  against existing grants; an unmatched action is DENY.
- **Validation:** register a Standard Schema validator and its matching JSON
  Schema through OpenCode's existing `Tool.ValueSchema` API. The inspected exact
  binary calls `~standard.validate` on the original arguments; it does not use
  the projecting JSON Schema parser for that path. The first native run showed
  that Code Mode first builds another decoder from the catalog JSON Schema and
  projects there. Therefore the catalog uses an explicitly **lossless transport
  schema**. A second native run showed that retaining known field types also
  coerces `"false"` to boolean `false`. Therefore the transport accepts an
  arbitrary JSON object with no typed properties; all keys and values must
  reach the strict validator unchanged. That schema is not canonical Authority
  validation and exposes less type guidance in the Code Mode catalog.
  The registered Standard Schema then rejects unknown fields at every level,
  before the provider hook/callback. The canonical closed schema remains
  available on the registered input for direct validation and inspection.
  Revalidate at direct callback,
  pure evaluator, canary hook and policy-file boundaries.
- **Native transport restriction (final design):** the third run established
  rejection with untyped object transport, but the retained second run also
  shows Code Mode changing escaped string literals before it constructs the
  argument object. A provider cannot recover those original values. Authority
  therefore registers all four tools with `codemode:false` on 2.0.22 and uses
  an untyped object JSON Schema for direct host/model discovery plus strict
  Standard validation. The canonical closed schema remains inspectable locally.
  Code Mode calls to Authority are unavailable and fail closed.
  Payload shapes stay the same. The shared fixture runner must honor the
  registered mode, generically, rather than assume every plugin uses Code Mode.
  The earlier transport attempts above are diagnostic history, not the final
  accepted route. They and the failing escape/coercion evidence are retained.
- **Projection:** none is permitted. Validated tool arguments retain the original
  object. No coercion, defaults, unknown-key stripping or filtered context entries.
  Canary target resolution and proposal construction are explicit derivations;
  retain request, derived proposal and policy hashes to show that lineage.
  Permitting unknown fields in the transport decoder exists only to preserve
  untrusted information for rejection, never to accept them as policy fields.
- **Unknown fields:** reject at every object level. Invalid input emits a
  validation error, no policy verdict/receipt and no canary write. Native
  validation rejection must precede callback execution; direct callback entry
  is necessarily observable when a caller explicitly bypasses native admission.
- **Evidence:** preserve original scripted proposals, decoded callback arguments,
  errors, policy matches, native permissions and named effects independently.
  New boundary observations have an explicit schema identifier and hashes; the
  existing AuthorityReceipt and native acceptance v1 receipt are unchanged.
  Provider observations cannot prove input lost before their own boundary.
- **Failure:** invalid or ambiguous security input fails closed regardless of
  optional canary policy-failure settings. Reusing an invocation identity for a
  different proposal/policy cannot reuse a prior ALLOW. Trace I/O failure cannot
  weaken enforcement; evidence then remains unavailable.

Schema validity, Authority verdict, native admission/permission, callback entry
and world effect are distinct facts. A tool receipt is advice to its caller;
the canary tool hook enforces only the configured canary tool. It prevents the
original invocation on DENY, REFORMULATE or REQUIRE_APPROVAL; it does not execute
a substitute or implement an approval workflow. General interception and an
Authority canary native permission event require evidence and remain UNKNOWN.
