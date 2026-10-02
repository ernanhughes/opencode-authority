# Pass A recovery amendment — 2026-10-02

Written before the recovery implementation. The completed but unanalyzed
`native-final-01` run disproves the previous final transport design in
`CONTRACT.md`: opting out of Code Mode does not prevent the direct host's
JSON Schema decoder from projecting extra fields or coercing booleans.
It recorded 13 failing checks of 33, including the intentional shared
closed-schema control. A malformed canary with an extra field wrote its marker.
The prior verification record examined `native-after-03`, not this final run.

The corrected design retains BOTH restrictions: `codemode:false` to exclude
the interpreter's escaped-string transformations, AND an untyped object
transport from Standard Schema's JSON Schema input conversion. That transport
must preserve unknown keys and value types. The canonical closed schema and
strict Standard Schema validator still reject malformed requests before
provider callback entry. Callback, evaluator, policy-file and hook boundaries
continue to revalidate. No field may be projected, coerced or defaulted into
an Authority decision. The permissive transport is not an Authority grant.

Keep the canonical schema available on the registered schema object for local
inspection; host/model discovery receives the lossless transport, with less
field guidance. Tool descriptions must explain the input shapes. Do not
advertise the host transport as canonical validation.

Rerun the unchanged 33-case final fixture against the already-retained exact
2.0.22 binary, recording its hash and all original requests. An unavailable
Code Mode tool can produce an interpreter "Unknown tool" error rather than
the shared receipt classifier's native admission diagnostic. Keep the shared
receipt result intact and record this as a separate, evidenced transport
check; do not change that fixture or reclassify the shared schema control.

Acceptance: malformed inputs produce no Authority verdict, callback or named
canary effect; valid inputs arrive unchanged; all four verdicts remain distinct;
host ASK/reply/write and DENY/no-write remain independently observable.
Authority's own native permission event and general interception stay UNKNOWN.
Preserve all earlier raw evidence, frozen protocols and the README as found.
