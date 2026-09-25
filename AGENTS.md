# Build Brief for AI Agents

Implement **OpenCode Authority** as enforcement/policy, not an LLM "safety judge".

Read first:

1. `README.md`
2. `DESIGN.md`
3. https://github.com/ernanhughes/project-context-opencode
4. https://github.com/ernanhughes/opencode-remembering

## Priorities

Fail closed on malformed security/isolation policy, deterministic evaluation, explicit purpose/operations, independent data/action/speech authority, minimised receipts, versioned policy, enforcement proof before claims.

## Do not

- let model confidence grant permission;
- infer consent from behaviour;
- treat tool availability as authority;
- retain secrets in receipts;
- call sibling Language plugins;
- intercept everything before the pure evaluator works;
- claim revocation undoes past disclosure.

Deliver policy schema, deterministic engine, adversarial fixtures, OpenCode tools, health/validation, receipt explanation, tests, enforcement-hook design, and a live allow/deny canary when gating is added.
