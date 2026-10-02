import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join, normalize, resolve, sep } from "node:path";
import type { Info as ToolInfo } from "@opencode/plugin/promise/tool";
import { EvaluationCache, gateOptionsFromEnv, loadPolicyFile, verdictToEffect, type GateOptions } from "./gate.ts";
import { AuthorityError, type AuthorityPolicy, type AuthorityProposal } from "./engine/types.ts";
import { canarySchema, nativeInput, validateInput } from "./validation.ts";
import { requestHash } from "./boundary.ts";

function trace(options: GateOptions, record: Record<string, unknown>): void {
  try {
    mkdirSync(options.traceDir, { recursive: true });
    appendFileSync(join(options.traceDir, "authority-gate.jsonl"), JSON.stringify({ schema: "opencode.authority_boundary.v1", ts: new Date().toISOString(), ...record }) + "\n");
  } catch {
    // Tracing must never break enforcement.
  }
}

function targetInsideDir(canaryDir: string, target: string): string | null {
  const root = normalize(resolve(canaryDir)) + sep;
  const absolute = normalize(isAbsolutePath(target) ? target : resolve(canaryDir, target));
  if (absolute === normalize(resolve(canaryDir)) || !absolute.startsWith(root)) return null;
  return absolute;
}

function isAbsolutePath(p: string): boolean {
  return /^[a-zA-Z]:[\\/]/.test(p) || p.startsWith("/");
}

/** Build the authority proposal for a canary invocation.
 *  Target access is declared necessary; extra context sources are declared
 *  unnecessary. The canary input has no required-context override. */
function canaryProposal(id: string, target: string, contextSources: string[]): AuthorityProposal {
  return {
    proposal_id: id,
    purpose: "authority-canary",
    external_operation: { kind: "ACT", action: "canary-write", target },
    data_uses: [
      { source: { id: `canary:target:${target}`, kind: "canary-target" }, operation: "ACCESS", necessary: true },
      ...contextSources.map((s) => ({
        source: { id: s, kind: "canary-context" },
        operation: "ACCESS" as const,
        necessary: false,
      })),
    ],
  };
}

interface HookHost {
  tool: {
    transform: (cb: (editor: { add: (t: ToolInfo) => void }) => void) => Promise<unknown>;
    hook: (name: string, cb: (event: Record<string, unknown>) => Promise<void> | void) => Promise<unknown>;
  };
  permission: {
    hook: (name: string, cb: (event: Record<string, unknown>) => Promise<void> | void) => Promise<unknown>;
  };
}

export async function registerAuthorityGate(host: HookHost, options: GateOptions = gateOptionsFromEnv()): Promise<void> {
  if (!options.enabled) return;
  const cache = new EvaluationCache();

  const loadPolicy = (): AuthorityPolicy => {
    if (!options.policyFile) throw new AuthorityError("POLICY_INVALID", "AUTHORITY_POLICY_FILE is not set");
    return loadPolicyFile(options.policyFile);
  };

  // Native permission boundary: coarse action authority. Never weakens a host deny.
  await host.permission.hook("evaluate", async (event) => {
    if (event["effect"] === "deny") {
      trace(options, { boundary: "permission", stage: "OPEN_CODE_PERMISSION_RESULT", host_decision: "deny-final", action: event["action"] });
      return;
    }
    const action = event["action"];
    if (typeof action !== "string" || !action.includes("canary")) return;
    try {
      const policy = loadPolicy();
      const key = `perm:${String(event["sessionID"] ?? "")}:${action}`;
      const record = cache.getOrEvaluate(
        key,
        {
          proposal_id: key,
          purpose: "authority-canary",
          external_operation: { kind: "ACT", action: "canary-write" },
          data_uses: [],
        },
        policy,
      );
      event["effect"] = verdictToEffect(record.receipt.verdict);
      if (record.receipt.verdict === "REFORMULATE" || record.receipt.verdict === "DENY") {
        event["message"] = record.receipt.reformulation ?? `denied by authority policy ${policy.version}`;
      }
      trace(options, { boundary: "permission", stage: "AUTHORITY_DECIDED", action, verdict: record.receipt.verdict, mapped_permission_effect: event["effect"], receipt: record.receipt, proposal_sha256: record.proposal_sha256, policy_sha256: record.policy_sha256, receipt_id: record.receipt.receipt_id });
    } catch (error) {
      if (error instanceof AuthorityError || options.mandatory) {
        event["effect"] = "deny";
        event["message"] = error instanceof AuthorityError ? `authority fail-closed: ${error.code}` : "authority fail-closed: engine unavailable";
        trace(options, { boundary: "permission", stage: "VALIDATION_REJECTED", action, reason: "fail-closed", mapped_permission_effect: "deny" });
      }
    }
  });

  // Tool execution boundary: rich proposal inspection incl. data-use path.
  await host.tool.hook("execute.before", async (event) => {
    if (event["tool"] !== options.canaryTool) return;
    const key = `tool:${String(event["sessionID"] ?? "")}:${String(event["id"] ?? "")}`;
    try {
      const input = validateInput(canarySchema, event["input"]);
      const absolute = targetInsideDir(options.canaryDir, input.target);
      if (!absolute) throw new AuthorityError("POLICY_INVALID", "canary target escapes the canary directory");
      const policy = loadPolicy();
      const proposal = canaryProposal(key, absolute, input.context_sources ?? []);
      // Bind the marker too: it is not a policy field but is part of the actual effect.
      const record = cache.getOrEvaluate(`${key}:${requestHash(input)}`, proposal, policy);
      trace(options, {
        boundary: "tool.execute.before",
        stage: "AUTHORITY_DECIDED",
        sessionID: event["sessionID"], callID: event["id"],
        tool: event["tool"],
        received_sha256: requestHash(input), proposal_sha256: record.proposal_sha256,
        policy_sha256: record.policy_sha256, receipt: record.receipt,
        enforcement: "authority_canary_before_hook", execution: record.receipt.verdict === "ALLOW" ? "PERMITTED_BY_AUTHORITY" : "PREVENTED_BY_AUTHORITY",
        host_permission: "UNKNOWN", world_effect: "UNKNOWN",
        verdict: record.receipt.verdict,
        receipt_id: record.receipt.receipt_id,
        reformulation: record.receipt.reformulation ?? null,
      });
      if (record.receipt.verdict === "DENY" || record.receipt.verdict === "REFORMULATE") {
        throw new Error(`authority blocked canary invocation: ${record.receipt.verdict}${record.receipt.reformulation ? ` — ${record.receipt.reformulation}` : ""}`);
      }
      if (record.receipt.verdict === "REQUIRE_APPROVAL") {
        throw new Error("authority requires approval before canary execution");
      }
    } catch (error) {
      if (error instanceof AuthorityError) {
        trace(options, { boundary: "tool.execute.before", stage: "VALIDATION_REJECTED", tool: event["tool"], sessionID: event["sessionID"], callID: event["id"], received_sha256: event["input"] === undefined ? null : requestHash(event["input"]), reason: `fail-closed: ${error.code}`, execution: "PREVENTED_BY_AUTHORITY" });
        throw new Error(`authority fail-closed: ${error.code}`);
      }
      throw error;
    }
  });
}

export function CanaryWriteTool(options: GateOptions = gateOptionsFromEnv()): ToolInfo {
  return {
    name: options.canaryTool,
    options: { codemode: false },
    description: "Harmless deterministic canary: write a marker string to a file inside the authority canary directory exactly once. Gated by authority hooks; fails closed outside the canary dir.",
    input: nativeInput(canarySchema),
    async execute(input) {
      const args = validateInput(canarySchema, input);
      const absolute = targetInsideDir(options.canaryDir, args.target);
      if (!absolute) throw new Error("canary target escapes the canary directory");
      mkdirSync(dirname(absolute), { recursive: true });
      const { writeFileSync, existsSync } = await import("node:fs");
      if (existsSync(absolute)) throw new Error("canary target already exists; refusing to overwrite");
      writeFileSync(absolute, args.marker, { flag: "wx" });
      return { content: JSON.stringify({ written: absolute, marker_bytes: args.marker.length }) };
    },
  };
}
