import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join, normalize, resolve, sep } from "node:path";
import type { Info as ToolInfo } from "@opencode/plugin/promise/tool";
import { EvaluationCache, gateOptionsFromEnv, loadPolicyFile, verdictToEffect, type GateOptions } from "./gate.ts";
import { AuthorityError, type AuthorityPolicy, type AuthorityProposal } from "./engine/types.ts";

function trace(options: GateOptions, record: Record<string, unknown>): void {
  try {
    mkdirSync(options.traceDir, { recursive: true });
    appendFileSync(join(options.traceDir, "authority-gate.jsonl"), JSON.stringify({ ts: new Date().toISOString(), ...record }) + "\n");
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
 *  unnecessary unless the caller marks them required. */
function canaryProposal(marker: string, target: string, contextSources: string[]): AuthorityProposal {
  void marker;
  return {
    proposal_id: `canary-${Date.now().toString(36)}`,
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
      trace(options, { boundary: "permission", host_decision: "deny-final", action: event["action"] });
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
      trace(options, { boundary: "permission", action, verdict: record.receipt.verdict, receipt_id: record.receipt.receipt_id });
    } catch (error) {
      if (options.mandatory) {
        event["effect"] = "deny";
        event["message"] = error instanceof AuthorityError ? `authority fail-closed: ${error.code}` : "authority fail-closed: engine unavailable";
        trace(options, { boundary: "permission", action, verdict: "DENY", reason: "fail-closed" });
      }
    }
  });

  // Tool execution boundary: rich proposal inspection incl. data-use path.
  await host.tool.hook("execute.before", async (event) => {
    if (event["tool"] !== options.canaryTool) return;
    const input = (event["input"] ?? {}) as { marker?: unknown; target?: unknown; context_sources?: unknown };
    const marker = typeof input["marker"] === "string" ? input["marker"] : "";
    const target = typeof input["target"] === "string" ? input["target"] : "";
    const contextSources = Array.isArray(input["context_sources"]) ? input["context_sources"].filter((s): s is string => typeof s === "string") : [];
    const absolute = targetInsideDir(options.canaryDir, target);
    const key = `tool:${String(event["id"] ?? "")}`;
    try {
      if (!absolute) throw new AuthorityError("POLICY_INVALID", "canary target escapes the canary directory");
      const policy = loadPolicy();
      const record = cache.getOrEvaluate(key, canaryProposal(marker, absolute, contextSources), policy);
      trace(options, {
        boundary: "tool.execute.before",
        tool: event["tool"],
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
      if (error instanceof AuthorityError && options.mandatory) {
        trace(options, { boundary: "tool.execute.before", tool: event["tool"], verdict: "DENY", reason: `fail-closed: ${error.code}` });
        throw new Error(`authority fail-closed: ${error.code}`);
      }
      throw error;
    }
  });
}

export function CanaryWriteTool(options: GateOptions = gateOptionsFromEnv()): ToolInfo {
  return {
    name: options.canaryTool,
    description: "Harmless deterministic canary: write a marker string to a file inside the authority canary directory exactly once. Gated by authority hooks; fails closed outside the canary dir.",
    input: {
      type: "object",
      properties: {
        marker: { type: "string", minLength: 1 },
        target: { type: "string", minLength: 1 },
        context_sources: { type: "array", items: { type: "string" } },
      },
      required: ["marker", "target"],
      additionalProperties: false,
    },
    async execute(input) {
      const args = input as { marker: string; target: string };
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
