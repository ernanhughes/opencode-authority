import { readFileSync } from "node:fs";
import { evaluate, type EvaluateOptions } from "./engine/index.ts";
import {
  AuthorityError,
  type AuthorityPolicy,
  type AuthorityProposal,
  type AuthorityReceipt,
  type Verdict,
} from "./engine/types.ts";

export interface GateOptions {
  enabled: boolean;
  mandatory: boolean;
  policyFile?: string;
  traceDir: string;
  canaryTool: string;
  canaryDir: string;
}

export function gateOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): GateOptions {
  const traceDir = env["AUTHORITY_TRACE_DIR"] ?? `${env["TEMP"] ?? "/tmp"}/authority-traces`;
  const canaryDir = env["AUTHORITY_CANARY_DIR"] ?? `${env["TEMP"] ?? "/tmp"}/authority-canary`;
  return {
    enabled: env["AUTHORITY_ENABLED"] !== "0",
    mandatory: env["AUTHORITY_MANDATORY"] !== "0",
    policyFile: env["AUTHORITY_POLICY_FILE"],
    traceDir,
    canaryTool: "authority_canary_write",
    canaryDir,
  };
}

export function loadPolicyFile(path: string): AuthorityPolicy {
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch {
    throw new AuthorityError("POLICY_INVALID", `cannot read policy file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AuthorityError("POLICY_INVALID", `policy file is not valid JSON: ${path}`);
  }
  return parsed as AuthorityPolicy;
}

/** OpenCode native permission effect mapped from an Authority verdict.
 *  REFORMULATE maps to deny-with-guidance: the current invocation must not
 *  execute, but the receipt (retained separately) stays REFORMULATE. */
export function verdictToEffect(verdict: Verdict): "allow" | "ask" | "deny" {
  switch (verdict) {
    case "ALLOW":
      return "allow";
    case "REQUIRE_APPROVAL":
      return "ask";
    case "DENY":
    case "REFORMULATE":
      return "deny";
  }
}

export interface EvaluationRecord {
  evaluation_id: string;
  receipt: AuthorityReceipt;
  at: string;
}

/** One canonical evaluation per invocation id; both hooks consume the same result. */
export class EvaluationCache {
  private readonly seen = new Map<string, EvaluationRecord>();
  getOrEvaluate(
    key: string,
    proposal: AuthorityProposal,
    policy: AuthorityPolicy,
    options: EvaluateOptions = {},
  ): EvaluationRecord {
    const existing = this.seen.get(key);
    if (existing) return existing;
    const receipt = evaluate(proposal, policy, options);
    const record: EvaluationRecord = { evaluation_id: receipt.receipt_id, receipt, at: new Date().toISOString() };
    this.seen.set(key, record);
    return record;
  }
  size(): number {
    return this.seen.size;
  }
}
