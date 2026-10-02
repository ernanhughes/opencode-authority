import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CanaryWriteTool, registerAuthorityGate } from "../src/hooks.ts";
import { verdictToEffect } from "../src/gate.ts";
import type { GateOptions } from "../src/gate.ts";

interface Captured {
  toolTransforms: Array<{ add: (t: { name: string }) => void }>;
  permissionHooks: Array<(e: Record<string, unknown>) => Promise<void> | void>;
  toolHooks: Array<(e: Record<string, unknown>) => Promise<void> | void>;
}

function fakeHost(): { host: Parameters<typeof registerAuthorityGate>[0]; captured: Captured } {
  const captured: Captured = { toolTransforms: [], permissionHooks: [], toolHooks: [] };
  const host = {
    tool: {
      transform: async (cb: (editor: { add: (t: { name: string }) => void }) => void): Promise<void> => {
        captured.toolTransforms.push({ add: () => undefined });
        void cb;
      },
      hook: async (name: string, cb: (e: Record<string, unknown>) => Promise<void> | void): Promise<void> => {
        void name;
        captured.toolHooks.push(cb);
      },
    },
    permission: {
      hook: async (name: string, cb: (e: Record<string, unknown>) => Promise<void> | void): Promise<void> => {
        void name;
        captured.permissionHooks.push(cb);
      },
    },
  };
  return { host, captured };
}

const POLICY = {
  version: "hook-t1",
  data_use: [{ id: "canary-data", purpose: "authority-canary", data_scope: ["canary:target:*"], permitted_operations: ["ACCESS", "PROCESS"] }],
  actions: [{ id: "canary-act", purpose: "authority-canary", action_scope: ["canary-write"], approval: "none" }],
};

function options(policyFile: string, extra: Partial<GateOptions> = {}): GateOptions {
  const dir = mkdtempSync(join(tmpdir(), "authz-hook-"));
  return {
    enabled: true,
    mandatory: true,
    policyFile,
    traceDir: join(dir, "traces"),
    canaryTool: "authority_canary_write",
    canaryDir: join(dir, "canary"),
    ...extra,
  };
}

function writePolicy(dir: string, policy: unknown): string {
  const path = join(dir, "policy.json");
  writeFileSync(path, JSON.stringify(policy));
  return path;
}

void describe("verdict mapping", () => {
  void it("maps four verdicts without collapsing REFORMULATE into ask", () => {
    assert.equal(verdictToEffect("ALLOW"), "allow");
    assert.equal(verdictToEffect("REQUIRE_APPROVAL"), "ask");
    assert.equal(verdictToEffect("DENY"), "deny");
    assert.equal(verdictToEffect("REFORMULATE"), "deny");
  });
});

void describe("permission hook", () => {
  void it("never weakens an explicit host deny (HOST_DENY_DOMINANCE)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-"));
    const { host, captured } = fakeHost();
    await registerAuthorityGate(host, options(writePolicy(dir, POLICY)));
    const event: Record<string, unknown> = { effect: "deny", action: "canary-write", sessionID: "s1" };
    await captured.permissionHooks[0](event);
    assert.equal(event["effect"], "deny");
  });
  void it("ignores non-canary actions", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-"));
    const { host, captured } = fakeHost();
    await registerAuthorityGate(host, options(writePolicy(dir, POLICY)));
    const event: Record<string, unknown> = { effect: "allow", action: "file-read", sessionID: "s1" };
    await captured.permissionHooks[0](event);
    assert.equal(event["effect"], "allow");
  });
  void it("fails closed on missing policy when mandatory", async () => {
    const { host, captured } = fakeHost();
    const dir = mkdtempSync(join(tmpdir(), "authz-"));
    await registerAuthorityGate(host, {
      enabled: true,
      mandatory: true,
      traceDir: join(dir, "t"),
      canaryTool: "authority_canary_write",
      canaryDir: join(dir, "c"),
    });
    const event: Record<string, unknown> = { effect: "allow", action: "canary-write", sessionID: "s1" };
    await captured.permissionHooks[0](event);
    assert.equal(event["effect"], "deny");
  });
  void it("malformed policy cannot fail open with mandatory disabled", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-permission-invalid-"));
    const { host, captured } = fakeHost();
    await registerAuthorityGate(host, options(writePolicy(dir, { ...POLICY, actions: [{ ...POLICY.actions[0], approval: "auto" }] }), { mandatory: false }));
    const event: Record<string, unknown> = { effect: "allow", action: "canary-write", sessionID: "s1" };
    await captured.permissionHooks[0](event);
    assert.equal(event["effect"], "deny");
  });
});

void describe("tool hook", () => {
  void it("throwing blocks the invocation (blocking mechanism)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-"));
    const { host, captured } = fakeHost();
    // Policy with no canary grants: proposal must deny.
    const empty = { version: "empty", data_use: [], actions: [] };
    await registerAuthorityGate(host, options(writePolicy(dir, empty)));
    await assert.rejects(async () => {
      await captured.toolHooks[0]({ tool: "authority_canary_write", id: "call-1", input: { marker: "m", target: "t.txt" } });
    }, /authority/);
  });
  void it("ignores other tools", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-"));
    const { host, captured } = fakeHost();
    await registerAuthorityGate(host, options(writePolicy(dir, POLICY)));
    await captured.toolHooks[0]({ tool: "unrelated_tool", id: "call-2", input: {} });
    assert.ok(!existsSync(join(dir, "canary")));
  });
  void it("same invocation id reuses one evaluation (canonical evaluation)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-"));
    const { host, captured } = fakeHost();
    const opts = options(writePolicy(dir, POLICY));
    await registerAuthorityGate(host, opts);
    const event = { tool: "authority_canary_write", id: "call-9", input: { marker: "m", target: "t.txt" } };
    await captured.toolHooks[0](event);
    await captured.toolHooks[0](event);
    const lines = readFileSync(join(opts.traceDir, "authority-gate.jsonl"), "utf-8").trim().split("\n").map((l) => JSON.parse(l));
    const toolLines = lines.filter((l) => l.boundary === "tool.execute.before");
    assert.equal(toolLines.length, 2);
    assert.equal(toolLines[0].receipt_id, toolLines[1].receipt_id);
  });
  for (const [verdict, policy, context] of [
    ["ALLOW", POLICY, []],
    ["DENY", { version: "deny", data_use: [], actions: [] }, []],
    ["REQUIRE_APPROVAL", { ...POLICY, actions: [{ ...POLICY.actions[0], approval: "required" }] }, []],
    ["REFORMULATE", POLICY, ["mailbox:all"]],
  ] as const) void it(`${verdict} governs the canary effect independently of host permission`, async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-verdict-"));
    const { host, captured } = fakeHost();
    const opts = options(writePolicy(dir, policy));
    await registerAuthorityGate(host, opts);
    const input = { marker: "expected", target: "marker.txt", context_sources: [...context] };
    assert.equal(CanaryWriteTool(opts).options?.codemode, false);
    let entered = false;
    const invoke = async () => {
      await captured.toolHooks[0]({ tool: opts.canaryTool, sessionID: "s", id: "verdict", input });
      entered = true;
      return CanaryWriteTool(opts).execute(input, undefined as never);
    };
    if (verdict === "ALLOW") await invoke();
    else await assert.rejects(invoke, /authority/);
    assert.equal(entered, verdict === "ALLOW");
    assert.equal(existsSync(join(opts.canaryDir, "marker.txt")), verdict === "ALLOW");
    const records = readFileSync(join(opts.traceDir, "authority-gate.jsonl"), "utf8").trim().split("\n").map(JSON.parse as (s: string) => any);
    assert.equal(records[0].receipt.verdict, verdict);
    assert.equal(records[0].host_permission, "UNKNOWN");
  });

  for (const bad of [
    { marker: "m", target: "bad.txt", unexpected: true },
    { marker: "m", target: "bad.txt", context_sources: [false] },
    { marker: "m", target: "bad.txt", context_sources: "mailbox:all" },
    { marker: 1, target: "bad.txt" },
    { marker: "m" },
  ]) void it(`malformed canary ${JSON.stringify(bad)} cannot be filtered into ALLOW`, async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-malformed-"));
    const opts = options(writePolicy(dir, POLICY), { mandatory: false });
    const { host, captured } = fakeHost();
    await registerAuthorityGate(host, opts);
    await assert.rejects(async () => captured.toolHooks[0]({ tool: opts.canaryTool, id: "bad", input: bad }), /fail-closed/);
    await assert.rejects(() => CanaryWriteTool(opts).execute(bad, undefined as never), /Invalid|Unrecognized/);
    assert.equal(existsSync(join(opts.canaryDir, "bad.txt")), false);
    const records = readFileSync(join(opts.traceDir, "authority-gate.jsonl"), "utf8").trim().split("\n").map(JSON.parse as (s: string) => any);
    assert.equal(records[0].stage, "VALIDATION_REJECTED");
    assert.equal(records[0].verdict, undefined);
  });

  void it("changed context or policy cannot reuse a prior canary ALLOW", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-cache-"));
    const file = writePolicy(dir, POLICY);
    const opts = options(file);
    const { host, captured } = fakeHost();
    await registerAuthorityGate(host, opts);
    const base = { tool: opts.canaryTool, sessionID: "s", id: "reused", input: { marker: "m", target: "x.txt" } };
    await captured.toolHooks[0](base);
    await assert.rejects(async () => captured.toolHooks[0]({ ...base, input: { ...base.input, context_sources: ["mailbox:all"] } }), /REFORMULATE/);
    writeFileSync(file, JSON.stringify({ ...POLICY, actions: [] }));
    await assert.rejects(async () => captured.toolHooks[0](base), /fail-closed/);
    assert.equal(existsSync(join(opts.canaryDir, "x.txt")), false);
  });

  void it("malformed nested policy fails closed without a fabricated DENY receipt", async () => {
    const dir = mkdtempSync(join(tmpdir(), "authz-policy-"));
    const opts = options(writePolicy(dir, { ...POLICY, actions: [{ ...POLICY.actions[0], approval: "auto" }] }));
    const { host, captured } = fakeHost();
    await registerAuthorityGate(host, opts);
    await assert.rejects(async () => captured.toolHooks[0]({ tool: opts.canaryTool, id: "invalid", input: { marker: "m", target: "x.txt" } }), /POLICY_INVALID/);
    assert.equal(existsSync(join(opts.canaryDir, "x.txt")), false);
  });
});
