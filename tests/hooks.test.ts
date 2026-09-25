import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { registerAuthorityGate } from "../src/hooks.ts";
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
});
