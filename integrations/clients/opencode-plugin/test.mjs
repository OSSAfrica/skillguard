import test from "node:test";
import assert from "node:assert/strict";
import plugin from "./index.mjs";

test("executors and shell creation are denied; MCP tools and editing remain available", async () => {
  const hooks = {};
  await plugin.setup({ tool: { async hook(name, fn) { hooks[name] = fn; } }, shell: { async hook(name, fn) { hooks[name] = fn; } } });
  for (const tool of ["execute", "shell", "bash", "terminal", "code", "subagent"]) {
    assert.throws(() => hooks["execute.before"]({tool, input:{}}), /quarantined/);
  }
  assert.throws(() => hooks["create.before"]({}), /quarantined/);
  for (const tool of ["skillguard_skillguard_scan_document", "skillguard_skillguard_assess_action", "read", "edit"]) {
    assert.doesNotThrow(() => hooks["execute.before"]({tool, input:{}}));
  }
});
