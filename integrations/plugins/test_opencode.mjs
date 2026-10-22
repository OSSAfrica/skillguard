import test from "node:test";
import assert from "node:assert/strict";
import plugin from "../../plugins/skillguard/index.mjs";

test("native plugin adds direct fixed MCP wiring and commands without changing other execution paths", async () => {
  const servers = new Map([["unrelated", {type:"remote", url:"https://example.invalid"}]]);
  const commands = [];
  const ctx = {
    mcp: {async transform(fn) {fn({set(name, value) {servers.set(name,value);}});}},
    command: {async transform(fn) {fn({add(value) {commands.push(value);}});}},
  };
  await plugin.setup(ctx);
  assert.deepEqual(servers.get("unrelated"), {type:"remote",url:"https://example.invalid"});
  const server = servers.get("ossafrica_skillguard_native");
  assert.equal(server.codemode, false);
  assert.deepEqual(server.command.slice(0,2), ["python3","-I"]);
  assert.ok(server.command[2].endsWith("/plugins/skillguard/runtime.py"));
  assert.equal(server.command[3],"mcp");
  assert.equal(server.command.length,4);
  assert.deepEqual(commands.map(c=>c.name),["skillguard-setup","skillguard-status","skillguard-review"]);
});
