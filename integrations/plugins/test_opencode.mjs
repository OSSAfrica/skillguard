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

const { runtimeResult } = await import('../../plugins/skillguard/index.mjs');
test('nonzero helper exit preserves structured diagnostic instead of inventing a transport failure', async () => {
  const response = {status:'unavailable', scan_available:false, enforcement:'advisory', execution_authorized:false, reason:'runtime_cache_inside_workspace', next_step:'Use project directory', mcp_connection:'not_checked'};
  const result = await runtimeResult('status', async () => {throw Object.assign(new Error('exit 2'), {stdout:JSON.stringify(response), code:2});});
  assert.deepEqual(result,response);
});
test('missing Python, timeout and malformed helper output have fixed diagnostics', async () => {
  for (const [error, reason] of [[{code:'ENOENT'},'python_unavailable'], [{killed:true},'helper_timeout'], [{stdout:'not json'},'helper_failed']]) {
    const result=await runtimeResult('status',async()=>{throw error;});
    assert.equal(result.reason,reason);
    assert.equal(result.execution_authorized,false);
    assert.equal(result.mcp_connection,'not_checked');
    assert.ok(!JSON.stringify(result).includes('not json'));
  }
});
test('ready helper response retains version information',async()=>{
  const response={status:'ready',scan_available:true,enforcement:'advisory',execution_authorized:false,plugin_version:'0.2.0',pinned_engine_version:'0.13.0'};
  assert.deepEqual(await runtimeResult('status',async()=>({stdout:JSON.stringify(response)})),response);
});
