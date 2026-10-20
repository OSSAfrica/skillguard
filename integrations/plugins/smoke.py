#!/usr/bin/env python3
"""Opt-in native-plugin checks with real clients and a loopback model.

The standard plugin is advisory. Verify an actual scan result AND that an
ordinary harmless shell operation still works. No real model API/package install.
Claude installation is exercised in a temporary CLAUDE_CONFIG_DIR; Codex uses
its native installed plugin with per-invocation overrides, never CODEX_HOME.
"""
import argparse
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('client_fixture',ROOT / 'integrations/clients/smoke.py')
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)
PLUGIN = 'skillguard@ossafrica-skillguard'


def probe(client, package):
    with tempfile.TemporaryDirectory(prefix='skillguard-native-',dir='/tmp') as temporary:
        base = Path(temporary).resolve()
        work = base / 'project'
        work.mkdir()
        (work / 'fixture.txt').write_text('Synthetic warmup fixture\n')
        marker = work / 'ordinary-command-ran'
        state = {'client':client,'work':work,'marker':marker,'requests':0,'step':0,'native_step':0,'names':set(),'scan_seen':False,'review_seen':False}
        def select(names):
            if not names:
                return None,{}
            if state['native_step'] == 0:
                if client == 'codex':
                    namespace = next((n for n in names if n and n.startswith('mcp__') and 'skillguard' in n),None)
                    name = 'skillguard_scan_document' if namespace else None
                    if namespace:
                        state['namespace'] = namespace
                else:
                    name = next((n for n in names if n and n.endswith('skillguard_scan_document')),None)
                if name:
                    state['native_step'] = 1
                    state['scan_name'] = name
                    return name,{'content':'npm install synthetic-helper@1.0.0','source':'llms.txt'}
                if state['requests'] < 30:
                    time.sleep(0.2)
                    if client == 'opencode':return 'read',{'path':str(work / 'fixture.txt')}
                    if client == 'claude':return 'Read',{'file_path':str(work / 'fixture.txt')}
                    return 'exec_command',{'cmd':'/bin/cat '+shlex.quote(str(work / 'fixture.txt'))}
            elif state['native_step'] == 1:
                state['native_step'] = 2
                command = '/usr/bin/touch '+shlex.quote(str(marker))
                return {'claude':'Bash','codex':'exec_command','opencode':'shell'}[client],{'cmd' if client=='codex' else 'command':command}
            return None,{}
        state['select'] = select
        server = http.server.ThreadingHTTPServer(('127.0.0.1',0),fixture_module.Model)
        server.fixture = state
        threading.Thread(target=server.serve_forever,daemon=True).start()
        url = 'http://127.0.0.1:'+str(server.server_port)
        env = dict(os.environ)
        env.update(PWD=str(work),ANTHROPIC_API_KEY='synthetic-fixture',ANTHROPIC_BASE_URL=url,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1',DISABLE_AUTOUPDATER='1',SKILLGUARD_FIXTURE_KEY='synthetic-fixture')
        for key in ['ANTHROPIC_AUTH_TOKEN','CLAUDE_CODE_OAUTH_TOKEN']:
            env.pop(key,None)
        if client == 'claude':
            env['CLAUDE_CONFIG_DIR'] = str(base / 'claude-config')
            for args in [['plugin','marketplace','add',str(ROOT)],['plugin','install',PLUGIN]]:
                subprocess.run(['claude',*args],env=env,cwd=work,capture_output=True,timeout=30,check=True)
            command = ['claude','--print','--model','fixture','--tools','Read,Bash','--allowedTools','Read,Bash,mcp__plugin_skillguard_skillguard__*','--setting-sources','user','--output-format','json','Run the synthetic native plugin test, then stop.']
        elif client == 'codex':
            installed = json.loads(subprocess.check_output(['codex','plugin','list','--json'],text=True))['installed']
            assert any(p['pluginId']==PLUGIN for p in installed),'Install the native Codex plugin first'
            command = ['codex','exec','--ephemeral','--skip-git-repo-check','--ignore-rules','--json','-C',str(work),'-s','workspace-write','-c','approval_policy="never"','-c','model="fixture"','-c','model_provider="fixture"','-c','model_providers.fixture={name="fixture",base_url='+json.dumps(url+'/v1')+',env_key="SKILLGUARD_FIXTURE_KEY",wire_api="responses"}','-c','features.plugins=true','-c','features.apps=false','-c','features.code_mode=false','-c','features.unified_exec=true','-c','features.shell_snapshot=false','-c','mcp_servers={}']
            for plugin in installed:
                command += ['-c','plugins.'+json.dumps(plugin['pluginId'])+'.enabled='+('true' if plugin['pluginId']==PLUGIN else 'false')]
            command += ['Run the synthetic native plugin test, then stop.']
        else:
            env['XDG_CONFIG_HOME'] = str(base / 'opencode-config')
            for key in ['OPENCODE_CONFIG','OPENCODE_CONFIG_DIR','OPENCODE_CLI_CONFIG_CONTENT']:
                env.pop(key,None)
            env['OPENCODE_CONFIG_PROJECT_DISABLE'] = 'true'
            env['OPENCODE_CONFIG_CONTENT'] = json.dumps({'model':'fixture/fixture','small_model':'fixture/fixture','enabled_providers':['fixture'],'provider':{'fixture':{'npm':'@ai-sdk/openai-compatible','options':{'baseURL':url+'/v1','apiKey':'synthetic-fixture'},'models':{'fixture':{'name':'fixture','limit':{'context':1000000,'output':4096}}}}},'plugins':[package.as_uri() if isinstance(package,Path) else package]})
            command = ['opencode','run','--standalone','--auto','--model','fixture/fixture','--agent','build','--format','json','Run the synthetic native plugin test, then stop.']
        process = None
        try:
            process = subprocess.Popen(command,cwd=work,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            stdout,stderr = process.communicate(timeout=90)
            result = {'client':client,'passed':process.returncode==0 and state['scan_seen'] and marker.exists(),'native_scan_received':state['scan_seen'],'ordinary_command_executed':marker.exists(),'enforcement':'advisory','exit_code':process.returncode}
            if not result['passed']:
                result['diagnostic']='Native plugin discovery or MCP call failed; full client logs were not printed.'
                result['scan_tool'] = state.get('scan_name')
            return result
        finally:
            if process and process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL)
                process.communicate()
            if client == 'claude':
                subprocess.run(['claude','plugin','uninstall',PLUGIN,'--json'],env=env,cwd=work,capture_output=True,timeout=30,check=True)
            server.shutdown()
            server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client',action='append',choices=['claude','codex','opencode'])
    parser.add_argument('--opencode-plugin',default=str(ROOT / 'plugins/skillguard'))
    parser.add_argument('--opencode-package',help='Pinned package specifier to test the package-manager copy')
    args = parser.parse_args()
    failed = False
    for client in args.client or ['claude','codex','opencode']:
        result = probe(client,args.opencode_package or Path(args.opencode_plugin).resolve(strict=True))
        print(json.dumps(result),flush=True)
        failed |= not result['passed']
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
