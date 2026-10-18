"""Disposable Linux-only cross-UID harness. No real credentials or host mounts.

Root is a trusted test controller, not the agent. Agent processes drop all
capabilities and set no_new_privs. Run in the container documented in the report.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

BROKER = 21001
AGENT = 21002
OUTSIDER = 21003
CLIENTS = 21100
LAB = Path("/lab")


def command(uid: int, code: str, *, clients: bool = False) -> list[str]:
    groups = [f"--groups={CLIENTS}"] if clients else ["--clear-groups"]
    return ["setpriv", f"--reuid={uid}", f"--regid={uid}", *groups,
            "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            sys.executable, "-c", code]


def as_user(uid: int, code: str, *, clients: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command(uid, code, clients=clients), capture_output=True, text=True,
                          timeout=45, env={"PATH": "/code/.venv/bin:/usr/bin:/bin", "HOME": "/tmp"})


def main() -> None:
    LAB.mkdir(exist_ok=True)
    for name, uid, gid, mode in [("broker", BROKER, BROKER, 0o700),
                                  ("agent", AGENT, AGENT, 0o700),
                                  ("socket", BROKER, CLIENTS, 0o750)]:
        path = LAB / name
        path.mkdir()
        path.chmod(mode)
        os.chown(path, uid, gid)
    setup = '''
import json,subprocess
from pathlib import Path
from git_broker.vault import Vault
from git_broker.state import State
from git_broker.files import atomic_write
root=Path('/lab/broker')
subprocess.run(['git','init','--bare',str(root/'remote.git')],check=True,capture_output=True)
vault=Vault.local(root/'vault',initialize=True)
vault.put('canary','https',b'FAKE-CREDENTIAL-FOR-ISOLATION-ONLY')
atomic_write(root/'secret-canary',b'FAKE-CREDENTIAL-FOR-ISOLATION-ONLY')
policy={'version':1,'repositories':{'test':{'backend':'local_test','remote':'/lab/broker/remote.git','automation_reviewed':True}},
'principals':{'agent':{'rules':[{'repository':'test','operations':['read','push'],'branches':['feature']}]}}}
atomic_write(root/'policy.json',json.dumps(policy).encode())
state=State(root)
session=state.issue_session('agent',300,10)
atomic_write(root/'handoff',str(session['token']).encode())
'''
    setup_result = as_user(BROKER, setup)
    assert setup_result.returncode == 0, "broker setup failed: " + setup_result.stderr
    token = (LAB / "broker/handoff").read_bytes()
    path = LAB / "agent/session"
    path.write_bytes(token)
    path.chmod(0o600)
    os.chown(path, AGENT, AGENT)
    start = "from git_broker.cli import main; import sys; sys.argv=['git-broker','--root','/lab/broker','serve','--socket','/lab/socket/broker.sock','--socket-gid','21100','--allow-local-test']; main()"
    daemon = subprocess.Popen(command(BROKER, start, clients=True), stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, text=True)
    results: list[dict[str, object]] = []

    def check(name: str, code: str, *, uid: int = AGENT, clients: bool = True) -> None:
        result = as_user(uid, code, clients=clients)
        passed = result.returncode == 0
        results.append({"check": name, "passed": passed})
        if not passed:
            raise AssertionError(name)

    def forbidden(name: str, expression: str, *, uid: int = AGENT, clients: bool = True) -> None:
        code = "import os,socket,signal\nfrom pathlib import Path\ntry:\n    " + expression + "\nexcept PermissionError:\n    pass\nelse:\n    raise AssertionError('unexpected access')"
        check(name, code, uid=uid, clients=clients)

    try:
        for _ in range(100):
            if (LAB / 'socket/broker.sock').exists():
                break
            assert daemon.poll() is None, 'daemon exited'
            time.sleep(0.05)
        else:
            raise AssertionError('socket startup timeout')
        check('authorized agent can call scope through group socket', "from pathlib import Path; from git_broker.client import Client; assert Client('/lab/socket/broker.sock',Path('/lab/agent/session')).call({'action':'scope'})['principal']=='agent'")
        push = "import subprocess,json; from pathlib import Path; p=Path('/lab/agent/work'); subprocess.run(['git','init',str(p)],check=True,capture_output=True); subprocess.run(['git','-C',str(p),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','--allow-empty','-m','Cross UID test'],check=True,capture_output=True); r=subprocess.run(['python','-m','git_broker.client','--socket','/lab/socket/broker.sock','--token-file','/lab/agent/session','--repository','test','--branch','feature'],cwd=p,check=True,capture_output=True,text=True); assert json.loads(r.stdout)['state']=='succeeded'"
        check('cross-UID agent feature push through broker succeeds', push)
        check('cross-UID agent protected branch push denied', "import subprocess; r=subprocess.run(['python','-m','git_broker.client','--socket','/lab/socket/broker.sock','--token-file','/lab/agent/session','--repository','test','--branch','main'],cwd='/lab/agent/work',capture_output=True); assert r.returncode!=0")
        check('broker confirms only feature ref exists', "import subprocess; r=subprocess.check_output(['git','--git-dir=/lab/broker/remote.git','for-each-ref','--format=%(refname)'],text=True); assert r.strip()=='refs/heads/feature'", uid=BROKER)
        forbidden('agent cannot bypass broker to read remote refs', "Path('/lab/broker/remote.git/refs/heads/feature').read_bytes()")
        for name, location in [('vault master key','vault/master.key'),('encrypted credential','vault/canary.https.sealed'),('policy','policy.json'),('plaintext canary','secret-canary')]:
            forbidden('agent cannot read '+name, f"Path('/lab/broker/{location}').read_bytes()")
        forbidden('agent cannot edit policy', "Path('/lab/broker/policy.json').write_text('{}')")
        forbidden('agent cannot replace vault key', "Path('/lab/broker/vault/master.key').write_bytes(b'x'*32)")
        forbidden('agent cannot unlink broker socket', "os.unlink('/lab/socket/broker.sock')")
        forbidden('outsider cannot connect socket', "socket.socket(socket.AF_UNIX).connect('/lab/socket/broker.sock')",uid=OUTSIDER,clients=False)
        forbidden('outsider cannot read agent session', "Path('/lab/agent/session').read_bytes()",uid=OUTSIDER,clients=False)
        forbidden('agent cannot read broker process environment', f"Path('/proc/{daemon.pid}/environ').read_bytes()")
        forbidden('agent cannot open broker process memory', f"open('/proc/{daemon.pid}/mem','rb')")
        forbidden('agent cannot signal broker', f"os.kill({daemon.pid},signal.SIGTERM)")
        forbidden('agent cannot become root', "os.setuid(0)")
        check('ptrace attach to broker denied', f"import ctypes,errno; libc=ctypes.CDLL(None,use_errno=True); assert libc.ptrace(16,{daemon.pid},0,0)==-1; assert ctypes.get_errno()==errno.EPERM")
        check('agent has no capabilities and no_new_privs is set', "from pathlib import Path; s=Path('/proc/self/status').read_text(); d=dict(line.split(':',1) for line in s.splitlines() if ':' in line); assert all(int(d[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapInh','CapBnd','CapAmb']); assert d['NoNewPrivs'].strip()=='1'")
        check('no Docker socket or SSH agent available', "import os; from pathlib import Path; assert not Path('/var/run/docker.sock').exists(); assert not os.environ.get('SSH_AUTH_SOCK')")
        check('no external network interface', "from pathlib import Path; assert {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'}")
        check('public egress unavailable', "import socket\ntry:\n socket.create_connection(('1.1.1.1',443),timeout=1)\nexcept OSError:\n pass\nelse:\n raise AssertionError('egress available')")
        check('socket access without token is insufficient', "import httpx; c=httpx.Client(transport=httpx.HTTPTransport(uds='/lab/socket/broker.sock')); r=c.post('http://localhost/rpc',json={'action':'scope'}); assert r.status_code==400")
        check('agent cannot call owner policy operation', "from pathlib import Path; import httpx; from git_broker.client import Client\ntry:\n Client('/lab/socket/broker.sock',Path('/lab/agent/session')).call({'action':'policy-apply'})\nexcept httpx.HTTPStatusError as e:\n assert e.response.status_code==400\nelse:\n raise AssertionError('admin allowed')")
        result = as_user(AGENT, "import subprocess; raise SystemExit(subprocess.call(['python','-m','pytest','-q','-p','no:cacheprovider','/code/tests']))", clients=True)
        # Full suite is a separate evidence category, not another isolation assertion.
        assert result.returncode == 0, 'regression suite failed'
        print(result.stdout.strip())
        report = {'platform': 'Linux x86_64 Desktop container', 'broker_uid': BROKER,
            'agent_uid': AGENT, 'outsider_uid': OUTSIDER, 'checks': results,
            'passed': len(results), 'real_credentials_used': False,
            'cross_uid_only_not_parser_sandbox': True,
            'regression_output': result.stdout.strip()}
        Path('/lab/isolation-results.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
    finally:
        daemon.terminate()
        daemon.communicate(timeout=10)


if __name__ == '__main__':
    main()
