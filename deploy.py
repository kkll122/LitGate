"""Deterministic local installer. Credentials are generated locally and never printed."""
import argparse
import asyncio
import contextlib
import csv
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

FILES = ('litgate.py','search_core.py','mcp_client.py','deploy.py','requirements.txt','install.ps1','register-mcp.ps1','SKILL.md')
VERSION = '2026.10.08-auto1'

class InstallError(Exception):
    pass

def default_root():
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA',Path.home()/'AppData'/'Local'))/'LitGate'/'auto'
    if sys.platform == 'darwin':
        return Path.home()/'Library'/'Application Support'/'LitGate'/'auto'
    return Path(os.environ.get('XDG_DATA_HOME',Path.home()/'.local'/'share'))/'litgate'/'auto'

def executable(root):
    return root/'app'/'.venv'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')

def hidden_flags():
    return subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0

def protect(path):
    """Remove inherited broad permissions, including on existing runtime files."""
    if os.name != 'nt':
        path.chmod(0o700 if path.is_dir() else 0o600)
        return
    import ctypes
    from ctypes import wintypes
    result=subprocess.run(['whoami','/user','/fo','csv','/nh'],capture_output=True,check=True,creationflags=hidden_flags())
    sid=next((cell for row in csv.reader(result.stdout.decode(errors='replace').splitlines()) for cell in row if cell.startswith('S-1-')),None)
    if not sid or not all(c.isdigit() or c in 'S-' for c in sid):
        raise InstallError('Cannot determine current Windows user SID')
    flags='OICI' if path.is_dir() else ''
    sddl=f'D:P(A;{flags};FA;;;{sid})(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)'
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.ULONG)]
    adv.SetFileSecurityW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.c_void_p]
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    descriptor=ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not adv.SetFileSecurityW(str(path),0x80000004,descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:kernel.LocalFree(descriptor)

def atomic(path,data,private=False):
    path.parent.mkdir(parents=True,exist_ok=True)
    raw=data.encode('utf-8') if isinstance(data,str) else data
    fd,name=tempfile.mkstemp(prefix='.litgate-',dir=path.parent)
    temporary=Path(name)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        if private:protect(temporary)
        os.replace(temporary,path)
    finally:
        if temporary.exists():temporary.unlink()

@contextlib.contextmanager
def locked(data,timeout=40):
    data.mkdir(parents=True,exist_ok=True)
    with (data/'runtime.lock').open('a+b') as stream:
        stream.seek(0);stream.write(b'0');stream.flush()
        until=time.monotonic()+timeout
        while True:
            try:
                stream.seek(0)
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic()>=until:raise InstallError('Another LitGate operation is still running')
                time.sleep(.15)
        try:yield
        finally:
            stream.seek(0)
            if os.name=='nt':msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)

def read_state(root):
    path=root/'data'/'runtime.json'
    if not path.exists():raise InstallError('Run install before starting MCP')
    value=json.loads(path.read_text(encoding='utf-8'))
    if value.get('root')!=str(root.resolve()) or not 1<=int(value.get('port',0))<=65535:
        raise InstallError('Invalid runtime metadata; do not copy runtime data to another installation')
    uuid.UUID(value['installation_id'])
    return value

def state_write(root,value):
    atomic(root/'data'/'runtime.json',json.dumps(value,ensure_ascii=False,indent=2),True)

def gateway_url(state):return f"http://127.0.0.1:{state['port']}"

def http_json(url,headers=None,timeout=2):
    # Local calls must never be routed through a configured external HTTP proxy.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(urllib.request.Request(url,headers=headers or {}),timeout=timeout) as response:
        return json.loads(response.read())

def health(state):
    try:
        result=http_json(gateway_url(state)+'/healthz',timeout=.7)
        return result.get('ok') is True and result.get('installation_id')==state['installation_id']
    except (OSError,ValueError):return False

def own_process(root,pid):
    if not pid:return False
    pid=int(pid)
    if os.name=='nt':
        command=f"[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); (Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}').CommandLine"
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],capture_output=True,encoding='utf-8',errors='replace',creationflags=hidden_flags())
        command_line=result.stdout
    else:
        try:command_line=Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0',b' ').decode()
        except OSError:
            command_line=subprocess.run(['ps','-p',str(pid),'-o','args='],capture_output=True,text=True).stdout
    return str(root/'app'/'litgate.py') in command_line and str(root/'data'/'litgate.db') in command_line

def stop(root):
    with locked(root/'data'):
        state=read_state(root)
        pid=state.get('pid')
        if own_process(root,pid):
            os.kill(int(pid),signal.SIGTERM)
            until=time.monotonic()+8
            while health(state) and time.monotonic()<until:time.sleep(.15)
            if health(state):raise InstallError('Owned gateway did not stop')
        elif health(state):
            raise InstallError('Gateway identity matches but PID ownership cannot be confirmed; no process was stopped')
        state['pid']=None;state_write(root,state)

def free_port(preferred):
    for port in range(preferred,min(preferred+100,65536)):
        with socket.socket() as sock:
            try:sock.bind(('127.0.0.1',port));return port
            except OSError:continue
    raise InstallError('No local port available in requested range')

def ensure_running(root):
    with locked(root/'data'):
        state=read_state(root)
        if health(state):return state
        if own_process(root,state.get('pid')):
            raise InstallError('Owned gateway is alive but health check failed; inspect private gateway.log')
        state['port']=free_port(state['port']);state['pid']=None
        state_write(root,state)
        command=[str(executable(root)),'-B',str(root/'app'/'litgate.py'),'--db',str(root/'data'/'litgate.db'),'--port',str(state['port']),'--no-browser']
        with (root/'data'/'gateway.log').open('ab') as out:
            opts={'creationflags':subprocess.DETACHED_PROCESS|subprocess.CREATE_NEW_PROCESS_GROUP} if os.name=='nt' else {'start_new_session':True}
            proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=out,cwd=root/'app',**opts)
        state['pid']=proc.pid;state_write(root,state)
        until=time.monotonic()+15
        while time.monotonic()<until:
            if proc.poll() is not None:raise InstallError('Gateway exited during startup; inspect private gateway.log')
            if health(state):return state
            time.sleep(.15)
        if own_process(root,proc.pid):proc.terminate();proc.wait(timeout=5)
        state['pid']=None;state_write(root,state)
        raise InstallError('Gateway health check timed out; inspect private gateway.log')

def provision(root,port):
    # Runs in the installed interpreter after dependency installation.
    sys.path.insert(0,str(root/'app'))
    import litgate
    data=root/'data'
    litgate.DB_PATH=str(data/'litgate.db');litgate.init_db()
    existing=read_state(root) if (data/'runtime.json').exists() else None
    identifier=(existing or {}).get('installation_id') or json.loads((data/'owner.json').read_text(encoding='utf-8'))['installation_id']
    password_path=data/'admin-password.txt';key_path=data/'client.key'
    with litgate.db() as conn:
        initialized=conn.execute("SELECT value FROM config WHERE key='pw_hash'").fetchone()
        known_id=conn.execute("SELECT value FROM config WHERE key='installation_id'").fetchone()
        if (known_id and known_id[0]!=identifier) or (initialized and not known_id):raise InstallError('Database belongs to another installation; original credentials were not changed')
        if not initialized:
            password=secrets.token_urlsafe(24);salt=secrets.token_bytes(16)
            atomic(password_path,password,True)
            conn.executemany('INSERT OR REPLACE INTO config(key,value) VALUES(?,?)',
                [('pw_salt',salt.hex()),('pw_hash',litgate.hash_password(password,salt))])
            # Start with working keyless sources; additional services remain configurable.
            conn.execute("UPDATE endpoints SET enabled=CASE WHEN adapter IN ('crossref','openalex','arxiv') THEN 1 ELSE 0 END")
        if key_path.exists():
            key=key_path.read_text(encoding='utf-8').strip()
            row=conn.execute('SELECT enabled FROM apikeys WHERE key_hash=?',(hashlib.sha256(key.encode()).hexdigest(),)).fetchone()
            if not row or not row[0]:raise InstallError('Saved client key was revoked or changed; install does not undo revocation')
        else:
            key,prefix,digest=litgate.generate_api_key()
            atomic(key_path,key,True)
            conn.execute('INSERT INTO apikeys(name,prefix,key_hash,enabled,rate_limit,window_seconds,allowed,created) VALUES(?,?,?,?,?,?,?,?)',
                ('local-install',prefix,digest,1,30,60,'["*"]',litgate.now_iso()))
        conn.execute("INSERT OR REPLACE INTO config(key,value) VALUES('installation_id',?)",(identifier,))
    for name in ('litgate.db','client.key','admin-password.txt'):
        if (data/name).exists():protect(data/name)
    state=existing or {'root':str(root),'installation_id':identifier,'port':port,'pid':None}
    state['version']=VERSION;state_write(root,state)

def resolve_clients(client):
    if client!='auto':return [] if client=='none' else (['codex','opencode'] if client=='both' else [client])
    if os.environ.get('CODEX_THREAD_ID'):return ['codex']
    present=[n for n in ('codex','opencode') if shutil.which(n)]
    if len(present)==1:return present
    raise InstallError('Use --client codex, opencode, both, or none; the installing agent should select its current client')

def config_paths(clients,codex_home=None,opencode_config=None):
    result={}
    if 'codex' in clients:
        home=Path(codex_home or os.environ.get('CODEX_HOME') or Path.home()/'.codex').expanduser()
        result['codex']=[(home/'config.toml').resolve()]
    if 'opencode' in clients:
        explicit=opencode_config or os.environ.get('OPENCODE_CONFIG')
        if explicit:paths=[Path(explicit).expanduser().resolve()]
        else:
            directory=Path(os.environ.get('XDG_CONFIG_HOME',Path.home()/'.config'))/'opencode'
            # Both formats may coexist; update this one server in both to avoid precedence ambiguity.
            paths=[p for p in (directory/'opencode.json',directory/'opencode.jsonc') if p.exists()] or [directory/'opencode.json']
        result['opencode']=paths
    if 'claude' in clients:
        if not opencode_config:raise InstallError('For Claude, explicitly specify --opencode-config as the client JSON path')
        result['claude']=[Path(opencode_config).expanduser().resolve()]
    return result

def config_plan(root,paths):
    import tomlkit,json5
    plans=[]
    state=read_state(root)
    command=str(executable(root));args=['-X','utf8',str(root/'app'/'deploy.py'),'mcp','--install-dir',str(root)]
    env={'LITGATE_URL':gateway_url(state),'LITGATE_API_KEY_FILE':str(root/'data'/'client.key')}
    for client,files in paths.items():
        for path in files:
            old=path.read_bytes() if path.exists() else None
            text=(old or b'').decode('utf-8-sig')
            try:
                if client=='codex':
                    document=tomlkit.parse(text)
                    servers=document.setdefault('mcp_servers',tomlkit.table())
                    servers['litgate']={'command':command,'args':args,'env':env,'enabled':True,'startup_timeout_sec':30,'tool_timeout_sec':120}
                    new=tomlkit.dumps(document).encode()
                    parsed=tomlkit.parse(new.decode()).unwrap();original=tomlkit.parse(text).unwrap()
                    field='mcp_servers'
                else:
                    document=json5.loads(text,allow_duplicate_keys=False) if text.strip() else {}
                    if not isinstance(document,dict):raise ValueError('Configuration must be an object')
                    field='mcpServers' if client=='claude' else 'mcp'
                    original=json.loads(json.dumps(document))
                    server={'command':command,'args':args,'env':env} if client=='claude' else {'type':'local','command':[command,*args],'environment':env,'enabled':True,'timeout':30000}
                    document.setdefault(field,{})['litgate']=server
                    new=(json.dumps(document,ensure_ascii=False,indent=2)+'\n').encode()
                    parsed=json.loads(new)
                # Verify that every value outside this one server is unchanged.
                for value in (original,parsed):
                    value.get(field,{}).pop('litgate',None)
                    if not value.get(field):value.pop(field,None)
                if parsed!=original:raise ValueError('Unrelated settings would change')
            except Exception as ex:
                raise InstallError(f'{client} configuration cannot be safely updated ({type(ex).__name__}); file left unchanged') from None
            plans.append((client,path,old,new))
    return plans

def apply_configs(root,plans):
    backups=[];written=[]
    directory=root/'data'/'config-backups';directory.mkdir(exist_ok=True);protect(directory)
    try:
        for client,path,old,new in plans:
            if (path.read_bytes() if path.exists() else None)!=old:raise InstallError('Client configuration changed during installation; retry after that edit finishes')
            backup=None
            if old is not None and old!=new:
                backup=directory/f'{client}-{time.time_ns()}.bak';atomic(backup,old,True)
            if old!=new:
                atomic(path,new);written.append((path,old))
            backups.append({'client':client,'config':str(path),'backup':str(backup) if backup else None})
    except Exception:
        for path,old in reversed(written):
            if old is None:path.unlink()
            else:atomic(path,old)
        raise
    return backups

async def verify_mcp(root):
    from mcp import ClientSession,StdioServerParameters
    from mcp.client.stdio import stdio_client
    env=dict(os.environ,PYTHONUTF8='1',PYTHONIOENCODING='utf-8');env.pop('LITGATE_API_KEY',None)
    params=StdioServerParameters(command=str(executable(root)),args=['-X','utf8',str(root/'app'/'deploy.py'),'mcp','--install-dir',str(root)],env=env)
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            tools=await session.list_tools()
            if {t.name for t in tools.tools}!={'litgate_search','litgate_usage','litgate_quota'}:raise InstallError('MCP tool list mismatch')
            quota=await session.call_tool('litgate_quota',{})
            text=' '.join(getattr(c,'text','') for c in quota.content)
            if quota.isError or '本机配额' not in text:raise InstallError('MCP quota authentication failed')
    return {'handshake':True,'tools':3,'authenticated_quota':True}

def verify(root):
    state=ensure_running(root)
    key=(root/'data'/'client.key').read_text(encoding='utf-8').strip()
    result=http_json(gateway_url(state)+'/v1/quota',{'X-Api-Key':key})
    if 'remaining' not in result:raise InstallError('Gateway client authentication failed')
    return {'health':True,'client_auth':True,'mcp':asyncio.run(verify_mcp(root))}

def install(args,root):
    clients=resolve_clients(args.client)
    paths=config_paths(clients,args.codex_home,args.opencode_config)
    source=Path(__file__).resolve().parent
    for name in FILES:
        if not (source/name).is_file():raise InstallError('Incomplete release; all eight files are required')
    app=root/'app';data=root/'data'
    if root.exists() and any(root.iterdir()) and not (data/'owner.json').exists():
        raise InstallError('Install directory must be empty or an existing automatic LitGate installation')
    root.mkdir(parents=True,exist_ok=True);protect(root)
    data.mkdir(exist_ok=True);protect(data)
    owner=data/'owner.json'
    if not owner.exists():
        atomic(owner,json.dumps({'root':str(root),'installation_id':str(uuid.uuid4())}),True)
    elif json.loads(owner.read_text(encoding='utf-8')).get('root')!=str(root):
        raise InstallError('Installation directory was moved; choose a fresh directory')
    changes=any(not (app/n).exists() or (app/n).read_bytes()!=(source/n).read_bytes() for n in FILES)
    if changes and (data/'runtime.json').exists():stop(root)
    app.mkdir(exist_ok=True)
    with locked(data):
        for name in FILES:
            if source!=app:atomic(app/name,(source/name).read_bytes())
        exe=executable(root)
        if not exe.exists():
            subprocess.run([sys.executable,'-X','utf8','-m','venv',str(app/'.venv')],check=True)
        stamp=app/'.venv'/'.litgate-requirements'
        requirement_hash=hashlib.sha256((app/'requirements.txt').read_bytes()).hexdigest()
        if not stamp.exists() or stamp.read_text(encoding='utf-8')!=requirement_hash:
            subprocess.run([str(exe),'-X','utf8','-m','pip','install','-r',str(app/'requirements.txt')],check=True)
            atomic(stamp,requirement_hash)
        subprocess.run([str(exe),'-X','utf8','-c','import fastapi,httpx,uvicorn,mcp,tomlkit,json5'],check=True)
        subprocess.run([str(exe),'-X','utf8','-B',str(app/'deploy.py'),'provision','--install-dir',str(root),'--port',str(args.port)],check=True)
    # All config parsing happens before mutating client configs.
    state=ensure_running(root)
    command=[str(exe),'-X','utf8','-B',str(app/'deploy.py'),'finish','--install-dir',str(root),'--client',args.client]
    if args.codex_home:command+=['--codex-home',args.codex_home]
    if args.opencode_config:command+=['--opencode-config',args.opencode_config]
    subprocess.run(command,check=True)

def main():
    parser=argparse.ArgumentParser(description='LitGate one-sentence local installation and MCP deployment')
    parser.add_argument('mode',nargs='?',default='install',choices=['install','provision','finish','mcp','verify','status','stop'])
    parser.add_argument('--client',choices=['auto','codex','opencode','both','none','claude'],default='auto')
    parser.add_argument('--install-dir');parser.add_argument('--codex-home');parser.add_argument('--opencode-config')
    parser.add_argument('--port',type=int,default=8791)
    args=parser.parse_args();root=Path(args.install_dir).expanduser().resolve() if args.install_dir else default_root().resolve()
    if not 1024<=args.port<=65535:raise InstallError('Port must be between 1024 and 65535')
    if args.mode=='install':install(args,root);return
    if args.mode=='provision':provision(root,args.port);return
    if args.mode=='stop':stop(root);print('Stopped the owned LitGate gateway. MCP can start it again when needed.');return
    if args.mode=='mcp':
        state=ensure_running(root)
        os.environ.pop('LITGATE_API_KEY',None)
        os.environ['LITGATE_URL']=gateway_url(state);os.environ['LITGATE_API_KEY_FILE']=str(root/'data'/'client.key')
        os.environ['LITGATE_INSTALL_DIR']=str(root)
        sys.path.insert(0,str(root/'app'))
        from mcp_client import mcp
        mcp.run(transport='stdio');return
    if args.mode=='verify':print(json.dumps(verify(root),ensure_ascii=False));return
    state=read_state(root)
    if args.mode=='status':
        print(json.dumps({'running':health(state),'url':gateway_url(state),'install_dir':str(root),'credentials_directory':str(root/'data')},ensure_ascii=False));return
    if args.mode=='finish':
        plans=config_plan(root,config_paths(resolve_clients(args.client),args.codex_home,args.opencode_config))
        checks=verify(root)
        registered=apply_configs(root,plans)
        result={'ok':True,'version':VERSION,'url':gateway_url(read_state(root)),'install_dir':str(root),'clients':registered,
            'admin_password_file':str(root/'data'/'admin-password.txt'),'client_key_file':str(root/'data'/'client.key'),'verification':checks,
            'next_step':'Reload the MCP connection or restart the current client once; private credentials are not printed.'}
        atomic(root/'data'/'installation-result.json',json.dumps(result,ensure_ascii=False,indent=2),True)
        print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    try:main()
    except Exception as error:
        # Do not print raw upstream errors, config content, or subprocess output.
        message=str(error) if isinstance(error,InstallError) else type(error).__name__
        print('LitGate operation failed: '+message,file=sys.stderr)
        sys.exit(1)
