#!/usr/bin/env python3
"""Bounded native ZAP crawl/passive analysis of the bundled loopback-only fixture."""
import argparse, hashlib, importlib.util, json, os, pathlib, signal, socket, subprocess, sys, tempfile, threading
from http.server import HTTPServer
ROOT=pathlib.Path(__file__).resolve().parents[1]

def plan(url, output):
    # JSON is a YAML subset; quoted values cannot inject additional jobs.
    return {'env':{'contexts':[{'name':'fictional-fixture','urls':[url]}],
                   'parameters':{'failOnError':True,'failOnWarning':False,'progressToStdout':True}},
            'jobs':[{'type':'spider','parameters':{'context':'fictional-fixture','url':url+'/','maxDuration':1}},
                    {'type':'passiveScan-wait','parameters':{'maxDuration':1}},
                    {'type':'report','parameters':{'template':'traditional-json','reportDir':str(output),'reportFile':'zap.json','reportTitle':'Fictional localhost fixture scan'}}]}

def run(zap, output, authorized):
    if not authorized: raise ValueError('Authorization required')
    exe=pathlib.Path(zap).resolve()
    if not exe.is_file(): raise ValueError('ZAP launcher not found')
    out=pathlib.Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('fictional_fixture',ROOT/'demo/site/server.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    server=HTTPServer(('127.0.0.1',0),m.Handler)
    try:
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        url='http://127.0.0.1:'+str(server.server_port)
        with socket.socket() as s: s.bind(('127.0.0.1',0));proxyport=s.getsockname()[1]
        path=out/'plan.yaml';path.write_text(json.dumps(plan(url,out),indent=2))
        receipt={'scope':'bundled fictional loopback fixture only','mode':'spider plus passive analysis; no activeScan job','timed_out':False}
        with tempfile.TemporaryDirectory(prefix='security-zap-') as home:
            cmd=[str(exe),'-cmd','-dir',str(pathlib.Path(home)/'zap'),'-host','127.0.0.1','-port',str(proxyport),'-config','autoupdate.checkOnStart=false','-config','autoupdate.checkAddonUpdates=false','-config','autoupdate.downloadNewRelease=false','-autorun',str(path)]
            env={k:v for k,v in os.environ.items() if k in {'PATH','JAVA_HOME','LANG','LC_ALL','TMPDIR'}}
            env.update(HOME=home,JAVA_TOOL_OPTIONS='-Djava.awt.headless=true -Duser.home='+home)
            with (out/'run.log').open('w') as log:
                proc=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=True)
                try: receipt['exit_code']=proc.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    receipt['timed_out']=True;os.killpg(proc.pid,signal.SIGTERM)
                    try: proc.wait(timeout=5)
                    except subprocess.TimeoutExpired: os.killpg(proc.pid,signal.SIGKILL);proc.wait()
                    receipt['exit_code']=None
        receipt['report_present']=(out/'zap.json').is_file()
        receipt['fixture_sha256']=hashlib.sha256((ROOT/'demo/site/server.py').read_bytes()).hexdigest()
        receipt['plan_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        if receipt['report_present']:
            try: receipt['scanner_version']=json.loads((out/'zap.json').read_text()).get('@version','unknown')
            except (ValueError,AttributeError): receipt['scanner_version']='unknown'
        receipt['interpretation']='Review logs and report; no security pass inferred. Native Automation Framework exit codes differ from Docker baseline.'
        (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        return receipt
    finally: server.shutdown();server.server_close()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--zap',required=True);p.add_argument('--output',required=True);p.add_argument('--authorize-local-demo',action='store_true');a=p.parse_args()
    try:
        r=run(a.zap,a.output,a.authorize_local_demo);print(json.dumps(r,indent=2))
        return 0 if r.get('exit_code')==0 and r.get('report_present') and not r.get('timed_out') else 2
    except (ValueError,OSError):
        print('Unable to run. Check authorization, trusted ZAP launcher, Java and fresh output path.',file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
