#!/usr/bin/env python3
"""Run Semgrep against bundled fictional source or summarize local scanner exports."""
import argparse, hashlib, json, os, pathlib, shutil, signal, subprocess, sys, tempfile
from security_review import load, fail
ROOT=pathlib.Path(__file__).resolve().parents[1]

def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,allow_nan=False).encode()).hexdigest()

def semgrep_inventory(doc):
    if not isinstance(doc,dict) or not isinstance(doc.get('results'),list) or not isinstance(doc.get('errors'),list): fail('Semgrep JSON requires results and errors lists')
    rows=[]
    for n,r in enumerate(doc['results']):
        if not isinstance(r,dict): fail('invalid result')
        rows.append({'index':n,'sha256':fingerprint(r),'state':'untriaged','severity':'unknown'})
    return {'kind':'semgrep_inventory','records':rows,'scanner_error_count':len(doc['errors']),
            'coverage':'incomplete' if doc['errors'] else 'requires_review','security_conclusion':'not_established'}

def zap_inventory(doc):
    if not isinstance(doc,dict) or not isinstance(doc.get('site'),list): fail('ZAP JSON requires site list')
    rows=[]
    for si,site in enumerate(doc['site']):
        if not isinstance(site,dict) or not isinstance(site.get('alerts'),list): fail('invalid site')
        for ai,a in enumerate(site['alerts']):
            if not isinstance(a,dict): fail('invalid alert')
            risk=str(a.get('riskcode',''))
            if risk not in {'0','1','2','3'}: fail('invalid riskcode')
            rows.append({'site_index':si,'alert_index':ai,'sha256':fingerprint(a),'scanner_riskcode':risk,'state':'untriaged','severity':'unknown'})
    return {'kind':'zap_inventory','records':rows,'coverage':'requires_run_receipt_and_scope_review','security_conclusion':'not_established'}

def run_sast(output, authorized):
    if not authorized: fail('explicit authorization is required for the local fictional scan')
    binary=shutil.which('semgrep')
    if not binary: fail('Semgrep is not installed; follow scanners.md')
    out=pathlib.Path(output).resolve()
    # No overwrite or broad target option; only the bundled static fixture is scanned.
    out.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='security-semgrep-') as home:
        env={k:v for k,v in os.environ.items() if k in {'PATH','LANG','LC_ALL','SYSTEMROOT','TMPDIR'}}
        env.update(HOME=home,SEMGREP_SEND_METRICS='off',SEMGREP_ENABLE_VERSION_CHECK='0')
        cmd=[binary,'scan','--config',str(ROOT/'rules/demo-python.yml'),'--metrics=off','--disable-version-check','--no-git-ignore','--json','--output',str(out/'semgrep.json'),str(ROOT/'demo/source')]
        receipt={'scanner':'Semgrep CE','scope':'bundled fictional source only','rules_sha256':hashlib.sha256((ROOT/'rules/demo-python.yml').read_bytes()).hexdigest(),'timed_out':False}
        with (out/'run.log').open('w') as log:
            proc=subprocess.Popen(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try: receipt['exit_code']=proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                receipt['timed_out']=True;os.killpg(proc.pid,signal.SIGTERM)
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: os.killpg(proc.pid,signal.SIGKILL);proc.wait()
                receipt['exit_code']=None
        (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        if receipt['timed_out'] or receipt['exit_code']!=0: fail('scanner failed or timed out; review local receipt')
        raw=load(out/'semgrep.json')
        receipt['scanner_version']=raw.get('version','unknown')
        receipt['source_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'demo/source').glob('*.py'))}
        (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        inventory=semgrep_inventory(raw)
        (out/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
        return inventory

def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='cmd',required=True)
    r=sub.add_parser('run-sast-demo');r.add_argument('--output',required=True);r.add_argument('--authorize-local-demo',action='store_true')
    for name in ('semgrep-inventory','zap-inventory'):
        q=sub.add_parser(name);q.add_argument('input')
    a=p.parse_args()
    try:
        result=run_sast(a.output,a.authorize_local_demo) if a.cmd=='run-sast-demo' else semgrep_inventory(load(a.input)) if a.cmd=='semgrep-inventory' else zap_inventory(load(a.input))
        print(json.dumps(result,indent=2));return 0
    except (ValueError,TypeError,KeyError,OSError,RecursionError):
        print(json.dumps({'error':'Operation rejected or scanner unavailable. Review scanner instructions, authorization, input format, output directory and run receipt.'}),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
