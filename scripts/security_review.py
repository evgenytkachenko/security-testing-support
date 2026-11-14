#!/usr/bin/env python3
"""Offline ledger checks and conservative SARIF inventory. No network calls."""
import argparse, datetime as dt, hashlib, json, math, pathlib, sys

STATES = {'untriaged','validating','confirmed','remediating','ready_for_retest','closed_verified','false_positive','risk_accepted'}
SEVERITIES = {'unknown','informational','low','medium','high','critical'}
MAX_BYTES = 5_000_000

def fail(msg):
    raise ValueError(msg)

def load(path):
    with pathlib.Path(path).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw)>MAX_BYTES: fail('input exceeds 5 MB')
    def pairs(items):
        result={}
        for k,v in items:
            if k in result: fail('duplicate JSON key')
            result[k]=v
        return result
    def finite(s):
        value = float(s)
        if not math.isfinite(value): fail('nonfinite JSON number')
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite, parse_constant=lambda _: fail('nonfinite JSON number'))

def text(obj, key):
    val=obj.get(key)
    if not isinstance(val,str) or not val.strip(): fail('missing or invalid '+key)
    return val

def date(value):
    if not isinstance(value,str): fail('date must be YYYY-MM-DD')
    try:
        out=dt.date.fromisoformat(value)
        if out.isoformat()!=value: fail('date must be YYYY-MM-DD')
        return out
    except ValueError: fail('date must be YYYY-MM-DD')

def evidence(obj,key):
    values=obj.get(key)
    if not isinstance(values,list) or not values or any(not isinstance(x,str) or not x.strip() for x in values):
        fail('missing evidence list: '+key)

def validate(doc):
    if not isinstance(doc,dict) or type(doc.get('schema_version')) is not int or doc.get('schema_version')!=1: fail('unsupported ledger schema')
    text(doc,'product'); text(doc,'target_build')
    scope=doc.get('scope')
    if not isinstance(scope,dict): fail('scope is required')
    text(scope,'environment'); text(scope,'description')
    rows=doc.get('findings')
    if not isinstance(rows,list): fail('findings must be a list')
    ids=set()
    for row in rows:
        if not isinstance(row,dict): fail('finding must be an object')
        rid=text(row,'id')
        if rid in ids: fail('duplicate finding id')
        ids.add(rid)
        text(row,'title'); text(row,'source_ref'); text(row,'affected_build')
        if row.get('source_type') not in {'SAST','DAST','SCA','manual','other'}: fail('invalid source_type')
        if row.get('severity') not in SEVERITIES: fail('invalid severity')
        state=row.get('state')
        if state not in STATES: fail('invalid state')
        if row.get('due_date') is not None: date(row['due_date'])
        if row.get('owner') is not None: text(row,'owner')
        if state not in {'untriaged','false_positive'}: text(row,'owner')
        if state in {'confirmed','remediating','ready_for_retest','closed_verified'}: evidence(row,'validation_evidence')
        if state in {'ready_for_retest','closed_verified'}: text(row,'fix_ref')
        if state=='closed_verified':
            r=row.get('retest')
            if not isinstance(r,dict): fail('retest required')
            text(r,'reviewer'); evidence(r,'evidence'); date(text(r,'date'))
            if r.get('result')!='passed': fail('closure requires passed retest')
            if r.get('build')!=doc['target_build']: fail('retest must match target_build')
        if state=='false_positive':
            text(row,'reviewer'); text(row,'rationale'); evidence(row,'decision_evidence')
        if state=='risk_accepted':
            a=row.get('acceptance')
            if not isinstance(a,dict): fail('acceptance required')
            text(a,'approver'); text(a,'rationale'); text(a,'scope'); evidence(a,'approval_evidence')
            if a.get('build') != doc['target_build']: fail('acceptance must match target_build')
            if date(text(a,'expires'))<=date(text(a,'approved_on')): fail('acceptance expiry must follow approval')
    return doc

def report(doc, as_of):
    validate(doc); today=date(as_of)
    counts={s:0 for s in sorted(STATES)}; issues=[]
    for row in doc['findings']:
        state=row['state']; counts[state]+=1
        if state not in {'closed_verified','false_positive','risk_accepted'}:
            if not row.get('owner'): issues.append({'id':row['id'],'issue':'owner_missing'})
            if not row.get('due_date'): issues.append({'id':row['id'],'issue':'due_date_missing'})
            elif date(row['due_date'])<today: issues.append({'id':row['id'],'issue':'overdue'})
        if row['severity']=='unknown': issues.append({'id':row['id'],'issue':'severity_unassessed'})
        if state=='closed_verified' and date(row['retest']['date'])>today: fail('retest is after report as-of date')
        if state=='risk_accepted':
            a=row['acceptance']
            if date(a['approved_on'])>today: fail('approval is after report as-of date')
            if date(a['expires'])<=today: issues.append({'id':row['id'],'issue':'acceptance_expired'})
    return {'schema_version':1,'as_of':as_of,'target_build':doc['target_build'],'finding_count':len(doc['findings']),
            'state_counts':counts,'attention':issues,'conclusion':'No security or compliance conclusion is inferred from this ledger.',
            'limitations':['Evidence references and approvals are user assertions, not independently verified.','An empty ledger does not establish test coverage or absence of vulnerabilities.']}

def sarif_inventory(doc):
    if not isinstance(doc,dict) or doc.get('version')!='2.1.0': fail('only SARIF 2.1.0 supported')
    runs=doc.get('runs')
    if not isinstance(runs,list): fail('runs must be a list')
    output=[]; coverage=[]
    for i,run in enumerate(runs):
        if not isinstance(run,dict): fail('invalid run')
        # No remote properties, URL visits, artifact reads or tool execution.
        if run.get('externalPropertyFileReferences'): fail('external properties unsupported; provide self-contained sanitized SARIF')
        results=run.get('results')
        if not isinstance(results,list): fail('embedded results list required')
        inv=run.get('invocations',[])
        if not isinstance(inv,list) or any(not isinstance(x,dict) for x in inv): fail('invalid invocations')
        coverage.append({'run_index':i,'execution_status':'failed' if any(x.get('executionSuccessful') is False for x in inv) else 'not_verified','results':len(results)})
        for j,r in enumerate(results):
            if not isinstance(r,dict): fail('invalid result')
            level=r.get('level','unspecified')
            if level not in {'none','note','warning','error','unspecified'}: fail('invalid SARIF level')
            # Only indices, enumerations and hashes leave the import. Messages/paths may hold secrets.
            digest=hashlib.sha256(json.dumps(r,sort_keys=True,allow_nan=False).encode()).hexdigest()
            output.append({'source_record':f'runs[{i}].results[{j}]','record_sha256':digest,
                           'scanner_level':level,'severity':'unknown','state':'untriaged',
                           'suppression_present':bool(r.get('suppressions')),
                           'baseline_absent':r.get('baselineState')=='absent'})
    return {'schema_version':1,'kind':'inventory_only','runs':coverage,'records':output,
            'warning':'Not a validated vulnerability ledger. No severity, closure, scan success or coverage inferred. Captured messages, rule names and locations omitted; map safe summaries manually.'}

def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='cmd',required=True)
    v=sub.add_parser('validate'); v.add_argument('input')
    r=sub.add_parser('report'); r.add_argument('input'); r.add_argument('--as-of',required=True)
    s=sub.add_parser('sarif-inventory'); s.add_argument('input')
    args=p.parse_args()
    try:
        doc=load(args.input)
        result=({'valid':True,'findings':len(validate(doc)['findings'])} if args.cmd=='validate' else report(doc,args.as_of) if args.cmd=='report' else sarif_inventory(doc))
        print(json.dumps(result,indent=2,allow_nan=False)); return 0
    except (ValueError,TypeError,KeyError,OSError,RecursionError) as e:
        # Do not echo input content or OS paths into output.
        print(json.dumps({'error':'Input rejected. Check the documented schema, required evidence, types and file availability.'}),file=sys.stderr); return 2

if __name__=='__main__': sys.exit(main())
