import copy, importlib.util, json, pathlib, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('review',ROOT/'scripts/security_review.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.d=json.loads((ROOT/'examples/ledger.json').read_text()); self.s=json.loads((ROOT/'examples/findings.sarif.json').read_text())
    def test_whitespace_owner(self):
        self.d['findings'][1]['owner']='   '; self.assertRaises(ValueError,m.validate,self.d)
    def test_nonstr_owner(self):
        self.d['findings'][1]['owner']=42; self.assertRaises(ValueError,m.validate,self.d)
    def test_acceptance_wrong_build(self):
        self.d['findings'][2]['acceptance']['build']='old'; self.assertRaises(ValueError,m.validate,self.d)
    def test_example(self): self.assertEqual(len(m.validate(self.d)['findings']),3)
    def test_overdue(self):
        f=self.d['findings'][1]; f.update(owner='Owner',due_date='2026-11-01')
        self.assertIn({'id':'DEMO-2','issue':'overdue'},m.report(self.d,'2026-11-14')['attention'])
    def test_expired_acceptance(self): self.assertIn({'id':'DEMO-3','issue':'acceptance_expired'},m.report(self.d,'2026-11-14')['attention'])
    def test_missing_owner(self): self.assertIn({'id':'DEMO-2','issue':'owner_missing'},m.report(self.d,'2026-11-14')['attention'])
    def test_missing_due(self): self.assertIn({'id':'DEMO-2','issue':'due_date_missing'},m.report(self.d,'2026-11-14')['attention'])
    def test_empty_not_pass(self):
        self.d['findings']=[]; r=m.report(self.d,'2026-11-14'); self.assertNotIn('pass',r); self.assertIn('No security',r['conclusion'])
    def test_duplicate_id(self):
        self.d['findings'].append(self.d['findings'][0]); self.assertRaises(ValueError,m.validate,self.d)
    def test_wrong_build(self):
        self.d['findings'][0]['retest']['build']='old'; self.assertRaises(ValueError,m.validate,self.d)
    def test_retest_failure(self):
        self.d['findings'][0]['retest']['result']='failed'; self.assertRaises(ValueError,m.validate,self.d)
    def test_missing_retest_evidence(self):
        self.d['findings'][0]['retest']['evidence']=[]; self.assertRaises(ValueError,m.validate,self.d)
    def test_future_retest(self):
        self.d['findings'][0]['retest']['date']='2027-01-01'; self.assertRaises(ValueError,m.report,self.d,'2026-11-14')
    def test_false_positive_requires_evidence(self):
        self.d['findings'][1].update(state='false_positive',reviewer='R',rationale='R'); self.assertRaises(ValueError,m.validate,self.d)
    def test_acceptance_requires_approval(self):
        self.d['findings'][2]['acceptance']['approval_evidence']=[]; self.assertRaises(ValueError,m.validate,self.d)
    def test_invalid_expiry(self):
        self.d['findings'][2]['acceptance']['expires']='2026-10-01'; self.assertRaises(ValueError,m.validate,self.d)
    def test_future_approval(self):
        self.d['findings'][2]['acceptance'].update(approved_on='2027-01-01',expires='2027-02-01'); self.assertRaises(ValueError,m.report,self.d,'2026-11-14')
    def test_unknown_state(self):
        self.d['findings'][1]['state']='secure'; self.assertRaises(ValueError,m.validate,self.d)
    def test_bad_severity(self):
        self.d['findings'][1]['severity']='error'; self.assertRaises(ValueError,m.validate,self.d)
    def test_missing_scope(self):
        del self.d['scope']; self.assertRaises(ValueError,m.validate,self.d)
    def test_invalid_date(self): self.assertRaises(ValueError,m.report,self.d,'20261114')
    def test_sarif_inventory(self):
        out=m.sarif_inventory(self.s); self.assertEqual(out['records'][0]['severity'],'unknown'); self.assertEqual(out['runs'][0]['execution_status'],'not_verified')
    def test_sarif_failed_run(self):
        self.s['runs'][0]['invocations'][0]['executionSuccessful']=False; self.assertEqual(m.sarif_inventory(self.s)['runs'][0]['execution_status'],'failed')
    def test_sarif_sensitive_fields_omitted(self):
        self.s['runs'][0]['results'][0]['message']['text']='SECRET do evil'; self.assertNotIn('SECRET',json.dumps(m.sarif_inventory(self.s)))
    def test_suppression_not_closure(self):
        self.s['runs'][0]['results'][0].update(suppressions=[{'kind':'external'}],baselineState='absent')
        self.assertEqual(m.sarif_inventory(self.s)['records'][0]['state'],'untriaged')
    def test_external_properties_rejected(self):
        self.s['runs'][0]['externalPropertyFileReferences']={'results':[{'location':{'uri':'https://example.com/private'}}]}; self.assertRaises(ValueError,m.sarif_inventory,self.s)
    def test_missing_results(self):
        del self.s['runs'][0]['results']; self.assertRaises(ValueError,m.sarif_inventory,self.s)
    def test_unsupported_version(self):
        self.s['version']='2.2.0'; self.assertRaises(ValueError,m.sarif_inventory,self.s)
    def test_bad_level(self):
        self.s['runs'][0]['results'][0]['level']='critical'; self.assertRaises(ValueError,m.sarif_inventory,self.s)
    def test_duplicate_json(self):
        with tempfile.NamedTemporaryFile('w',delete=True) as f:
            f.write('{"a":1,"a":2}'); f.flush(); self.assertRaises(ValueError,m.load,f.name)
    def test_nonfinite_json(self):
        with tempfile.NamedTemporaryFile('w',delete=True) as f:
            f.write('{"x":NaN}'); f.flush(); self.assertRaises(ValueError,m.load,f.name)
    def test_overflow_json(self):
        with tempfile.NamedTemporaryFile('w',delete=True) as f:
            f.write('{"x":1e309}'); f.flush(); self.assertRaises(ValueError,m.load,f.name)
    def test_bool_schema(self):
        self.d['schema_version']=True; self.assertRaises(ValueError,m.validate,self.d)
    def test_huge_input(self):
        with tempfile.NamedTemporaryFile('w',delete=True) as f:
            f.write(' '*5_000_001); f.flush(); self.assertRaises(ValueError,m.load,f.name)
if __name__=='__main__': unittest.main()
