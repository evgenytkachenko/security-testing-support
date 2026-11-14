import importlib.util, pathlib, sys, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import scanner_workflow as m
import run_zap_demo as z
class ScannerTests(unittest.TestCase):
    def test_native_zap_requires_authorization(self): self.assertRaises(ValueError,z.run,'unused','unused',False)
    def test_zap_plan_has_no_active_scan(self): self.assertEqual([j['type'] for j in z.plan('http://127.0.0.1:1','out')['jobs']],['spider','passiveScan-wait','report'])
    def test_zap_plan_bounds_spider(self): self.assertEqual(z.plan('http://127.0.0.1:1','out')['jobs'][0]['parameters']['maxDuration'],1)
    def test_requires_authorization(self): self.assertRaises(ValueError,m.run_sast,'unused-output',False)
    def test_semgrep_empty_not_secure(self): self.assertEqual(m.semgrep_inventory({'results':[],'errors':[]})['security_conclusion'],'not_established')
    def test_semgrep_errors_incomplete(self): self.assertEqual(m.semgrep_inventory({'results':[],'errors':[{}]})['coverage'],'incomplete')
    def test_semgrep_missing_errors(self): self.assertRaises(ValueError,m.semgrep_inventory,{'results':[]})
    def test_semgrep_invalid_result(self): self.assertRaises(ValueError,m.semgrep_inventory,{'results':['bad'],'errors':[]})
    def test_semgrep_omits_source(self):
        import json
        out=m.semgrep_inventory({'results':[{'extra':{'lines':'SECRET'}}],'errors':[]});self.assertNotIn('SECRET',json.dumps(out))
    def test_semgrep_state_untriaged(self): self.assertEqual(m.semgrep_inventory({'results':[{}],'errors':[]})['records'][0]['state'],'untriaged')
    def test_zap_empty_not_secure(self): self.assertEqual(m.zap_inventory({'site':[]})['security_conclusion'],'not_established')
    def test_zap_missing_site(self): self.assertRaises(ValueError,m.zap_inventory,{})
    def test_zap_missing_alerts(self): self.assertRaises(ValueError,m.zap_inventory,{'site':[{}]})
    def test_zap_bad_riskcode(self): self.assertRaises(ValueError,m.zap_inventory,{'site':[{'alerts':[{'riskcode':'critical'}]}]})
    def test_zap_untriaged(self): self.assertEqual(m.zap_inventory({'site':[{'alerts':[{'riskcode':'2'}]}]})['records'][0]['state'],'untriaged')
    def test_zap_omits_urls(self):
        import json
        self.assertNotIn('SECRET',json.dumps(m.zap_inventory({'site':[{'@name':'SECRET','alerts':[{'riskcode':'1','instances':[{'uri':'SECRET'}]}]}]})))
    def test_zap_retains_scanner_label_not_severity(self): self.assertEqual(m.zap_inventory({'site':[{'alerts':[{'riskcode':'3'}]}]})['records'][0]['severity'],'unknown')
if __name__=='__main__': unittest.main()
