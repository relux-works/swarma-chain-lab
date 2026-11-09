#!/usr/bin/env python3
"""Causal orchestration fixtures only. No names, signatures or chain are simulated as E2E."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile
from datetime import datetime, timezone
import assembly as a


class GateControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.root = Path(self.temp.name)
        for name in ('source-map.json', 'interface.md', 'result.json'):
            (self.root/name).write_text('{}\n')
        manifest = ''.join(a.sha(self.root/name)+'  '+name+'\n' for name in
                           ('source-map.json', 'interface.md', 'result.json'))
        (self.root/'SHA256SUMS').write_text(manifest)
        now = datetime.now(timezone.utc).timestamp()
        self.acceptance = {'at':datetime.fromtimestamp(now-1,timezone.utc).isoformat(), 'deadline':datetime.fromtimestamp(now+180,timezone.utc).isoformat()}
        c = {'root':str(self.root), 'head':'0'*40, 'tree':'1'*40,
             'manifest_sha256':a.sha(self.root/'SHA256SUMS')}
        self.plan = {'network':'regtest', 'owner_mxid':a.OWNER, 'target':a.TARGET,
                     'names':a.NAMES, 'action':'repository.create',
                     'accepted_at_unix':now-1, 'execution_deadline_unix':now+30, 'acceptance_deadline_unix':now+180,
                     'components':{name:copy.deepcopy(c) for name in a.COMPONENTS}}

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, plan=None):
        return a.admit(plan or self.plan, candidate_verifier=lambda *args:None, acceptance=self.acceptance)

    def test_complete_manifest_fixture(self):
        self.assertEqual(self.fixture()['status'], 'READY')
        self.assertFalse(self.fixture()['closed_regtest_executed'])

    def test_missing_candidate_hash_stays_null(self):
        self.plan['components']['signer']['manifest_sha256'] = None
        r = self.fixture()
        self.assertEqual(r['status'], 'MISSING_OR_REFUSED')
        self.assertEqual([x['component'] for x in r['missing']], ['signer'])
        self.assertIsNone(r['missing'][0]['manifest_sha256'])

    def test_mutation_refused(self):
        (self.root/'interface.md').write_text('replaced after pinning\n')
        self.assertTrue(all('artifact hash mismatch' in x['reason'] for x in self.fixture()['missing']))

    def test_symlink_refused(self):
        (self.root/'interface.md').unlink()
        (self.root/'interface.md').symlink_to('/usr/bin/python3')
        self.assertEqual(self.fixture()['status'], 'MISSING_OR_REFUSED')

    def test_no_real_candidate_substitution(self):
        self.assertEqual(a.admit(self.plan, acceptance=self.acceptance)['status'], 'MISSING_OR_REFUSED')

    def test_fixed_scope_guards(self):
        for key, bad in [('network','main'), ('owner_mxid','other-operator'), ('target','other/repo'),
                         ('names',['d/wrong']), ('action','repository.delete')]:
            with self.subTest(key=key):
                plan=copy.deepcopy(self.plan); plan[key]=bad
                self.assertEqual(self.fixture(plan)['status'],'MISSING_OR_REFUSED')

    def test_expired_clock_and_export_reserve(self):
        self.plan['execution_deadline_unix']=time.time()-1
        self.assertEqual(self.fixture()['status'],'MISSING_OR_REFUSED')

    def test_acceptance_clock_cannot_reset(self):
        self.plan['accepted_at_unix'] += 1
        self.assertEqual(self.fixture()['status'],'MISSING_OR_REFUSED')
        self.assertTrue(any(x['reason']=='immutable acceptance clock mismatch' for x in self.fixture()['missing']))
        self.plan['execution_deadline_unix']=self.plan['acceptance_deadline_unix']-119
        self.assertEqual(self.fixture()['status'],'MISSING_OR_REFUSED')

    def test_canonical_h1_not_zip_container_hash(self):
        one=self.root/'one.zip'; two=self.root/'two.zip'
        with zipfile.ZipFile(one,'w',compression=zipfile.ZIP_STORED) as z:
            z.writestr('example.test/mod@v1.0.0/b','second\n')
            z.writestr('example.test/mod@v1.0.0/a','first\n')
        with zipfile.ZipFile(two,'w',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('example.test/mod@v1.0.0/a','first\n')
            z.writestr('example.test/mod@v1.0.0/b','second\n')
        self.assertNotEqual(a.sha(one),a.sha(two))
        self.assertEqual(a.canonical_h1(one),a.canonical_h1(two))
        with zipfile.ZipFile(two,'a') as z: z.writestr('example.test/mod@v1.0.0/c','changed')
        self.assertNotEqual(a.canonical_h1(one),a.canonical_h1(two))

    def test_failed_stage_stops_causal_sequence(self):
        seen=[]
        def execute(stage, deadline):
            seen.append(stage)
            return {'exit':7 if stage=='spend_seal' else 0,'timeout':False,'reaped':True}
        with patch.object(a,'admit',return_value={'status':'READY'}):
            r=a.run_stages(self.plan,execute,self.acceptance)
        self.assertEqual(r['status'],'STAGE_FAILED')
        self.assertEqual(seen[-1],'spend_seal')
        self.assertNotIn('verify_mempool_refuse',seen)

    def test_unready_never_invokes_child(self):
        seen=[]
        self.plan['components']={}
        with self.assertRaises(a.Refusal):
            a.run_stages(self.plan,lambda *args:seen.append(args),self.acceptance)
        self.assertEqual(seen,[])

    def test_stage_exits_alone_never_claim_e2e(self):
        with patch.object(a,'admit',return_value={'status':'READY'}):
            r=a.run_stages(self.plan,lambda *args:{'exit':0,'timeout':False,'reaped':True},self.acceptance)
        self.assertFalse(r['closed_regtest_completed'])
        self.assertEqual([x['stage'] for x in r['stage_receipts']],list(a.STAGES))

    def test_owned_child_timeout_cleanup(self):
        r=a.run_child(['/usr/bin/python3','-B','-c','import time;time.sleep(5)'],0.05,time.time()+10)
        self.assertTrue(r['timeout'])
        self.assertTrue(r['reaped'])
        self.assertNotEqual(r['exit'],0)
        self.assertFalse(Path('/proc',str(r['pid'])).exists())


if __name__=='__main__':
    unittest.main(verbosity=2)
