#!/usr/bin/env python3
"""Bounded regression checks for independent judgments and fixture contracts."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('checker', ROOT / 'scripts/check-vectors.py')
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
ROWS = {r['id']: r for r in json.loads((ROOT / 'vectors.json').read_text())['vectors']}


class ContractTests(unittest.TestCase):
    # The checker decides from inputs, never a copied fixture expected code or id.
    def test_unspecified_codes_are_not_judged(self):
        for name in ('issuance-no-facts', 'issuance-vout-4294967296',
                     'issuer-age-before-consumed', 'consent-size-plus-0',
                     'signature-length-64'):
            row = ROWS[name]
            with self.subTest(name=name), self.assertRaises(CHECKER.NotJudged):
                CHECKER.checked_evaluate(row['operation'], row['input'])
        for name in ('issuance-stated-name', 'issuer-age-259200', 'consent-encode-name'):
            row = ROWS[name]
            self.assertEqual(CHECKER.checked_evaluate(row['operation'], row['input']), row['output'])

    # All readable shape pairs contain both defects: repairing only content,
    # identifier and its valid signature exposes the specified later refusal.
    def test_shape_pairs_expose_later_defect(self):
        expected = {'binding':'CONSENT_BINDING', 'key':'CONSENT_KEY',
                    'signature':'CONSENT_SIGNATURE', 'time':'CONSENT_TIME'}
        for late, code in expected.items():
            row = ROWS['consent-shape-before-' + late]
            x = copy.deepcopy(row['input'])
            v = json.loads(bytes.fromhex(x['raw_hex']))
            self.assertEqual(v['content'], 'x')
            self.assertEqual(CHECKER.checked_evaluate('consent', x), {'code':'CONSENT_SHAPE'})
            v['content'] = ''
            identifier = CHECKER.sha(CHECKER.event_preimage(v))
            v['id'] = identifier.hex()
            if late != 'signature':
                v['sig'] = CHECKER.sign(2, identifier).hex()
            x['raw_hex'] = CHECKER.event_bytes(v).hex()
            self.assertEqual(CHECKER.checked_evaluate('consent', x), {'code':code})

    # Actual envelope bytes and place signatures are checked before W3.1;
    # malformed octets and a zero signature cannot pass via expected_type alone.
    def test_memberless_input_is_read(self):
        for row in ROWS.values():
            if row['operation'] != 'memberless_signed':
                continue
            x = copy.deepcopy(row['input'])
            self.assertEqual(CHECKER.checked_evaluate('memberless_signed', x), {'code':'WIRE_TYPE'})
            x['raw_hex'] = '7b'
            self.assertEqual(CHECKER.checked_evaluate('memberless_signed', x), {'code':'WIRE_JSON'})
            x = copy.deepcopy(row['input'])
            envelope = json.loads(bytes.fromhex(x['raw_hex']))
            envelope['signature'] = '00' * 64
            x['raw_hex'] = CHECKER.encode(envelope, 2048).hex()
            self.assertEqual(CHECKER.checked_evaluate('memberless_signed', x), {'code':'WIRE_SIGNATURE'})

    # A successful byte output with an unjudged API verdict still has to agree.
    # Changing one output byte must fail the real command with the named field.
    def test_not_judged_does_not_skip_bytes(self):
        data = json.loads((ROOT / 'vectors.json').read_text())
        row = next(r for r in data['vectors'] if r['id'] == 'consent-size-plus-0')
        row['output']['event_id'] = '00' * 32
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / 'vectors.json'
            path.write_text(json.dumps(data))
            proc = subprocess.run([sys.executable, '-I', str(ROOT / 'scripts/check-vectors.py'), str(path)],
                                  text=True, capture_output=True)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn('FINDING consent-size-plus-0', proc.stderr)
        self.assertIn('event_id', proc.stderr)

    # Published transport uses spec-style names; no capitalized Go fields leak.
    def test_language_neutral_fact_names(self):
        def walk(x):
            if isinstance(x, dict):
                for key, value in x.items():
                    self.assertTrue(key == key.lower(), key)
                    walk(value)
            elif isinstance(x, list):
                for value in x:
                    walk(value)
        for row in ROWS.values():
            walk(row['input'])


if __name__ == '__main__':
    unittest.main()
