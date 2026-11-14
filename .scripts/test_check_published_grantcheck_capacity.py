"""Controls for the external capacity gate's observable acceptance rules."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('capacity', Path(__file__).with_name('check-published-grantcheck-capacity.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class PublishedCapacityControls(unittest.TestCase):
    # Claim: a named real pass over 64 KiB is required; empty, skipped, renamed,
    # and below-boundary outputs cannot masquerade as a successful regression.
    def test_named_boundary_required(self):
        good = '{"Test":"TestCoreProvisioning/CombinedCapacity","Action":"pass"}\n{"Output":"max_state_bytes=71520"}'
        self.assertTrue(gate.boundary_passed(good))
        for bad in ('', good.replace('pass', 'skip'), good.replace('CombinedCapacity', 'Other'), good.replace('71520', '65536')):
            self.assertFalse(gate.boundary_passed(bad))

    # Claim: the witness identifies missing bounded-writer API specifically;
    # unrelated compilation and RPC failures never count as the old-limit witness.
    def test_specific_api_witness(self):
        good = 'checker.go:1:2: s.WriteBounded undefined (type *durable.Store has no field or method WriteBounded)'
        self.assertTrue(gate.bounded_api_witness(good))
        self.assertTrue(gate.bounded_api_witness(json.dumps({"Action":"build-output", "Output":good + "\n"})))
        for bad in ('connection refused', 'checker.go:1:2: undefined: SomethingElse', good + '\nother.go:1:2: unrelated error'):
            self.assertFalse(gate.bounded_api_witness(bad))

    # Claim: no replacement or silently different selected snapshot is accepted.
    def test_exact_graph_without_replacements(self):
        good = [{'Path':gate.GRANTCHECK, 'Version':'candidate'}, {'Path':gate.SINGLE_USE, 'Version':'budget'}]
        self.assertTrue(gate.graph_valid(good, 'candidate', 'budget'))
        self.assertFalse(gate.graph_valid(good, 'candidate', 'old'))
        self.assertFalse(gate.graph_valid(good + [{'Path':'other', 'Replace':{'Dir':'local'}}], 'candidate', 'budget'))


if __name__ == '__main__':
    unittest.main()
