"""Bounded controls for the independent agreement gate (standard library only)."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("second_reader", Path(__file__).with_name("second-reader.py"))
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class AgreementControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((reader.MODULE / "testdata/name-vectors.json").read_text())
        cls.decisions = reader.calculate(cls.vectors)

    # An unchanged 84-case map passes; altered Go verdicts and missing cases fail specifically as disagreements.
    def test_go_disagreement_and_omission(self):
        reader.agree(self.decisions, dict(self.decisions))
        bad = dict(self.decisions, **{"live-03": "live"})
        with self.assertRaisesRegex(ValueError, "GO_DISAGREEMENT live-03"):
            reader.agree(self.decisions, bad)
        del bad["live-03"]
        with self.assertRaisesRegex(ValueError, "Go result ids differ: missing=.*live-03"):
            reader.agree(self.decisions, bad)

    # A wrong published expectation cannot be accepted merely because Go agrees with it; the valid source is the control.
    def test_vector_disagreement(self):
        self.assertEqual(len(reader.calculate(self.vectors)), 84)
        bad = copy.deepcopy(self.vectors)
        bad["live"][2]["expect"] = "live"
        with self.assertRaisesRegex(ValueError, "VECTOR_DISAGREEMENT live-03"):
            reader.calculate(bad)

    # Missing/duplicate Go output and a skip are gate failures beside a complete stream; this does not qualify arbitrary test runners.
    def test_stream_completeness(self):
        events = [{"Action": "pass", "Test": name} for name in reader.TESTS]
        events += [{"Action": "output", "Output": "SECOND_READER " + json.dumps({"id": key, "result": value})} for key, value in self.decisions.items()]
        events.append({"Action": "pass", "Package": "identity"})
        stream = "\n".join(map(json.dumps, events))
        reader.agree(self.decisions, reader.go_results(stream))
        with self.assertRaisesRegex(ValueError, "duplicate Go result"):
            reader.go_results(stream + "\n" + json.dumps(events[-2]))
        with self.assertRaisesRegex(ValueError, "Go test did not pass"):
            reader.go_results(stream + '\n{"Action":"skip","Test":"TestV4Writer"}')
        with self.assertRaisesRegex(ValueError, "missing passing Go tests"):
            reader.go_results("")
        with self.assertRaisesRegex(ValueError, "missing complete Go package pass"):
            reader.go_results("\n".join(map(json.dumps, events[:-1])))


if __name__ == "__main__":
    unittest.main()
