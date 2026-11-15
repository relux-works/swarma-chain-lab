"""Bounded controls for the independent agreement gate and its hash backend."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("second_reader", Path(__file__).with_name("second-reader.py"))
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class Ripemd160Vectors(unittest.TestCase):
    # The Python digest matches all nine original published answers, including multi-block and million-byte messages.
    def test_published_vectors(self):
        # Source: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        vectors = json.loads((reader.MODULE / "testdata/ripemd160-vectors.json").read_text())["vectors"]
        self.assertEqual(len(vectors), 9)
        for row in vectors:
            with self.subTest(vector=row["id"]):
                data = row["message"].encode("ascii") * row["repeat"]
                self.assertEqual(reader.ripemd160(data).hex(), row["digest"], "published RIPEMD-160 vector")

    # The published BIP-340 vector index 0 key yields the fixed HASH160 and P2PKH script through the second reader.
    def test_bip340_known_answer(self):
        # Public x: bitcoin/bips, bip-0340/test-vectors.csv, index 0; compressed with prefix 02.
        # Source: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
        key = bytes.fromhex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
        digest = reader.hash160(key)
        self.assertEqual(digest.hex(), "7dd65592d0ab2fe0d0257d571abf032cd9db93dc")
        script = b"\x76\xa9\x14" + digest + b"\x88\xac"
        self.assertEqual(script.hex(), "76a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac")
        self.assertEqual(reader.address_kind(script, None, 0), ("key", digest))



class AgreementControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((reader.MODULE / "testdata/name-vectors.json").read_text())
        cls.decisions = reader.calculate(cls.vectors)

    # Hashing and all 84 decisions still work with no executable search path and forbidden external/optional hash backends.
    def test_hash_backend(self):
        with mock.patch.dict("os.environ", {"PATH": ""}), \
             mock.patch.object(reader.subprocess, "run", side_effect=AssertionError("external command forbidden")), \
             mock.patch.object(reader.hashlib, "new", side_effect=AssertionError("optional hash provider forbidden")):
            self.assertEqual(reader.hash160(bytes.fromhex(self.vectors["test_pins"]["owner"])).hex(),
                             "7dd65592d0ab2fe0d0257d571abf032cd9db93dc")
            self.assertEqual(len(reader.calculate(self.vectors)), 84)

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
