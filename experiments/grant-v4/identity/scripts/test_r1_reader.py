"""Bounded R1 reader controls: input parsing and both disagreement directions."""
import copy
import json
from pathlib import Path
import unittest

import r1_reader as reader


class R1ReaderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1] / "testdata"
        cls.files = {name: json.loads((root / name).read_text()) for name in reader.HASHES}

    def test_all_vectors(self):
        # All pinned and revision independent results agree with the pinned expectations.
        self.assertEqual(len(reader.calculate(self.files)), 440)

    def test_both_disagreement_directions(self):
        # A false acceptance and a false refusal each fail agreement, beside a
        # valid control. Equality of two broken readers is not the expectation.
        independent = reader.calculate(self.files)
        reader.agree(independent, dict(independent))
        for key, changed in (("class-25", {"outcome": "pass", "attestation": "required"}),
                             ("class-01", {"outcome": "CLASS_WRITER"})):
            with self.subTest(vector=key):
                go = copy.deepcopy(independent)
                go[key] = changed
                with self.assertRaisesRegex(ValueError, "R1_GO_DISAGREEMENT"):
                    reader.agree(independent, go)

    def test_missing_and_duplicate_go_results(self):
        # A partial or duplicate test stream is never an agreement result.
        with self.assertRaisesRegex(ValueError, "missing"):
            reader.go_results("")
        event = json.dumps({"Output": 'R1_RESULT {"id":"class-01","result":{}}\n'})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            reader.go_results(event + "\n" + event)
        independent = reader.calculate(self.files)
        go = dict(independent)
        del go["class-25"]
        with self.assertRaisesRegex(ValueError, "R1_GO_DISAGREEMENT"):
            reader.agree(independent, go)

    def test_expectation_tamper(self):
        # Replacing the gift's expected rejection with pass cannot alter the
        # independent calculation. This control plants the intended violation.
        changed = copy.deepcopy(self.files)
        gift = next(v for v in changed["class-vectors.json"]["admissions"] if v["id"] == "class-25")
        gift["expect"] = {"outcome": "pass", "attestation": "required"}
        with self.assertRaisesRegex(ValueError, "R1_VECTOR_DISAGREEMENT class-25"):
            reader.calculate(changed)

    def test_recipient_status_byte_domain(self):
        # Only CurrentOutput proceeds; O7.2 row 1 assigns NOT_HELD to proved
        # absence and row 3 assigns UNAVAILABLE to unknown/undefined facts.
        control = self.files["class-vectors.json"]["admissions"][0]
        self.assertEqual(reader.admission_decision(control)["outcome"], "pass")
        for status in range(256):
            with self.subTest(status=status):
                row = copy.deepcopy(control)
                row["node"]["recipient_name"]["current_status"] = status
                expected = ("pass" if status == 1 else "RECIPIENT_NAME_NOT_HELD"
                            if status == 2 else "RECIPIENT_NAME_UNAVAILABLE")
                self.assertEqual(reader.admission_decision(row)["outcome"], expected)

    def test_landlord_current_status(self):
        # R9.5 step 1 distinguishes proved absence from unknown/undefined facts.
        row = self.files["class-vectors.json"]["admissions"][0]
        state = next(iter(row["node"]["landlords"].values()))
        self.assertIsNone(reader.landlord_decision(state, row["context"], False))
        for status in (0, 2, 3, 99, 255):
            with self.subTest(status=status):
                absent = dict(state, current_status=status, history=[])
                expected = "CLASS_LANDLORD_CHANGED" if status == 2 else "CLASS_HISTORY_UNAVAILABLE"
                self.assertEqual(reader.landlord_decision(absent, row["context"], False), expected)

    def test_post_object_bytes(self):
        # LIP-0010 2.1 forbids every suffix, including JSON whitespace, beside
        # a valid control. Both binding and exact-name top-level readers reject.
        key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        raw = '{"swarma":{"landlord":{"grant":"' + key + '"}}}'
        for suffix in (" ", "\t", "\n", "\r\n", " {}"):
            with self.subTest(suffix=suffix):
                self.assertEqual(reader.value_read(raw)["grant"], key)
                with self.assertRaises(ValueError):
                    reader.value_read(raw + suffix)
                reader.value_members(raw)
                with self.assertRaises(ValueError):
                    reader.value_members(raw + suffix)

    def test_pre_object_bytes(self):
        # The strict first-byte reading rejects each JSON whitespace prefix in
        # binding and exact-name readers, beside their canonical positives.
        key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        raw = '{"swarma":{"landlord":{"grant":"' + key + '"}}}'
        for prefix in (" ", "\t", "\n", "\r\n"):
            with self.subTest(prefix=prefix):
                self.assertEqual(reader.value_read(raw)["grant"], key)
                with self.assertRaises(ValueError):
                    reader.value_read(prefix + raw)
                reader.value_members(raw)
                with self.assertRaises(ValueError):
                    reader.value_members(prefix + raw)

    def test_value_read_member_boundaries(self):
        # Ignored owner duplicates are allowed; read-member duplicates/aliases
        # and noncompact bindings refuse beside the canonical landlord control.
        key = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        binding = '{"landlord":{"grant":"' + key + '"}}'
        self.assertEqual(reader.value_read('{"unused":1,"unused":2,"swarma":' + binding + '}')["grant"], key)
        for raw in ('{"Swarma":' + binding + '}',
                    '{"swarma":' + binding + ',"swarma":' + binding + '}',
                    '{"swarma":' + binding.replace(':', ': ', 1) + '}'):
            with self.subTest(raw=raw), self.assertRaises((KeyError, ValueError)):
                reader.value_read(raw)


if __name__ == "__main__":
    unittest.main()
