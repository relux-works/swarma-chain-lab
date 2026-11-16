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

    # M2 gives no holder by either form in both profiles, including malformed
    # opposite forms; the inline-only and pinned-only controls still parse.
    def test_dual_holder_forms(self):
        key = "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"
        inline = {"swarma": {"landlord": {"grant": key[2:], "holders": [key]}}}
        pin = {"seq": 3, "sha256": "ab" * 32}
        encode = lambda value: json.dumps(value, separators=(",", ":"))
        for profile in ("draft", "in-force-051"):
            with self.subTest(profile=profile):
                self.assertEqual(reader.value_read(encode(inline), profile)["holders"], [key])
                pinned = {"swarma": {"landlord": {"grant": key[2:]}}, "swarma-holders": pin}
                self.assertEqual(reader.value_read(encode(pinned), profile)["holders"], [])
                for dual in (dict(inline, **{"swarma-holders": pin}),
                             {"swarma-holders": pin, **inline},
                             dict(inline, **{"swarma-holders": None}),
                             {"swarma": {"landlord": {"grant": key[2:], "holders": None}}, "swarma-holders": pin}):
                    with self.assertRaisesRegex(ValueError, "^CLASS_HOLDER$"):
                        reader.value_read(encode(dual), profile)

    def test_all_vectors(self):
        # All pinned and revision independent results agree with the pinned expectations.
        self.assertEqual(len(reader.calculate(self.files)), 1870)

    def test_executor_shape(self):
        # R8.1 requires both fields, including an actual curve key. The valid
        # synthetic fixture neighbour passes; each single defect refuses R8.1.
        template = reader.fixture_template(self.files["class-vectors.json"]["templates"][0]["template"])
        self.assertEqual(reader.template_decision(template), {"outcome": "valid"})
        for executor in ({"name": "", "key": template["executor"]["key"]},
                         {"name": "service.example", "key": "0"*64}):
            with self.subTest(executor=executor):
                self.assertEqual(reader.template_decision(dict(template, executor=executor)),
                                 {"outcome": "refused", "rule": "R8.1"})

    def test_capacity_full_range(self):
        # Independently enumerate the byte budget, including every no-room size;
        # invalid shapes refuse with no partial numbers beside valid controls.
        cases = list(reader.capacity_cases())
        self.assertEqual(len(cases), 537)
        for identifier, raw in cases:
            with self.subTest(case=identifier):
                actual = reader.capacity_result(raw)
                if identifier.startswith("invalid/") or (identifier.startswith("size/") and len(raw) < 100):
                    self.assertEqual(actual, {"outcome": "refused", "most": 0, "with": 0, "more": 0})
                else:
                    size = len(raw)
                    counts = [n for n in range(1, 8) if size + 12 + 69*n <= 520]
                    most = max(counts, default=0)
                    self.assertEqual(actual, {"without": size, "most": most,
                                             "with": size + 12 + 69*most if most else size,
                                             "more": size + 12 + 69*(most+1)})

    def test_executor_recipient_order(self):
        # Single defects expose each refusal; their compound prefers R8.1.
        # Full composition is draft-only; in-force keeps its availability gate.
        results = reader.executor_recipient_decisions(self.files)
        for profile in ("draft", "in-force-051"):
            for path in ("template", "parent", "child"):
                for defect in ("valid", "executor", "recipient", "both"):
                    with self.subTest(profile=profile, path=path, defect=defect):
                        expected = (reader.DRAFT_ERROR if profile == "in-force-051" and path != "template"
                                    else {"valid": "valid", "executor": "R8.1", "recipient": "R9.1", "both": "R8.1"}[defect])
                        self.assertEqual(results[f"a4-order/{profile}/{path}/{defect}"], expected)

    def test_profile_checkpoint(self):
        # Explicit checkpoint remains authoritative when Recent differs. A
        # missing/future checkpoint refuses beside that valid control.
        row = copy.deepcopy(self.files["class-vectors.json"]["admissions"][0])
        for state in row["node"]["landlords"].values():
            state["pinned_checkpoint"] = 500
        row["context"]["recent_block_height"] = 0
        self.assertEqual(reader.admission_decision(row, "in-force-051")["outcome"], "pass")
        for checkpoint in (None, 900):
            changed = copy.deepcopy(row)
            for state in changed["node"]["landlords"].values():
                if checkpoint is None:
                    del state["pinned_checkpoint"]
                else:
                    state["pinned_checkpoint"] = checkpoint
            self.assertEqual(reader.admission_decision(changed, "in-force-051")["outcome"], "CLASS_HISTORY_UNAVAILABLE")

    def test_profile_decision_boundaries(self):
        # Actual predicates exclude the landlord-writer and holder-order
        # proposals; core gifted-recipient rejection remains in force.
        results = reader.profile_vectors(self.files, "in-force-051")
        self.assertEqual(results["class-16"]["outcome"], "pass")
        self.assertEqual(results["class-25"]["outcome"], "CLASS_WRITER")
        self.assertEqual(results["value-24"]["outcome"], "valid")
        self.assertEqual(results["ordinal-01"], reader.DRAFT_ERROR)

    def test_both_disagreement_directions(self):
        # A false acceptance and a false refusal each fail agreement, beside a
        # valid control. Equality of two broken readers is not the expectation.
        independent = reader.calculate(self.files)
        reader.agree(independent, dict(independent))
        for key, changed in (("a4-capacity/size/440", {"without": 440, "most": 0, "with": 452, "more": 521}),
                             ("a4-capacity/size/520", {"without": 520, "most": -1, "with": 463, "more": 532}),
                             ("a4-order/draft/parent/both", "R9.1"),
                             ("class-25", {"outcome": "pass", "attestation": "required"}),
                             ("class-01", {"outcome": "CLASS_WRITER"}),
                             ("a3-executor/in-force-051/empty-name", "valid"),
                             ("a3-executor/in-force-051/valid", "R8.1")):
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
