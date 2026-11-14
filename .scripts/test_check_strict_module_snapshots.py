"""Controls for ancestry and selected-source checks, using real Git objects."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("strict_snapshots", ROOT / ".scripts/check-strict-module-snapshots.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
MODULE = guard.PREFIX + "experiments/rental"
GOOD = "v0.5.1-0.20261114202108-27d39435cdc4"
BAD = "v0.5.1-0.20261114150118-3baa201bafb6"


class StrictModuleSnapshots(unittest.TestCase):
    # Claim: all protected selections in the real graph retain strict ancestry/sites.
    def test_repository_selections(self):
        self.assertEqual(guard.check(ROOT), [])

    # Claim: the exact bad published rental selection fails containment, beside
    # the compatible current-branch snapshot; semantic ordering is insufficient.
    def test_published_rental_strict_parse_bypass(self):
        self.assertEqual(guard.check_selection(ROOT, MODULE, GOOD), [])
        errors = guard.check_selection(ROOT, MODULE, BAD)
        self.assertEqual(len(errors), 1)
        self.assertIn("does not contain strict change", errors[0])

    # Claim: even a higher timestamp is rejected if its commit lacks the change.
    def test_higher_pseudo_version_without_fix_fails(self):
        errors = guard.check_selection(ROOT, MODULE, "v0.5.1-0.20990101000000-3baa201bafb6")
        self.assertEqual(len(errors), 1)
        self.assertIn("does not contain strict change", errors[0])

    # Claim: source-equivalent pre-rebase history cannot stand in for the pinned
    # strict ancestor. This isolates ancestry from the source-marker predicate.
    def test_strict_source_on_unrelated_history_fails(self):
        errors = guard.check_selection(ROOT, MODULE, "v0.5.1-0.20261114144010-ffefc6d423ae")
        self.assertEqual(len(errors), 1)
        self.assertIn("does not contain strict change", errors[0])

    # Claim: known ancestry alone cannot waive a missing required source site.
    def test_missing_selected_source_site_fails(self):
        policy = {"experiments/rental": {"certificate.go": ["required_missing_strict_call_site"]}}
        errors = guard.check_selection(ROOT, MODULE, GOOD, policy)
        self.assertEqual(len(errors), 1)
        self.assertIn("selected source lacks strict call site", errors[0])

    # Claim: shallow/missing Git objects cannot be reported as containment.
    def test_unavailable_selection_fails_closed(self):
        errors = guard.check_selection(ROOT, MODULE, "v0.5.1-0.20990101000000-000000000000")
        self.assertEqual(len(errors), 1)
        self.assertIn("selected commit unavailable", errors[0])


if __name__ == "__main__":
    unittest.main()
