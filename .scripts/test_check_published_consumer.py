"""The release-minimum gate accepts supported versions and refuses newer ones."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('consumer', Path(__file__).with_name('check-published-consumer.py'))
consumer = importlib.util.module_from_spec(spec)
# dataclass annotations need the module registry entry during import.
import sys
sys.modules[spec.name] = consumer
spec.loader.exec_module(consumer)


class ReleaseMinimumTests(unittest.TestCase):
    # Positive controls prevent a blanket rejection from satisfying the gate.
    def test_supported_minima(self):
        for version in ('1.25.0', '1.26', '1.26.0', '1.26.8'):
            consumer.require_release_minimum(version)

    def test_above_release_pin(self):
        for version in ('1.26.9', '1.26.10', '1.27.0', '2.0.0'):
            with self.subTest(version=version), self.assertRaisesRegex(RuntimeError, 'exceeds release pin'):
                consumer.require_release_minimum(version)

    def test_malformed_minimum(self):
        with self.assertRaisesRegex(RuntimeError, 'invalid consumed module'):
            consumer.require_release_minimum('1.26rc1')
