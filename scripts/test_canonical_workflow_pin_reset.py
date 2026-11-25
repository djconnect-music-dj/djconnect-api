"""Exact reset overlay must preserve historical proof and reject modified inputs."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('validator', Path(__file__).with_name('validate_rendezvous_deployment_plan.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class CanonicalPinResetTests(unittest.TestCase):
    def test_exact_workflows_and_manifests_reconstruct_previous_bytes(self):
        delta = v.canonical_pin_delta()
        self.assertEqual(len(delta['workflow_changes']), 20)
        self.assertEqual(len(delta['manifest_changes']), 10)
        for name, change in {**delta['workflow_changes'], **delta['manifest_changes']}.items():
            with self.subTest(path=name):
                raw = v.native_before_bytes(name)
                self.assertEqual(v.digest(v.canonical_pin_previous(name, raw)), change['before'])
                candidates = [raw + b'\n', raw.replace(delta['new_pin'].encode(), b'0'*40), raw.replace(b'permissions:', b'permissions_changed:')]
                for candidate in candidates:
                    if candidate != raw:
                        with self.assertRaises(ValueError):
                            v.canonical_pin_previous(name, candidate)

    def test_delta_tampering_rejected_even_with_unchanged_input(self):
        original = v.safe_path
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'delta.json'
            fake.write_bytes((v.ROOT / v.CANONICAL_PIN_DELTA_PATH).read_bytes() + b'\n')
            with patch.object(v, 'safe_path', side_effect=lambda n: fake if n == v.CANONICAL_PIN_DELTA_PATH else original(n)):
                with self.assertRaises(ValueError):
                    v.canonical_pin_delta()

    def test_all_consumed_blobs_identical_and_guard_is_not_an_overlay_input(self):
        delta = v.canonical_pin_delta()
        self.assertEqual(len(delta['consumed_blobs']), 5)
        for value in delta['consumed_blobs'].values():
            self.assertEqual(value['old'], value['new'])
        self.assertNotIn('scripts/check_reusable_workflow_refs.sh', delta['workflow_changes'])
