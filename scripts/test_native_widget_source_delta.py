"""Independent exact current/source-history bindings, never device acceptance."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('validator', Path(__file__).with_name('validate_rendezvous_deployment_plan.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class NativeWidgetSourceDeltaTests(unittest.TestCase):
    def test_original_bytes_remain_exact_and_tampered_actual_input_is_not_reconstructed(self):
        delta = v.native_widget_delta()
        original = v.safe_path
        for name, change in {**delta['changes'], **delta['reference_changes']}.items():
            with self.subTest(path=name):
                self.assertEqual(v.digest(v.native_before_bytes(name)), change['before'])
                with tempfile.TemporaryDirectory() as directory:
                    fake = Path(directory) / 'source'
                    fake.write_bytes((v.ROOT / name).read_bytes() + b'\n')
                    with patch.object(v, 'safe_path', side_effect=lambda n: fake if n == name else original(n)):
                        with self.assertRaises(ValueError):
                            v.native_before_bytes(name)

    def test_immutable_delta_cannot_be_tampered_or_widened(self):
        original = v.safe_path
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'delta'
            fake.write_bytes((v.ROOT / v.NATIVE_WIDGET_DELTA_PATH).read_bytes() + b'\n')
            with patch.object(v, 'safe_path', side_effect=lambda n: fake if n == v.NATIVE_WIDGET_DELTA_PATH else original(n)):
                with self.assertRaises(ValueError):
                    v.native_widget_delta()

    def test_unrelated_source_still_uses_actual_bytes_and_new_inputs_match_their_pins(self):
        delta = v.native_widget_delta()
        self.assertEqual(v.native_before_bytes('src/crypto.ts'), (v.ROOT / 'src/crypto.ts').read_bytes())
        self.assertEqual(len(delta['changes']), 5)
        self.assertEqual(len(delta['additions']), 15)
        for name, pin in {**delta['additions'], **delta['reference_additions']}.items():
            self.assertEqual(v.digest(v.counter_previous_bytes(name, v.wrangler_4164_previous_bytes(name))), pin)

    def test_counter_successor_reconstructs_each_exact_predecessor_and_rejects_actual_drift(self):
        delta = v.counter_widget_delta()
        self.assertEqual(len(delta['changes']), 2)
        for name, change in {**delta['changes'], **delta['reference_changes']}.items():
            raw = v.wrangler_4164_previous_bytes(name)
            self.assertEqual(v.digest(v.counter_previous_bytes(name, raw)), change['before'])
            with self.assertRaises(ValueError):
                v.counter_previous_bytes(name, raw + b'\n')

    def test_counter_successor_cannot_be_modified_or_grant_permission(self):
        original = v.safe_path
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'delta'
            fake.write_bytes((v.ROOT / v.COUNTER_WIDGET_DELTA_PATH).read_bytes() + b'\n')
            with patch.object(v, 'safe_path', side_effect=lambda n: fake if n == v.COUNTER_WIDGET_DELTA_PATH else original(n)):
                with self.assertRaises(ValueError):
                    v.counter_widget_delta()

    def test_ack_successor_retains_exact_original_receipt_writer_and_doc_inputs(self):
        delta = v.ack_bounds_delta()
        self.assertEqual(len(delta['changes']), 2)
        for name, change in {**delta['changes'], **delta['reference_changes']}.items():
            raw = v.wrangler_4164_previous_bytes(name)
            self.assertEqual(v.digest(v.ack_previous_bytes(name, raw)), change['before'])
            with self.assertRaises(ValueError):
                v.ack_previous_bytes(name, raw + b'\n')

    def test_ack_successor_cannot_forge_an_original_bound_or_permission(self):
        original = v.safe_path
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'delta'
            fake.write_bytes((v.ROOT / v.ACK_BOUNDS_DELTA_PATH).read_bytes() + b'\n')
            with patch.object(v, 'safe_path', side_effect=lambda n: fake if n == v.ACK_BOUNDS_DELTA_PATH else original(n)):
                with self.assertRaises(ValueError):
                    v.ack_bounds_delta()

    def test_unique_identity_successor_retains_exact_writer_and_contract_predecessors(self):
        delta = v.unique_apple_delta()
        self.assertEqual(len(delta['changes']), 1)
        self.assertEqual(len(delta['additions']), 1)
        for name, change in {**delta['changes'], **delta['reference_changes']}.items():
            raw = (v.ROOT / name).read_bytes()
            self.assertEqual(v.digest(v.unique_previous_bytes(name, raw)), change['before'])
            with self.assertRaises(ValueError):
                v.unique_previous_bytes(name, raw + b'\n')
        for name, pin in delta['additions'].items():
            self.assertEqual(v.digest((v.ROOT / name).read_bytes()), pin)

    def test_unique_identity_successor_does_not_allow_forged_identity_or_scope(self):
        original = v.safe_path
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'delta'
            fake.write_bytes((v.ROOT / v.UNIQUE_APPLE_DELTA_PATH).read_bytes() + b'\n')
            with patch.object(v, 'safe_path', side_effect=lambda n: fake if n == v.UNIQUE_APPLE_DELTA_PATH else original(n)):
                with self.assertRaises(ValueError):
                    v.unique_apple_delta()

    def test_selected_40533_policy_reconstructs_exact_predecessors_and_rejects_actual_drift(self):
        delta = v.policy40533_delta()
        self.assertEqual(len(delta['changes']), 3)
        for name, change in {**delta['changes'], **delta['reference_changes']}.items():
            raw = v.wrangler_4164_previous_bytes(name)
            self.assertEqual(v.digest(v.policy40533_previous_bytes(name, raw)), change['before'])
            with self.assertRaises(ValueError):
                v.policy40533_previous_bytes(name, raw + b'\n')

    def test_selected_40533_delta_and_static_evidence_cannot_be_tampered(self):
        original = v.safe_path
        for name in (v.POLICY40533_DELTA_PATH, *v.POLICY40533_REFERENCE_ADDITIONS):
            with tempfile.TemporaryDirectory() as directory:
                fake = Path(directory) / 'tampered'
                fake.write_bytes((v.ROOT / name).read_bytes() + b'\n')
                with patch.object(v, 'safe_path', side_effect=lambda n: fake if n == name else original(n)):
                    with self.assertRaises(ValueError):
                        v.validate(v.decode((v.ROOT / "docs/rendezvous/deployment-preparation-v1.json").read_bytes()))
