import os
import tempfile
import unittest

from admission_gate import ActionProposal, GateConfig, gated_shell
from admission_gate.gate import _DEFAULT_LIMITER


class TestVerifyOnly(unittest.TestCase):
    def setUp(self):
        _DEFAULT_LIMITER.history.clear()
        _DEFAULT_LIMITER.last_tier3_time = 0.0
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.temp_dir.name, "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        self.log_file = os.path.join(self.temp_dir.name, "audit_verify_only.jsonl")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_verify_only_passed(self):
        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=True,
            log_file=self.log_file,
        )
        p = ActionProposal("v1", "echo verify test", self.workspace, 1)
        passed, reason, code = gated_shell(p, config=cfg, verify_only=True)
        self.assertTrue(passed)
        self.assertEqual(code, 0)
        self.assertIn("Passed automated policy checks", reason)

    def test_verify_only_blocked(self):
        cfg = GateConfig(
            allowed_roots=[self.workspace],
            protected_paths=["/etc"],
            require_confirm=True,
            log_file=self.log_file,
        )
        p = ActionProposal("v2", "cat /etc/shadow", self.workspace, 1)
        passed, reason, code = gated_shell(p, config=cfg, verify_only=True)
        self.assertFalse(passed)
        self.assertEqual(code, -1)
        self.assertIn("protected directory", reason)


if __name__ == "__main__":
    unittest.main()
