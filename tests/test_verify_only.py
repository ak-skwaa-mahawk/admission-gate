import json
import os
import tempfile
import unittest

from admission_gate import ActionProposal, GateConfig, gated_shell


class TestVerifyOnly(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = os.path.join(self.temp_dir.name, "verify_audit.jsonl")
        self.config = GateConfig(
            allowed_roots=["./workspace"],
            log_file=self.log_file,
            require_confirm=True,  # Would block on TTY if not in verify_only
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_verify_only_passed(self):
        # A valid proposal in verify_only mode should pass without prompting TTY
        p = ActionProposal("v_ok", "echo 'dry_run_test'", "./workspace", 1)
        passed, reason, code = gated_shell(p, config=self.config, verify_only=True)

        self.assertTrue(passed)
        self.assertEqual(code, 0)
        self.assertIn("Passed automated policy checks", reason)

        # Inspect audit log: human_accepted must be null
        with open(self.log_file, "r", encoding="utf-8") as f:
            entry = json.loads(f.readline())
            self.assertTrue(entry["policy_passed"])
            self.assertIsNone(entry["human_accepted"])
            self.assertEqual(entry["proposal"]["action_id"], "v_ok")

    def test_verify_only_blocked(self):
        # A blocked proposal in verify_only mode records policy failure
        p = ActionProposal("v_fail", "cat /etc/passwd", "/etc/passwd", 1)
        passed, reason, code = gated_shell(p, config=self.config, verify_only=True)

        self.assertFalse(passed)
        self.assertEqual(code, -1)
        self.assertIn("protected directory", reason)

        with open(self.log_file, "r", encoding="utf-8") as f:
            entry = json.loads(f.readline())
            self.assertFalse(entry["policy_passed"])
            self.assertIsNone(entry["human_accepted"])


if __name__ == "__main__":
    unittest.main()
