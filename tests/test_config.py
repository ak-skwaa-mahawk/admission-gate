import os
import tempfile
import unittest

from admission_gate import ActionProposal, GateConfig, evaluate


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "admission_gate.toml")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_toml_loading(self):
        toml_content = """
[policy]
blocked_patterns = ["rm -rf", "reboot"]
require_confirm = false

[filesystem]
allowed_roots = ["/safe/path", "/workspace"]
protected_paths = ["/etc", "/var/secret"]

[logging]
log_file = "custom_audit.jsonl"
"""
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(toml_content)

        cfg = GateConfig.load_from_file(self.config_path)

        self.assertEqual(cfg.blocked_patterns, ["rm -rf", "reboot"])
        self.assertFalse(cfg.require_confirm)
        self.assertEqual(cfg.allowed_roots, ["/safe/path", "/workspace"])
        self.assertEqual(cfg.protected_paths, ["/etc", "/var/secret"])
        self.assertEqual(cfg.log_file, "custom_audit.jsonl")

    def test_evaluate_with_custom_config(self):
        toml_content = """
[policy]
blocked_patterns = ["git push --force"]

[filesystem]
allowed_roots = ["./workspace"]
"""
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(toml_content)

        cfg = GateConfig.load_from_file(self.config_path)

        # Blocked pattern check from config
        p1 = ActionProposal("1", "git push --force origin main", "./workspace", 1)
        passed, reason = evaluate(p1, config=cfg)
        self.assertFalse(passed)
        self.assertIn("git push --force", reason)


if __name__ == "__main__":
    unittest.main()
