import io
import json
import os
import sys
import tempfile
import unittest

from admission_gate import ActionProposal, ExecConfig, GateConfig, ProcessConfig, gated_shell
from admission_gate.gate import AuditLogger, _DEFAULT_LIMITER
from admission_gate.query import run_replay


class TestV040Features(unittest.TestCase):
    def setUp(self):
        _DEFAULT_LIMITER.history.clear()
        _DEFAULT_LIMITER.last_tier3_time = 0.0
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = os.path.join(self.temp_dir.name, "audit_test.jsonl")
        self.workspace = os.path.join(self.temp_dir.name, "workspace")
        os.makedirs(self.workspace, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_audit_log_schema_version_and_precedence(self):
        logger = AuditLogger(log_path=self.log_file)
        p = ActionProposal("v040-1", "echo ok", self.workspace, 1)
        logger.commit(p, passed=True, reason="ok", human_decision=True)

        with open(self.log_file, "r", encoding="utf-8") as f:
            entry = json.loads(f.readline())

        self.assertEqual(entry.get("schema_version"), "0.4.0")
        self.assertIn("flags > env > file > defaults", entry.get("config_precedence"))
        self.assertIn("resolved_binaries", entry)
        self.assertIn("env_scrubbed", entry)
        self.assertIn("timeout_fired", entry)

    def test_replay_detects_legacy_gap_and_divergence(self):
        # 1. Write a legacy pre-0.4.0 entry without resolved_binaries
        legacy_entry = {
            "prev_hash": "0" * 64,
            "timestamp_ns": 1000,
            "proposal": {"action_id": "leg-1", "command": "echo old", "target_path": self.workspace, "risk_tier": 1},
            "effective_risk_tier": 1,
            "policy_passed": True,
            "policy_reason": "ok",
            "entry_hash": "a" * 64
        }
        # 2. Write a 0.4.0 entry that will diverge under a strict execution policy
        v4_divergent = {
            "schema_version": "0.4.0",
            "prev_hash": "a" * 64,
            "timestamp_ns": 2000,
            "proposal": {"action_id": "div-2", "command": "curl http://example.com", "target_path": self.workspace, "risk_tier": 1},
            "effective_risk_tier": 1,
            "resolved_binaries": ["curl"],
            "policy_passed": True,
            "policy_reason": "ok",
            "entry_hash": "b" * 64
        }
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(legacy_entry) + "\n")
            f.write(json.dumps(v4_divergent) + "\n")

        # Replay with strict denylist
        cfg_path = os.path.join(self.temp_dir.name, "strict.toml")
        with open(cfg_path, "w") as f:
            f.write('[exec]\ndeny = ["curl"]\n')

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            run_replay(self.log_file, config_path=cfg_path)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertIn("CANNOT REPLAY: Pre-0.4.0 record lacks resolved_binaries metadata", output)
        self.assertIn("WOULD NOW DENY (divergence: argv0)", output)


if __name__ == "__main__":
    unittest.main()
