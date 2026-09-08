import json
import tempfile
import time
import unittest

from admission_gate import ActionProposal, AuditLogger, GateConfig
from admission_gate.query import filter_entries, parse_relative_time, replay_proposal


class TestAuditQuery(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = f"{self.temp_dir.name}/test_query_log.jsonl"
        self.logger = AuditLogger(log_path=self.log_file)

        # Seed sample entries
        p1 = ActionProposal("act_1", "ls -la", "./workspace", 1)
        self.logger.commit(p1, passed=True, reason="ok", human_decision=True, effective_tier=1)

        p2 = ActionProposal("act_2", "cat /etc/shadow", "/etc/shadow", 1)
        self.logger.commit(p2, passed=False, reason="protected path", human_decision=None, effective_tier=1)

        p3 = ActionProposal("act_3", "rm file.txt", "./workspace", 1)
        self.logger.commit(p3, passed=True, reason="ok", human_decision=False, effective_tier=3)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_filter_by_action_id(self):
        records = list(filter_entries(self.log_file, action_id="act_2"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["proposal"]["action_id"], "act_2")

    def test_filter_by_tier(self):
        records = list(filter_entries(self.log_file, tier=3))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["proposal"]["action_id"], "act_3")

    def test_filter_by_status(self):
        passed = list(filter_entries(self.log_file, status="passed"))
        self.assertEqual(len(passed), 1)
        self.assertEqual(passed[0]["proposal"]["action_id"], "act_1")

        blocked = list(filter_entries(self.log_file, status="blocked"))
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["proposal"]["action_id"], "act_2")

        rejected = list(filter_entries(self.log_file, status="rejected"))
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["proposal"]["action_id"], "act_3")

    def test_replay_policy_evaluation(self):
        records = list(filter_entries(self.log_file, action_id="act_3"))
        cfg = GateConfig(blocked_patterns=["rm"])
        result = replay_proposal(records[0], config=cfg)

        self.assertTrue(result["historical_passed"])
        self.assertFalse(result["replay_passed"])
        self.assertIn("matched hazardous pattern", result["replay_reason"])

    def test_parse_relative_time(self):
        now = time.time()
        parsed = parse_relative_time("10m")
        self.assertAlmostEqual(parsed, now - 600, delta=2)


if __name__ == "__main__":
    unittest.main()
