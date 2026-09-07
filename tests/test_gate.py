import os
import tempfile
import unittest
from admission_gate.gate import ActionProposal, PolicyEngine, AuditLogger, evaluate
from admission_gate.verify import verify_log


class TestPolicyEngine(unittest.TestCase):
    def test_blocks_dangerous_commands(self):
        p = ActionProposal("1", "rm -rf /", "./workspace", 1)
        passed, _ = evaluate(p)
        self.assertFalse(passed)

    def test_blocks_protected_directories(self):
        p = ActionProposal("2", "touch /etc/config", "/etc/config", 1)
        passed, _ = evaluate(p)
        self.assertFalse(passed)

    def test_enforces_allowed_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            allowed = os.path.join(tmp, "allowed")
            os.makedirs(allowed, exist_ok=True)

            good_p = ActionProposal("3", "touch test", os.path.join(allowed, "file.txt"), 1)
            passed, _ = evaluate(good_p, allowed_roots=[allowed])
            self.assertTrue(passed)

            bad_p = ActionProposal("4", "touch test", os.path.join(tmp, "outside.txt"), 1)
            passed, _ = evaluate(bad_p, allowed_roots=[allowed])
            self.assertFalse(passed)


class TestAuditChain(unittest.TestCase):
    def test_log_and_verification(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            log_path = f.name

        try:
            logger = AuditLogger(log_path=log_path)
            p1 = ActionProposal("1", "echo hi", "./workspace", 1)
            p2 = ActionProposal("2", "ls", "./workspace", 1)

            logger.commit(p1, True, "passed", True)
            logger.commit(p2, True, "passed", False)

            ok, count, _ = verify_log(log_path)
            self.assertTrue(ok)
            self.assertEqual(count, 2)
        finally:
            if os.path.exists(log_path):
                os.remove(log_path)


if __name__ == "__main__":
    unittest.main()
