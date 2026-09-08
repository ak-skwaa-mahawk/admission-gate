import unittest
from admission_gate import ActionProposal, PolicyEngine


class TestRiskClassification(unittest.TestCase):
    def test_read_only_commands(self):
        commands = [
            "ls -la ./workspace",
            "cat file.txt",
            "grep -rn 'pattern' src/",
            "head -n 20 log.txt",
            "wc -l data.csv",
        ]
        for cmd in commands:
            tier, _ = PolicyEngine.classify_risk(cmd)
            self.assertEqual(tier, 1, f"Expected tier 1 for: {cmd}")

    def test_write_and_mutating_commands(self):
        commands = [
            "echo 'hello' > output.txt",
            "echo 'append' >> log.txt",
            "touch newfile.txt",
            "mkdir -p build",
            "python3 script.py",
        ]
        for cmd in commands:
            tier, _ = PolicyEngine.classify_risk(cmd)
            self.assertGreaterEqual(tier, 2, f"Expected tier >= 2 for: {cmd}")

    def test_destructive_commands(self):
        commands = [
            "rm -f ./workspace/temp.txt",
            "mv old.txt new.txt",
            "chmod +x script.sh",
            "sed -i 's/foo/bar/g' config.ini",
            "dd if=/dev/zero of=test.img bs=1M count=1",
        ]
        for cmd in commands:
            tier, _ = PolicyEngine.classify_risk(cmd)
            self.assertEqual(tier, 3, f"Expected tier 3 for: {cmd}")

    def test_upward_ratchet_enforcement(self):
        # An agent claiming Tier 1 on 'rm' gets ratcheted to Tier 3
        p = ActionProposal("esc_1", "rm -f ./workspace/temp.txt", "./workspace", risk_tier=1)
        _, _, effective_tier = PolicyEngine.evaluate(p, allowed_roots=["./workspace"])
        self.assertEqual(effective_tier, 3)

        # An agent declaring Tier 3 on a read-only command stays Tier 3
        p2 = ActionProposal("esc_2", "cat ./workspace/file.txt", "./workspace", risk_tier=3)
        _, _, effective_tier2 = PolicyEngine.evaluate(p2, allowed_roots=["./workspace"])
        self.assertEqual(effective_tier2, 3)


if __name__ == "__main__":
    unittest.main()
