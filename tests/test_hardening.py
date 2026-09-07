import unittest
from admission_gate import ActionProposal, evaluate


class TestHardening(unittest.TestCase):
    def test_subshell_substitution_blocked(self):
        # $(...) syntax
        p1 = ActionProposal("sub1", "echo $(cat /etc/shadow)", "./workspace", 1)
        passed, reason = evaluate(p1, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("subshell substitution", reason)

        # Backtick substitution
        p2 = ActionProposal("sub2", "echo `whoami`", "./workspace", 1)
        passed, reason = evaluate(p2, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("subshell substitution", reason)

    def test_command_redirection_escape_blocked(self):
        # Target path claims to be benign workspace, but command redirects into /etc
        p1 = ActionProposal("redir1", "echo evil > /etc/crontab", "./workspace", 2)
        passed, reason = evaluate(p1, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("resolves to protected directory '/etc'", reason)

        # Space-free redirection token: >>/etc/hosts
        p2 = ActionProposal("redir2", "echo evil >>/etc/hosts", "./workspace", 2)
        passed, reason = evaluate(p2, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("resolves to protected directory '/etc'", reason)

    def test_relative_token_escape_blocked(self):
        # Embedded traversal in command argument escaping allowed root
        p = ActionProposal("arg_esc", "cat ./workspace/../../etc/passwd", "./workspace", 1)
        passed, reason = evaluate(p, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertTrue(
            "protected directory" in reason or "escapes allowed roots" in reason
        )

    def test_benign_command_with_flags_allowed(self):
        # Legitimate commands containing paths inside workspace should pass
        p = ActionProposal("ok_run", "ls -la ./workspace/subfolder", "./workspace", 1)
        passed, _ = evaluate(p, allowed_roots=["./workspace"])
        self.assertTrue(passed)


if __name__ == "__main__":
    unittest.main()
