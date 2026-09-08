import unittest
from admission_gate import ActionProposal, evaluate


class TestEnvVarHardening(unittest.TestCase):
    def test_posix_env_var_in_command_blocked(self):
        # $VAR syntax in path argument
        p1 = ActionProposal("env1", "cat $SECRET_DIR/file.txt", "./workspace", 1)
        passed, reason = evaluate(p1, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("unexpanded environment variable", reason)

        # ${VAR} syntax in path argument
        p2 = ActionProposal("env2", "cat ${HOME}/.ssh/id_rsa", "./workspace", 1)
        passed, reason = evaluate(p2, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("unexpanded environment variable", reason)

    def test_windows_env_var_blocked(self):
        # %VAR% syntax
        p = ActionProposal("env3", "type %USERPROFILE%\\secret.txt", "./workspace", 1)
        passed, reason = evaluate(p, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("unexpanded environment variable", reason)

    def test_env_var_in_target_path_blocked(self):
        # Explicit target_path using environment variable
        p = ActionProposal("env4", "cat file.txt", "$TARGET_DIR/file.txt", 1)
        passed, reason = evaluate(p, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("unexpanded environment variable", reason)

    def test_env_var_in_redirection_blocked(self):
        # Output redirection into variable-defined target
        p = ActionProposal("env5", "echo test > $CONF_DIR/bad.conf", "./workspace", 2)
        passed, reason = evaluate(p, allowed_roots=["./workspace"])
        self.assertFalse(passed)
        self.assertIn("unexpanded environment variable", reason)


if __name__ == "__main__":
    unittest.main()
