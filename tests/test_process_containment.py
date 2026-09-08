import os
import tempfile
import unittest

from admission_gate import ActionProposal, ExecConfig, GateConfig, gated_shell
from admission_gate.config import ProcessConfig


class TestProcessContainment(unittest.TestCase):
    def setUp(self):
        from admission_gate.gate import _DEFAULT_LIMITER
        _DEFAULT_LIMITER.history.clear()
        _DEFAULT_LIMITER.last_tier3_time = 0.0
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.temp_dir.name, "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        self.log_file = os.path.join(self.temp_dir.name, "audit_proc.jsonl")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_environment_variable_scrubbing(self):
        # Inject sensitive and hijacking variables into parent env
        os.environ["SUPER_SECRET_API_KEY"] = "sk-live-secret-value-12345"
        os.environ["LD_PRELOAD"] = "/fake/preload.so"
        os.environ["CUSTOM_TEST_ENV"] = "kept_value"

        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=False,
            log_file=self.log_file,
            exec_policy=ExecConfig(allow=["python", "python3", "sh", "echo"], deny=[]),
            process=ProcessConfig(
                scrub_env=True,
                env_allow=["PATH", "HOME", "LANG", "TERM", "CUSTOM_TEST_ENV"],
            ),
        )

        p = ActionProposal(
            "env1",
            'python3 -c "import os; print(os.environ.get(\'SUPER_SECRET_API_KEY\', \'NOT_FOUND\'), os.environ.get(\'LD_PRELOAD\', \'NOT_FOUND\'), os.environ.get(\'CUSTOM_TEST_ENV\', \'NOT_FOUND\'))"',
            self.workspace,
            1,
        )
        executed, out, code = gated_shell(p, config=cfg)
        self.assertTrue(executed)
        self.assertEqual(code, 0)
        self.assertIn("NOT_FOUND NOT_FOUND kept_value", out.strip())

    def test_command_timeout_kills_process_group(self):
        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=False,
            log_file=self.log_file,
            exec_policy=ExecConfig(allow=["python", "python3", "sleep", "sh"], deny=[]),
            process=ProcessConfig(
                timeout_seconds=0.5,
            ),
        )

        # Sleep longer than timeout
        p = ActionProposal(
            "timeout1",
            'python3 -c "import time; time.sleep(5)"',
            self.workspace,
            1,
        )
        executed, out, code = gated_shell(p, config=cfg)
        self.assertFalse(executed)
        self.assertEqual(code, -1)
        self.assertIn("timed out", out.lower())


if __name__ == "__main__":
    unittest.main()
