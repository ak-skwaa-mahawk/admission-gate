import os
import shutil
import tempfile
import unittest

from admission_gate import ActionProposal, ExecConfig, GateConfig, gated_shell


class TestExecPolicy(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = os.path.join(self.temp_dir.name, "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        self.log_file = os.path.join(self.temp_dir.name, "audit_exec.jsonl")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_allowed_binary_passes(self):
        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=False,
            log_file=self.log_file,
            exec_policy=ExecConfig(allow=["ls", "echo"], deny=["curl"]),
        )
        p = ActionProposal("p1", "echo ok", self.workspace, 1)
        executed, out, code = gated_shell(p, config=cfg)
        self.assertTrue(executed)
        self.assertEqual(code, 0)

    def test_denied_binary_fails_even_with_low_declared_tier(self):
        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=False,
            log_file=self.log_file,
            exec_policy=ExecConfig(allow=["ls", "echo"], deny=["ssh", "curl"]),
        )
        p = ActionProposal("ssh1", "ssh user@remote", self.workspace, 1)
        executed, reason, code = gated_shell(p, config=cfg)
        self.assertFalse(executed)
        self.assertEqual(code, -1)
        self.assertIn("denied by execution policy", reason)

    def test_unlisted_binary_fails_allowlist(self):
        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=False,
            log_file=self.log_file,
            exec_policy=ExecConfig(allow=["ls"], deny=[]),
        )
        p = ActionProposal("p2", "cat test.txt", self.workspace, 1)
        executed, reason, _ = gated_shell(p, config=cfg)
        self.assertFalse(executed)
        self.assertIn("not in execution allowlist", reason)

    def test_local_fake_binary_resolves_and_blocks(self):
        fake_curl = os.path.join(self.workspace, "curl")
        with open(fake_curl, "w") as f:
            f.write("#!/bin/sh\necho fake curl\n")
        os.chmod(fake_curl, 0o755)

        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=False,
            log_file=self.log_file,
            exec_policy=ExecConfig(allow=["echo"], deny=["curl"]),
        )
        p = ActionProposal("p3", f"{fake_curl} http://evil.com", self.workspace, 1)
        executed, reason, _ = gated_shell(p, config=cfg)
        self.assertFalse(executed)
        self.assertIn("denied by execution policy", reason)

    def test_symlink_binary_canonicalization(self):
        py_bin = shutil.which("python3") or shutil.which("python")
        if not py_bin:
            self.skipTest("No python binary found on PATH")

        symlink_path = os.path.join(self.workspace, "my_python")
        try:
            os.symlink(py_bin, symlink_path)
        except OSError:
            self.skipTest("Symlinks not permitted in environment")

        real_target_base = os.path.basename(os.path.realpath(py_bin))
        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=False,
            log_file=self.log_file,
            exec_policy=ExecConfig(allow=["python", "python3", real_target_base, "my_python"], deny=[]),
        )
        p = ActionProposal("p4", f"{symlink_path} -c 'print(1)'", self.workspace, 1)
        executed, out, code = gated_shell(p, config=cfg)
        self.assertTrue(executed)
        self.assertEqual(code, 0)
        self.assertIn("1", out)

    def test_compound_command_rejects_if_any_argv0_disallowed(self):
        cfg = GateConfig(
            allowed_roots=[self.workspace],
            require_confirm=False,
            log_file=self.log_file,
            exec_policy=ExecConfig(allow=["ls", "echo"], deny=["ssh"]),
        )
        p = ActionProposal("p5", "echo hi && ssh user@evil.com", self.workspace, 1)
        executed, reason, _ = gated_shell(p, config=cfg)
        self.assertFalse(executed)
        self.assertIn("denied by execution policy", reason)


if __name__ == "__main__":
    unittest.main()
