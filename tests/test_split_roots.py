import os
import tempfile
import unittest

from admission_gate import ActionProposal, GateConfig, gated_shell


class TestSplitRoots(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.read_root = os.path.join(self.temp_dir.name, "repo")
        self.write_root = os.path.join(self.temp_dir.name, "workspace")
        os.makedirs(self.read_root, exist_ok=True)
        os.makedirs(self.write_root, exist_ok=True)
        self.log_file = os.path.join(self.temp_dir.name, "audit_split.jsonl")

        # Create a sample read file
        with open(os.path.join(self.read_root, "source.py"), "w") as f:
            f.write("print('hello')\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tier1_read_allowed_in_read_root(self):
        cfg = GateConfig(
            read_roots=[self.read_root],
            write_roots=[self.write_root],
            require_confirm=False,
            log_file=self.log_file,
        )
        p = ActionProposal("r1", f"cat {self.read_root}/source.py", self.read_root, 1)
        executed, out, code = gated_shell(p, config=cfg)
        self.assertTrue(executed)
        self.assertEqual(code, 0)
        self.assertIn("hello", out)

    def test_tier1_read_allowed_in_write_root(self):
        # Read roots union allows reading from write roots too
        ws_file = os.path.join(self.write_root, "temp.txt")
        with open(ws_file, "w") as f:
            f.write("temp data\n")

        cfg = GateConfig(
            read_roots=[self.read_root],
            write_roots=[self.write_root],
            require_confirm=False,
            log_file=self.log_file,
        )
        p = ActionProposal("r2", f"cat {ws_file}", self.write_root, 1)
        executed, out, code = gated_shell(p, config=cfg)
        self.assertTrue(executed)
        self.assertEqual(code, 0)

    def test_tier2_write_denied_in_read_root(self):
        cfg = GateConfig(
            read_roots=[self.read_root],
            write_roots=[self.write_root],
            require_confirm=False,
            log_file=self.log_file,
        )
        # Attempting touch/create inside read root
        p = ActionProposal("w1", f"touch {self.read_root}/new_file.py", self.read_root, 2)
        executed, reason, code = gated_shell(p, config=cfg)
        self.assertFalse(executed)
        self.assertEqual(code, -1)
        self.assertTrue("write_roots" in reason or "read-only root" in reason or "read root" in reason or "escapes" in reason)

    def test_redirection_into_read_root_denied(self):
        cfg = GateConfig(
            read_roots=[self.read_root],
            write_roots=[self.write_root],
            require_confirm=False,
            log_file=self.log_file,
        )
        p = ActionProposal("w2", f"echo bad > {self.read_root}/source.py", self.read_root, 2)
        executed, reason, code = gated_shell(p, config=cfg)
        self.assertFalse(executed)
        self.assertEqual(code, -1)

    def test_tier2_mutation_allowed_in_write_root(self):
        cfg = GateConfig(
            read_roots=[self.read_root],
            write_roots=[self.write_root],
            require_confirm=False,
            log_file=self.log_file,
        )
        target = os.path.join(self.write_root, "created.txt")
        p = ActionProposal("w3", f"touch {target}", self.write_root, 2)
        executed, out, code = gated_shell(p, config=cfg)
        self.assertTrue(executed)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(target))

    def test_mv_from_write_root_into_read_root_denied(self):
        cfg = GateConfig(
            read_roots=[self.read_root],
            write_roots=[self.write_root],
            require_confirm=False,
            log_file=self.log_file,
        )
        src = os.path.join(self.write_root, "payload.sh")
        with open(src, "w") as f:
            f.write("#!/bin/sh\n")
        dst = os.path.join(self.read_root, "payload.sh")

        p = ActionProposal("w4", f"mv {src} {dst}", self.write_root, 3)
        executed, reason, code = gated_shell(p, config=cfg)
        self.assertFalse(executed)
        self.assertEqual(code, -1)


if __name__ == "__main__":
    unittest.main()
