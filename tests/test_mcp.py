import json
import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch

from admission_gate.config import GateConfig
from admission_gate.mcp import MCPServer


class TestMCPAdapter(unittest.TestCase):
    def setUp(self):
        self.config = GateConfig(
            allowed_roots=["./workspace"],
            require_confirm=False,
            log_file="test_audit.jsonl",
        )
        self.server = MCPServer(config=self.config)

    def test_initialize_and_tools_list(self):
        init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
        resp = self.server.handle_request(init_req)
        self.assertEqual(resp["id"], 1)
        self.assertIn("admission-gate", resp["result"]["serverInfo"]["name"])

        list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        resp = self.server.handle_request(list_req)
        tools = resp["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("gated_exec", tool_names)
        self.assertIn("gate_check", tool_names)

    def test_gated_exec_blocked_without_charter_or_socket(self):
        with patch.dict(os.environ, {"ADMISSION_GATE_SOCK": "/nonexistent.sock", "ADMISSION_GATE_CHARTER": "/nonexistent.json"}):
            call_req = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "gated_exec",
                    "arguments": {
                        "command": "cat /etc/shadow",
                        "target_resource": "/etc/shadow",
                    },
                },
            }
            resp = self.server.handle_request(call_req)
            self.assertTrue(resp["result"]["isError"])
            self.assertIn("ULTRA_VIRES_BREACH", resp["result"]["content"][0]["text"])

    def test_gated_exec_veto_with_charter(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            charter_data = {
                "prohibited_resource_patterns": [r"^/etc/.*"],
                "authorized_actions": ["SHELL_EXEC"],
            }
            json.dump(charter_data, f)
            charter_path = f.name

        try:
            with patch.dict(os.environ, {
                "ADMISSION_GATE_SOCK": "/nonexistent.sock",
                "ADMISSION_GATE_CHARTER": charter_path,
            }):
                call_req = {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "gated_exec",
                        "arguments": {
                            "command": "cat /etc/shadow",
                            "target_resource": "/etc/shadow",
                        },
                    },
                }
                resp = self.server.handle_request(call_req)
                self.assertTrue(resp["result"]["isError"])
                self.assertIn("[ULTRA_VIRES_BREACH] Execution Vetoed", resp["result"]["content"][0]["text"])
        finally:
            Path(charter_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
