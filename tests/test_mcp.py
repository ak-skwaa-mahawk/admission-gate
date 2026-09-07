import json
import unittest

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
        self.assertEqual(resp["result"]["serverInfo"]["name"], "admission-gate")

        list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        resp = self.server.handle_request(list_req)
        tools = resp["result"]["tools"]
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["name"], "gated_bash")

    def test_gated_bash_blocked(self):
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "gated_bash",
                "arguments": {
                    "command": "cat /etc/shadow",
                    "target_path": "/etc/shadow",
                    "risk_tier": 2,
                },
            },
        }
        resp = self.server.handle_request(call_req)
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("Admission Gate Refusal", resp["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
