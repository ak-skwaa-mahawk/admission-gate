#!/usr/bin/env python3
"""
admission_gate.mcp - Zero-dependency Model Context Protocol (MCP) server.
Exposes admission-gate protected shell execution over JSON-RPC stdio.
"""

import json
import sys
import uuid
from typing import Any, Dict, Optional

from admission_gate.config import GateConfig, find_default_config
from admission_gate.gate import ActionProposal, gated_shell

PROTOCOL_VERSION = "2024-11-05"

TOOL_DEFINITION = {
    "name": "gated_bash",
    "description": (
        "Execute a shell command through the admission-gate security kernel. "
        "Commands are subjected to deterministic path canonicalization, sandbox jail checks, "
        "dangerous pattern blocking, human authorization (if required), and append-only cryptographic audit logging."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The exact shell command line to execute.",
            },
            "target_path": {
                "type": "string",
                "description": "The primary file or directory path affected by this action.",
            },
            "risk_tier": {
                "type": "integer",
                "enum": [1, 2, 3],
                "description": "Risk assessment level: 1 (read/low impact), 2 (create/modify), 3 (destructive/critical).",
                "default": 1,
            },
        },
        "required": ["command", "target_path"],
    },
}


class MCPServer:
    def __init__(self, config: Optional[GateConfig] = None):
        self.config = config or GateConfig()

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "admission-gate",
                        "version": "0.2.0",
                    },
                },
            }

        elif method == "notifications/initialized":
            return None

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": [TOOL_DEFINITION]},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if tool_name != "gated_bash":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }

            cmd = arguments.get("command", "")
            target = arguments.get("target_path", ".")
            risk = int(arguments.get("risk_tier", 1))

            proposal = ActionProposal(
                action_id=f"mcp_{uuid.uuid4().hex[:8]}",
                command=cmd,
                target_path=target,
                risk_tier=risk,
            )

            executed, output, exit_code = gated_shell(proposal, config=self.config)

            if not executed:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "isError": True,
                        "content": [
                            {
                                "type": "text",
                                "text": f"[Admission Gate Refusal]: {output}",
                            }
                        ],
                    },
                }

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": exit_code != 0,
                    "content": [
                        {
                            "type": "text",
                            "text": f"Exit Code: {exit_code}\nOutput:\n{output}",
                        }
                    ],
                },
            }

        elif msg_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not supported: {method}"},
            }

        return None

    def run(self):
        # Stdio JSON-RPC event loop
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                response = self.handle_request(msg)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


def main():
    cfg_file = find_default_config()
    cfg = GateConfig.load_from_file(cfg_file) if cfg_file else GateConfig()
    server = MCPServer(config=cfg)
    server.run()


if __name__ == "__main__":
    main()
