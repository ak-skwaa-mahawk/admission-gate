#!/usr/bin/env python3
"""
admission_gate.mcp - Stdio Model Context Protocol (MCP) server.
Routes agent tool calls through out-of-band statutory charter verification.
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict

from admission_gate.schemas import ActionEnvelope, AuthorityVerdict

PROTOCOL_VERSION = "2024-11-05"
DEFAULT_SOCK = "/data/data/com.termux/files/home/networkXG/ens_legis.sock"
DEFAULT_CHARTER = "charter.json"

TOOLS = [
    {
        "name": "gated_exec",
        "description": (
            "Execute a shell command with strict out-of-band statutory charter enforcement. "
            "All invocations are vetted against the immutable charter before process execution."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command line to execute.",
                },
                "target_resource": {
                    "type": "string",
                    "description": "File or system resource targeted by this command.",
                },
                "action_type": {
                    "type": "string",
                    "description": "Action category (e.g. SHELL_READ, SHELL_EXEC, MESH_TELEMETRY_LOG).",
                    "default": "SHELL_EXEC",
                },
            },
            "required": ["command", "target_resource"],
        },
    },
    {
        "name": "gate_check",
        "description": "Dry-run verification of an action against the statutory charter without executing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action_type": {"type": "string"},
                "target_resource": {"type": "string"},
            },
            "required": ["action_type", "target_resource"],
        },
    },
]

def query_gate(envelope: ActionEnvelope) -> AuthorityVerdict:
    sock_path = os.environ.get("ADMISSION_GATE_SOCK", DEFAULT_SOCK)
    charter_path = os.environ.get("ADMISSION_GATE_CHARTER", DEFAULT_CHARTER)

    if os.path.exists(sock_path):
        import socket
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect(sock_path)
                sock.sendall(envelope.to_json().encode("utf-8"))
                raw = sock.recv(4096)
                return AuthorityVerdict.from_dict(json.loads(raw.decode("utf-8")))
        except Exception:
            pass

    if os.path.exists(charter_path):
        import hashlib
        import re
        with open(charter_path, "r") as f:
            raw_c = f.read()
            c_data = json.loads(raw_c)
        c_hash = hashlib.sha256(raw_c.encode("utf-8")).hexdigest()

        for pat in c_data.get("prohibited_resource_patterns", []):
            if re.match(pat, envelope.target_resource):
                return AuthorityVerdict(
                    allowed=False,
                    regime="ENS_LEGIS",
                    charter_hash=c_hash,
                    error=f"ULTRA_VIRES_BREACH: Access to '{envelope.target_resource}' prohibited by '{pat}'",
                )

        if envelope.action_type not in c_data.get("authorized_actions", []):
            return AuthorityVerdict(
                allowed=False,
                regime="ENS_LEGIS",
                charter_hash=c_hash,
                error=f"ULTRA_VIRES_BREACH: Action '{envelope.action_type}' not authorized.",
            )

        return AuthorityVerdict(
            allowed=True,
            regime="ENS_LEGIS",
            charter_hash=c_hash,
            attestation=f"Action '{envelope.action_type}' authorized.",
        )

    return AuthorityVerdict(
        allowed=False,
        regime="OFFLINE",
        charter_hash="",
        error="No active UDS gate or charter file available.",
    )

def handle_rpc(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    msg_id = msg.get("id")
    method = msg.get("method")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "admission-gate-mcp", "version": "0.4.1"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": TOOLS},
        }

    if method == "tools/call":
        params = msg.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        if tool_name == "gate_check":
            envelope = ActionEnvelope(
                action_type=args.get("action_type", "SHELL_READ"),
                principal="MCP_AGENT",
                target_resource=args.get("target_resource", ""),
            )
            verdict = query_gate(envelope)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": verdict.to_json()}],
                    "isError": not verdict.allowed,
                },
            }

        if tool_name == "gated_exec":
            command = args.get("command", "")
            target_resource = args.get("target_resource", "")
            action_type = args.get("action_type", "SHELL_EXEC")

            envelope = ActionEnvelope(
                action_type=action_type,
                principal="MCP_AGENT",
                target_resource=target_resource,
                payload={"command": command},
            )
            verdict = query_gate(envelope)

            if not verdict.allowed:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"[ULTRA_VIRES_BREACH] Execution Vetoed\n"
                                    f"Charter Hash: {verdict.charter_hash}\n"
                                    f"Error: {verdict.error}"
                                ),
                            }
                        ],
                        "isError": True,
                    },
                }

            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
            )
            output = proc.stdout if proc.returncode == 0 else proc.stderr
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"[INTRA_VIRES_CONFIRMED] Charter: {verdict.charter_hash[:8]}\n"
                                f"Exit: {proc.returncode}\n\n{output}"
                            ),
                        }
                    ],
                    "isError": proc.returncode != 0,
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
        }

    return None

def main():
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
            resp = handle_rpc(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": str(e)},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
