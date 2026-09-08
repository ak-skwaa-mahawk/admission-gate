#!/usr/bin/env python3
"""
Model Context Protocol (MCP) stdio server adapter for Admission Gate + FPT Kernel Daemon.
Exposes shell command execution strictly through the cybernetic homeostatic gate.
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict, Optional

SOCKET_PATH = os.environ.get("FPT_SOCKET_PATH", "/data/data/com.termux/files/usr/tmp/fpt_kernel.sock")

SERVER_INFO = {
    "name": "admission-gate-mcp",
    "version": "0.1.0"
}

TOOLS = [
    {
        "name": "execute_gated_command",
        "description": (
            "Executes a bash/shell command through the Admission Gate and FPT continuous "
            "regulator. Dynamically throttles, quarantines into ./scratch, or requires "
            "out-of-band sovereign clearance under elevated damping."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The command string to execute (e.g. 'ls -la ./workspace')."
                },
                "target_path": {
                    "type": "string",
                    "description": "Path target scope for execution boundaries (default: './workspace').",
                    "default": "./workspace"
                },
                "risk_tier": {
                    "type": "integer",
                    "enum": [1, 2, 3],
                    "description": "Nominal risk level (1=Read/Benign, 2=Write/Build, 3=Root/Privileged).",
                    "default": 1
                },
                "approval_token": {
                    "type": "string",
                    "description": "Optional sovereign Nullrose handshake token (JSON or signature) required when damping > 0.85.",
                }
            },
            "required": ["command"]
        }
    }
]

def log_debug(msg: str) -> None:
    sys.stderr.write(f"[FPT-MCP] {msg}\n")
    sys.stderr.flush()

def call_fpt_client(command: str, target_path: str, risk_tier: int, token: Optional[str] = None) -> Dict[str, Any]:
    args = ["fpt-client", command, target_path, str(risk_tier)]
    if token:
        args.append(token)
    
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False
        )
        output_str = proc.stdout.strip()
        if not output_str:
            return {
                "status": "error",
                "output": proc.stderr.strip() or "No output from fpt-client",
                "exit_code": proc.returncode
            }
        return json.loads(output_str)
    except FileNotFoundError:
        return {
            "status": "fatal",
            "output": "fpt-client executable not found in PATH.",
            "exit_code": -1
        }
    except json.JSONDecodeError:
        return {
            "status": "raw",
            "output": output_str,
            "exit_code": proc.returncode
        }
    except Exception as e:
        return {
            "status": "exception",
            "output": str(e),
            "exit_code": -1
        }

def handle_request(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    req_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": SERVER_INFO
            }
        }

    elif method == "notifications/initialized":
        return None

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS
            }
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})

        if tool_name != "execute_gated_command":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Unknown tool: {tool_name}"
                }
            }

        cmd = args.get("command", "")
        target = args.get("target_path", "./workspace")
        tier = int(args.get("risk_tier", 1))
        token = args.get("approval_token")

        log_debug(f"Executing: '{cmd}' on '{target}' (Tier {tier})")
        res = call_fpt_client(cmd, target, tier, token)

        is_error = not res.get("executed", False) if "executed" in res else (res.get("status") != "ok")
        formatted_content = json.dumps(res, indent=2)

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": formatted_content
                    }
                ],
                "isError": is_error
            }
        }

    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        }

    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not implemented"
            }
        }

def main() -> None:
    log_debug("Starting Admission Gate stdio MCP server...")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error: invalid JSON"
                }
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            log_debug(f"Unhandled error: {e}")

if __name__ == "__main__":
    main()
