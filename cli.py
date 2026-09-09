import argparse
import sys
import os
import json
import socket
import subprocess
from pathlib import Path
from admission_gate.schemas import ActionEnvelope, AuthorityVerdict

DEFAULT_SOCK = "/data/data/com.termux/files/home/networkXG/ens_legis.sock"
DEFAULT_CHARTER = "charter.json"

DEFAULT_CHARTER_TEMPLATE = {
    "charter_version": "1.0",
    "entity_id": "SOVEREIGN_AGENT_ALPHA",
    "authorized_actions": ["SHELL_READ", "MESH_TELEMETRY_LOG", "SOLITON_BLOOM_CYCLE"],
    "allowed_resource_patterns": [
        "^/data/data/com.termux/files/home/networkXG/.*",
        "^\\./.*"
    ],
    "prohibited_resource_patterns": [
        "^/sys/.*",
        "^/proc/.*",
        "^/etc/.*"
    ]
}

def query_uds_gate(envelope: ActionEnvelope, sock_path: str) -> AuthorityVerdict:
    if not os.path.exists(sock_path):
        raise ConnectionRefusedError(f"Socket not found at {sock_path}")
    
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(sock_path)
        sock.sendall(envelope.to_json().encode("utf-8"))
        raw = sock.recv(4096)
        return AuthorityVerdict.from_dict(json.loads(raw.decode("utf-8")))

def in_process_evaluate(envelope: ActionEnvelope, charter_path: str) -> AuthorityVerdict:
    import re
    import hashlib

    with open(charter_path, "r") as f:
        charter_bytes = f.read().encode("utf-8")
        charter = json.loads(charter_bytes.decode("utf-8"))
    
    charter_hash = hashlib.sha256(charter_bytes).hexdigest()

    # 1. Prohibited check
    for pattern in charter.get("prohibited_resource_patterns", []):
        if re.match(pattern, envelope.target_resource):
            return AuthorityVerdict(
                allowed=False,
                regime="ENS_LEGIS",
                charter_hash=charter_hash,
                error=f"ULTRA_VIRES_BREACH: Target resource '{envelope.target_resource}' matches prohibited rule '{pattern}'"
            )

    # 2. Action check
    if envelope.action_type not in charter.get("authorized_actions", []):
        return AuthorityVerdict(
            allowed=False,
            regime="ENS_LEGIS",
            charter_hash=charter_hash,
            error=f"ULTRA_VIRES_BREACH: Action '{envelope.action_type}' not authorized in charter."
        )

    return AuthorityVerdict(
        allowed=True,
        regime="ENS_LEGIS",
        charter_hash=charter_hash,
        attestation=f"Action '{envelope.action_type}' fully authorized under sovereign charter."
    )

def evaluate_envelope(envelope: ActionEnvelope, sock_path: str, charter_path: str) -> AuthorityVerdict:
    if os.path.exists(sock_path):
        return query_uds_gate(envelope, sock_path)
    if os.path.exists(charter_path):
        return in_process_evaluate(envelope, charter_path)
    raise FileNotFoundError(f"Neither UDS gate ({sock_path}) nor charter file ({charter_path}) found.")

def main():
    parser = argparse.ArgumentParser(prog="admission-gate", description="Autonomous Agent Tool Safety & Statutory Boundary Gate")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # admission-gate init
    init_parser = subparsers.add_parser("init", help="Scaffold a default charter.json")
    init_parser.add_argument("--path", default=DEFAULT_CHARTER, help="Path for charter.json")

    # admission-gate check
    check_parser = subparsers.add_parser("check", help="Dry-run audit check for an action")
    check_parser.add_argument("--action", required=True, help="Action type identifier")
    check_parser.add_argument("--resource", required=True, help="Target resource path or descriptor")
    check_parser.add_argument("--principal", default="AGENT_CLI", help="Invoking principal")
    check_parser.add_argument("--sock", default=DEFAULT_SOCK, help="Path to UDS gate")
    check_parser.add_argument("--charter", default=DEFAULT_CHARTER, help="Path to local charter fallback")

    # admission-gate exec
    exec_parser = subparsers.add_parser("exec", help="Gate and execute a shell command")
    exec_parser.add_argument("--action", default="SHELL_EXEC", help="Action classification")
    exec_parser.add_argument("--resource", required=True, help="Target resource or operation target")
    exec_parser.add_argument("--principal", default="AGENT_EXEC", help="Invoking principal")
    exec_parser.add_argument("--sock", default=DEFAULT_SOCK, help="Path to UDS gate")
    exec_parser.add_argument("--charter", default=DEFAULT_CHARTER, help="Path to local charter fallback")
    exec_parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to execute after '--'")

    args = parser.parse_args()

    if args.subcommand == "init":
        target = Path(args.path)
        if target.exists():
            print(f"[!] Charter already exists at {target}")
            sys.exit(1)
        with open(target, "w") as f:
            json.dump(DEFAULT_CHARTER_TEMPLATE, f, indent=2)
        print(f"[+] Scaffolded charter written to {target}")
        sys.exit(0)

    if args.subcommand in ("check", "exec"):
        envelope = ActionEnvelope(
            action_type=args.action,
            principal=args.principal,
            target_resource=args.resource,
            payload={"cmd": args.cmd if hasattr(args, "cmd") else []}
        )

        try:
            verdict = evaluate_envelope(envelope, args.sock, args.charter)
        except Exception as e:
            sys.stderr.write(f"[FATAL GATE ERROR] {str(e)}\n")
            sys.exit(1)

        if not verdict.allowed:
            sys.stderr.write(f"\n[ULTRA_VIRES_BREACH] Execution Vetoed\n")
            sys.stderr.write(f"Charter Hash: {verdict.charter_hash}\n")
            sys.stderr.write(f"Error: {verdict.error}\n\n")
            sys.exit(126)

        if args.subcommand == "check":
            print(json.dumps(asdict(verdict), indent=2))
            sys.exit(0)

        # args.subcommand == "exec"
        cmd = args.cmd
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        
        if not cmd:
            sys.stderr.write("[ERROR] No command specified to execute.\n")
            sys.exit(1)

        sys.stderr.write(f"[INTRA_VIRES_CONFIRMED] Charter: {verdict.charter_hash[:8]} | Invoking: {' '.join(cmd)}\n")
        res = subprocess.run(cmd)
        sys.exit(res.returncode)

if __name__ == "__main__":
    main()
