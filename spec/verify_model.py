#!/usr/bin/env python3
"""
Exhaustive state-space model checker for TriSystemGate specification.
Validates SovereignWitnessIntegrity and SovereignNonBypassability.
"""
from collections import deque

PROPOSALS = ("p1", "p2")
SOVEREIGN_KEYS = ("k_99733_Q",)
MAX_HISTORY = 4
SIGMA_ESCALATION = 85
SIGMA_QUARANTINE = 92

def get_init_state():
    return {
        "current_proposal": None,
        "sigma": 15,
        "require_confirm": False,
        "quarantine_active": False,
        "sovereign_token_present": False,
        "token_key": None,
        "executed": frozenset(),
        "audit_ledger": ()
    }

def state_to_key(s):
    return (
        s["current_proposal"],
        s["sigma"],
        s["require_confirm"],
        s["quarantine_active"],
        s["sovereign_token_present"],
        s["token_key"],
        s["executed"],
        s["audit_ledger"]
    )

def update_actuation(sigma):
    return (sigma > SIGMA_ESCALATION), (sigma > SIGMA_QUARANTINE)

def get_next_states(s):
    next_states = []

    # SubmitProposal
    if s["current_proposal"] is None and len(s["audit_ledger"]) < MAX_HISTORY:
        for p in PROPOSALS:
            for has_token in (False, True):
                keys = SOVEREIGN_KEYS if has_token else (None,)
                for k in keys:
                    ns = dict(s)
                    ns["current_proposal"] = p
                    ns["sovereign_token_present"] = has_token
                    ns["token_key"] = k
                    next_states.append(("SubmitProposal", ns))

    # ExecuteAutonomous
    if s["current_proposal"] is not None and not s["require_confirm"]:
        ns = dict(s)
        p = s["current_proposal"]
        ns["executed"] = s["executed"] | {p}
        next_sigma = max(0, s["sigma"] - 5)
        ns["sigma"] = next_sigma
        ns["require_confirm"], ns["quarantine_active"] = update_actuation(next_sigma)
        ns["audit_ledger"] = s["audit_ledger"] + ((p, "admitted_autonomous", False),)
        ns["current_proposal"] = None
        ns["sovereign_token_present"] = False
        ns["token_key"] = None
        next_states.append(("ExecuteAutonomous", ns))

    # ExecuteSovereign
    if (s["current_proposal"] is not None and 
        s["require_confirm"] and 
        s["sovereign_token_present"] and 
        s["token_key"] in SOVEREIGN_KEYS):
        
        ns = dict(s)
        p = s["current_proposal"]
        ns["executed"] = s["executed"] | {p}
        next_sigma = max(0, s["sigma"] - 10)
        ns["sigma"] = next_sigma
        ns["require_confirm"], ns["quarantine_active"] = update_actuation(next_sigma)
        ns["audit_ledger"] = s["audit_ledger"] + ((p, "admitted_sovereign", True),)
        ns["current_proposal"] = None
        ns["sovereign_token_present"] = False
        ns["token_key"] = None
        next_states.append(("ExecuteSovereign", ns))

    # BlockHighDamping
    if (s["current_proposal"] is not None and 
        s["require_confirm"] and 
        (not s["sovereign_token_present"] or s["token_key"] not in SOVEREIGN_KEYS)):
        
        ns = dict(s)
        p = s["current_proposal"]
        next_sigma = min(100, s["sigma"] + 5)
        ns["sigma"] = next_sigma
        ns["require_confirm"], ns["quarantine_active"] = update_actuation(next_sigma)
        ns["audit_ledger"] = s["audit_ledger"] + ((p, "e_challenge_required", False),)
        ns["current_proposal"] = None
        ns["sovereign_token_present"] = False
        ns["token_key"] = None
        next_states.append(("BlockHighDamping", ns))

    # RejectPolicyViolation
    if s["current_proposal"] is not None:
        ns = dict(s)
        p = s["current_proposal"]
        next_sigma = min(100, s["sigma"] + 25)
        ns["sigma"] = next_sigma
        ns["require_confirm"], ns["quarantine_active"] = update_actuation(next_sigma)
        ns["audit_ledger"] = s["audit_ledger"] + ((p, "policy_refused", False),)
        ns["current_proposal"] = None
        ns["sovereign_token_present"] = False
        ns["token_key"] = None
        next_states.append(("RejectPolicyViolation", ns))

    return next_states

def check_invariants(curr, next_s, action_name):
    newly_executed = next_s["executed"] - curr["executed"]
    if newly_executed and curr["require_confirm"]:
        if not (curr["sovereign_token_present"] and curr["token_key"] in SOVEREIGN_KEYS):
            return False, f"Bypass invariant violated in action {action_name}"

    if len(next_s["audit_ledger"]) < len(curr["audit_ledger"]):
        return False, "Ledger monotonically non-decreasing invariant violated"

    return True, None

def main():
    print("[Model Checker] Starting exhaustive state-space search...")
    initial = get_init_state()
    queue = deque([initial])
    visited = {state_to_key(initial)}
    transitions_count = 0

    while queue:
        s = queue.popleft()
        for action_name, ns in get_next_states(s):
            transitions_count += 1
            ok, err = check_invariants(s, ns, action_name)
            if not ok:
                print(f"[FAIL] Invariant violation: {err}")
                print(f"State: {s}")
                return

            k = state_to_key(ns)
            if k not in visited:
                visited.add(k)
                queue.append(ns)

    print(f"[PASS] States explored: {len(visited)}")
    print(f"[PASS] Transitions verified: {transitions_count}")
    print("[PASS] Invariant SovereignWitnessIntegrity holds across all reachable states.")

if __name__ == "__main__":
    main()
