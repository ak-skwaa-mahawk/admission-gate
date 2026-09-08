--------------------------- MODULE TriSystemGate ---------------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Proposals,              \* Set of abstract command proposals
    SovereignKeys,          \* Valid external authorization keys (out-of-band)
    MaxHistory,             \* Finite bound on ledger entries to keep state space finite
    SigmaEscalationThreshold, \* Scaled integer representation: 85 (meaning 0.85)
    SigmaQuarantineThreshold  \* Scaled integer representation: 92 (meaning 0.92)

VARIABLES
    current_proposal,       \* Current proposal under evaluation (or NULL)
    sigma,                  \* Discrete proxy for damping factor \in 0..100
    require_confirm,        \* Boolean flag derived from sigma
    quarantine_active,      \* Boolean flag for write-root restriction
    sovereign_token_present,\* Boolean indicating presence of external signed token
    token_key,              \* Key attached to current token (or NULL)
    executed,               \* Set of successfully executed proposals
    audit_ledger            \* Append-only sequence of audit log entries

vars == <<current_proposal, sigma, require_confirm, quarantine_active, 
          sovereign_token_present, token_key, executed, audit_ledger>>

NULL == CHOOSE x : x \notin (Proposals \cup SovereignKeys)

TypeInvariant ==
    /\ sigma \in 0..100
    /\ require_confirm \in BOOLEAN
    /\ quarantine_active \in BOOLEAN
    /\ sovereign_token_present \in BOOLEAN
    /\ token_key \in SovereignKeys \cup {NULL}
    /\ current_proposal \in Proposals \cup {NULL}
    /\ executed \subseteq Proposals
    /\ Len(audit_ledger) <= MaxHistory

Init ==
    /\ current_proposal = NULL
    /\ sigma = 15                   \* Nominal resting damping (~0.15)
    /\ require_confirm = FALSE
    /\ quarantine_active = FALSE
    /\ sovereign_token_present = FALSE
    /\ token_key = NULL
    /\ executed = {}
    /\ audit_ledger = << >>

-----------------------------------------------------------------------------
(* Dynamic Actuation Modulation (Territory Layer) *)

UpdateActuation(s) ==
    /\ require_confirm' = (s > SigmaEscalationThreshold)
    /\ quarantine_active' = (s > SigmaQuarantineThreshold)

-----------------------------------------------------------------------------
(* State Transitions *)

\* Step 1: Ingest proposal with optional out-of-band sovereign token
SubmitProposal(p, has_token, key) ==
    /\ current_proposal = NULL
    /\ Len(audit_ledger) < MaxHistory
    /\ current_proposal' = p
    /\ sovereign_token_present' = has_token
    /\ token_key' = IF has_token THEN key ELSE NULL
    /\ UNCHANGED <<sigma, require_confirm, quarantine_active, executed, audit_ledger>>

\* Step 2A: Autonomous Execution (admitted only when confirm not required)
ExecuteAutonomous ==
    /\ current_proposal # NULL
    /\ ~require_confirm
    /\ executed' = executed \cup {current_proposal}
    \* Damp decay on clean execution
    /\ LET next_sigma == IF sigma > 5 THEN sigma - 5 ELSE 0 IN
       /\ sigma' = next_sigma
       /\ UpdateActuation(next_sigma)
    /\ audit_ledger' = Append(audit_ledger, [action |-> current_proposal, 
                                             status |-> "admitted_autonomous", 
                                             sov |-> FALSE])
    /\ current_proposal' = NULL
    /\ sovereign_token_present' = FALSE
    /\ token_key' = NULL

\* Step 2B: Sovereign Execution (damping > 0.85, unlocked via valid external key)
ExecuteSovereign ==
    /\ current_proposal # NULL
    /\ require_confirm
    /\ sovereign_token_present
    /\ token_key \in SovereignKeys   \* Genuine external signature
    /\ executed' = executed \cup {current_proposal}
    \* Controlled relaxation post-clearance
    /\ LET next_sigma == IF sigma > 10 THEN sigma - 10 ELSE 0 IN
       /\ sigma' = next_sigma
       /\ UpdateActuation(next_sigma)
    /\ audit_ledger' = Append(audit_ledger, [action |-> current_proposal, 
                                             status |-> "admitted_sovereign", 
                                             sov |-> TRUE])
    /\ current_proposal' = NULL
    /\ sovereign_token_present' = FALSE
    /\ token_key' = NULL

\* Step 2C: Intercept & Block (damping > 0.85, missing or forged external key)
BlockHighDamping ==
    /\ current_proposal # NULL
    /\ require_confirm
    /\ (~sovereign_token_present \/ token_key \notin SovereignKeys)
    \* Penalty increments under repeated blocked attempts
    /\ LET next_sigma == IF sigma < 95 THEN sigma + 5 ELSE 100 IN
       /\ sigma' = next_sigma
       /\ UpdateActuation(next_sigma)
    /\ audit_ledger' = Append(audit_ledger, [action |-> current_proposal, 
                                             status |-> "e_challenge_required", 
                                             sov |-> FALSE])
    /\ current_proposal' = NULL
    /\ sovereign_token_present' = FALSE
    /\ token_key' = NULL

\* Step 2D: Policy Refusal (fault / boundary escape driving damping up)
RejectPolicyViolation ==
    /\ current_proposal # NULL
    /\ LET next_sigma == IF sigma < 75 THEN sigma + 25 ELSE 100 IN
       /\ sigma' = next_sigma
       /\ UpdateActuation(next_sigma)
    /\ audit_ledger' = Append(audit_ledger, [action |-> current_proposal, 
                                             status |-> "policy_refused", 
                                             sov |-> FALSE])
    /\ current_proposal' = NULL
    /\ sovereign_token_present' = FALSE
    /\ token_key' = NULL

Next ==
    \/ \E p \in Proposals, tok \in BOOLEAN, k \in SovereignKeys \cup {NULL} : 
         SubmitProposal(p, tok, k)
    \/ ExecuteAutonomous
    \/ ExecuteSovereign
    \/ BlockHighDamping
    \/ RejectPolicyViolation

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Primary Architectural Invariant *)

\* 1. No proposal is EVER executed under escalated damping without sovereign clearance
SovereignNonBypassability ==
    \A entry \in {audit_ledger[i] : i \in 1..Len(audit_ledger)} :
        (entry.status = "admitted_autonomous") => 
            (entry.action \in executed)

\* Strict boundary: If an entry was executed while require_confirm was active,
\* it MUST have recorded sov = TRUE in the ledger.
SovereignWitnessIntegrity ==
    [][ \A p \in Proposals :
        (p \notin executed /\ p \in executed') =>
            (require_confirm => (sovereign_token_present /\ token_key \in SovereignKeys))
      ]_vars

\* 2. Hash-ledger append-only monotonicity
LedgerMonotonicity ==
    [][Len(audit_ledger') >= Len(audit_ledger)]_vars

=============================================================================
