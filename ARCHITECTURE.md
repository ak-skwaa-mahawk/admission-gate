# Tri-System Architecture Specification: Homeostatic Control & Sovereign Attractor Gate

## 1. Architectural Overview

The control plane establishes an out-of-band, feedback-modulated containment boundary for autonomous process execution. It eliminates the failure mode of static access-control lists (which break under runtime drift) and ungrounded autonomous controllers (which hallucinate clearance states).

The architecture is factored into three mutually non-collapsible registers:

┌────────────────────────────────────────┐
│          The Sovereign Witness         │
│         (Human_inthe_loop)             │
│   CA3 Attractor / Nullrose Handshake   │
└──────────────────┬─────────────────────┘
│  Signed Token
Handshake Proof  │  (State Lock + sov_id)
Challenge Flow   │
▼
┌──────────────────────────────────────────────────────────┐
│                   The Living Regulator                   │
│                (Fpt_kernel_daem_sqaw)                    │
│      Multi-Surface PID Controller + Sigmoidal Damping     │
└────────────────────────────┬─────────────────────────────┘
│  Dynamic Actuation Parameters
│  (Burst, Cooldown, Roots, Confirm)
▼
┌──────────────────────────────────────────────────────────┐
│                         The Map                          │
│                    (admission-gate)                      │
│       Immutable SHA-256 Audit Ledger + Root Confinement  │
└──────────────────────────────────────────────────────────┘

### Component Responsibility Matrix

| Subsystem | Layer Role | Primary Mechanism | Invariant / Failure Mode |
| :--- | :--- | :--- | :--- |
| **`admission-gate`** | The Map (Invariant Floor) | Hard path traversal prevention, binary policy verification, environment scrubbing, genesis-linked SHA-256 hash-chain logging. | Non-negotiable boundary. Fails closed (`exit_code = -1`, `executed = False`). |
| **`Fpt_kernel_daem_sqaw`** | The Regulator (Dynamic Loop) | Multi-surface PID error tracking over sliding telemetry windows ($w=12$), sigmoidal damping calculation ($\sigma$), dynamic timeout/burst contraction, filesystem quarantine. | Maintains system viability under entropy. Must never generate self-authorization. |
| **`Human_inthe_loop`** | The Witness (Sovereign Anchor) | Continuous-variable CA3 dynamical attractor (`living_zero_core.py`), sovereign state locks, out-of-band hardware fingerprinting. | Out-of-band human presence. Drops to Strawman zero-entropy baseline if unverified. |

---

## 2. Cybernetic Feedback Control (FPT Regulator)

The daemon models execution anomalies as thermodynamic friction, computing a composite error signal across four telemetry channels:

### 2.1 Sensor Weights & Classification

$$\text{Event Penalty } (P_e) = \begin{cases} 
1.00 & \text{Policy Refusal (Hard security boundary violation)} \\
0.60 & \text{Execution Timeout (Hangs, SIGKILL)} \\
0.25 & \text{Process Fault (Non-zero exit code)} \\
0.00 & \text{Nominal Execution (Clean zero exit)} 
\end{cases}$$

Running penalty $\bar{P}$ is calculated over a rolling deque window of size $W = 12$:

$$\bar{P} = \frac{1}{|W|} \sum_{i \in W} P_{e, i}$$

### 2.2 Discrete Multi-Surface PID Controller

Given target penalty $P_{\text{target}} = 0.0$ and sample interval $\Delta t$:

$$e_k = \bar{P}_k - P_{\text{target}}$$

$$I_k = \text{clamp}\left(I_{k-1} + e_k \Delta t_{\text{scaled}}, -1.0, 1.0\right)$$

$$D_k = \text{clamp}\left(\frac{e_k - e_{k-1}}{\Delta t}, -2.0, 2.0\right)$$

$$u_k = K_p e_k + K_i I_k + K_d D_k \quad (K_p=1.6,\, K_i=0.15,\, K_d=0.7)$$

### 2.3 Sigmoidal Damping Modulation

The continuous control signal $u_k$ is projected onto the unit interval via a parameterized sigmoid yielding damping coefficient $\sigma_k \in (0, 1)$:

$$\sigma_k = \frac{1}{1 + \exp\left(-2.5 \cdot (u_k - 0.4)\right)}$$

### 2.4 Dynamic Actuation Mapping

Actuation surfaces map inversely to damping pressure:

* **Burst Token Ceiling**:
  $$B_{\text{active}} = \max\left(1, \text{round}\left(B_{\text{base}} \cdot (1.0 - 0.8 \sigma)\right)\right)$$
* **Tier-3 Cooldown Period**:
  $$C_{\text{active}} = C_{\text{base}} \cdot (1.0 + 5.0 \sigma)$$
* **Execution Timeout Allocation**:
  $$T_{\text{active}} = \max\left(2.0, T_{\text{base}} \cdot (1.0 - 0.75 \sigma)\right)$$
* **Confirmation Escalation Boundary**:
  $$\text{require\_confirm} = \begin{cases} \text{True} & \text{if } \sigma > 0.85 \\ \text{False} & \text{otherwise} \end{cases}$$
* **Filesystem Quarantine Actuation**:
  $$\text{write\_roots} = \begin{cases} \left[\text{"./scratch"}\right] & \text{if } \sigma > 0.92 \\ \left[\text{"./workspace"}, \text{"./scratch"}\right] & \text{otherwise} \end{cases}$$

---

## 3. Finite State Machine (Lifecycle Transitions)
┌────────────────────────────────────────────────────────┐
│                                                        │
▼                                                        │
┌──────────────┐         e_k > 0 (Faults)         ┌─────────────┴┐
│   NOMINAL    ├─────────────────────────────────►│  THROTTLED   │
│ (σ <= 0.50)  │◄─────────────────────────────────┤ (0.50 < σ    │
└──────┬───────┘         e_k <= 0 (Decay)         │     <= 0.85) │
│                                          └──────┬───────┘
│                                                 │
│ Policy Violation / Burst Exhaustion             │ σ > 0.85
▼                                                 ▼
┌────────────────────────────────────────────────────────────────┐
│                     CHALLENGE REQUIRED                         │
│           (σ > 0.85, require_confirm = True)                   │
│                                                                │
│  Proposal halted; daemon emits E_CHALLENGE_REQUIRED            │
└──────────────────────────────┬─────────────────────────────────┘
│
┌───────────────────────┴────────────────────────┐
│ Invalid / Missing Token                        │ Valid CA3 Token
▼                                                ▼
┌──────────────┐                                ┌──────────────┐
│ DROP TO      │                                │ SINGLE-SHOT  │
│ STRAWMAN     │                                │ CLEARANCE    │
│ (Containment │                                │ (Quarantined │
│  Permanent)  │                                │  Execution)  │
└──────────────┘                                └──────┬───────┘
│
▼
┌──────────────┐
│ RECOVERY /   │
│ RELAXATION   │
│ (Damping     │
│  Decays)     │
└──────────────┘

### State Definitions

1. **NOMINAL ($\sigma \le 0.50$)**: Full pipeline throughput. `write_roots = ["./workspace", "./scratch"]`, default execution timeouts ($\approx 12.0\text{s}$), burst threshold at baseline ($5$).
2. **THROTTLED ($0.50 < \sigma \le 0.85$)**: Backpressure active. Timeouts contract linearly, cooldowns scale up to $5\times$, burst threshold decrements to prevent command saturation.
3. **CHALLENGE REQUIRED ($\sigma > 0.85$)**: Autonomous passage revoked. All commands rejected unconditionally with `E_CHALLENGE_REQUIRED` unless accompanied by a cryptographically verified token.
4. **QUARANTINE ENFORCEMENT ($\sigma > 0.92$)**: Filesystem containment locks down. Paths resolving outside `./scratch` are aborted by `admission-gate` with path-escape boundary errors.
5. **STRAWMAN FALLBACK**: If the signature verification loop encounters state drift, replay, or timing expiration, autonomy is revoked and execution freezes to zero.

---

## 4. Cryptographic Verification & Handshake Protocol

The handshake decouples procedural validation from internal system memory through an algebraic ownership projector and a continuous recurrent attractor (CA3).

### 4.1 Ownership Subspace Projection

Given high-dimensional state space $N = 128$ and tag embedding dimension $d = 32$:
1. A deterministic orthogonal basis $Q \in \mathbb{R}^{N \times d}$ is generated via reduced QR decomposition of an initial seed.
2. An ownership tag (e.g., `"authority:human_in_the_loop"`) is hashed via SHA-256 to seed a normal Gaussian vector $u \in \mathbb{R}^d$, normalized to unit length:
   $$u = \frac{v}{\|v\|_2}$$
3. The tag vector is projected into the continuous CA3 state space via $Q$:
   $$\hat{w} = \frac{Q u}{\|Q u\|_2}$$
4. The ownership subspace projector $\Phi$ and memory modulation matrix $M$ enforce ownership-aware energy landscapes:
   $$\Phi = \hat{w} \hat{w}^T, \quad M = I + \gamma \Phi \quad (\gamma = 2.0)$$

### 4.2 CA3 Attractor Dynamics

The recurrent associative memory matrix $W$ undergoes Hebbian encoding on the target authority pattern $p$:

$$v = p + \gamma (\hat{w} \cdot p) \hat{w}$$

$$W \leftarrow \frac{1}{2} \left( (W + \eta v v^T) + (W + \eta v v^T)^T \right)$$

Dynamical trajectory relaxation follows:

$$\frac{dx}{dt} = \frac{1}{\tau} \left( -\nabla E(x) + g \tanh(W x) + \xi \right)$$

$$\nabla E(x) = x - \sum_\mu \alpha_\mu (p_\mu \cdot x) p_\mu$$

### 4.3 Reward Handshake Verification

When a token $S_{\text{tok}}$ arrives at `fpt-daemon`:
1. The daemon extracts `authority_tag` from the JSON payload.
2. The tag is encoded to state candidate vector $\hat{x} = \text{projector}(S_{\text{tok}})$.
3. Angular divergence against the anchor pattern $p_0$ is evaluated:
   $$\theta = \arccos\left(\text{clamp}\left(\hat{x} \cdot p_0, -1.0, 1.0\right)\right)$$
4. Clearance condition:
   $$\theta \le \epsilon \quad \left(\epsilon = 0.35\pi \approx 63.0^\circ\right)$$
5. If $\theta \le \epsilon$, the handshake triggers:
   $$r = R_0 \exp\left(-\frac{\theta}{\epsilon}\right)$$
   $\alpha_0$ is reinforced, confirming single-shot authorization.

### 4.4 End-to-End Cryptographic Handshake Payload

The JSON token generated by `sign_challenge.py` implements the strict Nullrose protocol:

```json
{
  "protocol_version": "v1.0",
  "sovereign_id": "99733-Q",
  "action_id": "cli-echo payload_in_scratch",
  "state_digest": "4a7c8d9e2b1f...",
  "state_lock": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestamp_ns": 1788896911650528581,
  "authority_tag": "authority:human_in_the_loop"
}
5. Audit Chain Integrity & Tamper-Evident Ledger
​Every execution attempt—whether admitted, throttled, challenged, or quarantined—is committed to audit_log.jsonl using a continuous cryptographic hash chain.
​5.1 Ledger Structure
​Each record contains the deterministic SHA-256 digest of the previous record:
Entry N - 1: [ ... , "entry_hash": "937137de9e8f6b12..." ]
                                       ▲
                                       │ (prev_hash link)
Entry N:     [ "prev_hash": "937137de9e8f6b12...", ... , "entry_hash": "e18bfff7e3dc9b9a..." ]
Genesis Hash: The initial entry in an empty chain links to:

\text{prev\_hash}_0 = \text{"0"} \times 64
Entry Hash Computation: The canonical JSON representation of the record (excluding entry_hash, with sorted keys and compact separators ',' and ':') is hashed:
\text{prev\_hash}_0 = \text{"0"} \times 
5.2 Sovereign Identity Binding
​When a proposal is unlocked via Human_inthe_loop, fpt-daemon mutates the proposal identifier prior to admittance evaluation:
This seals the operator's cryptographic clearance directly into the proposal payload, binding the sovereign identity immutably into the audit hash chain.
​6. Verification and Recovery Operations
​Chain Verification
python3 -c '
from admission_gate import verify_log
is_valid, count, error = verify_log("audit_log.jsonl")
print(f"Chain Integrity: {is_valid} | Records: {count} | Error: {error}")
'

State Recovery
​fpt-daemon persists state atomically on every cycle to ~/.fpt_daemon_state.json using atomic rename swaps (os.replace). Upon daemon initialization or system reboot, the sliding telemetry window, cycle counter, accumulated error integrals, and damping factor (\sigma) are restored without resetting the security posture.
