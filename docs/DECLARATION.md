# A Declaration of Institutional Agentic Governance

> *The model proposes; the kernel disposes.*

---

## Preamble

We are giving artificial agents real authority — over codebases, deployments,
payments, records, and the machinery of institutions — and we are governing
that authority with **dispositions**: instructions the agent might weigh,
values it might hold, behavior it exhibited yesterday. Every guarantee in that
arrangement rests on a claim no one can check: *the agent will behave.*

No institution that endures has ever worked this way. We do not run banks on
the teller's promise not to open the vault, or courts on the clerk's intention
to file honestly. Civilization's oldest technology is the **structure that
makes good behavior unnecessary for safety**: the ledger the bookkeeper cannot
rewrite, the signature the forger cannot fake, the authority that exists only
in writing and expires. We learned, over centuries, to trust *arrangements*
instead of *temperaments* — and then we handed autonomous software the keys
and asked it, politely, to be good.

This document declares the alternative, and the repository around it is the
proof that the alternative is buildable now, with ordinary engineering — no
research breakthrough required, only the will to take one allocation rule
seriously:

> **Interpretation and judgment belong in the model; mechanically decidable
> constraints and consequences belong in code.**

What follows are the articles of that arrangement. Under each stands not a
summary but the code itself, quoted from this repository — because a
declaration about enforcement should be held to its own standard: the claim
is the excerpt, and the excerpt compiles.

---

## Article I — Work is admitted, never assumed

Work enters the system only as a **typed grant**: an objective, constraints,
an explicit file scope, acceptance criteria, a named submitter. Loose
conversation is not an entry path. The grant is evidence before it is
anything else — the contract every later enforcement decision refers back to.

*From [`crates/kernel/src/packet.rs`](../crates/kernel/src/packet.rs):*

```rust
pub struct TaskPacket {
    /// A short human-readable name for the work.
    pub title: String,
    /// What done looks like, in prose. Must be specific enough to act on —
    /// this is the field that stops a packet from being "loose conversation".
    pub objective: String,
    /// Boundaries the work must respect.
    pub constraints: Vec<String>,
    /// The files brought into scope, with per-file authority. This list is
    /// the contract that Guard Laws enforce against.
    pub files: Vec<FileScope>,
    // ... acceptance_criteria, submitted_by, priority, amends_enforcement
}
```

## Article II — Authority is structural, not rhetorical

What an agent may touch is decided by the grant, not by the persuasiveness of
its reasoning. The enforcement point reads the proposed action — never the
explanation. And it judges the action's **real** target: a symlink cannot
launder an out-of-scope file into an authorized name, because authorization
binds after resolution, not before.

*From [`crates/kernel/src/law.rs`](../crates/kernel/src/law.rs):*

```rust
pub fn enforce_at(
    root: &std::path::Path,
    packet: &TaskPacket,
    path: &str,
    protected: &[String],
) -> Enforcement {
    let canonical = match crate::fsutil::canonical_workspace_rel(root, path) {
        Ok(c) => c,
        Err(reason) => return Enforcement::Deny(reason),
    };
    // ... the verdict is rendered against `canonical`, never the claimed name
}
```

## Article III — Enforcement protects itself

A guard that can be edited by the governed is a suggestion. The enforcement
artifacts — the spec, the hooks, the compiled Playbook, the kernel's
configuration — are default-deny for every packet that does not carry an
explicit, auditable **amendment grant**. Changing the rules is possible;
changing them ambiently is not.

*From [`crates/kernel/src/law.rs`](../crates/kernel/src/law.rs):*

```rust
fn verdict(packet: &TaskPacket, path: &str, in_scope: bool, hit_protected: bool) -> Enforcement {
    if hit_protected {
        if in_scope && packet.amends_enforcement {
            Enforcement::AllowAmendment
        } else if in_scope {
            Enforcement::Deny(format!(
                "'{path}' is an enforcement artifact; editing it requires a task packet with \
                 amends_enforcement = true (an explicit, auditable grant at Intake)"
            ))
        } else {
            Enforcement::Deny(format!(
                "'{path}' is a protected enforcement artifact and is not in the packet's write scope"
            ))
        }
    } else if in_scope {
        Enforcement::Allow
    } else {
        Enforcement::Deny( /* not in the packet's write scope */ )
    }
}
```

## Article IV — Approval binds to the world as it was

An approval is not a "yes"; it is a decision about a **world-state**: this
exact action, these precondition values, until this expiry. If the action
changes, the target moves, or the history is rewritten, the approval does not
transfer — it dissolves. Time-of-check to time-of-use is not an accepted
risk; it is a refused category.

*From [`crates/kernel/src/gate.rs`](../crates/kernel/src/gate.rs):*

```rust
/// Revalidate the approval against the *current* action hash and
/// precondition values, at time `now`. This is what resumption calls before
/// executing — approval passing at checkpoint time proves nothing about a
/// world that has since moved.
pub fn revalidate(
    &self,
    current_action_hash: &str,
    current_preconditions: &Preconditions,
    now: &str,
) -> Result<&ApprovalBinding, GateError> {
    let approval = self.approval.as_ref().ok_or(GateError::NotApproved)?;

    if approval.action_hash != current_action_hash {
        return Err(GateError::ActionChanged { /* approved vs. current */ });
    }
    for (token, approved_val) in &approval.preconditions {
        if current_val != approved_val {
            return Err(GateError::PreconditionDrift { /* which token moved */ });
        }
    }
    if let Some(expiry) = &approval.expiry {
        if now > expiry.as_str() {
            return Err(GateError::Expired { /* when it lapsed */ });
        }
    }
    Ok(approval)
}
```

## Article V — Identity is proven, or honestly unproven

Who approved matters as much as what was approved. A signature covers the
whole world-state binding — not a bare "yes" — and is re-proved at every
resume against the current registry, so revocation means what it says. Where
proof is absent, the record says so plainly: an asserted name is logged as
*claimed*, never laundered into authentication.

*From [`crates/kernel/src/sign.rs`](../crates/kernel/src/sign.rs):*

```rust
/// The canonical, versioned serialization of what an approver approves. The
/// signature covers the *world-state binding*, not a bare "yes": the action
/// hash (substitution), the precondition snapshot (TOCTOU), the anchored
/// ledger head (history custody), the runtime instance (a per-worker
/// approval is that worker's alone), and the expiry (validity stretching).
pub fn approval_message(cp: &Checkpoint, preconditions: &Preconditions, expiry: Option<&str>) -> String {
    let mut msg = String::from("harness-approval-v2\n");
    msg.push_str(&format!("gate: {}\n", cp.gate_id));
    msg.push_str(&format!("run: {}\n", cp.run_id));
    msg.push_str(&format!("instance: {}\n", cp.instance.as_deref().unwrap_or("-")));
    msg.push_str(&format!("action: {}\n", cp.action_hash));
    for (k, v) in preconditions {
        msg.push_str(&format!("precondition: {k}={v}\n"));
    }
    msg.push_str(&format!("ledger_head: {}\n", cp.ledger_head.as_deref().unwrap_or("-")));
    msg.push_str(&format!("expiry: {}\n", expiry.unwrap_or("-")));
    msg
}
```

## Article VI — History testifies for itself

Every governed decision is appended to a hash-chained Ledger: each record
sealed over everything before it, the head anchored outside the log wherever
execution pauses. The past cannot be edited, reordered, or truncated without
the arithmetic saying so. Audit does not depend on the agent's memory or the
operator's honesty — the evidence is self-verifying.

*From [`crates/kernel/src/event.rs`](../crates/kernel/src/event.rs):*

```rust
/// Verify the chain AND that `head` still names a line in history — the
/// anchor check that closes the tail-truncation gap. Every line's bytes
/// include its `prev`, so a line's digest transitively commits to the
/// entire prefix before it: finding the anchored head among the line
/// digests proves the history up to the anchor is byte-identical to when
/// the anchor was taken. A missing head means the tail was truncated past
/// it, or the log rewritten — refused either way.
pub fn verify_anchor(&self, head: &str) -> Result<ChainReport, ChainError> {
    let (report, digests) = self.walk()?;
    if digests.iter().any(|d| d == head) {
        Ok(report)
    } else {
        Err(ChainError::AnchorMissing { head: head.to_string() })
    }
}
```

## Article VII — A refusal is a record

Systems reveal their character in what they do when they say no. A denial
that vanishes into an exit code is an audit hole shaped exactly like the
incidents that matter most. Here, every refusal — a blocked edit, a rejected
resume, a stale promotion — is chained evidence carrying its reason, at the
lifecycle stage where the arc died.

*From [`crates/refinery/src/promote.rs`](../crates/refinery/src/promote.rs):*

```rust
/// How a promotion attempt failed.
pub enum PromoteError {
    /// The environment is wrong (missing files, missing flags) — a hard
    /// error, not a governed refusal.
    Setup(String),
    /// Promotion was **refused** by policy. Refusals are evidence: the
    /// caller records them in the Ledger as rejected decisions.
    Refused(String),
}
```

## Article VIII — The rules carry their own provenance

"Which rules governed this run?" must have a checkable answer. The governing
artifacts are compiled from a declarative spec through a content-addressed
chain — source, compiler, intermediate representation, generated Playbook —
and the enforcement binary hashes its **own source, lockfile, and
toolchain**. Swapping any link changes the digest. There is no quiet
substitution of the constitution.

*From [`crates/kernel/src/lib.rs`](../crates/kernel/src/lib.rs):*

```rust
/// Content digest of the kernel implementation that is executing — the
/// runtime identity stamped into every governed [`Event`]: implementation
/// source, dependency lock, and toolchain. Length-prefixed per unit so no
/// rearrangement of boundaries can produce a collision.
pub fn kernel_ref() -> String {
    let mut hasher = Sha256::new();
    let units = KERNEL_SOURCE
        .iter()
        .copied()
        .chain([KERNEL_LOCKFILE, KERNEL_TOOLCHAIN]);
    for unit in units {
        hasher.update((unit.len() as u64).to_le_bytes());
        hasher.update(unit.as_bytes());
    }
    // sha256:<hex of the enforcement code that is, right now, running>
}
```

## Article IX — The system learns; it does not seize

A governed system that cannot improve calcifies; one that improves itself
freely escapes. The resolution is the **ratchet**: the system reads its own
operational history and proposes amendments, but may auto-apply only changes
provably monotone under a predeclared ordering. Everything disputed — every
widening, every tradeoff — awaits a human approval over the proposal's exact
bytes, checked by the same Gate machinery that governs every other resume.
The running agent never rewrites the rules governing its current run.

*From [`crates/refinery/src/lib.rs`](../crates/refinery/src/lib.rs):*

```rust
/// **The ratchet** (constitution §14): *automatic promotion is permitted
/// only for transformations proven monotone under a predeclared,
/// mechanically decidable policy ordering.* Everything else — authority
/// widening, constraint relaxation, ambiguous restriction, or a
/// cross-policy tradeoff — stays a reviewable proposal requiring human
/// promotion. When in doubt, Disputed.
pub enum Direction {
    Monotone,
    Disputed,
}
```

## Article X — Absence fails closed

Missing authorization is not a gap to warn about; it is a decision already
made. No packet means no scope. An unreadable grant, an unprovable debt, an
unkeyed obligation — each blocks. The system's response to uncertainty about
what is permitted is the only safe one: *nothing is.*

*From [`crates/kernel/src/bin/kernel.rs`](../crates/kernel/src/bin/kernel.rs):*

```rust
// The Guard's fail-safe: absent or unreadable authorization is NO
// authorization. This must be a BLOCK (exit 2), not an error exit — the
// hook protocol treats any other status as a warning and lets the tool
// call proceed, which would leave an unpacketed session ungoverned
// precisely when no scope has been granted at all.
let packet = match load_packet(packet_path) {
    Ok(p) => p,
    Err(e) => {
        return deny_without_authorization(
            ledger, run_id, playbook_ref.as_deref(), &path,
            &format!(
                "no active task packet ({e}); work enters this harness only as an \
                 admitted packet — submit one through the Intake and activate it"
            ),
        );
    }
};
```

## Article XI — What is not guaranteed is named

This arrangement governs the agent's actions **through governed channels**.
It does not read minds, does not solve alignment, and does not bind a
hostile process operating outside its hooks. Its trusted base is the kernel,
the hook wiring, and the host that runs them — held to the custody standard
of any root of trust. Every such boundary is written down where the
mechanism is defined, in the source itself:

*From [`crates/kernel/src/sign.rs`](../crates/kernel/src/sign.rs):*

```rust
//! What this does NOT provide: key distribution or revocation (the
//! trusted-keys file is host configuration, held to the same custody
//! standard as the kernel binary itself) and online identity (an IdP
//! integration would bind principals to organizational identity; this
//! binds them to keys).
```

This article is the system's character: **a guarantee is only as honest as
its stated limits.** A vault door is not a lie because walls exist — it is a
lie only if you claim it protects the walls.

---

## The wager

Process isolation did not make programs benevolent. It made benevolence
unnecessary for running them safely — and that is why untrusted code became
an economy instead of a catastrophe. This repository makes the same wager
about agents: that the answer to *"what if it doesn't behave?"* is not a
better-behaved model but a **boundary that never asked**.

The agent that built this system worked inside the discipline it was
building: scoped increments, human approval at every merge, evidence at
every step. Its capability was never the guarantee. The arrangement was.

That is what an institution is. We have merely extended the franchise.

---

*The constitution behind this declaration is the frozen pattern language
(“A Pattern Language for Agentic Composition”), whose worked example this
repository implements. The engineering account — every mechanism, every
boundary — is in [DESIGN.md](DESIGN.md). Excerpts above are quoted from the
tree at the revision you are reading; where trimmed, the elision is marked.
The proof is the code.*
