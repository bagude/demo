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

What follows are the articles of that arrangement. Each is enforced in this
repository by running code, and each names honestly what it does not provide —
because an unprovable claim is a claim this system refuses to make anywhere,
including about itself.

---

## Article I — Work is admitted, never assumed

Work enters the system only as a **typed grant**: an objective, constraints,
an explicit file scope, acceptance criteria, a named submitter. Loose
conversation is not an entry path. The grant is evidence before it is
anything else — the contract every later enforcement decision refers back to.

*Made real:* the Intake admits a `TaskPacket` through deterministic checks;
the packet's write scope is the Guard's whole authority model.

## Article II — Authority is structural, not rhetorical

What an agent may touch is decided by the grant, not by the persuasiveness of
its reasoning. The enforcement point reads the proposed action — never the
explanation. There is no phrasing of "this is obviously fine" that widens a
write scope, because the check that matters has no concept of *obviously*.

*Made real:* the file-scope Guard judges the canonical target of every edit —
symlinks resolved, aliases collapsed — against the packet's allowlist, and
exits with the one status the platform cannot ignore.

## Article III — Enforcement protects itself

A guard that can be edited by the governed is a suggestion. The enforcement
artifacts — the spec, the hooks, the compiled Playbook, the kernel's
configuration — are default-deny for every packet that does not carry an
explicit, auditable **amendment grant**. Changing the rules is possible;
changing them ambiently is not.

*Made real:* `enforcement.protected`, the `amends_enforcement` grant, and a
distinct Ledger transition when enforcement is lawfully amended — so even
legitimate rule changes are loud.

## Article IV — Approval binds to the world as it was

An approval is not a "yes"; it is a signature over a **world-state**: this
exact action, these precondition values, this runtime instance, this history,
until this expiry. If the action changes, the target moves, or the history is
rewritten, the approval does not transfer — it dissolves. Time-of-check to
time-of-use is not an accepted risk; it is a refused category.

*Made real:* Gate checkpoints bind action hash, precondition snapshot,
anchored ledger head, and instance; resume revalidates all of them, and a
drifted world is a recorded refusal.

## Article V — Identity is proven, or honestly unproven

Who approved matters as much as what was approved. A signature is re-proved
at every resume against the current registry — so revocation means what it
says. And where proof is absent, the record says so plainly: an asserted name
is logged as *claimed*, never laundered into authentication. The system would
rather admit it trusted than pretend it verified.

*Made real:* Ed25519 approvals over canonical messages; an authority-signed
identity registry with expiry, serial rollback defense, and
revocation-wins resolution; `Claimed` as an honest, first-class auth method.

## Article VI — History testifies for itself

Every governed decision is appended to a hash-chained Ledger: each record
sealed over everything before it, the head anchored outside the log wherever
execution pauses. The past cannot be edited, reordered, or truncated without
the arithmetic saying so. Audit does not depend on the agent's memory or the
operator's honesty — the evidence is self-verifying, and every record names
the exact compiled rules and the exact kernel that governed it.

*Made real:* `seq`/`prev` chaining with `ledger verify`, chain heads anchored
in Gate checkpoints, and `playbook_ref` + `kernel_ref` stamped on every event.

## Article VII — A refusal is a record

Systems reveal their character in what they do when they say no. A denial
that vanishes into an exit code is an audit hole shaped exactly like the
incidents that matter most. Here, every refusal — a blocked edit, a rejected
resume, a stale promotion — is chained evidence carrying its reason, at the
lifecycle stage where the arc died.

*Made real:* denied `pre_tool.edit` events with reasons, `gate.verify`
rejections with their cause, refused promotions recorded at the
authorization stage — the protocol's stages (`proposed → authorized →
executing → completed`) on every envelope.

## Article VIII — The rules carry their own provenance

"Which rules governed this run?" must have a checkable answer. The governing
artifacts are compiled from a declarative spec through a content-addressed
chain — source, compiler (its own implementation source, not its version
label), intermediate representation, generated Playbook — and the enforcement
binary hashes its own source, lockfile, and toolchain. Swapping any link
changes the digest. There is no quiet substitution of the constitution.

*Made real:* `source_ref → compiler_ref → ir_ref → playbook_ref`, `kernel_ref`
on every event, exact bundle verification, and a CI test that fails the
build when the checked-in Playbook is stale.

## Article IX — The system learns; it does not seize

A governed system that cannot improve calcifies; one that improves itself
freely escapes. The resolution is the **ratchet**: the system reads its own
operational history and proposes amendments, but may auto-apply only changes
provably monotone under a predeclared ordering. Everything disputed — every
widening, every tradeoff — awaits a human signature over the proposal's
exact bytes, checked by the same machinery that gates every other resume.
The running agent never rewrites the rules governing its current run.

*Made real:* the Refinery's proposals, the monotone/disputed classification,
and gated promotion — action-bound, base-bound, signature-verified, with
hand-edits recorded honestly and every outcome chained.

## Article X — Absence fails closed

Missing authorization is not a gap to warn about; it is a decision already
made. No packet means no scope. An unreadable grant, an unprovable debt, an
unkeyed obligation — each blocks. The system's response to uncertainty about
what is permitted is the only safe one: *nothing is.*

*Made real:* an unpacketed session's edits are refused (exit 2, reason
chained), unproven approvals refuse promotion without an explicit override,
and unkeyed obligation debt blocks everyone — found and fixed by testing the
real thing, which is the only way fail-opens are ever found.

## Article XI — What is not guaranteed is named

This arrangement governs the agent's actions **through governed channels**.
It does not read minds, does not solve alignment, and does not bind a
hostile process operating outside its hooks. Its trusted base is the kernel,
the hook wiring, and the host that runs them — held to the custody standard
of any root of trust. Signed documents bound history only until their
expiry; same-disk state defends against rollback only as far as disk custody
extends. Every one of these boundaries is written down where the mechanism
is defined.

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
boundary — is in [DESIGN.md](DESIGN.md). The proof is the code.*
