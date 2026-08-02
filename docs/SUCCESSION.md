# Constitutional Succession

> How one trusted runtime hands governance to its successor — the protocol the
> first self-trial proved missing. Status: **design**, admitted as a task
> packet through the Intake; not yet implemented.

## The finding

The self-hosting trial produced the counterexample this document answers. The
kernel's Guard had an interface defect (platform-absolute paths were denied
wholesale), severe enough to block every in-scope edit — including the repair.
What happened next was recorded honestly but governed by nothing:

```
detect defect
  → record trial.disarm            (under the old kernel)
  → repair outside enforcement     (no packet events, no authorization)
  → restart with a new kernel      (kernel_ref changed, playbook_ref did not)
  → resume the trial
```

The ledger could *distinguish* the two kernels only because `kernel_ref` rides
every event. It could not show that the transition itself was authorized,
validated, or even deliberate. The repair packet in the intake ledger carried
`amends_enforcement: false` and no execution events referenced it. In
constitutional terms: the governor was replaced by decree, and the decree is
legible only in hindsight.

Two of the preconditions that trial exposed are now closed by implementation,
not by this design:

- **`runtime_ref`** — every event now carries
  `sha256(playbook_ref + kernel_ref + envelope ABI)` as one digest, and
  `kernel ledger verify` reports history as contiguous **runtime segments**.
  A change of governor is a visible partition boundary.
- **Derived amendment classification** — a packet whose write scope
  intersects the protected set (which now includes the kernel and compiler
  source, declared in `harness.patterns.yaml` under `harness.protected`) is
  refused at Intake unless it declares `amends_enforcement: true`. Kernel
  surgery can no longer be self-classified as ordinary work.

What remains — the subject of this design — is the governed transition itself.

## The self-governance paradox, stated

> What governs repair of the governor when the governor is defective enough to
> prevent its own repair?

No protocol eliminates the residual trust here; a kernel too broken to execute
its own gate cannot mediate its replacement, full stop. The honest goal is
narrower: make the window of ungoverned action **explicit, bounded, evidenced,
and externally authorized**, and make the resumption of governance prove
continuity with what came before. Disarm becomes a recorded state with an
approver, not an ambient absence of rules.

## Protocol

```
1. defect detected            → succession.disarm      (old runtime, Denied-capable)
2. maintenance packet         → intake admission        (amends_enforcement: true, derived)
3. candidate kernel built     → source + lock digests
4. conformance suite run      → evidence refs           (the candidate judges the fixture
                                                         matrix; the suite is versioned)
5. digest approved            → gate approve            (signature auth; binds the envelope below)
6. new runtime activated      → succession.activate     (FIRST event under the new runtime)
7. old head linked            → the activate event's input_refs carry the old chain head
```

### The bound evidence envelope

A succession approval is a Gate approval whose action hash covers a
**succession manifest** — a single canonical document containing:

| field | meaning |
|---|---|
| `old_runtime_ref` | the constitution being retired |
| `old_ledger_head` | chain head at disarm — the history the successor inherits |
| `maintenance_task_id` | the admitted packet that authorized the surgery |
| `reason` | the defect, in prose and as a `policy:` code where one exists |
| `patch_ref` | digest of the source change (commit hash or diff digest) |
| `conformance_ref` | digest of the conformance run's output |
| `new_kernel_ref` | the successor's implementation digest |
| `new_runtime_ref` | the successor constitution (recomputable, but bound explicitly) |
| approver identity | via the existing signature path (`gate sign` / trusted keys) |

Every field already has kernel machinery behind it: action-hash binding,
ledger-head anchoring (`gate request --ledger`), Ed25519 approver identity,
and checkpoint revalidation at resume. Succession composes existing
primitives; it does not invent new trust.

### Genesis linking

The first event the new kernel writes (`succession.activate`, stage
`completed`) carries `prev` continuity automatically — the chain is one file —
but must *also* carry `old_ledger_head` and `old_runtime_ref` as input refs.
That makes the constitutional splice self-describing at the event layer, so a
reader partitioning by `runtime_ref` finds, at every boundary, a record under
the **new** constitution attesting to exactly which history and which
predecessor it succeeded. A boundary without such a record is what the
verifier should flag: an **unattested succession** — precisely what the
self-trial produced.

### Disarm semantics

`succession.disarm` is written under the old runtime, names the defect and the
maintenance packet, and marks the start of the ungoverned window. From disarm
to activate, the ledger makes no governance claims — and that absence is now a
*bounded, declared* interval between two events rather than something inferred
from silence. If the old kernel cannot even write the disarm event, the
activate event must say so (`disarm_recorded: false` in the manifest): the
window's start is then attested only by the successor, which is the residual
trust made explicit rather than hidden.

## What to build (implementation packet scope)

- `kernel succession disarm|activate` subcommands writing the two events,
  with the manifest as the gate-bound action document.
- `kernel ledger verify`: flag runtime-segment boundaries that lack an
  attesting `succession.activate` record (warning, not failure — history
  predating the protocol stays legible).
- A conformance fixture matrix the candidate kernel must pass, versioned so
  `conformance_ref` names both the suite and the outcome.
- Generator support so a compiled Playbook documents the succession commands
  beside the gate it already emits.

## Deliberate non-goals

- **Self-hosted bootstrap proof.** The successor is validated by tests the
  incumbent (or a human) chooses; proving the successor correct from inside
  the failing system is not attempted.
- **Automatic succession.** Every activation requires a signature-backed
  human approval. The ratchet's invariant — the running agent never rewrites
  the rules governing its current run — extends upward: the running *kernel*
  never approves its own successor.
