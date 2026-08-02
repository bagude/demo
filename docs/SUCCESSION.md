# Constitutional Succession

> How one trusted runtime hands governance to its successor — the protocol the
> first self-trial proved missing. Status: **implemented and
> boundary-enforced** (`kernel succession disarm|activate|abort`, the
> gate-bound manifest, candidate mode, the boundary invariant and
> legacy-bootstrap allowlist in `kernel ledger verify`, and the conformance
> fixture matrix in `crates/kernel/tests/conformance.rs`), under task packets
> `a6b89a7737f0` (protocol) and `bf3646c39e39` (boundary repair).
>
> The constitutional statement the boundary repair enforces:
>
> **A candidate runtime may describe and prove its proposed succession, but
> it may not govern until its authority is anchored to the exact final head
> of the predecessor and a valid activation has entered the ledger.**

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

## What is built

- **`kernel succession disarm`** — refuses a maintenance packet without the
  `amends_enforcement` grant (recording the refusal,
  `policy:succession.amendment_required`), records the window's start under
  the old runtime, and prints the recorded facts (`old_runtime_ref`,
  `old_kernel_ref`, chain head) a manifest must bind — so the operator
  authors it from the ledger, not from memory.
- **`kernel succession activate`** — the successor's first governed event.
  Refusals are recorded, coded decisions: `succession.manifest_mismatch` (the
  approved action hash no longer matches the manifest bytes),
  `succession.not_approved` (gate refusal, incl. failed signature
  re-verification), `succession.approval_unproven` (a Claimed/Token approval
  without the explicit `--allow-unproven` override — the running kernel never
  approves its own successor), `succession.head_missing` (the inherited chain
  head is gone: history was truncated or rewritten across the window),
  `succession.kernel_mismatch` / `succession.runtime_mismatch` (the
  self-attestation step: the activating binary must *be* the approved
  successor, under the constitution it claims), `succession.no_transition`,
  and `succession.conformance_failed` (`--check` command failed).
- **Boundary attestation** — `kernel ledger verify` warns on every
  runtime-segment boundary whose incoming segment contains no *approved*
  `succession.activate` naming the runtime it succeeded. A warning, not a
  failure: history predating the protocol stays legible, but never quiet. A
  recorded refusal is honestly written under the successor's own runtime, so
  it may open the segment its eventual approval attests.
- **The conformance fixture matrix** — `crates/kernel/tests/conformance.rs`:
  default-deny scope authority, fail-closed absence of authorization,
  platform-path rebinding at the workspace boundary, never-ambient
  enforcement amendment, the obligation-to-gate loop, and tamper-evident
  history. The file's content digest names the suite version a manifest's
  `conformance_ref` commits to.
- **Generator support** — the compiled `harness/README.md` documents the
  succession commands beside the gate.

The full cycle — disarm → manifest → signature approval → tampered-manifest
refusal → activation → attested boundary, plus the silent-handover
counterfactual the verifier flags — runs in
`crates/kernel/tests/succession.rs`.

## The boundary invariant and candidate mode

The founding ceremony exposed a second-order defect: the *attestation* was
present but the *transfer* was not causally sound. Its manifest bound an
"old ledger head" that was two records deep into the candidate's own
governance, and the verifier of that era accepted the boundary because it
only checked that an activation eventually existed. The boundary repair
(packet `bf3646c39e39`) makes the transfer itself mechanical:

- **Manifests declare `transition_mode`** (`normal` | `bootstrap`) and bind
  **both** authorities: `maintenance_task_id` (who built the candidate) and
  `ceremony_task_id` (who is seating it). For `normal` transitions
  `disarm_recorded` must be true and a recorded `succession.disarm` under
  the predecessor runtime must precede the bound head.
- **The boundary invariants**, enforced at activation and re-checked by the
  verifier: the declared head names the predecessor's exact final record,
  emitted under the declared predecessor runtime; the candidate boundary
  record's `prev` equals that head; and every candidate-runtime record
  through the activation is **candidate-safe** — a closed allowlist
  (`succession.candidate_started`, `conformance_requested`,
  `conformance_recorded`, `approval_requested`, `approval_recorded`,
  `activate`, `abort`), never a naming convention. Violations are refusals:
  `succession-boundary-head-mismatch`,
  `succession-predecessor-runtime-mismatch`,
  `succession-candidate-governance-before-activation`,
  `succession-candidate-event-not-allowed`.
- **Candidate mode is automatic.** A kernel whose computed runtime differs
  from the ledger's active runtime (the last approved activation) refuses
  ordinary governance mechanically — pre-tool, obligations, discharges, the
  commit gate, hive operations, gate ledger-appends, disarm, and task
  admission all return `succession-runtime-not-active`. Refusals are **not
  recorded**: any kind they could carry is itself ordinary governance, and
  recording one would poison the candidate-safe span. A ceremony therefore
  runs its gate without `--ledger`; the manifest carries the head, and the
  activation is the ceremony's ledger record. `succession.abort` abandons a
  ceremony without ever opening governance. A ledger with **no** approved
  activation has no regime — every runtime governs, and the first
  activation founds the regime.
- **Bootstraps are never self-declared.** `activate` refuses
  `transition_mode: bootstrap` outright; the verifier accepts a bootstrap
  (or legacy mode-absent) activation only through an exact, digest-pinned,
  **single-use** allowlist entry (`--exceptions`), reports it as
  `VALID_WITH_LEGACY_BOOTSTRAP_EXCEPTION` with its anomaly retained, and
  never describes it as satisfying the normal invariant
  (`succession-bootstrap-not-authorized`, `succession-bootstrap-reused`).

## The founding transition's known boundary defect

`succession-0001` is immutable — never edited, regenerated, or re-signed —
and is accepted solely through the allowlist entry in
[`evidence/succession-exceptions.json`](../evidence/succession-exceptions.json).
Its recorded anomaly, which the repaired verifier reports verbatim:

- true predecessor head: `sha256:65ffd83f…` (the hash of record 68, the
  final event under runtime `02a6c163…`);
- manifest-bound head: `sha256:fd5777db…` (the hash of record 70);
- records 69–70 (a validation discharge and a commit-gate allow) were
  emitted by the candidate runtime before formal activation;
- the historical verifier accepted the transition without adjacency
  enforcement.

Verification without the allowlist **fails** on this ledger; with it, the
boundary is classified `VALID_WITH_LEGACY_BOOTSTRAP_EXCEPTION` — visible,
specific, and never normal.

## The first attested succession

This workspace's live ledger carries the protocol's first real use
([`evidence/succession-0001.json`](../evidence/succession-0001.json), packet
`77f6efb8e2d4`). The seating of the succession-protocol kernel itself —
runtime `02a6c163…` → `c70149d8…`, patch `git:ceeb4ae7…` (PR #24),
maintenance packet `a6b89a7737f0` — was bound through the gate, approved by
an Ed25519 signature registered to `bagude` in [`approvers.toml`](../approvers.toml),
preconditioned on the conformance matrix passing live, and activated with
`disarm_recorded: false` (the window predated the protocol; its start is
attested only by the successor — the residual-trust case, stated). The
verifier accepts that boundary as governed.

One earlier boundary (record 17, the first trial-era kernel repair) remains
**permanently unattested**: its segment closed before the protocol existed,
and the protocol does not manufacture governance retroactively. The warning
is the honest scar.

## Deliberate non-goals

- **Self-hosted bootstrap proof.** The successor is validated by tests the
  incumbent (or a human) chooses; proving the successor correct from inside
  the failing system is not attempted.
- **Automatic succession.** Every activation requires a signature-backed
  human approval. The ratchet's invariant — the running agent never rewrites
  the rules governing its current run — extends upward: the running *kernel*
  never approves its own successor.
