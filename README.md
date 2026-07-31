# patterns → harness compiler

An executable form of *A Pattern Language for Agentic Composition*. Instead of
configuring an agent with hand-written Markdown, you **declare** a harness in
`harness.patterns.yaml` and **compile** it into a Claude Code Playbook backed by
a trusted runtime kernel.

```
harness.patterns.yaml        (the spec — one system, declared)
        │  harnessc build
        ▼
CLAUDE.md + .claude/ + harness/ + tasks/ evidence/ checkpoints/   (compiled Playbook)
        │  runs on
        ▼
kernel  (the deterministic core the model operates inside)
```

The compiler's job is not just to emit files — it is to **statically reject a
composition that would lie about its guarantees**. A Gate whose approval binds
to nothing but an artifact is a confirmation prompt, so the compiler refuses it.
A Ledger that would log raw credentials is refused. A Law the kernel cannot
actually enforce is refused rather than stubbed.

## The frozen specimen

The reference system is the Enablement Workbench:

```
Intake -> Verb within (Law + Gate) + Ledger
```

Work enters only as a typed task packet (**Intake**); a command does the work
(**Verb**) under a file-scope Guard Law and a commit Gate (**within (Law +
Gate)**); every governed decision is appended to an event log (**Ledger**). Its
declaration is [`harness.patterns.yaml`](harness.patterns.yaml).

## Workspace

Three crates, mirroring the compiler pipeline:

| Crate | Role | Key contents |
|-------|------|--------------|
| [`spec`](crates/spec) | Compiler **front-end** (platform-agnostic) | metamodel, composition-algebra parser, the checker |
| [`harnessc`](crates/harnessc) | Compiler **back-end** (claude-code binding) | generates the Playbook, stamps provenance |
| [`harness-kernel`](crates/kernel) | Trusted **runtime kernel** | task packets, Guard Laws, Gate checkpoints, Ledger, obligations |
| [`refinery`](crates/refinery) | The **Refinery** | reads the Ledger, proposes a reviewable patch against the spec |

The front-end knows nothing about any platform; a back-end supplies the
capabilities and the file layout for one target. The same spec compiles to more
than one — that split is the whole point of a portable pattern language.

## Use it

```sh
cargo build

# validate the spec — rejects incomplete or unsafe compositions
./target/debug/harnessc check

# inspect the compiled model before generating anything
./target/debug/harnessc show

# compile the Playbook (target defaults to the spec's platform.type)
./target/debug/harnessc build --out .

# the SAME spec, a different binding
./target/debug/harnessc build --target portable --out dist/portable

# turn operational state into a proposed spec change (never applied automatically)
./target/debug/refinery --ledger evidence/events.jsonl
```

Generated files carry a provenance header (`GENERATED FROM … / SPEC HASH … / DO
NOT EDIT DIRECTLY`) so the source-of-truth hierarchy stays legible: edits flow
*down* from the spec, never up from generated output.

## What the compiler rejects (the interesting part)

Each of these is a compile **error**, verified by tests in
[`crates/spec/src/check.rs`](crates/spec/src/check.rs):

- **`gate.missing_action_hash` / `gate.no_precondition_binding`** — a Gate whose
  approval does not bind to the action *and* at least one material precondition.
  Binding the artifact alone leaves a time-of-check/time-of-use gap.
- **`ledger.redact_incomplete`** — a Ledger that would record `secrets` or
  `credentials`. An append-only log of raw inputs is a durable credential leak.
- **`law.unsupported`** — a Law the *selected binding* cannot enforce.
  Generating a stub would pretend a guarantee that isn't there. (Which laws are
  enforceable is a capability of the target binding, not of the language.)
- **`law.event_mismatch`** — a Guard bound post-tool or an Obligation pre-tool.
- **`composition.referenced_but_unbound`** — a pattern named in the composition
  with no binding supplied.
- **Composition case law** — obligations that exist only because two patterns
  meet: `Gate + NightShift` ⇒ durable, revalidating suspension;
  `Sandbox + Ledger` ⇒ recorded lineage; **`Obligation Law + Gate` ⇒ the
  obligation must be discharged *through* the Gate** (`requires_obligations`),
  not merely recorded.

## What the kernel actually enforces

The generated hooks are thin shims; the enforcement lives in the compiled
`kernel` binary, so it runs regardless of what the model decides:

- **`enforce-file-scope`** (Guard Law) — reads a proposed tool call on stdin and
  **blocks** (exit 2) any edit outside the active packet's write scope, logging
  the allow/deny to the Ledger.
- **Gate** — `kernel gate request|approve|verify` persist a durable checkpoint,
  bind approval to an action hash + precondition snapshot + approver + expiry,
  and **revalidate at resume**: a changed action, drifted precondition, or
  expired approval is refused. This is what lets a Gate work across process
  death (cron, CI, a fresh container), not just in one session.
- **`require-validation`** (Obligation Law) — an obligation event is recorded
  after each edit, and the commit gate hook **blocks `git commit`** (exit 2)
  while it is outstanding. `kernel validate` discharges it (optionally gated on a
  check command as evidence). This is "recorded" turned into "enforced".
- **Gate** — `kernel gate request|approve|verify` persist a durable checkpoint,
  bind approval to an action hash + precondition snapshot + approver + expiry,
  and **revalidate at resume**: a changed action, drifted precondition, expired
  approval, or outstanding obligation is refused. This is what lets a Gate work
  across process death (cron, CI, a fresh container), not just in one session.
- **Ledger** — an append-only event log whose envelope carries only references
  and hashes, never raw payloads.

The generated [`harness/README.md`](harness/README.md) states each law's
enforcement level plainly — nothing claims a guarantee the kernel does not
provide.

## Two bindings, one spec

`platform.type` (or `--target`) selects a back-end. Both implement the same
`spec::Binding` capability interface, so the checker validates the spec against
whatever target it compiles for:

- **`claude-code`** — `CLAUDE.md`, `.claude/settings.json` hook registration,
  `.claude/commands/`, and `harness/` hooks.
- **`portable`** — no launcher; a `harness.manifest.json` declaring the
  hook→event bindings plus the exact `kernel` command each hook runs. Same spec,
  same kernel, different packaging.

## The Refinery

`refinery` reads the Ledger and produces a **reviewable patch against the spec**,
written under `refinery/proposals/<id>/` — never an edit to a generated artifact,
never a hot-patch to the running system. It *strengthens* automatically (e.g.
hardening redaction) but **never widens a Guard**: a frequently-denied path is
surfaced as a manual-review lesson, not applied. Promotion — reviewing the diff
and applying it to `harness.patterns.yaml` — is a separate human step, upholding
the invariant that *the running agent never rewrites the rules governing its
current run*.

## Tests

```sh
cargo test --workspace     # 63 tests: metamodel, checker rejections (incl.
                           # obligation-not-discharged), composition parser,
                           # kernel enforcement, gate revalidation + obligations,
                           # both backends, and the Refinery's no-touch guardrail
```

## Status and next steps

This is the bootstrap carried through **Stage 3**: the obligation is discharged
through the Gate, a second platform binding rides the same front-end, and the
Refinery closes the loop from operational state to proposed memory. Natural
continuations: a Python/OpenAI-Agents back-end behind the same `Binding`
interface; richer obligation kinds; and version-promotion tooling that applies an
approved Refinery proposal and recompiles.
