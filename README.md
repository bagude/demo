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
| [`harness-kernel`](crates/kernel) | Trusted **runtime kernel** | task packets, Guard Laws, Gate checkpoints, Ledger |

The front-end knows nothing about Claude Code; a different backend could compile
the same spec to a different platform. That split is the whole point of a
portable pattern language.

## Use it

```sh
cargo build

# validate the spec — rejects incomplete or unsafe compositions
./target/debug/harnessc check

# inspect the compiled model before generating anything
./target/debug/harnessc show

# compile the Playbook into the repo (idempotent)
./target/debug/harnessc build --out .
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
- **`law.unsupported`** — a Law the claude-code binding cannot enforce.
  Generating a stub would pretend a guarantee that isn't there.
- **`law.event_mismatch`** — a Guard bound post-tool or an Obligation pre-tool.
- **`composition.referenced_but_unbound`** — a pattern named in the composition
  with no binding supplied.
- **Composition case law** — obligations that exist only because two patterns
  meet: `Gate + NightShift` ⇒ durable, revalidating suspension;
  `Sandbox + Ledger` ⇒ recorded lineage.

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
- **Ledger** — an append-only event log whose envelope carries only references
  and hashes, never raw payloads.

`require-validation` is currently **recorded** (an obligation event is appended
after each edit), not yet enforced end-to-end. The generated
[`harness/README.md`](harness/README.md) states this plainly — nothing claims a
guarantee the kernel does not provide.

## Tests

```sh
cargo test --workspace     # 50 tests: metamodel, checker rejections, kernel
                           # enforcement, gate revalidation, generation
```

## Status and next steps

This is the **bootstrap** (Stage 0–2): a hand-built kernel plus a compiler that
generates the specimen Playbook. Natural next increments, in the spec's own
terms: discharge the `require-validation` obligation by wiring it into the Gate
precondition; add more platform bindings behind the same front-end; and let a
Refinery propose changes to `harness.patterns.yaml` — never to generated
artifacts — closing the loop from operational state back to improved memory.
