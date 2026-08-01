# patterns → harness compiler

Declare an AI-agent harness in one YAML file. Compile it into a working,
**enforced** Claude Code setup — hooks, commands, schemas, boot context —
backed by a small trusted Rust kernel.

```
harness.patterns.yaml         you declare the architecture
        │  harnessc build
        ▼
CLAUDE.md · .claude/ · harness/    the compiled Playbook
        │  runs on
        ▼
kernel                        the deterministic core the model operates inside
```

The idea in one sentence: **the model proposes, the kernel disposes.** Rules
for an agent are usually prose it is asked to follow; here they are compiled
into hooks that call a binary which allows or blocks each action — and every
decision leaves evidence.

## Quick start

```sh
cargo build

./target/debug/harnessc check     # validate the spec (rejects unsafe compositions)
./target/debug/harnessc show      # inspect the compiled model before generating
./target/debug/harnessc build     # generate the Playbook into this directory
./target/debug/harnessc verify    # prove the generated tree matches the spec
```

This repository is itself the reference harness — the **Enablement
Workbench**, declared in [`harness.patterns.yaml`](harness.patterns.yaml):

```
Intake -> Verb within (Law + Gate) + Ledger
```

Work enters only as a typed **task packet** (Intake). A command does the work
(Verb) under a file-scope guard (Law) and a commit gate (Gate). Every governed
decision is appended to an event log (Ledger). More compositions live in
[`examples/`](examples/).

## What the kernel actually enforces

- **File scope** — edits outside the active task packet's declared write scope
  are blocked, not discouraged — and judged against the **canonical** target:
  a symlink cannot launder an out-of-scope or protected file into an
  authorized name. Enforcement artifacts are self-protected: amending them
  requires an explicit, auditable grant.
- **The commit gate** — `git commit` is blocked while validation is owed;
  every allow/deny is recorded.
- **Durable approvals** — a Gate halts at a boundary and persists a
  checkpoint; approval binds to the action hash, a precondition snapshot, the
  approver, and an expiry, and is **revalidated at resume** — in another
  process, on another day.
- **Tamper-evident evidence** — the Ledger is a hash chain (`kernel ledger
  verify`); checkpoints anchor the chain head, so even tail truncation is
  caught at the Gate.
- **Cryptographic approvers** — approvals can be Ed25519-signed over the full
  world-state binding and are re-verified at resume; approver keys can be
  issued by a signing **authority** with expiry and revocation, and a revoked
  key stops resuming checkpoints it validly approved.

Everything is labeled with its honest enforcement level — nothing claims a
guarantee the kernel does not provide.

## Provenance

Every generated artifact and every runtime event is content-addressed back to
what produced it:

```
spec bytes → compiler (source + lockfile + toolchain) → resolved IR
  → exact bundle (paths, bytes, modes; versioned + restorable)
  → kernel (source + lockfile + toolchain)
  → run-bound, chain-linked Ledger event
```

So a Ledger entry doesn't just say *what* was decided — it proves *which*
spec, compiler, bundle, and enforcement binary decided it. `harnessc verify`
fails CI if the checked-in Playbook drifts from the spec; `harnessc restore`
rolls the live tree back to a retained, self-verified bundle version.

## Workspace

| Crate | Role |
|-------|------|
| [`spec`](crates/spec) | Front-end: metamodel, composition parser, resolved graph, checker |
| [`harnessc`](crates/harnessc) | Back-ends (claude-code, portable): generate the Playbook, stamp provenance |
| [`harness-kernel`](crates/kernel) | Runtime kernel: packets, guards, gates, ledger, signatures, identity |
| [`refinery`](crates/refinery) | Reads the Ledger, proposes reviewable spec changes |

The front-end knows nothing about any platform; the same spec compiles to
multiple targets.

## Going deeper

The full design rationale — the composition algebra, what the compiler
rejects and why, the enforcement taxonomy, the identity chain, and the
documented boundaries of every guarantee — is in
[`docs/DESIGN.md`](docs/DESIGN.md).
