# intake

A small Rust implementation of **The Intake** pattern from
*A Pattern Language for Agentic Composition*.

> **The Intake** — Work enters the system only as a typed artifact — objective,
> constraints, files, acceptance criteria — never as loose conversation. The
> packet becomes evidence in state, and the contract that Laws enforce against.
>
> **Ingredients:** Invocable Workflow + structured task packet.

This crate is that pattern made concrete: a typed **task packet**, the
deterministic **Guard Laws** that gate its admission, an append-only **Ledger**
that holds it as evidence, and a CLI — the **Invocable Workflow** — that ties
them together.

## Why

When multiple people or agents hand work to each other, ambiguity is the
dominant failure mode. The Intake removes the "loose conversation" entry path:
the *only* way work enters the system is a packet that names, up front, what
"done" means, what may be touched, and how success is checked. Once admitted it
is content-addressed evidence that later Laws can enforce against.

## The four named fields

Every packet must carry the pattern's four fields, plus minimal provenance:

| Field                 | Meaning                                                        |
|-----------------------|----------------------------------------------------------------|
| `objective`           | What "done" looks like, specifically — not "fix the bug".      |
| `constraints`         | Boundaries the work must respect (may be empty).               |
| `files`               | Paths in scope, each `read` or `write`.                        |
| `acceptance_criteria` | Mechanically checkable success statements (at least one).      |

The set of `write` paths is the contract a Guard Law enforces against
(*"only files listed in the task packet may be edited"*).

## Build / test

```sh
cargo build
cargo test      # 20 tests: unit + end-to-end CLI + doctest
```

## Usage

```sh
# 1. Emit a blank, annotated template (TOML, or --format json).
intake template > my-task.toml

# 2. Dry-run the Guard Laws without recording anything.
intake validate my-task.toml

# 3. Admit the packet: validate, then append it to the ledger as evidence.
intake submit my-task.toml
#   recorded 72912a5ae0e8 'Preserve rows in migration 0007' -> .intake/ledger.jsonl

# 4. Read the evidence back.
intake list
intake show 72912a5           # full record as JSON, by task-id prefix

# 5. Enforce the packet's file-scope contract (the Guard Law primitive).
intake check-edit 72912a5 migrations/0007_backfill_ids.sql   # exit 0: allow
intake check-edit 72912a5 src/secret.rs                       # exit 1: deny
```

The ledger location defaults to `.intake/ledger.jsonl` and can be overridden
with `--ledger <path>`. A worked packet lives in
[`examples/task-packet.toml`](examples/task-packet.toml).

## How it maps to the pattern

| Pattern element                          | Where it lives                       |
|------------------------------------------|--------------------------------------|
| Structured task packet (typed template)  | `src/packet.rs`, `intake template`   |
| Guard Laws (admission is deterministic)  | `src/validate.rs`                    |
| Evidence in state (append-only)          | `src/ledger.rs`                      |
| Invocable Workflow                       | `src/main.rs` (`submit`)             |
| The contract Laws enforce against        | `files` scope + `check-edit`         |

Design choices worth noting:

- **Validate, then record — never the reverse.** `intake::admit` runs the Guard
  Laws and only on success produces a record; there is no code path that stores
  an unvalidated packet.
- **Content-addressed evidence.** Each record carries a SHA-256 `content_hash`
  over the packet and a `task_id` derived from it, so a reader can prove the
  recorded bytes are the ones that were validated.
- **Append-only.** The ledger handle opens strictly in append mode; a status
  change is a *new* appended record, never an in-place edit — mirroring the
  spec's *"historical evidence is append-only."*
- **All violations at once.** Validation collects every problem so a submitter
  fixes them in one pass.

## Layout

```
src/packet.rs    TaskPacket, FileScope, IntakeRecord, content hashing
src/validate.rs  the Guard Laws
src/ledger.rs    append-only JSONL evidence store
src/intake.rs    admit(): validate -> record
src/clock.rs     dependency-free RFC 3339 UTC timestamps
src/main.rs      the CLI (Invocable Workflow)
tests/cli.rs     end-to-end tests driving the built binary
```
