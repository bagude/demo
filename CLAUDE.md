<!--
  GENERATED FROM: harness.patterns.yaml
  SPEC HASH: sha256:2f5e6f998a975990b68df1c3884e66ead9e1d9b9742b65d6971b2e4f0fc7be8a
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# enablement-workbench — harness boot context

This CLAUDE.md is a compiled artifact of the **enablement-workbench** pattern harness (version 0.1.0). It is the Boot Context role of the pattern language, bound to Claude Code.

## Composition in force

```
Intake -> Verb within (Law + Gate) + Ledger
```

Work enters this system **only** as a typed task packet admitted through the Intake. Loose conversation is not an entry path.

## Laws in force

- `enforce-file-scope` (Guard at PreTool, applies to edit, write, delete): **enforced** — the kernel blocks edits outside the packet's write scope
- `require-validation` (Obligation at PostTool, applies to edit, write): **recorded** — the kernel logs the obligation to the Ledger after each edit

## Gate

`approve-commit` halts at **before_commit**. Approval binds to: action_hash, repository_revision, working_tree_hash, approver, expiry. A change to the action or any bound precondition invalidates approval and requires renewal.

## Ledger

Governed actions and decisions are appended to `evidence/events.jsonl`. Redacted: secrets, credentials, raw_model_context.

## How enforcement works

Hooks in `.claude/settings.json` invoke the trusted `kernel` binary. The model proposes actions; the kernel disposes. Do not attempt to satisfy a Law by describing compliance — the check runs in code regardless.
