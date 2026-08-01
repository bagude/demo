<!--
  GENERATED FROM: harness.patterns.yaml
  SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
  PLAYBOOK: sha256:bf3a90abb89c825b85a46a0399f8672b4139616891db98955deb8ba8086a815a
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# enablement-workbench — harness boot context

This CLAUDE.md is a compiled artifact of the **enablement-workbench** pattern harness (version 0.1.0). It is the Boot Context role, bound to Claude Code.

## Composition in force

```
Intake -> Verb within (Law + Gate) + Ledger
```

Work enters this system **only** as a typed task packet admitted through the Intake. Loose conversation is not an entry path.

## Laws in force

- `enforce-file-scope` (Guard at PreTool, applies to edit, write, delete): **enforced** — the kernel blocks edits outside the packet's write scope; enforcement artifacts additionally require an explicit `amends_enforcement` grant
- `require-validation` (Obligation at PostTool, applies to edit, write; scope run): **enforced via the Gate** — recorded after each edit and required clear before commit

## Gate

`approve-commit` halts at **before_commit**. Approval binds to: action_hash, repository_revision, working_tree_hash, approver, expiry. A change to the action or any bound precondition invalidates approval.

A commit is blocked until these obligations are discharged: require-validation. Run the validation step (`kernel validate`) to discharge.

## Ledger

Governed actions and decisions are appended to `evidence/events.jsonl`. Redacted: secrets, credentials, raw_model_context.

## How enforcement works

Hooks in `.claude/settings.json` invoke the trusted `kernel` binary. The model proposes actions; the kernel disposes. Do not attempt to satisfy a Law by describing compliance — the check runs in code regardless.
