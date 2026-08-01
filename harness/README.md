<!--
  GENERATED FROM: harness.patterns.yaml
  SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
  PLAYBOOK: sha256:5bd0adc51c51dd8ff0b180727d0d7c58cc6f0c8ed60eae0848782e57dba03ae1
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# harness/ — compiled Playbook (claude-code)

Compiled from `harness.patterns.yaml` by `harnessc 0.1.0`.

- source `sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2` — the specification bytes
- compiler `sha256:c744a06904107264c2e187b8bb13f4f0dbdb473a7ff368bf98b6df326c0c2c21` — compiler, back-end, IR schema, target
- IR `sha256:ded0b776aa4cb1f62bc0ef55019a23b125dd0dfde6876ddb646be506b87b3536` — the resolved composition graph
- **playbook `sha256:5bd0adc51c51dd8ff0b180727d0d7c58cc6f0c8ed60eae0848782e57dba03ae1`** — all of the above; the identity of this compiled
interpretation, and what runtime evidence binds to

## Regenerating

```sh
harnessc check
harnessc build --target claude-code
```

## Enforcement honesty

- `enforce-file-scope` is **enforced**: the kernel blocks (exit 2) any edit outside the packet's write scope and logs the decision.
- `require-validation` is **enforced via the Gate**: an obligation is recorded after each edit, and `approve_commit.sh` blocks `git commit` (exit 2) until it is discharged by the validation step.
- The `Gate` checkpoint, approval binding, and precondition revalidation are enforced by the kernel's `gate` subcommands.
- **Self-protection**: the enforcement artifacts listed in `enforcement.protected` (this tree and the spec) are default-deny like everything else; editing one requires a packet with `amends_enforcement = true`, and `protect_enforcement.sh` blocks a `rm`/`mv` of them via Bash. Amending enforcement is never an ambient capability.

Nothing here claims a guarantee the kernel does not provide.
