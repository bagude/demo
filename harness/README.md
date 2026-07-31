<!--
  GENERATED FROM: harness.patterns.yaml
  SPEC HASH: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# harness/ — compiled Playbook (claude-code)

Compiled from `harness.patterns.yaml` (spec hash `sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2`) by `harnessc 0.1.0`.

## Regenerating

```sh
harnessc check
harnessc build --target claude-code
```

## Enforcement honesty

- `enforce-file-scope` is **enforced**: the kernel blocks (exit 2) any edit outside the packet's write scope and logs the decision.
- `require-validation` is **enforced via the Gate**: an obligation is recorded after each edit, and `approve_commit.sh` blocks `git commit` (exit 2) until it is discharged by the validation step.
- The `Gate` checkpoint, approval binding, and precondition revalidation are enforced by the kernel's `gate` subcommands.

Nothing here claims a guarantee the kernel does not provide.
