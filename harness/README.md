<!--
  GENERATED FROM: harness.patterns.yaml
  SOURCE: sha256:6f0092445976b94c5ffe3ced3dd924638700a22c8bf1668df8397bbe1d4c76e7
  PLAYBOOK: sha256:d1d481267c1ce4acadd3df9e7ecbbe9c361bf6c21c1204e3473d004ce293b85d
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# harness/ — compiled Playbook (claude-code)

Compiled from `harness.patterns.yaml` by `harnessc 0.1.0`.

- source `sha256:6f0092445976b94c5ffe3ced3dd924638700a22c8bf1668df8397bbe1d4c76e7` — the specification bytes
- compiler `sha256:4de946510de7250f6724e9fe731c6f7523b40ff6c930eccb458adaa057aaf745` — a content digest of the compiler and front-end
implementation source, dependency lock, and toolchain, folded with
the IR schema and target
- IR `sha256:ded0b776aa4cb1f62bc0ef55019a23b125dd0dfde6876ddb646be506b87b3536` — the resolved composition graph
- **playbook `sha256:d1d481267c1ce4acadd3df9e7ecbbe9c361bf6c21c1204e3473d004ce293b85d`** — all of the above; the identity of this compiled
interpretation, and what runtime evidence binds to

A compiled identity is not a runtime identity: every Ledger event also
records `kernel_ref`, a content digest of the kernel binary that actually
executed the transition, so the same Playbook enforced by a different
kernel is distinguishable in the evidence.

## Regenerating

```sh
harnessc check
harnessc build --target claude-code
```

## Enforcement honesty

- `enforce-file-scope` is **enforced**: the kernel blocks (exit 2) any edit outside the packet's write scope and logs the decision.
- `require-validation` is **enforced via the Gate**: an obligation is recorded after each edit, and `approve_commit.sh` blocks `git commit` (exit 2) until it is discharged by the validation step. Every commit evaluation — allow or deny — is itself a run-bound Ledger event, so a blocked commit is evidence, not just an exit code.
- The `Gate` checkpoint, approval binding, and precondition revalidation are enforced by the kernel's `gate` subcommands.
- **Self-protection**: the enforcement artifacts listed in `enforcement.protected` (this tree and the spec) are default-deny like everything else; editing one requires a packet with `amends_enforcement = true`, and `protect_enforcement.sh` blocks a `rm`/`mv` of them via Bash. Amending enforcement is never an ambient capability.

Nothing here claims a guarantee the kernel does not provide.
