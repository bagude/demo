<!--
  GENERATED FROM: harness.patterns.yaml
  SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
  PLAYBOOK: sha256:69123d8af9624692b67a024a1c86f3a3e1c83a07780bff229ec8eb284c7dfa9d
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# harness/ — compiled Playbook (claude-code)

Compiled from `harness.patterns.yaml` by `harnessc 0.1.0`.

- source `sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2` — the specification bytes
- compiler `sha256:ec34ec2184378ebd6bf218b66c253ab41def942c359aac9eee7c4e30b879c35a` — a content digest of the compiler and front-end
implementation source, dependency lock, and toolchain, folded with
the IR schema and target
- IR `sha256:ded0b776aa4cb1f62bc0ef55019a23b125dd0dfde6876ddb646be506b87b3536` — the resolved composition graph
- **playbook `sha256:69123d8af9624692b67a024a1c86f3a3e1c83a07780bff229ec8eb284c7dfa9d`** — all of the above; the identity of this compiled
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
