<!--
  GENERATED FROM: harness.patterns.yaml
  SPEC HASH: sha256:2f5e6f998a975990b68df1c3884e66ead9e1d9b9742b65d6971b2e4f0fc7be8a
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# harness/ — compiled Playbook

Compiled from `harness.patterns.yaml` (spec hash `sha256:2f5e6f998a975990b68df1c3884e66ead9e1d9b9742b65d6971b2e4f0fc7be8a`) by `harnessc 0.1.0`.

## Regenerating

```sh
harnessc check   # validate the spec
harnessc build   # regenerate this Playbook
```

## Enforcement honesty

- `enforce-file-scope` is **enforced**: the kernel exits non-zero and blocks the tool call for any edit outside the packet's write scope.
- `require-validation` is **recorded**: the kernel appends an obligation event after each edit. Discharging that obligation (e.g. gating the commit on it) is a documented next step, not yet enforced end-to-end.
- The `Gate` checkpoint, approval binding, and precondition revalidation are enforced by the kernel's `gate` subcommands.

Nothing here claims a guarantee the kernel does not actually provide.
