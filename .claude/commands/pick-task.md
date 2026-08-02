<!--
  GENERATED FROM: harness.patterns.yaml
  SOURCE: sha256:6f0092445976b94c5ffe3ced3dd924638700a22c8bf1668df8397bbe1d4c76e7
  PLAYBOOK: sha256:d1d481267c1ce4acadd3df9e7ecbbe9c361bf6c21c1204e3473d004ce293b85d
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# /pick-task

The Verb of this harness. Consumes a `TaskPacket` and produces a `TaskResult`.

## Contract

1. Read the active task packet from the Intake storage. If none is active, stop and ask.
2. Do the work described by the packet's objective, staying within its constraints.
3. Every edit is checked by `enforce-file-scope`: only files the packet lists with `access: write` may be edited. If you need another file, the packet is wrong — stop and revise it, do not work around the Law.
4. Satisfy every acceptance criterion, then run the validation step to discharge the `require-validation` obligation. Until you do, the commit Gate will block.
5. At the commit boundary the Gate halts for approval. Do not attempt to bypass it.
