<!--
  GENERATED FROM: harness.patterns.yaml
  SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
  PLAYBOOK: sha256:e08cdf607f7b12231b8a72eb819eaae77fbf695371b7517bcae385765ed9c277
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
