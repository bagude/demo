<!--
  GENERATED FROM: harness.patterns.yaml
  SPEC HASH: sha256:2f5e6f998a975990b68df1c3884e66ead9e1d9b9742b65d6971b2e4f0fc7be8a
  GENERATOR: harnessc 0.1.0
  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
-->

# /pick-task

The Verb of this harness. Consumes a `TaskPacket` and produces a `TaskResult`.

## Contract

1. Read the active task packet from the Intake storage. If none is active, stop and ask.
2. Do the work described by the packet's objective, staying within its constraints.
3. Every edit you make is checked by `enforce-file-scope`: only files the packet lists with `access: write` may be edited. If you need another file, the packet is wrong — stop and revise it, do not work around the Law.
4. Satisfy every acceptance criterion and record evidence to the Ledger.
5. At the commit boundary, the Gate will halt for approval. Do not attempt to bypass it.
