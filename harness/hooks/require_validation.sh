#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SOURCE: sha256:6f0092445976b94c5ffe3ced3dd924638700a22c8bf1668df8397bbe1d4c76e7
# PLAYBOOK: sha256:d1d481267c1ce4acadd3df9e7ecbbe9c361bf6c21c1204e3473d004ce293b85d
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Obligation Law: record to the Ledger that validation is owed after an edit
# (debt scoped 'run', as the spec declares).
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" post-tool \
  --ledger "evidence/events.jsonl" \
  --run-id "${CLAUDE_SESSION_ID:-unbound-$PPID}" \
  --playbook-ref "sha256:d1d481267c1ce4acadd3df9e7ecbbe9c361bf6c21c1204e3473d004ce293b85d" \
  --scope run \
  --packet "${INTAKE_ACTIVE_PACKET:-tasks/active.json}"
