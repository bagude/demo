#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SPEC HASH: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Guard Law: block edits outside the active packet's write scope.
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" pre-tool \
  --packet "${INTAKE_ACTIVE_PACKET:-tasks/active.json}" \
  --ledger "evidence/events.jsonl" \
  --run-id "${CLAUDE_SESSION_ID:-unknown}"
