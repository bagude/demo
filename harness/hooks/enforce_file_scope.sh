#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SPEC HASH: sha256:2f5e6f998a975990b68df1c3884e66ead9e1d9b9742b65d6971b2e4f0fc7be8a
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Guard Law: block edits outside the active packet's write scope.
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" pre-tool \
  --packet "${INTAKE_ACTIVE_PACKET:-tasks/active.json}" \
  --ledger "evidence/events.jsonl" \
  --run-id "${CLAUDE_SESSION_ID:-unknown}"
