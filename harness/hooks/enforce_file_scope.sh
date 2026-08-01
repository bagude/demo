#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
# PLAYBOOK: sha256:7e2ce1e14822042e88eb03e7bd36788fe85ce41881f2778789dce78c21fe9be1
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Guard Law: block edits outside the active packet's write scope
# (and protect enforcement artifacts unless amends_enforcement is granted).
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" pre-tool \
  --packet "${INTAKE_ACTIVE_PACKET:-tasks/active.json}" \
  --ledger "evidence/events.jsonl" \
  --run-id "${CLAUDE_SESSION_ID:-unknown}" \
  --playbook-ref "sha256:7e2ce1e14822042e88eb03e7bd36788fe85ce41881f2778789dce78c21fe9be1" \
  --protected "harness/enforcement.protected"
