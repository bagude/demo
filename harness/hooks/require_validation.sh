#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
# PLAYBOOK: sha256:2edb2f4935ce22d89039c7462a9b1a38e84b96017fc700ed47c197fd20c2105d
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Obligation Law: record to the Ledger that validation is owed after an edit
# (debt scoped 'run', as the spec declares).
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" post-tool \
  --ledger "evidence/events.jsonl" \
  --run-id "${CLAUDE_SESSION_ID:-unknown}" \
  --playbook-ref "sha256:2edb2f4935ce22d89039c7462a9b1a38e84b96017fc700ed47c197fd20c2105d" \
  --scope run
