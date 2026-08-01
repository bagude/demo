#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
# PLAYBOOK: sha256:2edb2f4935ce22d89039c7462a9b1a38e84b96017fc700ed47c197fd20c2105d
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Gate: block `git commit` while a required obligation is outstanding, each
# at its declared scope. Every commit evaluation is recorded to the Ledger.
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" pre-commit --ledger "evidence/events.jsonl" --run-id "${CLAUDE_SESSION_ID:-unknown}" --playbook-ref "sha256:2edb2f4935ce22d89039c7462a9b1a38e84b96017fc700ed47c197fd20c2105d" --packet "${INTAKE_ACTIVE_PACKET:-tasks/active.json}" --require require-validation:run
