#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
# PLAYBOOK: sha256:aae0d2bb43d17d95c01de7c037ede4a904addaafc9133131aace9cb7a4c64c7e
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Self-protection: block `rm`/`mv`/redirect against enforcement artifacts.
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" pre-bash \
  --packet "${INTAKE_ACTIVE_PACKET:-tasks/active.json}" \
  --protected "harness/enforcement.protected" \
  --ledger "evidence/events.jsonl" \
  --run-id "${CLAUDE_SESSION_ID:-unknown}" \
  --playbook-ref "sha256:aae0d2bb43d17d95c01de7c037ede4a904addaafc9133131aace9cb7a4c64c7e"
