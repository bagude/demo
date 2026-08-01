#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
# PLAYBOOK: sha256:bf3a90abb89c825b85a46a0399f8672b4139616891db98955deb8ba8086a815a
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Obligation Law: record to the Ledger that validation is owed after an edit
# (debt scoped 'run', as the spec declares).
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" post-tool \
  --ledger "evidence/events.jsonl" \
  --run-id "${CLAUDE_SESSION_ID:-unknown}" \
  --playbook-ref "sha256:bf3a90abb89c825b85a46a0399f8672b4139616891db98955deb8ba8086a815a" \
  --scope run
