#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SPEC HASH: sha256:2f5e6f998a975990b68df1c3884e66ead9e1d9b9742b65d6971b2e4f0fc7be8a
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Obligation Law: record to the Ledger that validation is now owed after an edit.
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" post-tool \
  --ledger "evidence/events.jsonl" \
  --run-id "${CLAUDE_SESSION_ID:-unknown}"
