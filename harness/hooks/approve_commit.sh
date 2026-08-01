#!/usr/bin/env bash
# GENERATED FROM: harness.patterns.yaml
# SOURCE: sha256:d0a4e9e22a20d2681b56fb179f56f782d292e1b2f012514bc226b14eec30b9d2
# PLAYBOOK: sha256:e08cdf607f7b12231b8a72eb819eaae77fbf695371b7517bcae385765ed9c277
# GENERATOR: harnessc 0.1.0
# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.
# Gate: block `git commit` while a required obligation is outstanding (per run).
# Every commit evaluation is recorded to the Ledger, run-bound like any other decision.
set -euo pipefail
exec "${KERNEL_BIN:-kernel}" pre-commit --ledger "evidence/events.jsonl" --run-id "${CLAUDE_SESSION_ID:-unknown}" --playbook-ref "sha256:e08cdf607f7b12231b8a72eb819eaae77fbf695371b7517bcae385765ed9c277" --require require-validation
