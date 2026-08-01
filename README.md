# patterns → harness compiler

An executable form of *A Pattern Language for Agentic Composition* (tracks
constitution **v1.2**). Instead of configuring an agent with hand-written
Markdown, you **declare** a harness in `harness.patterns.yaml` and **compile** it
into a Claude Code Playbook backed by a trusted runtime kernel.

```
harness.patterns.yaml        (the spec — one system, declared)
        │  harnessc build
        ▼
CLAUDE.md + .claude/ + harness/ + tasks/ evidence/ checkpoints/   (compiled Playbook)
        │  runs on
        ▼
kernel  (the deterministic core the model operates inside)
```

The compiler's job is not just to emit files — it is to **statically reject a
composition that would lie about its guarantees**. A Gate whose approval binds
to nothing but an artifact is a confirmation prompt, so the compiler refuses it.
A Ledger that would log raw credentials is refused. A Law the kernel cannot
actually enforce is refused rather than stubbed.

## The frozen specimen

The reference system is the Enablement Workbench:

```
Intake -> Verb within (Law + Gate) + Ledger
```

Work enters only as a typed task packet (**Intake**); a command does the work
(**Verb**) under a file-scope Guard Law and a commit Gate (**within (Law +
Gate)**); every governed decision is appended to an event log (**Ledger**). Its
declaration is [`harness.patterns.yaml`](harness.patterns.yaml).

All fourteen v1.2 patterns are bindable. Beyond the specimen, example specs
exercise the scale patterns — [`examples/research-org.patterns.yaml`](examples/research-org.patterns.yaml)
(`(Delegate × 3) -> Critic -> Refinery + Ledger + Hive + Port`) and
[`examples/safe-deploy.patterns.yaml`](examples/safe-deploy.patterns.yaml)
(`(Pipeline within Law) -> Gate + Ledger`) — and one shows **instance
addressability**: [`examples/instance-addressed.patterns.yaml`](examples/instance-addressed.patterns.yaml)
(`(Port[staging] within Sandbox) -> Gate + Port[metrics] + Law + Ledger`), where
a derived obligation binds to `Port[staging]` and leaves its sibling alone.

## Workspace

Three crates, mirroring the compiler pipeline:

| Crate | Role | Key contents |
|-------|------|--------------|
| [`spec`](crates/spec) | Compiler **front-end** (platform-agnostic) | metamodel, composition-algebra parser, the checker |
| [`harnessc`](crates/harnessc) | Compiler **back-end** (claude-code binding) | generates the Playbook, stamps provenance |
| [`harness-kernel`](crates/kernel) | Trusted **runtime kernel** | task packets, Guard Laws, Gate checkpoints, Ledger, obligations, Law of the Hive |
| [`refinery`](crates/refinery) | The **Refinery** | reads the Ledger, proposes a reviewable patch against the spec |

The front-end knows nothing about any platform; a back-end supplies the
capabilities and the file layout for one target. The same spec compiles to more
than one — that split is the whole point of a portable pattern language.

## Use it

```sh
cargo build

# validate the spec — rejects incomplete or unsafe compositions
./target/debug/harnessc check

# inspect the compiled model before generating anything
./target/debug/harnessc show

# compile the Playbook (target defaults to the spec's platform.type)
./target/debug/harnessc build --out .

# the SAME spec, a different binding
./target/debug/harnessc build --target portable --out dist/portable

# turn operational state into a proposed spec change (never applied automatically)
./target/debug/refinery --ledger evidence/events.jsonl
```

Generated files carry a provenance header (`GENERATED FROM … / SPEC HASH … / DO
NOT EDIT DIRECTLY`) so the source-of-truth hierarchy stays legible: edits flow
*down* from the spec, never up from generated output.

## What the compiler rejects (the interesting part)

Each of these is a compile **error**, verified by tests in
[`crates/spec/src/check.rs`](crates/spec/src/check.rs):

- **`gate.missing_action_hash` / `gate.no_precondition_binding`** — a Gate whose
  approval does not bind to the action *and* at least one material precondition.
  Binding the artifact alone leaves a time-of-check/time-of-use gap.
- **`ledger.redact_incomplete`** — a Ledger that would record `secrets` or
  `credentials`. An append-only log of raw inputs is a durable credential leak.
- **`law.unsupported`** — a Law the *selected binding* cannot enforce.
  Generating a stub would pretend a guarantee that isn't there. (Which laws are
  enforceable is a capability of the target binding, not of the language.)
- **`law.event_mismatch`** — a Guard bound post-tool or an Obligation pre-tool.
- **`composition.referenced_but_unbound`** — a pattern named in the composition
  with no binding supplied.
- **Reference integrity** — a named occurrence must resolve to exactly one real
  binding before any case law runs, so a typo cannot silently disconnect the
  declared topology from the system. `composition.unknown_instance`
  (`Port[ghost]` matches no Port binding — the fail-open hole that would
  otherwise *suppress* the derived obligation), `composition.instance_kind_mismatch`
  (`Port[x]` where `x` is a Law id), `composition.unaddressable_pattern`
  (`Sandbox[x]` — a singleton with no id to name), and `binding.duplicate_id`
  (two bindings share an id, so no reference resolves to exactly one).
- **`pipeline.stage_type_mismatch`** — a Pipeline whose typed stage interfaces
  don't chain (one stage's output ≠ the next's input). That, not a fixed order,
  is what makes it a Pipeline.
- **`port.unguarded_write`** — a Port with write authority but no Guard Law.
  Connectivity without a capability boundary is ambient privilege.
- **`delegate.no_authority` / `delegate.unstructured_return` / `delegate.unknown_port`** —
  a Delegate must declare its delegated tools, return through a schema, and only
  reference declared Ports (never broader authority than granted).
- **`hive.*`** — the Law of the Hive: a Hive must declare budget, depth,
  termination, merge, worker isolation, and a real worker contract.
- **Composition case law (relation-aware, instance-addressed)** — obligations
  that exist only because two patterns meet *in a particular topology*. The
  checker asks the composition AST direction-honest relational questions
  (`is_within`, `flows_to`, `provisions`, `flow_connected`, `runs_under`,
  `may_execute_concurrently`), not mere presence, so a Gate in one independent
  branch and a Night Shift in another do **not** trip the rule. A Gate **running
  under** a Night Shift ⇒ durable, revalidating suspension; a Port on the
  unattended data path ⇒ replay-safe idempotency; a Port **within** a Sandbox ⇒
  declared external isolation; a Gate **within** a Hive ⇒ declared approval
  scope; **`Obligation Law + Gate`** ⇒ the obligation discharged *through* the
  Gate; `Sandbox + Ledger` ⇒ recorded lineage. Occurrences are
  **instance-addressable**: `Port[staging] within Sandbox + Port[metrics]`
  attaches the isolation obligation to `staging` alone — the derived obligation
  binds to the named component, not to every Port binding. A bare `Port`
  conservatively still stands for every Port binding. See
  [`examples/instance-addressed.patterns.yaml`](examples/instance-addressed.patterns.yaml).

## Enforcement honesty

"Bindable" is not "enforced", so every pattern carries an explicit
**enforcement level** — `scaffolded` < `declared` < `statically-checked` <
`runtime-monitored` < `runtime-enforced` < `kernel-mediated`. `harnessc show`
prints it per pattern, and `harness/playbook.json` records it:

```
Gate         runtime-enforced
Law          runtime-enforced
Ledger       runtime-monitored
Port         statically-checked
Delegate     scaffolded
```

The top rung, `kernel-mediated`, is intentionally **unclaimed**: it would
require a conformance proof that the effect *cannot* occur without passing the
kernel, and nothing in the current binding demonstrates that. The Gate is a
registered hook (runtime-enforced), not proven-complete mediation — so the
taxonomy says `runtime-enforced` and reserves the stronger word.

## What the kernel actually enforces

The generated hooks are thin shims; the enforcement lives in the compiled
`kernel` binary, so it runs regardless of what the model decides:

- **`enforce-file-scope`** (Guard Law) — reads a proposed tool call on stdin and
  **blocks** (exit 2) any edit outside the active packet's write scope, logging
  the allow/deny to the Ledger.
- **Self-protection** (§4) — the Guard is a default-deny allowlist, so it covers
  its own enforcement artifacts (the generated tree and the spec, listed in
  `enforcement.protected`). Editing one requires a packet with
  `amends_enforcement: true` — logged distinctly as `pre_tool.enforcement_amendment` —
  and a Bash hook blocks `rm`/`mv` of them. Amending enforcement is never ambient.
- **Run binding** (§13) — every Ledger event carries `playbook_ref` (the spec
  content digest that governed the run), so the log proves which constitutional
  version was in force. The generated hooks bake in the digest they compiled from.
- **Gate** — `kernel gate request|approve|verify` persist a durable checkpoint,
  bind approval to an action hash + precondition snapshot + approver + expiry,
  and **revalidate at resume**: a changed action, drifted precondition, or
  expired approval is refused. This is what lets a Gate work across process
  death (cron, CI, a fresh container), not just in one session.
- **`require-validation`** (Obligation Law) — an obligation event is recorded
  after each edit, and the commit gate hook **blocks `git commit`** (exit 2)
  while it is outstanding. `kernel validate` discharges it (optionally gated on a
  check command as evidence). This is "recorded" turned into "enforced".
- **Gate** — `kernel gate request|approve|verify` persist a durable checkpoint,
  bind approval to an action hash + precondition snapshot + approver + expiry,
  and **revalidate at resume**: a changed action, drifted precondition, expired
  approval, or outstanding obligation is refused. This is what lets a Gate work
  across process death (cron, CI, a fresh container), not just in one session.
- **Ledger** — an append-only event log whose envelope carries only references
  and hashes, never raw payloads.

The generated [`harness/README.md`](harness/README.md) states each law's
enforcement level plainly — nothing claims a guarantee the kernel does not
provide.

## Two bindings, one spec

`platform.type` (or `--target`) selects a back-end. Both implement the same
`spec::Binding` capability interface, so the checker validates the spec against
whatever target it compiles for:

- **`claude-code`** — `CLAUDE.md`, `.claude/settings.json` hook registration,
  `.claude/commands/`, and `harness/` hooks.
- **`portable`** — no launcher; a `harness.manifest.json` declaring the
  hook→event bindings plus the exact `kernel` command each hook runs. Same spec,
  same kernel, different packaging.

## The Refinery and the ratchet

`refinery` reads the Ledger and produces a **reviewable patch against the spec**,
written under `refinery/proposals/<id>/` — never an edit to a generated artifact,
never a hot-patch to the running system.

It obeys the **ratchet** (§14): *automatic promotion only for transformations
proven monotone under a predeclared, mechanically-decidable ordering.* The
ordering is small and total — an administrative version bump is monotone
(auto-applied); everything that touches a policy is **disputed** and withheld for
human promotion. That deliberately includes changes that *look* like
strengthening: adding redaction is a cross-policy tradeoff (secrecy vs. audit
evidence), so the Refinery proposes it but does **not** apply it. Widening a
Guard is authority-widening and never auto-promoted. Promotion — reviewing the
diff and applying it to `harness.patterns.yaml` — is a separate human step,
upholding the invariant that *the running agent never rewrites the rules
governing its current run*.

## Tests

```sh
cargo test --workspace     # 120 tests: metamodel, checker rejections for every
                           # pattern, composition parser + precedence + instance
                           # addressability + case law, kernel enforcement +
                           # self-protection + Law of the Hive, gate revalidation +
                           # obligations, playbook_ref run binding, both backends,
                           # example specs, and the Refinery ratchet
```

## Status and next steps

Aligned to constitution **v1.2**, with **all fourteen patterns bindable** and a
**relation-aware, instance-addressable** composition checker. Hardening from two
external reviews is in: occurrences carry identity (`Port[staging]`), so a
derived obligation attaches to the named component rather than the pattern
category; the operator grammar has a **formal precedence** (`+` loosest) so a
mixed expression parses one way; the direction-reversing `governs` relation was
removed in favor of `flow_connected` / `runs_under`; obligations are scoped per
run; every named occurrence is **reference-resolved** to exactly one binding
(unknown/mismatched/unaddressable names and duplicate ids are rejected) so a typo
cannot silently disconnect the topology from the system; file authority is
decided on **platform-independent** normalized components (absolute, `..`,
backslash, drive-letter and alternate-data-stream vectors all rejected);
checkpoints are written with the POSIX atomic-replace sequence (temp → fsync →
rename → dir-fsync, with the directory fsync on Unix) and hashed, injection-safe
names, and the Ledger is fsynced; and approver identity distinguishes a *claimed*
label from an authenticated principal.

Documented follow-ups (not yet done). The next foundational change is to lower
the surface expression into an **explicit typed composition graph** —
`expression → AST → resolve instances/bindings → typed graph → derive
obligations` — so case law runs over a graph, not the syntax tree. That graph
separates **node identity from binding identity** (two architectural positions
may share one implementation: `staging_deployer` and `release_annotator` both
backed by `Port: github`), makes the subtree-based relation semantics explicit
(a grouped `(A + B) -> (C + D)` currently over-approximates to all four data
paths), and adds **semantically-typed relations** sourced from bindings (a
Delegate's declared Port list as an `invokes`/`uses` edge, not inferred from
linear syntax). Beyond it: a **three-level identity** model (pattern kind →
composition node → runtime instance) for per-worker Gate approval and
worker-scoped obligations; a **declared obligation scope** (`run | task | branch
| workspace | action`); a **unified transition protocol**
(Proposed→Authorized→Executing→…→Recorded); **transactional Hive budget**
reservations; a **tamper-evident Ledger** (sequence + prev-hash chain);
**symlink/canonical and case/Unicode-alias** resolution for existing write
targets; a real **IdP/signature** integration for approvals; a
**Python/OpenAI-Agents** back-end behind the same `Binding`; and version-promotion
tooling for approved Refinery proposals.
