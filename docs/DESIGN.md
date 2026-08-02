# patterns → harness compiler

> The design deep-dive: composition algebra, checker case law, enforcement
> taxonomy, identity chain, and the stated boundary of every guarantee. For
> the short introduction, see the [README](../README.md).

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
declaration is [`harness.patterns.yaml`](../harness.patterns.yaml).

Every v1.2 pattern is bindable. (The expression grammar exposes fifteen addressable kinds: the constitution's fourteen patterns plus **Critic**, which is formally the review-only *variant of Delegate* — bound via `critic: true` on a delegate — but stays separately addressable so a composition can place the reviewer distinctly from the workers.) Beyond the specimen, example specs
exercise the scale patterns — [`examples/research-org.patterns.yaml`](../examples/research-org.patterns.yaml)
(`(Delegate × 3) -> Critic -> Refinery + Ledger + Hive + Port`) and
[`examples/safe-deploy.patterns.yaml`](../examples/safe-deploy.patterns.yaml)
(`(Pipeline within Law) -> Gate + Ledger`) — and one shows **instance
addressability**: [`examples/instance-addressed.patterns.yaml`](../examples/instance-addressed.patterns.yaml)
(`(Port[staging] within Sandbox) -> Gate + Port[metrics] + Law + Ledger`), where
a derived obligation binds to `Port[staging]` and leaves its sibling alone.
[`examples/aliased-positions.patterns.yaml`](../examples/aliased-positions.patterns.yaml)
shows **named positions**: `Port[github as staging_deployer]` and
`Port[github as release_annotator]` are two architectural positions backed by
one implementation binding, named apart — and `Sandbox[as worker_sandbox]`
names a position of a singleton kind that has no binding id at all.

## Workspace

Four crates, mirroring the compiler pipeline:

| Crate | Role | Key contents |
|-------|------|--------------|
| [`spec`](../crates/spec) | Compiler **front-end** (platform-agnostic) | metamodel, composition-algebra parser, the checker |
| [`harnessc`](../crates/harnessc) | Compiler **back-end** (claude-code binding) | generates the Playbook, stamps provenance |
| [`harness-kernel`](../crates/kernel) | Trusted **runtime kernel** | task packets, Guard Laws, Gate checkpoints, Ledger, obligations, Law of the Hive |
| [`refinery`](../crates/refinery) | The **Refinery** | reads the Ledger, proposes a reviewable patch against the spec |

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

Generated files carry a provenance header (`GENERATED FROM … / SOURCE … /
PLAYBOOK … / DO NOT EDIT DIRECTLY`) so the source-of-truth hierarchy stays
legible: edits flow *down* from the spec, never up from generated output.

## Identity: source provenance is not executable provenance

The same `harness.patterns.yaml` compiled by a different compiler can govern a
materially different system — different case law, a different IR, a different
generated tree. Binding evidence to the spec bytes alone would let a **stale**
artifact carry a matching reference, which is exactly how a checked-in Playbook
came to claim `Gate: kernel-mediated` long after the compiler retracted that
guarantee. So the identity chain has four links:

```
source_ref   = sha256(spec bytes)
compiler_ref = sha256(compiler + front-end source + Cargo.lock + toolchain + IR schema + target)
ir_ref       = sha256(canonical serialized resolved IR)
playbook_ref = sha256(source_ref + compiler_ref + target + ir_ref)
```

`compiler_ref` hashes the compiler's *implementation source*, not its version
labels: two divergent trees that both still call themselves `0.1.0` — the exact
state in which a checked-in Playbook once kept claiming a retracted guarantee —
produce different references, so the divergence is detectable. The digest also
folds in the workspace `Cargo.lock` and the toolchain identity (`rustc
--version --verbose`: release, commit, host triple, captured at build time), so
identical source built against different dependency versions or a different
rustc is a different compiler too. `kernel_ref` binds the same way: source,
lock, and toolchain — the build gap closed on both sides of the chain.

Every artifact records `source_ref` and `playbook_ref` in its header; the JSON
manifests additionally expose `compiler_ref` and `ir_ref` (the shell and Markdown
headers omit them, but `playbook_ref` cryptographically commits to both). The
generated hooks stamp `playbook_ref` — the compiled *interpretation* — onto every
Ledger event, so a run is bound to the semantics that governed it and not merely
to the bytes it started from.

A compiled identity is still not a runtime identity, though: the same Playbook
enforced by a different `kernel` is a different governed system. So every Ledger
event *also* carries `kernel_ref`, a content digest of the kernel implementation
that executed the transition — recorded by the kernel itself, since only the
running binary knows which binary it is. The evidence therefore names both which
spec governed and which kernel ran.

```sh
# fail if the checked-in tree is not what this compiler produces
./target/debug/harnessc verify
```

`harnessc verify` compiles in memory and proves the tree on disk is **exactly**
this bundle — not merely that every expected file matches. Each backend's final
artifact is a **bundle manifest** (path, content digest, mode, and file type
per generated file, sorted), which makes the managed path set durable. Verify
checks four things per file — presence, bytes, regular-file type (a symlink in
an artifact's place fails), and mode (a hook whose executable bit was stripped
silently stops running, so identical bytes are not enough) — and, via the
previous manifest, flags **obsolete** files: paths an older compiler emitted
that this one no longer generates, which would otherwise remain live behavior
no current Playbook accounts for. A workspace test runs it against this
repository's own Playbook, so a stale artifact fails CI instead of shipping.

`harnessc build` promotes the bundle without ever presenting a torn Playbook,
in two layers. First, the **versioned copy**: the complete bundle is
materialized under `.harnessc/bundles/<playbook-ref>/`, fsynced, and
self-verified there (bytes, modes, types) before the live tree is touched — so
there is always a whole, coherent Playbook on disk, and `.harnessc/current`
keeps naming the old version until the new one has fully landed. Then the
**live tree**: files staged as fsynced tmp siblings, promoted by atomic
renames; obsolete files retired before the manifest is replaced; the manifest
promoted last; and finally `current` atomically switched to the new bundle as
the bundle-level commit point. The previously-current version is retained as
the rollback source (older ones are pruned), and `verify` cross-checks the
pointer when present — a crash mid-promotion leaves the old manifest and old
pointer describing the old set, so `verify` reports the exact divergence
rather than trusting either version. `.harnessc/` is local build state, not
checked in.

`harnessc restore` rolls the live tree back to any retained version — or
re-materializes the active one — without recompiling: the retained copy is
**self-verified against its own manifest** before anything is touched (a
rollback source that cannot prove itself is not a rollback source), files the
live bundle has that the restored one lacks are retired exactly as a build
would, and the `current` pointer follows. `harnessc restore --list` enumerates
the retained versions and marks the active one; `--playbook` accepts a full
ref or unique prefix.

## What the compiler rejects (the interesting part)

Each of these is a compile **error**, verified by tests in
[`crates/spec/src/check.rs`](../crates/spec/src/check.rs):

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
  (`Sandbox[x]` — a singleton with no id to name), `binding.duplicate_id`
  (two bindings share an id, so no reference resolves to exactly one), and
  `binding.unaddressable_id` (an id like `github.production` falls outside the
  grammar's `[A-Za-z0-9_-]+` alphabet — it would exist but be unnameable, so
  reference integrity holds at the lexical boundary too).
- **Alias integrity** — a position name is an identity, so: it is declared
  exactly once (a repeated declaration is a *parse* error, caught at the symbol
  layer); it must not shadow a binding id (`composition.alias_shadows_binding`);
  and it must not be a reserved name — a pattern kind or grammar keyword —
  because a bare `Gate` always parses as the language construct, leaving the
  position unreferenceable (`composition.alias_reserved_name`).
- **`composition.self_relation`** — an **irreflexive** relation between one
  position and itself. Under the all-pairs reading, `p -> (p + Gate)` declares
  `p -> p` just as `p -> p` does, so both are reported (the message says which);
  neither is silently erased, because deleting the syntax could delete a derived
  obligation. `Coexist` is exempt as *reflexive* — "p coexists with p" is
  vacuously true, which is what lets a reference appear in both operands of a
  `+` without declaring nonsense.
- **`composition.alias_replication_conflict`** — one position used at differing
  multiplicities. Cardinality is part of the IR (`× 2` and `× 20` do not lower
  alike, and nested `(A × 2) × 3` is `Exact(6)`), so `(p × 2) + (p × 3)` is a
  conflict just as `p + (p × 3)` is.
- **`composition.control_without_interceptor`** — a Verb composed `within` a
  Law whose enclosing occurrences resolve to no **Guard**. An Obligation Law
  records debt after the fact; it does not intercept the Verb, and "some Law
  binding exists" is not an interceptor.
- **`composition.enforcement_not_activated`** — a bound Law, Gate, or Ledger
  that nothing activates and that is not declared `always_on: true`.
  Enforcement is never installed implicitly: surplus enforcement can block
  permitted actions, open undischargeable obligations, deadlock a Gate, or
  over-record — so ambiguity is rejected, not resolved by installing more.
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
  rules run on the **resolved graph's typed edges** (`bindings_within`,
  `bindings_enclosing`, `bindings_flow_connected`, `bindings_provisioned`,
  `runs_under`), not on the syntax tree and not on mere presence — each rule
  reads which *bindings* stand in the relation straight off the graph, so a
  Gate in one independent branch and a Night Shift in another do **not** trip
  the rule. A Gate **running
  under** a Night Shift ⇒ durable, revalidating suspension; a Port on the
  unattended data path ⇒ replay-safe idempotency; a Port **within** a Sandbox ⇒
  declared external isolation; a Gate **within** a Hive ⇒ declared approval
  scope; **`Obligation Law + Gate`** ⇒ the obligation discharged *through* the
  Gate; `Sandbox + Ledger` ⇒ recorded lineage. Occurrences are
  **instance-addressable**: `Port[staging] within Sandbox + Port[metrics]`
  attaches the isolation obligation to `staging` alone — the derived obligation
  binds to the named component, not to every Port binding. A bare `Port`
  conservatively still stands for every Port binding. See
  [`examples/instance-addressed.patterns.yaml`](../examples/instance-addressed.patterns.yaml).

## The resolved graph: a valid reference is not yet an active node

The expression is lowered into an explicit intermediate representation —
`ResolvedGraph` — before anything is generated:

```
composition expression
        ↓ parse
AST
        ↓ resolve (nodes, typed edges, ACTIVE binding set)
ResolvedGraph
        ↓
case-law scoping + backend generation
```

Three properties the AST alone could not provide:

- **Positions are preserved and nameable.** Every syntactic occurrence is its
  own node, so `Port[github] within Sandbox + Port[github] -> Gate` is two
  architectural positions sharing one binding — not collapsed into one
  identity. An **alias names the position**: `Port[github as staging_deployer]`
  declares the position's identity distinct from the binding's, unique across
  the composition, carried on the IR node, serialized into the bundle, and
  addressable via `node_by_alias`. A singleton kind's position is nameable the
  same way (`Sandbox[as worker_sandbox]`) even though it has no binding id.
  Aliases are **referenceable in relations**: a bare identifier that is not a
  pattern kind refers to the position declared with `as`
  (`Port[github as gh] within Sandbox + gh -> Gate`), and a reference resolves
  to the **same IR node** as its declaration — one position participating in
  every relation that mentions it, which is what lets a linear expression
  declare a DAG. Alias-addressed queries (`alias_related_to`,
  `related_to_alias`) ask relations of one position rather than a kind or a
  binding, and case law fires through alias-mediated relations exactly as
  through direct ones.

  **Names survive as names.** A reference is *not* substituted with a copy of
  its declaration: `Expr::AliasRef` stays structurally distinct from the
  `Expr::Pattern` that declared it, so `X[b as a] + a` (declaration plus
  reference) never becomes indistinguishable from `X[b as a] + X[b as a]` (two
  declarations of a name that must be unique). A declaration scan runs before
  parsing and rejects a repeated declaration at the **symbol layer** — the only
  layer where declarations and references are still distinguishable — while
  references resolve against that table, so a forward reference works. An
  identifier matching no kind and no alias is a parse error; a reference takes
  no bracket clause.
- **Activation is explicit.** A binding is part of the compiled system only if
  the composition activates it: an anonymous `Port` activates every Port
  binding; `Port[staging]` activates exactly that one. Activation then **closes
  over the references bindings make to each other**, and each closure step is a
  **first-class `uses` edge in the IR** (`Hive -hive_worker-> Delegate`,
  `Delegate -delegate_port-> Port`, `Port -port_guard-> Law`,
  `Gate -gate_obligation-> Law`), carrying the bindings-block field it was read
  from — so case law can ask *which Delegate uses this Port* without returning
  to the raw bindings. **The backends generate only active bindings**: a
  `production` Port bound beside `Port[staging] within Sandbox` is not wired
  into the Playbook, and the checker says so
  (`composition.binding_not_activated`) rather than excluding it silently.
  Activation also scopes case law — a bound-but-unactivated obligation Law no
  longer becomes a Gate requirement by mere co-presence in the bindings block.
- **The over-approximation is stated.** An operator between grouped operands
  relates all pairs: `(A + B) -> (C + D)` declares all four data paths. That is
  a deliberate conservative reading (more declared paths ⇒ more derived
  obligations, never fewer), asserted by a test so it stays a stated choice.

Activation gates the capability-bearing collections (Specialists, Delegates,
Pipelines, Ports, Hives) in generation. Enforcement is handled the fail-closed
way in the *checker* instead: surplus enforcement is **not** monotonically safer
(an unactivated Guard can block permitted actions; an unactivated Obligation
opens debt nothing discharges; an unactivated Gate deadlocks progress; an
unactivated Ledger records — discloses — beyond the declared system). So a bound
Law, Gate, or Ledger must be activated by the composition, activated through a
`uses` dependency, or explicitly declared **`always_on: true`** — anything else
is the compile error `composition.enforcement_not_activated`, never an
automatically installed safety surplus. Generation may then read the
enforcement bindings directly, because the checker guarantees every one it
reads is active or declared.

The compiler resolves **one IR instance** and threads it through:
`compile()` lowers the graph once, `check()` receives that instance, the
`CompiledSpec` carries it, and generation reads it — so "the compiler checked a
different interpretation than it generated" is structurally impossible. The
same IR is **serialized into the compiled bundle** (`harness/playbook.json`
`graph` key, and the portable `harness.manifest.json`) as a two-layer object:
`nodes` and `position_edges` (architectural occurrences), `binding_edges` (the
`uses` dependencies, each with the bindings-block field it was read from), and
`components` — **every** bound component with `active` and its
`activation_origins` (`surface`, `surface:critic`, `uses:<kind>`, `always_on`),
plus `self_relations`. The inventory is keyed by *component*, not binding id, so
**singletons are covered too**: an `always_on` Ledger owns no id and occupies no
position, yet the backend can emit it, so it appears here — as does a Law
activated only through a `uses` edge, and a Delegate activated only by a
`Critic` position (which records `surface:critic` rather than an empty origin
set). Node cardinality is serialized as `multiplicity`. The pattern/enforcement
summary derives from the same resolved architecture, not from surface presence,
so a Law activated only through a dependency shows up in it. `harnessc show`
prints all of this. The spec hash proves *identity*; the serialized IR makes the
compiled *interpretation* auditable.

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
- **Run binding** (§13) — every Ledger event carries `playbook_ref` (the
  compiled-interpretation digest that governed the run), so the log proves which
  constitutional version was in force. The generated hooks bake in the digest they
  compiled from. Each event additionally carries `kernel_ref`, the digest of the
  enforcement binary that executed it. Both fields are **mandatory** — on the
  event type and in the generated schema — so the record distinguishes which
  kernel ran, not just which spec governed; an empty value is explicit legacy
  state, never an ordinary governed event.
- **`require-validation`** (Obligation Law) — an obligation event is recorded
  after each edit, and the commit gate hook **blocks `git commit`** (exit 2)
  while it is outstanding. `kernel validate` discharges it (optionally gated on a
  check command as evidence). This is "recorded" turned into "enforced". Every
  actual commit evaluation — allow or deny — is itself appended to the Ledger,
  run-bound, with a denial naming the obligations that stood in the way: a
  blocked commit is a governed decision, not just an exit code.
- **Gate** — `kernel gate request|approve|verify` persist a durable checkpoint,
  bind approval to an action hash + precondition snapshot + approver + expiry,
  and **revalidate at resume**: a changed action, drifted precondition, expired
  approval, or outstanding obligation is refused. This is what lets a Gate work
  across process death (cron, CI, a fresh container), not just in one session.
  `gate request --ledger` additionally **anchors the Ledger's chain head** into
  the checkpoint (refusing to notarize a broken chain), and `gate verify
  --ledger` refuses to resume over a log whose history no longer contains the
  anchored head — the durable checkpoint is exactly the out-of-band place the
  chain's one blind spot needs.
- **Ledger** — an append-only event log whose envelope carries only references
  and hashes, never raw payloads. Append-only is a *property*, not a posture:
  every record carries a contiguous `seq` and a `prev` digest of the previous
  line's exact bytes, and `kernel ledger verify` proves the chain — mutation,
  insertion, mid-deletion, and reordering are detected anywhere in history,
  and a pre-chain legacy prefix is frozen the moment the first chained record
  commits to it. The one stated limitation: tail truncation leaves a shorter
  but internally consistent chain, so the chain **head** must be anchored
  outside the file — which Gate checkpoints now do (`gate request --ledger`);
  `verify` also prints it for any other anchor (a push, a signed note). Racing
  writers produce a visible fork the verifier reports, never a silently merged
  history.

The generated [`harness/README.md`](../harness/README.md) states each law's
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
cargo test --workspace     # 159 tests: metamodel, checker rejections for every
                           # pattern, composition parser + precedence + instance
                           # addressability + case law, kernel enforcement +
                           # self-protection + Law of the Hive, gate revalidation +
                           # obligations, playbook_ref run binding, both backends,
                           # example specs, and the Refinery ratchet
```

## Status and next steps

Aligned to constitution **v1.2**, with **every pattern bindable** and a
**relation-aware, instance-addressable, reference-resolved** composition
checker over a **resolved graph IR** with explicit activation. Hardening from
three external reviews is in: occurrences carry identity (`Port[staging]`), so
a derived obligation attaches to the named component rather than the pattern
category; every named occurrence is **reference-resolved** to exactly one
binding (unknown/mismatched/unaddressable names, out-of-grammar ids, and
duplicate ids are rejected) so a typo cannot silently disconnect the topology
from the system; **generation consumes the active set** — a binding the
composition never activates produces no artifact, visibly; the operator grammar
has a **formal precedence** (`+` loosest); the direction-reversing `governs`
relation was removed in favor of `flow_connected` / `runs_under`; obligations
live at a **declared scope** (`run | task | branch | workspace | action`,
default `run`): the spec says whose debt an edit opens and what discharges it
— per run, following the task packet across runs (keyed by packet digest),
following the git branch, globally, or per edited path — with a stated
fail-safe (a debt that cannot be proven discharged for the asking context
blocks, including unkeyed legacy records); the Hive budget is a
**transactional pool** — one durable state file per Hive, mutated only under
an exclusive lock, where `hive-spawn` atomically reserves a spawn's budget
before it runs (refused when the pool cannot cover it, idempotent on replay)
and `hive settle` records actual spend and returns the remainder, so racing
spawns serialize instead of jointly overshooting a caller-claimed cap, and
every grant, refusal, and settlement is Ledger evidence; file authority is
decided on **platform-independent**
normalized components (absolute, `..`, backslash, drive-letter and
alternate-data-stream vectors all rejected) and judged against the
**canonical target** on the real filesystem — symlinks in the existing
portion are resolved fully, so a link cannot launder an out-of-scope or
protected file into an authorized name; authorization binds to the real
target, protection covers both names, an escape outside the workspace or a
dangling link is denied outright, and evidence records both the lexical path
and the canonical one; checkpoints are written with the
POSIX atomic-replace sequence (temp → fsync → rename → dir-fsync, with the
directory fsync on Unix) and hashed, injection-safe names, and the Ledger is
fsynced; and approver identity distinguishes a *claimed* label from an
authenticated principal — where `signature` auth is **cryptographically real**:
`kernel key generate` mints an Ed25519 approver keypair, `gate sign` signs the
canonical approval message (gate, run, action hash, precondition snapshot,
anchored ledger head, expiry), `gate approve --auth signature` verifies against
the trusted-keys registry *before recording anything*, and `gate verify
--trusted-keys` **re-verifies the stored signature at resume**. That last step
is the custody boundary moving from disk to key: a party who rewrites the
ledger and repoints the checkpoint's anchored head produces an internally
valid chain that file-level checks accept — but the approver signed the head
they actually saw, so the rewrite invalidates the approval. Forging a
resumable approval now requires the approver's private key, not write access.

The trusted-keys registry itself is bindable to an **identity authority** —
the offline trust core of an IdP integration. `kernel registry sign` turns the
registry into an authority-issued identity document (`[registry]` issuer +
monotonic serial + `expires_at`, `[approvers]`, `[revoked]`) with a detached
Ed25519 signature over the file's exact bytes; with `--authority <pinned key>`
on `gate approve`/`gate verify`, the kernel refuses an unsigned, edited,
expired, or rolled-back registry wholesale, and resolves the approver through
the **current** document — so a principal revoked in a later serial stops
resuming checkpoints they validly approved, which is exactly what revocation
means. Custody moves again: from registry-file custody to authority-key
custody. Stated plainly: the rollback high-water mark is same-disk state, so
the hard bound on replaying an old signed document is its `expires_at` —
issuers must roll documents; and binding the *authority* to an online IdP
(OIDC issuance, directory sync) is a protocol adapter deliberately not faked
here.

Documented follow-ups (not yet done). The graph IR drives activation,
generation, **and the relational case law**; binding dependencies are
**represented as typed `uses` edges**; one IR instance is checked, carried,
serialized, and generated from; enforcement activation is explicit
(`always_on` or activated, else rejected); and positions carry **declared
node identity** distinct from binding identity (`Port[github as
staging_deployer]`, unique, shadow-checked, serialized); **executable
provenance** binds evidence to the compiled interpretation
(`playbook_ref = source + compiler + IR + target`, where `compiler_ref` is a
digest of the compiler's implementation source, not its version labels) with
`harnessc verify` and a CI test proving the checked-in tree is fresh, and every
Ledger event additionally carries `kernel_ref` — the digest of the kernel that
executed it — so runtime evidence names the enforcement binary and not just the
compiled Playbook; replication **cardinality** is
part of the IR; every bound component — singleton or named — carries activation
status and provenance; aliases are
**referenceable in relations** (`staging_deployer -> Gate`), resolved *without
substitution* so a declaration stays distinguishable from a reference and a
repeated declaration is rejected at the symbol layer; and binding activation is
a **first-class serialized part of the IR** (every binding with its status and
provenance), so the proof object accounts for everything the backend emits;
and the identity model is **three-level** — pattern kind → composition node →
runtime instance (`run-42/worker/2`). The graph's uniquely-nameable positions
(alias, or an instance id owned by exactly one node) compile into a
`positions.json` registry with their multiplicity bounds, and the kernel holds
runtime instances to it: an instance of an undeclared position, or a replica
slot beyond the declared multiplicity, is refused — the IR's replication
cardinality, enforced at runtime. Gates bind per-instance (the checkpoint
stores its instance, the v2 approval message signs over it, resume must
present the matching instance, and the checkpoint filename hashes gate + run +
action + instance so per-instance checkpoints never overwrite each other), and
the obligation scope `instance` makes a worker's debt that worker's to clear.
The instance path's third segment addresses the **replica slot**; execution
retries deliberately stay on the event envelope's `attempt_id` — folding
retries into identity would make "the same worker, tried again" a different
worker. Every governed event now also names its place in a **unified
transition protocol** — a `stage` field on the envelope
(`proposed → authorized → executing → completed`, with `recorded` for
free-form evidence). The stage is a *field*, not a rewrite of transition
strings: the chained history is frozen and the Refinery matches transition
prefixes, so classification rides alongside identity rather than replacing
it. This closed a real evidence gap — the Gate's own lifecycle previously
left no Ledger trace at all; now `gate request` records the halt
(`proposed`), `gate approve` records the decision (`authorized`, approved
*or* rejected), and `gate verify` records every resume — including each
refusal, with its reason as an evidence ref, so a tampered-action rejection
is a first-class chained record and not just an exit code. The Refinery's
loop is now **closed by gated promotion**: `refinery promote` applies an
approved proposal to the live spec only as a Gate resume — the checkpoint's
`action_hash` must equal the digest of the proposal's bytes *as they are
now* (a post-approval edit is the same `action changed` refusal as a
substituted deploy artifact), the proposal's manifest binds the base spec
it was analyzed against (a moved spec makes the proposal stale, never
silently overwritten), and by default only a signature-authenticated
approval promotes — re-proved through the current identity registry via
the *same* kernel composition `gate verify` uses
(`sign::reverify_signed_approval`, one canonical implementation so the two
resume paths cannot drift), with `Claimed`/`Token` approvals requiring an
explicit `--allow-unproven`. A hand-edited proposal is legitimate — that
is how disputed changes get promoted — but the edit is recorded as
evidence, and both `propose` and `promote` (success *and* refusal, with
reason) land in the Ledger at their protocol stages. Promotion proves the
bytes parse, not that they compile: the compile gate stays `harnessc
build`, whose freshness test makes a promoted-but-uncompiled spec loud in
CI. Remaining on this arc: an **online IdP protocol adapter**
(OIDC issuance, directory sync) binding the identity authority itself to
organizational infrastructure — the offline trust core (authority-signed
registries with expiry and revocation) exists; and a
**Python/OpenAI-Agents** back-end behind the same `Binding`.

Hardening from the first **self-hosting trial** (the harness governing work on
itself) is in. Every denial now carries a stable machine-readable code beside
its prose (`policy:file_scope.outside`,
`policy:enforcement.amendment_required`, `policy:intake.no_active_packet`,
`policy:obligation.outstanding`, …), so a refusal is analyzable without
parsing sentences. Platform-shaped **absolute paths rebind** to their
workspace-relative form before policy runs — inside the workspace they are
judged like any other path (evidence records both spellings), outside it they
are refused with their own code; the trial's first defect, where every
platform edit was denied as "absolute", cannot recur. Identity fields are
real: guard, obligation, and gate events name the **admitted packet**
(`task_id`), a unique **`attempt_id`** distinguishes retries, `action_id`
names the logical action rather than the subcommand, and the generated hooks
derive a per-session run identity (`unbound-$PPID`) instead of the shared
`unknown` fallback — which the commit gate now **fails closed** on
(`policy:identity.run_unbound`), since debt that cannot be attributed cannot
be evaluated. Whether a packet **amends enforcement is derived, not
declared**: a write scope intersecting the protected set — which the spec
extends with the workspace's own TCB (`harness.protected`: kernel, compiler,
lock) — is refused at Intake without the grant. And every event carries
**`runtime_ref`** = `sha256(playbook_ref + kernel_ref + envelope ABI)`: the
runtime constitution as one digest, with `kernel ledger verify` reporting
history as contiguous runtime segments, because the trial proved the same
playbook can govern two different kernels. The governed *transition* between
runtimes — disarm, externally authorized repair, conformance, activation, and
genesis linking — is designed in [`docs/SUCCESSION.md`](SUCCESSION.md) and
admitted as a pending packet.
