//! Static checks: the compiler's conscience.
//!
//! Two layers run here. **Completeness** checks reject a binding that would
//! generate something weaker than the pattern promises — a Gate whose approval
//! binds to nothing but an artifact is a confirmation prompt, so we refuse it.
//! **Composition** checks encode the constitution's case law: obligations that
//! only exist because two patterns meet (Gate + Night Shift ⇒ durable,
//! revalidating suspension; Sandbox + Ledger ⇒ recorded lineage).
//!
//! Each discovered interaction becomes a rule here, exactly as the spec
//! intends: "When two patterns meet, ask what new obligation their meeting
//! creates."

use std::collections::BTreeSet;

use crate::binding::Binding;
use crate::compose::Expr;
use crate::graph::ResolvedGraph;
use crate::model::{Bindings, LawEvent, LawKind, PatternKind, SpecFile};

/// Whether a diagnostic blocks compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// A single finding from the checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}

impl Diagnostic {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Error,
            code,
            message: message.into(),
        }
    }

    fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Warning,
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{tag}[{}]: {}", self.code, self.message)
    }
}

/// Tokens that describe *what* is approved rather than a material precondition
/// whose drift should invalidate approval.
const NON_PRECONDITION_BINDINGS: &[&str] = &["action_hash", "approver", "expiry"];

/// Run every check against a parsed spec, its composition tree, the resolved
/// graph, and the target binding's capabilities. Returns all diagnostics; the
/// caller treats any `Error` as blocking.
///
/// The graph is passed in — not resolved here — so the instance that is
/// checked is literally the instance the compiler carries forward to
/// serialization and generation.
pub fn check(
    spec: &SpecFile,
    expr: &Expr,
    graph: &ResolvedGraph,
    binding: &dyn Binding,
) -> Vec<Diagnostic> {
    let mut d = Vec::new();
    check_cross_reference(spec, expr, &mut d);
    check_instance_references(spec, expr, &mut d);
    check_active_coverage(spec, graph, &mut d);
    check_aliases(spec, graph, &mut d);
    check_enforcement_activation(spec, graph, &mut d);
    check_gate(spec, &mut d);
    check_laws(spec, binding, &mut d);
    check_ledger(spec, &mut d);
    check_delegates(spec, &mut d);
    check_pipelines(spec, &mut d);
    check_ports(spec, &mut d);
    check_hives(spec, &mut d);
    check_specialists(spec, &mut d);
    check_composition(spec, graph, binding, &mut d);
    d
}

fn check_cross_reference(spec: &SpecFile, expr: &Expr, d: &mut Vec<Diagnostic>) {
    let b = &spec.bindings;
    let present = expr.patterns();

    // Referenced in the composition but not bound. Playbook is always satisfied
    // (the compiled output *is* the Playbook), so it is not listed here.
    let unbound = [
        (PatternKind::Intake, b.intake.is_some()),
        (PatternKind::Verb, b.verb.is_some()),
        (PatternKind::Law, !b.laws.is_empty()),
        (PatternKind::Gate, b.gate.is_some()),
        (PatternKind::Ledger, b.ledger.is_some()),
        (PatternKind::Sandbox, b.sandbox.is_some()),
        (PatternKind::NightShift, b.night_shift.is_some()),
        (PatternKind::Specialist, !b.specialists.is_empty()),
        (PatternKind::Delegate, !b.delegates.is_empty()),
        (PatternKind::Critic, b.delegates.iter().any(|dg| dg.critic)),
        (PatternKind::Pipeline, !b.pipelines.is_empty()),
        (PatternKind::Port, !b.ports.is_empty()),
        (PatternKind::Hive, !b.hives.is_empty()),
        (PatternKind::Refinery, b.refinery.is_some()),
    ];
    for (kind, bound) in unbound {
        if present.contains(&kind) && !bound {
            d.push(Diagnostic::error(
                "composition.referenced_but_unbound",
                format!("composition references {kind} but no binding is supplied for it"),
            ));
        }
        if !present.contains(&kind) && bound {
            d.push(Diagnostic::warning(
                "composition.bound_but_unreferenced",
                format!("{kind} is bound but never appears in the composition expression"),
            ));
        }
    }
}

/// The binding ids addressable for `kind`, or `None` if the pattern has no
/// id-addressable binding (a singleton like Sandbox or NightShift, or the
/// always-satisfied Playbook). The **Critic** is the review-only Delegate, so it
/// addresses the delegate ids whose binding sets `critic: true`.
fn addressable_ids(b: &Bindings, kind: PatternKind) -> Option<Vec<&str>> {
    use PatternKind::*;
    let ids: Vec<&str> = match kind {
        Law => b.laws.iter().map(|l| l.id.as_str()).collect(),
        Gate => b.gate.iter().map(|g| g.id.as_str()).collect(),
        Specialist => b.specialists.iter().map(|s| s.id.as_str()).collect(),
        Delegate => b.delegates.iter().map(|dg| dg.id.as_str()).collect(),
        Critic => b
            .delegates
            .iter()
            .filter(|dg| dg.critic)
            .map(|dg| dg.id.as_str())
            .collect(),
        Pipeline => b.pipelines.iter().map(|p| p.id.as_str()).collect(),
        Port => b.ports.iter().map(|p| p.id.as_str()).collect(),
        Hive => b.hives.iter().map(|h| h.id.as_str()).collect(),
        // Singleton bindings (or the always-satisfied Playbook): no id to name.
        Intake | Verb | Ledger | Sandbox | NightShift | Refinery | Playbook => return None,
    };
    Some(ids)
}

/// The id namespaces that do not overlap, for reporting a kind mismatch. Critic
/// is omitted because its ids are a subset of `Delegate`'s.
const ADDRESSABLE_KINDS: &[PatternKind] = &[
    PatternKind::Law,
    PatternKind::Gate,
    PatternKind::Specialist,
    PatternKind::Delegate,
    PatternKind::Pipeline,
    PatternKind::Port,
    PatternKind::Hive,
];

/// If `id` names a binding of some kind *other* than `exclude`, which one. Used
/// to turn a bare "unknown instance" into the sharper "you named the wrong kind".
fn other_kind_with_id(b: &Bindings, exclude: PatternKind, id: &str) -> Option<PatternKind> {
    ADDRESSABLE_KINDS
        .iter()
        .copied()
        .filter(|k| *k != exclude)
        .find(|k| addressable_ids(b, *k).is_some_and(|ids| ids.contains(&id)))
}

/// Reference integrity for the composition graph.
///
/// Instance addressing is only sound if every named occurrence resolves to
/// exactly one real binding. Without this, `Port[ghost] within Sandbox`
/// compiles: the relation yields the occurrence "ghost", which matches no Port
/// binding, so the derived isolation obligation silently attaches to nothing —
/// a misspelled component name suppresses the very obligation instance
/// addressing exists to enforce. This runs before composition case law so that
/// hole is a hard error, not a silent no-op.
/// The lexical contract on addressable binding ids: exactly what the
/// composition tokenizer can read back as an instance id. A binding whose id
/// falls outside this alphabet (e.g. `github.production`) would exist but be
/// unaddressable — reference integrity must hold at the lexical boundary, not
/// only after parsing.
fn id_is_addressable(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        // Grammar keywords can never be read back as an id.
        && id != "as"
        && id != "within"
}

fn check_instance_references(spec: &SpecFile, expr: &Expr, d: &mut Vec<Diagnostic>) {
    let b = &spec.bindings;

    // Duplicate binding ids make *every* id reference ambiguous (a Port's
    // write_guard, a Hive's worker, a named occurrence), not just addressing.
    // Ids outside the composition grammar's alphabet are rejected for the
    // mirror-image reason: such a binding could never be named at all.
    for (kind, label) in [
        (PatternKind::Law, "law"),
        (PatternKind::Gate, "gate"),
        (PatternKind::Specialist, "specialist"),
        (PatternKind::Delegate, "delegate"),
        (PatternKind::Pipeline, "pipeline"),
        (PatternKind::Port, "port"),
        (PatternKind::Hive, "hive"),
    ] {
        let Some(ids) = addressable_ids(b, kind) else {
            continue;
        };
        let mut seen = BTreeSet::new();
        let mut reported = BTreeSet::new();
        for id in ids {
            if !id_is_addressable(id) {
                d.push(Diagnostic::error(
                    "binding.unaddressable_id",
                    format!(
                        "{label} id '{id}' cannot be addressed by the composition grammar; ids \
                         must be non-empty and match [A-Za-z0-9_-]+"
                    ),
                ));
            }
            if !seen.insert(id) && reported.insert(id) {
                d.push(Diagnostic::error(
                    "binding.duplicate_id",
                    format!(
                        "two {label} bindings share id '{id}'; binding ids must be unique so a \
                         named occurrence resolves to exactly one"
                    ),
                ));
            }
        }
    }

    // Every `Kind[id]` must resolve to exactly one binding of that kind.
    for inst in expr.named_instances() {
        let id = inst.id.as_deref().unwrap_or_default();
        let kind = inst.kind;
        match addressable_ids(b, kind) {
            None => d.push(Diagnostic::error(
                "composition.unaddressable_pattern",
                format!(
                    "{kind}[{id}] names an instance, but {kind} is a singleton binding with no id \
                     to address; drop the '[{id}]'"
                ),
            )),
            Some(ids) if !ids.contains(&id) => match other_kind_with_id(b, kind, id) {
                Some(other) => d.push(Diagnostic::error(
                    "composition.instance_kind_mismatch",
                    format!(
                        "{kind}[{id}] names a {kind} occurrence, but '{id}' is a {other} binding, \
                         not a {kind}"
                    ),
                )),
                None => d.push(Diagnostic::error(
                    "composition.unknown_instance",
                    format!(
                        "{kind}[{id}] resolves to no {kind} binding; a named occurrence must match \
                         a declared binding id"
                    ),
                )),
            },
            Some(_) => {}
        }
    }
}

/// Activation coverage: a binding the composition never activates is not part
/// of the compiled architecture. When a kind is addressed *only* by named
/// occurrences, its unnamed siblings are inactive — the backends exclude them
/// from generation, and this warning says so, per binding, so the exclusion is
/// visible rather than silent. (A kind that is absent from the expression
/// entirely already gets the kind-level `bound_but_unreferenced` warning.)
fn check_active_coverage(spec: &SpecFile, graph: &ResolvedGraph, d: &mut Vec<Diagnostic>) {
    let b = &spec.bindings;
    for (kind, label) in [
        (PatternKind::Specialist, "specialist"),
        (PatternKind::Delegate, "delegate"),
        (PatternKind::Pipeline, "pipeline"),
        (PatternKind::Port, "port"),
        (PatternKind::Hive, "hive"),
    ] {
        if !graph.has_kind(kind) {
            continue; // kind-level warning already covers this
        }
        let Some(ids) = addressable_ids(b, kind) else {
            continue;
        };
        for id in ids {
            if !graph.is_active(kind, id) {
                d.push(Diagnostic::warning(
                    "composition.binding_not_activated",
                    format!(
                        "{label} '{id}' is bound, but no occurrence in the composition (nor any \
                         active binding's reference) activates it; it is excluded from the \
                         generated Playbook"
                    ),
                ));
            }
        }
    }
}

/// Position aliases (`Port[github as staging_deployer]`) name architectural
/// positions apart from binding identity. For the name to *be* an identity it
/// must be unambiguous: unique across the whole composition, and not shadowing
/// any addressable binding id (a reader of `staging` must never wonder whether
/// a position or a binding is meant).
fn check_aliases(spec: &SpecFile, graph: &ResolvedGraph, d: &mut Vec<Diagnostic>) {
    let b = &spec.bindings;

    // A relation written between one position and itself is not a topology the
    // algebra can express; it is almost certainly a mistake, and dropping it
    // silently would drop any obligation derived from it.
    for sr in graph.self_relations() {
        let name = graph
            .nodes()
            .iter()
            .find(|n| n.id == sr.node)
            .and_then(|n| n.alias.clone())
            .unwrap_or_else(|| "a position".to_string());
        let how = match sr.origin {
            crate::graph::SelfRelationOrigin::Direct => "written directly",
            crate::graph::SelfRelationOrigin::GroupExpansion => {
                "declared by expanding a grouped operand"
            }
        };
        d.push(Diagnostic::error(
            "composition.self_relation",
            format!(
                "'{name}' stands in a '{}' relation to itself ({how}); a position cannot be its \
                 own container, upstream, or provisioner",
                sr.relation.as_str()
            ),
        ));
    }

    // One position cannot be both a singleton and a replicated fan-out.
    for alias in graph.replication_conflicts() {
        d.push(Diagnostic::error(
            "composition.alias_replication_conflict",
            format!(
                "position '{alias}' is used both inside and outside a '× N' replication; one \
                 position cannot be both a singleton and a replicated set — declare separate \
                 positions instead"
            ),
        ));
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for node in graph.nodes() {
        let Some(alias) = node.alias.as_deref() else {
            continue;
        };
        // A pattern-kind spelling can never be read back as a reference:
        // `parse_primary` resolves a bare identifier as a kind first, so
        // `Port[github as Gate]` would declare a position nothing can name.
        if alias.parse::<PatternKind>().is_ok() || alias == "as" || alias == "within" {
            d.push(Diagnostic::error(
                "composition.alias_reserved_name",
                format!(
                    "alias '{alias}' is a reserved name (a pattern kind or grammar keyword); a \
                     bare '{alias}' would parse as the language construct, so the position could \
                     never be referenced"
                ),
            ));
        }
        if !seen.insert(alias) {
            // Unreachable in practice: `parse` rejects a repeated declaration at
            // the symbol layer, and every reference interns to the declared
            // node. Kept as a defence-in-depth invariant on the IR itself.
            d.push(Diagnostic::error(
                "composition.duplicate_alias",
                format!("alias '{alias}' names more than one position in the resolved graph"),
            ));
        }
        if let Some(kind) = ADDRESSABLE_KINDS
            .iter()
            .copied()
            .find(|k| addressable_ids(b, *k).is_some_and(|ids| ids.contains(&alias)))
        {
            d.push(Diagnostic::error(
                "composition.alias_shadows_binding",
                format!(
                    "alias '{alias}' is also the id of a {kind} binding; a position name must not \
                     shadow a binding id"
                ),
            ));
        }
    }
}

/// Enforcement activation is explicit, never ambient.
///
/// Capability exclusion is fail-safe, but surplus enforcement is NOT: an
/// unactivated Guard can block actions the declared architecture permits, an
/// unactivated Obligation opens debt no active workflow discharges, an
/// unactivated Gate halts progress nothing expects, and an unactivated Ledger
/// records (discloses) beyond the declared system. So a bound enforcement
/// binding must be (1) activated by a composition occurrence, (2) activated
/// through a binding dependency (a `uses` edge), or (3) explicitly declared
/// `always_on: true` — anything else is a compile error, not an automatically
/// installed safety surplus.
fn check_enforcement_activation(spec: &SpecFile, graph: &ResolvedGraph, d: &mut Vec<Diagnostic>) {
    let b = &spec.bindings;
    for law in &b.laws {
        if !law.always_on && !graph.is_active(PatternKind::Law, &law.id) {
            d.push(Diagnostic::error(
                "composition.enforcement_not_activated",
                format!(
                    "law '{}' is bound but nothing activates it; enforcement is never installed \
                     implicitly — reference it in the composition, depend on it from an active \
                     binding, declare `always_on: true`, or remove it",
                    law.id
                ),
            ));
        }
    }
    if let Some(gate) = &b.gate {
        if !gate.always_on && !graph.is_active(PatternKind::Gate, &gate.id) {
            d.push(Diagnostic::error(
                "composition.enforcement_not_activated",
                format!(
                    "gate '{}' is bound but nothing activates it; an unactivated Gate would halt \
                     progress no active workflow expects — reference it in the composition, \
                     declare `always_on: true`, or remove it",
                    gate.id
                ),
            ));
        }
    }
    if let Some(ledger) = &b.ledger {
        if !ledger.always_on && !graph.is_singleton_active(PatternKind::Ledger) {
            d.push(Diagnostic::error(
                "composition.enforcement_not_activated",
                "a Ledger is bound but nothing references it; recording is disclosure — \
                 reference it in the composition, declare `always_on: true`, or remove it",
            ));
        }
    }
}

fn check_gate(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
    let Some(gate) = &spec.bindings.gate else {
        return;
    };

    if gate.boundary.trim().is_empty() {
        d.push(Diagnostic::error(
            "gate.empty_boundary",
            "gate boundary must be named",
        ));
    }
    if gate.checkpoint_schema.trim().is_empty() {
        d.push(Diagnostic::error(
            "gate.missing_checkpoint_schema",
            "a Gate without a checkpoint schema is a confirmation prompt",
        ));
    }
    if !gate.bind.iter().any(|b| b == "action_hash") {
        d.push(Diagnostic::error(
            "gate.missing_action_hash",
            "approval must bind to an action_hash, or an approved action can be substituted",
        ));
    }
    if !gate.bind.iter().any(|b| b == "approver") {
        d.push(Diagnostic::error(
            "gate.missing_approver",
            "approval must record an approver identity",
        ));
    }
    let has_precondition = gate
        .bind
        .iter()
        .any(|b| !NON_PRECONDITION_BINDINGS.contains(&b.as_str()));
    if !has_precondition {
        d.push(Diagnostic::error(
            "gate.no_precondition_binding",
            "approval must bind at least one material precondition (e.g. repository_revision); \
             binding the artifact alone leaves a time-of-check/time-of-use gap",
        ));
    }
}

fn check_laws(spec: &SpecFile, binding: &dyn Binding, d: &mut Vec<Diagnostic>) {
    for law in &spec.bindings.laws {
        let consistent = matches!(
            (law.kind, law.event),
            (LawKind::Guard, LawEvent::PreTool) | (LawKind::Obligation, LawEvent::PostTool)
        );
        if !consistent {
            d.push(Diagnostic::error(
                "law.event_mismatch",
                format!(
                    "law '{}' is a {:?} but binds at {:?}; a Guard binds pre_tool, an Obligation post_tool",
                    law.id, law.kind, law.event
                ),
            ));
        }
        if law.applies_to.is_empty() {
            d.push(Diagnostic::error(
                "law.no_targets",
                format!("law '{}' must list at least one tool it applies to", law.id),
            ));
        }
        // Scope is an Obligation concept: a Guard decides instantaneously and
        // owes nothing afterwards, so a declared scope on one is a category
        // error the author should hear about, not a silently ignored field.
        if matches!(law.kind, LawKind::Guard) && law.scope != crate::model::ObligationScope::Run {
            d.push(Diagnostic::error(
                "law.scope_on_guard",
                format!(
                    "law '{}' is a Guard but declares scope '{}'; scope governs when an \
                     Obligation's debt is discharged, and a Guard opens no debt",
                    law.id,
                    law.scope.as_str()
                ),
            ));
        }
        if !binding.supports_law(&law.id) {
            d.push(Diagnostic::error(
                "law.unsupported",
                format!(
                    "the {} binding cannot enforce law '{}'; generating a stub would \
                     lie about the guarantee. Implement it in the kernel or remove it.",
                    binding.platform(),
                    law.id
                ),
            ));
        }
    }
}

fn check_ledger(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
    let Some(ledger) = &spec.bindings.ledger else {
        return;
    };

    if ledger.destination.trim().is_empty() {
        d.push(Diagnostic::error(
            "ledger.missing_destination",
            "ledger needs a destination",
        ));
    }
    for required in ["secrets", "credentials"] {
        if !ledger.redact.iter().any(|r| r == required) {
            d.push(Diagnostic::error(
                "ledger.redact_incomplete",
                format!(
                    "ledger.redact must include '{required}'; an append-only log of raw inputs is \
                     otherwise a durable credential leak"
                ),
            ));
        }
    }
    if !ledger.redact.iter().any(|r| r == "raw_model_context") {
        d.push(Diagnostic::warning(
            "ledger.redact_model_context",
            "consider redacting 'raw_model_context' to keep the ledger to decision products",
        ));
    }
}

fn check_specialists(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
    for s in &spec.bindings.specialists {
        if s.skill.trim().is_empty() {
            d.push(Diagnostic::error(
                "specialist.missing_skill",
                format!("specialist '{}' must point at a SKILL.md", s.id),
            ));
        }
        if s.description.trim().is_empty() {
            d.push(Diagnostic::error(
                "specialist.missing_description",
                format!(
                    "specialist '{}' needs a description so it is demand-loaded at the right time",
                    s.id
                ),
            ));
        }
    }
}

fn check_delegates(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
    for dg in &spec.bindings.delegates {
        if dg.contract_schema.trim().is_empty() {
            d.push(Diagnostic::error(
                "delegate.unstructured_return",
                format!(
                    "delegate '{}' must return through a schema, never unconstrained prose",
                    dg.id
                ),
            ));
        }
        if dg.tools.is_empty() {
            d.push(Diagnostic::error(
                "delegate.no_authority",
                format!(
                    "delegate '{}' must declare its delegated tools (authority); empty is ambiguous",
                    dg.id
                ),
            ));
        }
        // Delegated Port authority must be explicit and reference real ports.
        for port in &dg.ports {
            if !spec.bindings.ports.iter().any(|p| &p.id == port) {
                d.push(Diagnostic::error(
                    "delegate.unknown_port",
                    format!(
                        "delegate '{}' is granted port '{port}' which is not declared",
                        dg.id
                    ),
                ));
            }
        }
    }
}

fn check_pipelines(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
    for p in &spec.bindings.pipelines {
        if p.stages.len() < 2 {
            d.push(Diagnostic::error(
                "pipeline.too_few_stages",
                format!("pipeline '{}' needs at least two typed stages", p.id),
            ));
            continue;
        }
        // Typed stage interfaces must chain: each stage's output is the next
        // stage's input. This — not merely a fixed order — is what makes it a
        // Pipeline rather than a long prompt.
        for w in p.stages.windows(2) {
            let (a, b) = (&w[0], &w[1]);
            let chained = matches!((&a.produces, &b.consumes), (Some(p), Some(c)) if p == c);
            if !chained {
                d.push(Diagnostic::error(
                    "pipeline.stage_type_mismatch",
                    format!(
                        "pipeline '{}': stage '{}' produces {:?} but stage '{}' consumes {:?}; \
                         typed stage interfaces must chain",
                        p.id, a.name, a.produces, b.name, b.consumes
                    ),
                ));
            }
        }
    }
}

fn check_ports(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
    for p in &spec.bindings.ports {
        if p.observe.is_empty() && p.write.is_empty() {
            d.push(Diagnostic::error(
                "port.no_capability",
                format!(
                    "port '{}' must expose at least one observe or write capability",
                    p.id
                ),
            ));
        }
        // A Port with write authority is a capability boundary, not an
        // integration: writes must be governed by a Guard Law.
        if !p.write.is_empty() {
            match &p.write_guard {
                None => d.push(Diagnostic::error(
                    "port.unguarded_write",
                    format!(
                        "port '{}' has write authority but no write_guard; connectivity without a \
                         capability boundary is ambient privilege",
                        p.id
                    ),
                )),
                Some(g) if !spec.bindings.laws.iter().any(|l| &l.id == g) => {
                    d.push(Diagnostic::error(
                        "port.unknown_write_guard",
                        format!(
                            "port '{}' names write_guard '{g}' which is not a declared law",
                            p.id
                        ),
                    ));
                }
                _ => {}
            }
        }
    }
}

fn check_hives(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
    for h in &spec.bindings.hives {
        // The Law of the Hive: every spawned task has a budget, a depth, a
        // termination condition, and a merge destination (worker_isolation and
        // the worker contract are enforced by the struct's required fields).
        if h.budget == 0 {
            d.push(Diagnostic::error(
                "hive.no_budget",
                format!(
                    "hive '{}' must declare a non-zero budget (Law of the Hive)",
                    h.id
                ),
            ));
        }
        if h.max_depth == 0 {
            d.push(Diagnostic::error(
                "hive.no_depth",
                format!(
                    "hive '{}' must declare a non-zero max_depth (Law of the Hive)",
                    h.id
                ),
            ));
        }
        if h.termination.trim().is_empty() {
            d.push(Diagnostic::error(
                "hive.no_termination",
                format!(
                    "hive '{}' must declare a termination condition (Law of the Hive)",
                    h.id
                ),
            ));
        }
        if h.merge.trim().is_empty() {
            d.push(Diagnostic::error(
                "hive.no_merge",
                format!(
                    "hive '{}' must declare a merge destination (Law of the Hive)",
                    h.id
                ),
            ));
        }
        if !spec.bindings.delegates.iter().any(|dg| dg.id == h.worker) {
            d.push(Diagnostic::error(
                "hive.unknown_worker",
                format!(
                    "hive '{}' names worker delegate '{}' which is not declared",
                    h.id, h.worker
                ),
            ));
        }
    }
}

fn check_composition(
    spec: &SpecFile,
    graph: &ResolvedGraph,
    binding: &dyn Binding,
    d: &mut Vec<Diagnostic>,
) {
    let b = &spec.bindings;

    // Obligation Law + Gate ⇒ the obligation must be discharged *through* the
    // Gate, not merely recorded. If the binding's kernel can discharge an
    // obligation, the Gate must list it in requires_obligations; otherwise the
    // "every edit is followed by the test suite" promise is never enforced.
    // Scoped to *active* components: an obligation Law the composition never
    // activates is not part of this architecture, so it must not become a Gate
    // requirement by mere co-presence in the bindings block.
    if let Some(gate) = &b.gate {
        if graph.is_active(PatternKind::Gate, &gate.id) {
            for law in &b.laws {
                let active = graph.is_active(PatternKind::Law, &law.id);
                let is_obligation = matches!(law.kind, LawKind::Obligation);
                let dischargeable = binding
                    .dischargeable_obligations()
                    .contains(&law.id.as_str());
                if active
                    && is_obligation
                    && dischargeable
                    && !gate.requires_obligations.iter().any(|o| o == &law.id)
                {
                    d.push(Diagnostic::error(
                        "composition.obligation_not_discharged",
                        format!(
                            "obligation law '{}' is recorded but never discharged; gate '{}' must list \
                             it in requires_obligations so progress halts until it is satisfied",
                            law.id, gate.id
                        ),
                    ));
                }
            }
        }
    }

    // A Gate that runs within, or downstream of, a Night Shift ⇒ durable
    // suspension and precondition revalidation. A Gate in an independent branch
    // is used attended and needs neither.
    if graph.runs_under(PatternKind::NightShift, PatternKind::Gate) {
        if let Some(gate) = &b.gate {
            let durable = gate.durable == Some(true);
            let resume_ok = gate
                .resume
                .as_ref()
                .map(|r| r.process_independent && r.revalidate_preconditions)
                .unwrap_or(false);
            if !(durable && resume_ok) {
                d.push(Diagnostic::error(
                    "composition.gate_nightshift_durable",
                    "Gate + Night Shift requires durable suspension and a resume strategy that is \
                     process_independent and revalidate_preconditions; the world moves overnight",
                ));
            }
        }
    }

    // Sandbox + Ledger ⇒ recorded lineage between source and sandbox.
    if graph.has_kind(PatternKind::Sandbox) && graph.has_kind(PatternKind::Ledger) {
        if let Some(sandbox) = &b.sandbox {
            for field in ["source_revision", "sandbox_id", "merge_revision"] {
                if !sandbox.lineage.iter().any(|l| l == field) {
                    d.push(Diagnostic::error(
                        "composition.sandbox_ledger_lineage",
                        format!(
                            "Sandbox + Ledger requires lineage field '{field}' so every merged \
                             result traces to the state it derived from"
                        ),
                    ));
                }
            }
        }
    }

    // A Verb placed `within` a control context must have a real interceptor:
    // among the Law positions that enclose the Verb, at least one must resolve
    // to a **Guard** (a pre-execution control point). An Obligation Law records
    // debt after the fact — `Verb within Law[validate-after-edit]` where that
    // law is an obligation contains no interceptor at all, and the old "some
    // Law binding exists" test could not see the difference.
    if graph.kind_within(PatternKind::Verb, PatternKind::Law) {
        let enclosing = graph.bindings_enclosing(PatternKind::Verb, PatternKind::Law);
        let has_guard = b
            .laws
            .iter()
            .any(|l| enclosing.contains(&l.id) && matches!(l.kind, LawKind::Guard));
        if !has_guard {
            d.push(Diagnostic::error(
                "composition.control_without_interceptor",
                "a Verb is composed 'within' a Law, but no enclosing Law resolves to a Guard; \
                 an Obligation records debt after the fact — it does not intercept the Verb",
            ));
        }
    }

    // A Port that participates in an unattended pipeline ⇒ replay safety. The
    // Port may be upstream OR downstream of the Night Shift — the canonical
    // `Port -> Night Shift -> Gate` recipe has the Port feeding the unattended
    // run — so this reads data-path edges (either direction), nesting, and
    // provisioning off the graph. Only the bindings whose positions actually
    // stand in those relations carry the obligation, so an attended
    // `Port[metrics]` beside a `Port[deploy] -> NightShift` is left alone.
    let mut unattended = graph.bindings_within(PatternKind::Port, PatternKind::NightShift);
    unattended.extend(graph.bindings_flow_connected(PatternKind::Port, PatternKind::NightShift));
    unattended.extend(graph.bindings_provisioned(PatternKind::NightShift, PatternKind::Port));
    for p in b
        .ports
        .iter()
        .filter(|p| unattended.contains(&p.id) && !p.write.is_empty() && !p.idempotent)
    {
        d.push(Diagnostic::error(
            "composition.port_replay_safety",
            format!(
                "port '{}' has write authority and runs unattended (Night Shift) but is not \
                 idempotent; absence of a local success record is not evidence the external \
                 action did not occur",
                p.id
            ),
        ));
    }

    // A Port running *within* a Sandbox ⇒ external isolation. Copy-on-write
    // isolates the filesystem, not the world; a sandboxed Port write must be
    // isolated, disabled, or a proposal. Decided per position on the graph's
    // Within edges, so `Port[b]` beside `Port[a] within Sandbox` does not
    // inherit the obligation.
    let sandboxed = graph.bindings_within(PatternKind::Port, PatternKind::Sandbox);
    for p in b
        .ports
        .iter()
        .filter(|p| sandboxed.contains(&p.id) && !p.write.is_empty() && p.sandboxed.is_none())
    {
        d.push(Diagnostic::error(
            "composition.sandbox_port_isolation",
            format!(
                "port '{}' can write externally but does not declare `sandboxed` behavior; a \
                 filesystem Sandbox does not contain external effects",
                p.id
            ),
        ));
    }

    // A Gate *within* a Hive ⇒ approval scope must be declared: global vs.
    // per-worker are different systems. Only the Hive occurrence that actually
    // encloses the Gate needs the declaration; a sibling Hive is unaffected.
    let gated_hives = graph.bindings_enclosing(PatternKind::Gate, PatternKind::Hive);
    for h in b
        .hives
        .iter()
        .filter(|h| gated_hives.contains(&h.id) && h.approval_scope.is_none())
    {
        d.push(Diagnostic::error(
            "composition.hive_gate_approval_scope",
            format!(
                "hive '{}' contains a Gate but does not declare approval_scope (global vs. \
                 per-worker)",
                h.id
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compile, CompileError};

    const SPECIMEN: &str = r#"
harness:
  name: enablement-workbench
  version: 0.1.0
composition:
  expression: "Intake -> Verb within (Law + Gate) + Ledger"
bindings:
  intake:
    task_schema: schemas/task-packet.schema.json
    storage: tasks/
  verb:
    name: pick-task
    command: .claude/commands/pick-task.md
    accepts: TaskPacket
    produces: TaskResult
  laws:
    - id: enforce-file-scope
      kind: guard
      event: pre_tool
      applies_to: [edit, write]
    - id: require-validation
      kind: obligation
      event: post_tool
      applies_to: [edit, write]
  gate:
    id: approve-commit
    boundary: before_commit
    checkpoint_schema: schemas/checkpoint.schema.json
    bind: [action_hash, repository_revision, working_tree_hash, approver, expiry]
    requires_obligations: [require-validation]
  ledger:
    event_schema: schemas/event.schema.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials, raw_model_context]
platform:
  type: claude-code
  role_bindings:
    boot_context: CLAUDE.md
"#;

    /// A stand-in for the claude-code binding's capabilities.
    struct MockBinding;

    impl Binding for MockBinding {
        fn platform(&self) -> &str {
            "claude-code"
        }
        fn supports_law(&self, law_id: &str) -> bool {
            matches!(law_id, "enforce-file-scope" | "require-validation")
        }
        fn dischargeable_obligations(&self) -> &[&str] {
            &["require-validation"]
        }
    }

    fn check_yaml(yaml: &str) -> Vec<Diagnostic> {
        let spec: SpecFile = serde_yaml::from_str(yaml).expect("parses");
        let expr = crate::compose::parse(&spec.composition.expression).expect("composition parses");
        let graph = ResolvedGraph::resolve(&expr, &spec.bindings);
        check(&spec, &expr, &graph, &MockBinding)
    }

    fn codes(diags: &[Diagnostic]) -> Vec<&'static str> {
        diags.iter().map(|d| d.code).collect()
    }

    #[test]
    fn specimen_compiles_cleanly() {
        assert!(compile(SPECIMEN, &MockBinding).is_ok());
    }

    #[test]
    fn obligation_not_discharged_by_gate_is_rejected() {
        // Drop the requires_obligations line: the obligation is now recorded
        // but never discharged.
        let yaml = SPECIMEN.replace("    requires_obligations: [require-validation]\n", "");
        assert!(codes(&check_yaml(&yaml)).contains(&"composition.obligation_not_discharged"));
    }

    #[test]
    fn a_guard_declaring_a_scope_is_rejected() {
        // Scope governs when an Obligation's debt is discharged; a Guard
        // decides instantaneously and owes nothing — declaring a scope on one
        // is a category error, not a silently ignored field.
        let yaml = SPECIMEN.replace(
            "    - id: enforce-file-scope\n      kind: guard\n",
            "    - id: enforce-file-scope\n      kind: guard\n      scope: workspace\n",
        );
        assert!(codes(&check_yaml(&yaml)).contains(&"law.scope_on_guard"));
    }

    #[test]
    fn an_obligation_may_declare_any_scope() {
        for scope in ["run", "task", "branch", "workspace", "action"] {
            let yaml = SPECIMEN.replace(
                "    - id: require-validation\n      kind: obligation\n",
                &format!(
                    "    - id: require-validation\n      kind: obligation\n      scope: {scope}\n"
                ),
            );
            let diags = check_yaml(&yaml);
            assert!(
                !codes(&diags).contains(&"law.scope_on_guard"),
                "scope '{scope}' is legal on an obligation: {diags:?}"
            );
        }
    }

    #[test]
    fn gate_without_action_hash_is_rejected() {
        let yaml = SPECIMEN.replace(
            "bind: [action_hash, repository_revision, working_tree_hash, approver, expiry]",
            "bind: [repository_revision, approver, expiry]",
        );
        assert!(codes(&check_yaml(&yaml)).contains(&"gate.missing_action_hash"));
    }

    #[test]
    fn gate_without_precondition_is_rejected() {
        let yaml = SPECIMEN.replace(
            "bind: [action_hash, repository_revision, working_tree_hash, approver, expiry]",
            "bind: [action_hash, approver, expiry]",
        );
        assert!(codes(&check_yaml(&yaml)).contains(&"gate.no_precondition_binding"));
    }

    #[test]
    fn ledger_that_leaks_credentials_is_rejected() {
        let yaml = SPECIMEN.replace(
            "redact: [secrets, credentials, raw_model_context]",
            "redact: [secrets]",
        );
        assert!(codes(&check_yaml(&yaml)).contains(&"ledger.redact_incomplete"));
    }

    #[test]
    fn unknown_law_is_rejected_not_stubbed() {
        let yaml = SPECIMEN.replace("id: require-validation", "id: enforce-world-peace");
        assert!(codes(&check_yaml(&yaml)).contains(&"law.unsupported"));
    }

    #[test]
    fn guard_law_at_post_tool_is_rejected() {
        let yaml = SPECIMEN.replace(
            "    - id: enforce-file-scope\n      kind: guard\n      event: pre_tool",
            "    - id: enforce-file-scope\n      kind: guard\n      event: post_tool",
        );
        assert!(codes(&check_yaml(&yaml)).contains(&"law.event_mismatch"));
    }

    #[test]
    fn referencing_an_unbound_pattern_is_rejected() {
        let yaml = SPECIMEN.replace(
            r#"expression: "Intake -> Verb within (Law + Gate) + Ledger""#,
            r#"expression: "Intake -> Verb within (Law + Gate) + Ledger + Sandbox""#,
        );
        let err = compile(&yaml, &MockBinding).unwrap_err();
        assert!(matches!(err, CompileError::Rejected(_)));
    }

    #[test]
    fn gate_plus_nightshift_without_durable_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "NightShift => Gate + Ledger"
bindings:
  night_shift: { schedule: "0 3 * * *", entrypoint: claude-p }
  gate:
    id: g
    boundary: before_deploy
    checkpoint_schema: s.json
    bind: [action_hash, repository_revision, approver]
  ledger:
    event_schema: e.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.gate_nightshift_durable"));
    }

    #[test]
    fn a_gate_independent_of_the_night_shift_need_not_be_durable() {
        // The reviewer's case: a Gate in one branch, a Night Shift in another.
        // The old presence-based rule wrongly fired; the relational rule does not.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "NightShift + Gate"
bindings:
  night_shift: { schedule: "0 3 * * *", entrypoint: claude-p }
  gate:
    id: g
    boundary: before_deploy
    checkpoint_schema: s.json
    bind: [action_hash, repository_revision, approver]
platform: { type: claude-code }
"#;
        assert!(!codes(&check_yaml(yaml)).contains(&"composition.gate_nightshift_durable"));
    }

    #[test]
    fn sandbox_plus_ledger_without_lineage_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Sandbox + Ledger"
bindings:
  sandbox: { workspace: branch, lineage: [source_revision] }
  ledger:
    event_schema: e.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;
        let c = codes(&check_yaml(yaml));
        assert!(c.contains(&"composition.sandbox_ledger_lineage"));
    }

    // ---- v1.2 scale patterns ----

    #[test]
    fn pipeline_with_broken_stage_chain_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "Pipeline" }
bindings:
  pipelines:
    - id: p
      command: c.md
      stages:
        - { name: build, produces: Artifact }
        - { name: test, consumes: WrongType }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"pipeline.stage_type_mismatch"));
    }

    #[test]
    fn port_with_unguarded_write_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "Port" }
bindings:
  ports:
    - id: gh
      server: github
      write: [comments]
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"port.unguarded_write"));
    }

    #[test]
    fn hive_missing_budget_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "Hive + Delegate" }
bindings:
  delegates:
    - { id: w, agent: a.md, contract_schema: s.json, tools: [Read] }
  hives:
    - id: h
      orchestrator: o.md
      worker: w
      fan_out: dynamic
      budget: 0
      max_depth: 3
      termination: done
      merge: root
      worker_isolation: disjoint
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"hive.no_budget"));
    }

    #[test]
    fn hive_with_unknown_worker_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "Hive" }
bindings:
  hives:
    - id: h
      orchestrator: o.md
      worker: ghost
      fan_out: static
      budget: 100
      max_depth: 2
      termination: done
      merge: root
      worker_isolation: serialized
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"hive.unknown_worker"));
    }

    #[test]
    fn delegate_granted_unknown_port_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "Delegate" }
bindings:
  delegates:
    - { id: w, agent: a.md, contract_schema: s.json, tools: [Read], ports: [ghost] }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"delegate.unknown_port"));
    }

    #[test]
    fn sandbox_plus_port_without_isolation_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "Port within Sandbox" }
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: gh, server: github, write: [comments], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.sandbox_port_isolation"));
    }

    #[test]
    fn inactive_obligation_law_is_not_forced_into_the_gate() {
        // The reviewer's case: an obligation law that is bound but never
        // activated by the composition must not become a Gate requirement by
        // mere co-presence in the bindings block. `Law[enforce-file-scope]`
        // names only the guard, so `require-validation` stays inactive.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Intake -> Verb within (Law[enforce-file-scope] + Gate) + Ledger"
bindings:
  intake: { task_schema: s.json, storage: tasks/ }
  verb: { name: v, command: c.md, accepts: A, produces: B }
  laws:
    - { id: enforce-file-scope, kind: guard, event: pre_tool, applies_to: [edit] }
    - { id: require-validation, kind: obligation, event: post_tool, applies_to: [edit] }
  gate:
    id: g
    boundary: before_commit
    checkpoint_schema: s.json
    bind: [action_hash, repository_revision, approver]
  ledger:
    event_schema: e.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;
        let diags = check_yaml(yaml);
        let c = codes(&diags);
        assert!(
            !c.contains(&"composition.obligation_not_discharged"),
            "an inactive obligation law must not become a gate requirement: {diags:?}"
        );
        // And enforcement activation is explicit: the bound-but-unactivated law
        // is a compile ERROR demanding a decision (activate, always_on, or
        // remove) — never a silently installed or silently dropped mechanism.
        assert!(c.contains(&"composition.enforcement_not_activated"));
    }

    #[test]
    fn always_on_declares_unreferenced_enforcement_explicitly() {
        // Same spec, but the obligation law carries `always_on: true`: the
        // author has explicitly declared the surplus enforcement, so it
        // compiles — and being active by declaration, the Gate must discharge
        // it like any other active obligation.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Intake -> Verb within (Law[enforce-file-scope] + Gate) + Ledger"
bindings:
  intake: { task_schema: s.json, storage: tasks/ }
  verb: { name: v, command: c.md, accepts: A, produces: B }
  laws:
    - { id: enforce-file-scope, kind: guard, event: pre_tool, applies_to: [edit] }
    - { id: require-validation, kind: obligation, event: post_tool, applies_to: [edit], always_on: true }
  gate:
    id: g
    boundary: before_commit
    checkpoint_schema: s.json
    bind: [action_hash, repository_revision, approver]
    requires_obligations: [require-validation]
  ledger:
    event_schema: e.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;
        let c = codes(&check_yaml(yaml));
        assert!(!c.contains(&"composition.enforcement_not_activated"));
        assert!(!c.contains(&"composition.obligation_not_discharged"));
    }

    #[test]
    fn unactivated_gate_is_rejected_not_installed() {
        // A Gate bound but absent from the composition would halt progress no
        // active workflow expects — reject, do not install.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Intake -> Verb within Law"
bindings:
  intake: { task_schema: s.json, storage: tasks/ }
  verb: { name: v, command: c.md, accepts: A, produces: B }
  laws:
    - { id: enforce-file-scope, kind: guard, event: pre_tool, applies_to: [edit] }
  gate:
    id: g
    boundary: before_commit
    checkpoint_schema: s.json
    bind: [action_hash, repository_revision, approver]
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.enforcement_not_activated"));
    }

    #[test]
    fn active_obligation_law_still_requires_gate_discharge() {
        // Anonymous `Law` activates every law binding — the original rule holds.
        let yaml = SPECIMEN.replace("    requires_obligations: [require-validation]\n", "");
        assert!(codes(&check_yaml(&yaml)).contains(&"composition.obligation_not_discharged"));
    }

    #[test]
    fn verb_within_an_obligation_only_law_has_no_interceptor() {
        // The reviewer's case: the enclosing Law is an Obligation — it records
        // debt after the fact, it does not intercept the Verb.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Verb within Law[validate-after-edit]"
bindings:
  verb: { name: v, command: c.md, accepts: A, produces: B }
  laws:
    - { id: validate-after-edit, kind: obligation, event: post_tool, applies_to: [edit] }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.control_without_interceptor"));
    }

    #[test]
    fn verb_within_a_guard_law_has_its_interceptor() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Verb within Law[enforce-file-scope]"
bindings:
  verb: { name: v, command: c.md, accepts: A, produces: B }
  laws:
    - { id: enforce-file-scope, kind: guard, event: pre_tool, applies_to: [edit] }
platform: { type: claude-code }
"#;
        assert!(!codes(&check_yaml(yaml)).contains(&"composition.control_without_interceptor"));
    }

    #[test]
    fn binding_id_outside_the_grammar_is_rejected() {
        // `github.production` exists but could never be written as
        // `Port[github.production]` — reference integrity at the lexical boundary.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port"
bindings:
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: github.production, server: gh, write: [x], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"binding.unaddressable_id"));
    }

    #[test]
    fn case_law_fires_through_an_alias_mediated_relation() {
        // The unattended-flow relation is declared via a reference: the port
        // position `gh` feeds the Night Shift only through `gh -> NightShift`.
        // The replay-safety obligation must still attach to the binding.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[github as gh] within Sandbox + gh -> NightShift"
bindings:
  night_shift: { schedule: "0 3 * * *", entrypoint: claude-p }
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: github, server: gh, write: [comments], write_guard: guard-writes, sandboxed: propose }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.port_replay_safety"));
    }

    #[test]
    fn a_repeated_declaration_is_rejected_at_the_symbol_layer() {
        // Declaration vs. reference must stay distinguishable: `X[b as a] +
        // X[b as a]` is TWO declarations of a unique name, not a declaration
        // plus a reference, even though both name the same binding. Rejected
        // during parse, where declarations are still distinguishable.
        let err = crate::compose::parse(
            "Port[staging as edge] within Sandbox + Port[staging as edge] -> Gate",
        )
        .unwrap_err();
        assert!(err.contains("declared more than once"), "{err}");

        // A conflicting re-declaration is the same error at the same layer.
        let err =
            crate::compose::parse("Port[staging as edge] within Sandbox + Port[metrics as edge]")
                .unwrap_err();
        assert!(err.contains("declared more than once"), "{err}");

        // The legitimate way to relate one position twice is a REFERENCE.
        assert!(
            crate::compose::parse("Port[staging as edge] within Sandbox + edge -> Gate").is_ok()
        );
    }

    #[test]
    fn a_reserved_name_cannot_be_an_alias() {
        // `Gate` as an alias would declare a position nothing can reference:
        // a bare `Gate` always parses as the pattern kind.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[staging as Gate] within Sandbox"
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: a, write: [x], write_guard: guard-writes, sandboxed: propose }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.alias_reserved_name"));
    }

    #[test]
    fn an_explicit_self_relation_is_reported_not_erased() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[staging as p] -> p"
bindings:
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: a, write: [x], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.self_relation"));
    }

    #[test]
    fn an_alias_used_across_replication_contexts_is_rejected() {
        // One position cannot be both a singleton and a replicated set.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Delegate[worker as w] + (w × 3)"
bindings:
  delegates:
    - { id: worker, agent: a.md, contract_schema: s.json, tools: [Read] }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.alias_replication_conflict"));
    }

    #[test]
    fn alias_shadowing_a_binding_id_is_rejected() {
        // Naming a position `metrics` while a Port binding `metrics` exists
        // would make every later mention of `metrics` ambiguous.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[staging as metrics] within Sandbox"
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: a, write: [x], write_guard: guard-writes, sandboxed: propose }
    - { id: metrics, server: b, write: [y], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        let c = codes(&check_yaml(yaml));
        assert!(c.contains(&"composition.alias_shadows_binding"));
    }

    #[test]
    fn singleton_position_alias_is_allowed_where_binding_id_is_not() {
        // `Sandbox[worker]` is unaddressable (no binding id namespace), but
        // `Sandbox[as worker]` names the POSITION, which is exactly what a
        // singleton kind needs.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[staging] within Sandbox[as worker] + Law + Ledger"
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: a, write: [x], write_guard: guard-writes, sandboxed: propose }
  ledger:
    event_schema: e.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;
        let c = codes(&check_yaml(yaml));
        assert!(!c.contains(&"composition.unaddressable_pattern"));
        assert!(!c.contains(&"composition.duplicate_alias"));
    }

    #[test]
    fn unknown_named_instance_is_rejected_not_silently_dropped() {
        // The reviewer's fail-open case: `Port[ghost]` matches no Port binding,
        // so without reference resolution the isolation obligation would vanish.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[ghost] within Sandbox"
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: production, server: deploy, write: [release], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.unknown_instance"));
    }

    #[test]
    fn naming_an_instance_of_a_wrong_kind_is_a_kind_mismatch() {
        // `Port[guard-writes]` names a real id — but of a Law, not a Port.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[guard-writes] within Sandbox"
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: production, server: deploy, write: [release], write_guard: guard-writes, sandboxed: propose }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.instance_kind_mismatch"));
    }

    #[test]
    fn addressing_a_singleton_pattern_is_rejected() {
        // Sandbox has no id field, so `Sandbox[worker]` cannot resolve.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[p] within Sandbox[worker]"
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: p, server: deploy, write: [release], write_guard: guard-writes, sandboxed: propose }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.unaddressable_pattern"));
    }

    #[test]
    fn duplicate_binding_ids_are_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[dup]"
bindings:
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: dup, server: a, write: [x], write_guard: guard-writes }
    - { id: dup, server: b, write: [y], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"binding.duplicate_id"));
    }

    #[test]
    fn well_formed_named_instances_resolve_cleanly() {
        // Both Ports name real bindings; nothing about references is flagged.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "(Port[staging] within Sandbox) -> Gate + Port[metrics] + Law + Ledger"
bindings:
  sandbox: { workspace: branch, lineage: [source_revision, sandbox_id, merge_revision] }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: deploy, write: [release], write_guard: guard-writes, sandboxed: propose }
    - { id: metrics, server: obs, write: [annotate], write_guard: guard-writes }
  gate:
    id: g
    boundary: before_deploy
    checkpoint_schema: s.json
    bind: [action_hash, repository_revision, approver]
  ledger:
    event_schema: e.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;
        let c = codes(&check_yaml(yaml));
        for bad in [
            "composition.unknown_instance",
            "composition.instance_kind_mismatch",
            "composition.unaddressable_pattern",
            "binding.duplicate_id",
        ] {
            assert!(!c.contains(&bad), "unexpected {bad}");
        }
    }

    #[test]
    fn only_the_sandboxed_port_instance_needs_isolation() {
        // The reviewer's example: two Port bindings, one named inside the
        // Sandbox and one outside. Neither declares `sandboxed`, but only the
        // enclosed occurrence should trip the isolation rule — the obligation
        // attaches to the component, not the pattern category.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port[staging] within Sandbox + Port[metrics]"
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: deploy, write: [release], write_guard: guard-writes }
    - { id: metrics, server: obs, write: [annotate], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        let diags = check_yaml(yaml);
        let offenders: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "composition.sandbox_port_isolation")
            .collect();
        assert_eq!(offenders.len(), 1, "only the enclosed port should fire");
        assert!(
            offenders[0].message.contains("staging"),
            "the staging port is the one inside the sandbox: {}",
            offenders[0].message
        );
    }

    #[test]
    fn an_anonymous_port_still_covers_every_binding() {
        // A bare `Port within Sandbox` names no instance, so the obligation
        // conservatively applies to every Port binding, as before.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "Port within Sandbox"
bindings:
  sandbox: { workspace: branch }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: a, server: s1, write: [x], write_guard: guard-writes }
    - { id: b, server: s2, write: [y], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        let offenders = codes(&check_yaml(yaml))
            .into_iter()
            .filter(|c| *c == "composition.sandbox_port_isolation")
            .count();
        assert_eq!(offenders, 2, "anonymous Port covers both bindings");
    }

    #[test]
    fn port_writes_unattended_without_idempotency_is_rejected() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "NightShift -> Port" }
bindings:
  night_shift: { schedule: "0 3 * * *", entrypoint: claude-p }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: gh, server: github, write: [comments], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.port_replay_safety"));
    }

    #[test]
    fn a_port_independent_of_the_night_shift_needs_no_replay_safety() {
        // Topology matters: an attended Port coexisting with an unattended run
        // is a different system and must NOT trip the replay-safety rule.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "NightShift + Port" }
bindings:
  night_shift: { schedule: "0 3 * * *", entrypoint: claude-p }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: gh, server: github, write: [comments], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        assert!(!codes(&check_yaml(yaml)).contains(&"composition.port_replay_safety"));
    }

    #[test]
    fn canonical_port_feeding_a_night_shift_needs_replay_safety() {
        // The constitution's Inbox Triage recipe: `Port -> Night Shift -> Gate`.
        // The Port is UPSTREAM of the unattended run and must still be
        // replay-safe — the previous directional rule missed this.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "Port -> NightShift" }
bindings:
  night_shift: { schedule: "0 3 * * *", entrypoint: claude-p }
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: gh, server: github, write: [deploy], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.port_replay_safety"));
    }

    #[test]
    fn hive_with_gate_needs_approval_scope() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "(Gate within Hive) + Delegate" }
bindings:
  delegates:
    - { id: w, agent: a.md, contract_schema: s.json, tools: [Read] }
  gate:
    id: g
    boundary: before_merge
    checkpoint_schema: s.json
    bind: [action_hash, repository_revision, approver]
  hives:
    - id: h
      orchestrator: o.md
      worker: w
      fan_out: dynamic
      budget: 100
      max_depth: 2
      termination: done
      merge: root
      worker_isolation: disjoint
platform: { type: claude-code }
"#;
        assert!(codes(&check_yaml(yaml)).contains(&"composition.hive_gate_approval_scope"));
    }

    #[test]
    fn a_gate_independent_of_the_hive_needs_no_approval_scope() {
        // A Gate coexisting with (but not inside) a Hive is a separate system.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "Hive + Gate + Delegate" }
bindings:
  delegates:
    - { id: w, agent: a.md, contract_schema: s.json, tools: [Read] }
  gate:
    id: g
    boundary: before_merge
    checkpoint_schema: s.json
    bind: [action_hash, repository_revision, approver]
  hives:
    - id: h
      orchestrator: o.md
      worker: w
      fan_out: dynamic
      budget: 100
      max_depth: 2
      termination: done
      merge: root
      worker_isolation: disjoint
platform: { type: claude-code }
"#;
        assert!(!codes(&check_yaml(yaml)).contains(&"composition.hive_gate_approval_scope"));
    }
}
