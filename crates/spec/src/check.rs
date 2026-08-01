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

use crate::binding::Binding;
use crate::compose::Expr;
use crate::model::{LawEvent, LawKind, PatternKind, SpecFile};

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

/// Run every check against a parsed spec, its composition tree, and the target
/// binding's capabilities. Returns all diagnostics; the caller treats any
/// `Error` as blocking.
pub fn check(spec: &SpecFile, expr: &Expr, binding: &dyn Binding) -> Vec<Diagnostic> {
    let mut d = Vec::new();
    check_cross_reference(spec, expr, &mut d);
    check_gate(spec, &mut d);
    check_laws(spec, binding, &mut d);
    check_ledger(spec, &mut d);
    check_delegates(spec, &mut d);
    check_pipelines(spec, &mut d);
    check_ports(spec, &mut d);
    check_hives(spec, &mut d);
    check_specialists(spec, &mut d);
    check_composition(spec, expr, binding, &mut d);
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

fn check_composition(spec: &SpecFile, expr: &Expr, binding: &dyn Binding, d: &mut Vec<Diagnostic>) {
    let b = &spec.bindings;

    // Obligation Law + Gate ⇒ the obligation must be discharged *through* the
    // Gate, not merely recorded. If the binding's kernel can discharge an
    // obligation, the Gate must list it in requires_obligations; otherwise the
    // "every edit is followed by the test suite" promise is never enforced.
    if let Some(gate) = &b.gate {
        for law in &b.laws {
            let is_obligation = matches!(law.kind, LawKind::Obligation);
            let dischargeable = binding
                .dischargeable_obligations()
                .contains(&law.id.as_str());
            if is_obligation
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

    // A Gate that runs within, or downstream of, a Night Shift ⇒ durable
    // suspension and precondition revalidation. A Gate in an independent branch
    // is used attended and needs neither.
    if expr.runs_under(PatternKind::NightShift, PatternKind::Gate) {
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
    if expr.contains(PatternKind::Sandbox) && expr.contains(PatternKind::Ledger) {
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

    // A Verb placed `within` a control context must have real interceptors:
    // at least one Law present in the outer context.
    for (inner, outer) in expr.within_relations() {
        if inner.contains(&PatternKind::Verb)
            && outer.contains(&PatternKind::Law)
            && b.laws.is_empty()
        {
            d.push(Diagnostic::error(
                "composition.control_without_interceptor",
                "a Verb is composed 'within' a Law but no laws are bound to intercept it",
            ));
        }
    }

    // A Port that participates in an unattended pipeline ⇒ replay safety. The
    // Port may be upstream OR downstream of the Night Shift — the canonical
    // `Port -> Night Shift -> Gate` recipe has the Port feeding the unattended
    // run — so this uses data-path participation (either direction) or nesting,
    // not a directional "governs".
    let port_unattended = expr.contains(PatternKind::NightShift)
        && (expr.flow_connected(PatternKind::Port, PatternKind::NightShift)
            || expr.is_within(PatternKind::Port, PatternKind::NightShift)
            || expr.provisions(PatternKind::NightShift, PatternKind::Port));
    if port_unattended {
        for p in b
            .ports
            .iter()
            .filter(|p| !p.write.is_empty() && !p.idempotent)
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
    }

    // A Port running *within* a Sandbox ⇒ external isolation. Copy-on-write
    // isolates the filesystem, not the world; a sandboxed Port write must be
    // isolated, disabled, or a proposal. A Port outside the sandbox is unaffected.
    if expr.is_within(PatternKind::Port, PatternKind::Sandbox) {
        for p in b
            .ports
            .iter()
            .filter(|p| !p.write.is_empty() && p.sandboxed.is_none())
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
    }

    // A Gate *within* a Hive ⇒ approval scope must be declared: global vs.
    // per-worker are different systems. A Gate outside the Hive is unaffected.
    if expr.is_within(PatternKind::Gate, PatternKind::Hive) {
        for h in b.hives.iter().filter(|h| h.approval_scope.is_none()) {
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
        check(&spec, &expr, &MockBinding)
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
