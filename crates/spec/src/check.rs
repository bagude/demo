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

/// The claude-code binding only knows how to enforce a fixed set of Laws. A Law
/// whose id is not here cannot be compiled honestly, so it is rejected rather
/// than stubbed and pretended-enforced.
fn claude_code_supports_law(id: &str) -> bool {
    matches!(id, "enforce-file-scope" | "require-validation")
}

/// Tokens that describe *what* is approved rather than a material precondition
/// whose drift should invalidate approval.
const NON_PRECONDITION_BINDINGS: &[&str] = &["action_hash", "approver", "expiry"];

/// Run every check against a parsed spec and its composition tree. Returns all
/// diagnostics; the caller decides that any `Error` blocks compilation.
pub fn check(spec: &SpecFile, expr: &Expr) -> Vec<Diagnostic> {
    let mut d = Vec::new();
    check_platform(spec, &mut d);
    check_cross_reference(spec, expr, &mut d);
    check_gate(spec, &mut d);
    check_laws(spec, &mut d);
    check_ledger(spec, &mut d);
    check_composition(spec, expr, &mut d);
    d
}

fn check_platform(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
    if spec.platform.kind != "claude-code" {
        d.push(Diagnostic::error(
            "platform.unsupported",
            format!(
                "this bootstrap compiler only has a 'claude-code' binding, got '{}'",
                spec.platform.kind
            ),
        ));
    }
}

fn check_cross_reference(spec: &SpecFile, expr: &Expr, d: &mut Vec<Diagnostic>) {
    let b = &spec.bindings;
    let present = expr.patterns();

    // Referenced in the composition but not bound.
    let unbound = [
        (PatternKind::Intake, b.intake.is_some()),
        (PatternKind::Verb, b.verb.is_some()),
        (PatternKind::Law, !b.laws.is_empty()),
        (PatternKind::Gate, b.gate.is_some()),
        (PatternKind::Ledger, b.ledger.is_some()),
        (PatternKind::Sandbox, b.sandbox.is_some()),
        (PatternKind::NightShift, b.night_shift.is_some()),
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

fn check_laws(spec: &SpecFile, d: &mut Vec<Diagnostic>) {
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
        if !claude_code_supports_law(&law.id) {
            d.push(Diagnostic::error(
                "law.unsupported",
                format!(
                    "the claude-code binding cannot enforce law '{}'; generating a stub would \
                     lie about the guarantee. Implement it in the kernel or remove it.",
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

fn check_composition(spec: &SpecFile, expr: &Expr, d: &mut Vec<Diagnostic>) {
    let b = &spec.bindings;

    // Gate + Night Shift ⇒ durable suspension and precondition revalidation.
    if expr.contains(PatternKind::Gate) && expr.contains(PatternKind::NightShift) {
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
  ledger:
    event_schema: schemas/event.schema.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials, raw_model_context]
platform:
  type: claude-code
  role_bindings:
    boot_context: CLAUDE.md
"#;

    fn check_yaml(yaml: &str) -> Vec<Diagnostic> {
        let spec: SpecFile = serde_yaml::from_str(yaml).expect("parses");
        let expr = crate::compose::parse(&spec.composition.expression).expect("composition parses");
        check(&spec, &expr)
    }

    fn codes(diags: &[Diagnostic]) -> Vec<&'static str> {
        diags.iter().map(|d| d.code).collect()
    }

    #[test]
    fn specimen_compiles_cleanly() {
        assert!(compile(SPECIMEN).is_ok());
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
        let err = compile(&yaml).unwrap_err();
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
}
