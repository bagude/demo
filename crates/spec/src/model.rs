//! The metamodel: a typed representation of a harness specification.
//!
//! A `harness.patterns.yaml` deserializes into [`SpecFile`]. Required fields
//! are non-`Option`, so serde rejects a structurally incomplete binding at
//! parse time — the first line of defense behind "reject an incomplete Gate
//! rather than generate a confirmation prompt." The semantic checks in
//! [`crate::check`] are the second.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

/// A whole harness specification: one system, declared.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecFile {
    pub harness: HarnessMeta,
    pub composition: Composition,
    pub bindings: Bindings,
    pub platform: Platform,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessMeta {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Composition {
    /// The composition-algebra expression, e.g.
    /// `"Intake -> Verb within (Law + Gate) + Ledger"`.
    pub expression: String,
}

/// The `bindings:` block. Each concrete pattern named in the composition needs
/// a matching binding here; the checker cross-references the two.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    #[serde(default)]
    pub intake: Option<IntakeBinding>,
    #[serde(default)]
    pub verb: Option<VerbBinding>,
    #[serde(default)]
    pub laws: Vec<LawBinding>,
    #[serde(default)]
    pub gate: Option<GateBinding>,
    #[serde(default)]
    pub ledger: Option<LedgerBinding>,
    #[serde(default)]
    pub sandbox: Option<SandboxBinding>,
    #[serde(default)]
    pub night_shift: Option<NightShiftBinding>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntakeBinding {
    pub task_schema: String,
    pub storage: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerbBinding {
    pub name: String,
    pub command: String,
    pub accepts: String,
    pub produces: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LawKind {
    Guard,
    Obligation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LawEvent {
    PreTool,
    PostTool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LawBinding {
    pub id: String,
    pub kind: LawKind,
    pub event: LawEvent,
    pub applies_to: Vec<String>,
    #[serde(default)]
    pub implementation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateBinding {
    pub id: String,
    pub boundary: String,
    pub checkpoint_schema: String,
    /// The set of things approval binds to: an action hash plus the
    /// precondition tokens whose drift invalidates approval.
    pub bind: Vec<String>,
    /// Whether the checkpoint survives process death. Required to be true when
    /// composed with an unattended entrypoint (Night Shift).
    #[serde(default)]
    pub durable: Option<bool>,
    #[serde(default)]
    pub resume: Option<ResumeSpec>,
    /// Obligation ids that must be discharged before this Gate will approve or
    /// resume. This is how an Obligation Law is turned from "recorded" into
    /// "enforced": the Gate refuses to proceed while the obligation is open.
    #[serde(default)]
    pub requires_obligations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeSpec {
    #[serde(default)]
    pub process_independent: bool,
    #[serde(default)]
    pub revalidate_preconditions: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerBinding {
    pub event_schema: String,
    pub destination: String,
    pub redact: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxBinding {
    pub workspace: String,
    /// Lineage fields recorded between source and sandbox. Required when
    /// composed with a Ledger.
    #[serde(default)]
    pub lineage: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NightShiftBinding {
    pub schedule: String,
    pub entrypoint: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub role_bindings: std::collections::BTreeMap<String, String>,
}

/// The concrete, bindable patterns this bootstrap compiler understands. The
/// composition expression may name any of them; the checker enforces that each
/// named pattern is also bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PatternKind {
    Intake,
    Verb,
    Law,
    Gate,
    Ledger,
    Sandbox,
    NightShift,
}

impl PatternKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PatternKind::Intake => "Intake",
            PatternKind::Verb => "Verb",
            PatternKind::Law => "Law",
            PatternKind::Gate => "Gate",
            PatternKind::Ledger => "Ledger",
            PatternKind::Sandbox => "Sandbox",
            PatternKind::NightShift => "NightShift",
        }
    }
}

impl fmt::Display for PatternKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PatternKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Intake" => Ok(PatternKind::Intake),
            "Verb" => Ok(PatternKind::Verb),
            "Law" => Ok(PatternKind::Law),
            "Gate" => Ok(PatternKind::Gate),
            "Ledger" => Ok(PatternKind::Ledger),
            "Sandbox" => Ok(PatternKind::Sandbox),
            "NightShift" => Ok(PatternKind::NightShift),
            other => Err(format!("unknown pattern '{other}'")),
        }
    }
}
