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
    /// Additional protected enforcement-artifact prefixes, beyond the paths
    /// the backend itself generates. This is where a **self-hosting** spec
    /// declares its trusted computing base — the kernel source, the compiler
    /// source, the dependency lock — so that editing the enforcement
    /// *implementation* requires the same explicit `amends_enforcement` grant
    /// as editing the generated tree. Membership in the TCB is declared by the
    /// spec and enforced by the kernel; it is never inferred from a packet's
    /// own claims.
    #[serde(default)]
    pub protected: Vec<String>,
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
    #[serde(default)]
    pub specialists: Vec<SpecialistBinding>,
    #[serde(default)]
    pub delegates: Vec<DelegateBinding>,
    #[serde(default)]
    pub pipelines: Vec<PipelineBinding>,
    #[serde(default)]
    pub ports: Vec<PortBinding>,
    #[serde(default)]
    pub hives: Vec<HiveBinding>,
    #[serde(default)]
    pub refinery: Option<RefineryBinding>,
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

/// The scope an Obligation opens and discharges under — the answer to "owed
/// by WHOM, until WHEN". `run` (the default) is the narrowest: an edit in run
/// A opens debt only run A's validation can clear. `task` follows the task
/// packet across runs; `branch` follows the git branch; `workspace` is global;
/// `action` is per edited path — every touched file owes its own validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObligationScope {
    #[default]
    Run,
    Task,
    Branch,
    Workspace,
    Action,
    /// Per runtime instance: debt keyed to the specific occupant of a
    /// composition position (`run-42/worker/2`) that opened it — the
    /// worker-scoped obligation the three-level identity model exists for.
    Instance,
}

impl ObligationScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObligationScope::Run => "run",
            ObligationScope::Task => "task",
            ObligationScope::Branch => "branch",
            ObligationScope::Workspace => "workspace",
            ObligationScope::Action => "action",
            ObligationScope::Instance => "instance",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LawBinding {
    pub id: String,
    pub kind: LawKind,
    pub event: LawEvent,
    pub applies_to: Vec<String>,
    /// The scope this Obligation opens and discharges under. Declared, not
    /// assumed: `run` unless the spec says otherwise. Meaningless on a Guard
    /// (a Guard decides instantaneously and owes nothing) — the checker
    /// rejects a non-run scope there.
    #[serde(default)]
    pub scope: ObligationScope,
    #[serde(default)]
    pub implementation: Option<String>,
    /// Install this Law even when no composition occurrence (or binding
    /// dependency) activates it. Enforcement is never installed implicitly: a
    /// bound Law must be activated by the architecture or carry this explicit
    /// declaration — otherwise it is a compile error, because surplus
    /// enforcement can block permitted actions, open unexpected obligations,
    /// or log more than the declared system.
    #[serde(default)]
    pub always_on: bool,
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
    /// Install this Gate even when nothing in the composition activates it.
    /// See `LawBinding::always_on` — an unactivated Gate would halt progress
    /// no active workflow expects, so it must be activated or declared.
    #[serde(default)]
    pub always_on: bool,
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
    /// Record even when no composition occurrence references the Ledger. See
    /// `LawBinding::always_on` — recording is disclosure, so it too must be
    /// activated by the architecture or explicitly declared.
    #[serde(default)]
    pub always_on: bool,
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

/// The Specialist — Demand-Loaded Knowledge (a Skill).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecialistBinding {
    pub id: String,
    /// Path to the SKILL.md that is loaded on demand.
    pub skill: String,
    /// When the specialist should be brought into context.
    pub description: String,
}

/// The Delegate — a Nested Executor with a typed contract. The Critic is the
/// review-only variant (`critic: true`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegateBinding {
    pub id: String,
    /// Path to the subagent definition.
    pub agent: String,
    /// Schema the delegate's result must conform to (never unstructured prose).
    pub contract_schema: String,
    /// The delegated authority: tools the subagent may use. Must be a subset of
    /// the parent's — never broader.
    pub tools: Vec<String>,
    /// Capability Ports this delegate may use. Each must be a declared port; a
    /// Delegate operates under delegated authority, never broader than granted.
    #[serde(default)]
    pub ports: Vec<String>,
    /// A Critic judges work it did not produce; fresh context is the point.
    #[serde(default)]
    pub critic: bool,
}

/// One typed stage of a Pipeline.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineStage {
    pub name: String,
    /// The typed artifact this stage consumes (absent for the first stage).
    #[serde(default)]
    pub consumes: Option<String>,
    /// The typed artifact this stage produces (absent for the last stage).
    #[serde(default)]
    pub produces: Option<String>,
}

/// The Pipeline — control flow fixed at write-time, typed stage interfaces.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineBinding {
    pub id: String,
    pub command: String,
    pub stages: Vec<PipelineStage>,
}

/// How a Port behaves when the workflow is sandboxed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sandboxed {
    /// Writes target an isolated environment.
    Isolate,
    /// Writes are disabled.
    Disable,
    /// Writes become proposals awaiting acceptance.
    Propose,
}

/// The Port — a Capability Port (MCP server) with a write-authority boundary.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortBinding {
    pub id: String,
    pub server: String,
    /// Objects the port may observe.
    #[serde(default)]
    pub observe: Vec<String>,
    /// Transitions the port may request (its write authority).
    #[serde(default)]
    pub write: Vec<String>,
    /// Guard-law id governing writes. Required when `write` is non-empty —
    /// connectivity without a capability boundary is ambient privilege.
    #[serde(default)]
    pub write_guard: Option<String>,
    /// Reference to the credentials used (never the secret itself).
    #[serde(default)]
    pub credentials: Option<String>,
    /// Whether externally consequential actions carry an idempotency key —
    /// required for replay safety under retry/resumption/unattended runs.
    #[serde(default)]
    pub idempotent: bool,
    /// How the port behaves while sandboxed. Required when composed with a Sandbox.
    #[serde(default)]
    pub sandboxed: Option<Sandboxed>,
}

/// How a Hive fans work out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FanOut {
    Static,
    Dynamic,
    Iterative,
}

/// How concurrent Hive workers avoid clobbering a shared target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerIsolation {
    /// Disjoint declared write sets.
    Disjoint,
    /// Isolated workspaces merged by an explicit protocol.
    Isolated,
    /// Serialized mutation authority.
    Serialized,
}

/// Whether Gate approval in a Hive is granted once or per worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    Global,
    PerWorker,
}

/// The Hive — Delegate × N + orchestrator + budget/depth Laws + Critic. The
/// Law of the Hive: every spawned task has a parent, contract, budget, depth,
/// termination condition, merge destination, and declared read/write scope.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HiveBinding {
    pub id: String,
    pub orchestrator: String,
    /// The delegate id whose contract every worker is spawned against.
    pub worker: String,
    pub fan_out: FanOut,
    /// Total token/resource budget cap for the fan-out.
    pub budget: u64,
    /// Maximum recursion depth — the backstop against runaway dynamic fan-out.
    pub max_depth: u32,
    /// The termination condition for spawned work.
    pub termination: String,
    /// Where worker results are merged.
    pub merge: String,
    /// How workers avoid conflicting on a shared mutation target.
    pub worker_isolation: WorkerIsolation,
    /// Global vs. per-worker approval; required when the Hive contains a Gate.
    #[serde(default)]
    pub approval_scope: Option<ApprovalScope>,
}

/// The Refinery — a Night Shift that proposes reviewable Playbook patches.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefineryBinding {
    pub schedule: String,
    /// Directory proposals are written to (never the live spec).
    pub proposals: String,
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
    Specialist,
    Delegate,
    Critic,
    Pipeline,
    Port,
    Hive,
    Refinery,
    /// The reproducible harness bundle itself — always satisfied by the
    /// compiled output, so referencing it never needs a separate binding.
    Playbook,
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
            PatternKind::Specialist => "Specialist",
            PatternKind::Delegate => "Delegate",
            PatternKind::Critic => "Critic",
            PatternKind::Pipeline => "Pipeline",
            PatternKind::Port => "Port",
            PatternKind::Hive => "Hive",
            PatternKind::Refinery => "Refinery",
            PatternKind::Playbook => "Playbook",
        }
    }
}

impl fmt::Display for PatternKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single *occurrence* of a pattern in a composition, optionally naming which
/// binding it refers to.
///
/// This is what makes the composition graph instance-addressable. `Port` is an
/// anonymous occurrence — it stands for *every* Port binding of its kind, which
/// is the right (conservative) reading when the author has not disambiguated.
/// `Port[staging-deployer]` names exactly one binding, so a derived obligation
/// attaches to that component rather than to the pattern category. Two anonymous
/// occurrences of the same kind are indistinguishable; two labelled ones are
/// distinct iff their ids differ.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternInstance {
    pub kind: PatternKind,
    /// The binding id this occurrence names, or `None` for an anonymous
    /// occurrence that stands for every binding of `kind`.
    pub id: Option<String>,
    /// The declared name of this *position* (`Port[github as staging_deployer]`
    /// declares `staging_deployer`), distinct from the binding id: two
    /// positions may share one implementation binding yet be named apart. A
    /// singleton kind, which has no binding id at all, can still name its
    /// position (`Sandbox[as worker_sandbox]`). Aliases are unique across the
    /// whole composition.
    pub alias: Option<String>,
}

impl PatternInstance {
    pub fn anonymous(kind: PatternKind) -> Self {
        PatternInstance {
            kind,
            id: None,
            alias: None,
        }
    }

    pub fn named(kind: PatternKind, id: impl Into<String>) -> Self {
        PatternInstance {
            kind,
            id: Some(id.into()),
            alias: None,
        }
    }
}

impl fmt::Display for PatternInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.id, &self.alias) {
            (Some(id), Some(a)) => write!(f, "{}[{id} as {a}]", self.kind),
            (Some(id), None) => write!(f, "{}[{id}]", self.kind),
            (None, Some(a)) => write!(f, "{}[as {a}]", self.kind),
            (None, None) => f.write_str(self.kind.as_str()),
        }
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
            "Specialist" => Ok(PatternKind::Specialist),
            "Delegate" => Ok(PatternKind::Delegate),
            "Critic" => Ok(PatternKind::Critic),
            "Pipeline" => Ok(PatternKind::Pipeline),
            "Port" => Ok(PatternKind::Port),
            "Hive" => Ok(PatternKind::Hive),
            "Refinery" => Ok(PatternKind::Refinery),
            "Playbook" => Ok(PatternKind::Playbook),
            other => Err(format!("unknown pattern '{other}'")),
        }
    }
}
