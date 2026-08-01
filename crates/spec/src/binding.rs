//! Platform-binding capabilities.
//!
//! The front-end is platform-agnostic, but *whether a given Law can actually be
//! enforced* is a property of the target platform's binding, not of the pattern
//! language. So the checker takes a [`Binding`] and asks it. This is what lets
//! the same spec compile to more than one platform: each backend supplies its
//! own capabilities, and the front-end logic is identical.

use crate::model::PatternKind;

/// How strongly a bound pattern is *actually* enforced, weakest to strongest.
///
/// This is the project's "enforcement honesty" made explicit: a Specialist we
/// only scaffold and a Gate the kernel mediates are not the same, and the
/// compiler should say so rather than let "bindable" imply "enforced".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnforcementLevel {
    /// A placeholder artifact a human must fill in.
    Scaffolded,
    /// Declared in the spec; no automated check and no runtime effect.
    Declared,
    /// The compiler statically validates it, but nothing enforces it at runtime.
    StaticallyChecked,
    /// Observed/recorded at runtime, but not blocked.
    RuntimeMonitored,
    /// Blocked at runtime by a generated hook that calls the kernel.
    RuntimeEnforced,
    /// Every relevant action passes through the kernel as the policy point.
    KernelMediated,
}

impl EnforcementLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnforcementLevel::Scaffolded => "scaffolded",
            EnforcementLevel::Declared => "declared",
            EnforcementLevel::StaticallyChecked => "statically-checked",
            EnforcementLevel::RuntimeMonitored => "runtime-monitored",
            EnforcementLevel::RuntimeEnforced => "runtime-enforced",
            EnforcementLevel::KernelMediated => "kernel-mediated",
        }
    }
}

/// The default, honest enforcement level for each pattern under this bootstrap
/// (both current backends share the same kernel, so they share this map). A
/// backend may override [`Binding::enforcement_level`] if it provides more.
pub fn default_enforcement_level(pattern: PatternKind) -> EnforcementLevel {
    use EnforcementLevel::*;
    match pattern {
        // The kernel blocks out-of-scope edits against the packet.
        PatternKind::Intake => RuntimeEnforced,
        // A Markdown command; behavior is model-driven.
        PatternKind::Verb => Declared,
        // Guard Laws block via generated hooks calling the kernel.
        PatternKind::Law => RuntimeEnforced,
        // Checkpoint, approval binding, and revalidation all live in the kernel.
        PatternKind::Gate => KernelMediated,
        // Append-only recording; no blocking.
        PatternKind::Ledger => RuntimeMonitored,
        // Lineage/drift are checked statically; no sandbox runtime is generated.
        PatternKind::Sandbox => StaticallyChecked,
        // A schedule/entrypoint description.
        PatternKind::NightShift => Declared,
        // Skill/agent placeholders to fill in.
        PatternKind::Specialist | PatternKind::Delegate | PatternKind::Critic => Scaffolded,
        // The stage graph is validated; not executed by the kernel.
        PatternKind::Pipeline => StaticallyChecked,
        // MCP config + capability manifest; not yet kernel-mediated.
        PatternKind::Port => StaticallyChecked,
        // The Law of the Hive is validated per-spawn by the kernel.
        PatternKind::Hive => KernelMediated,
        // Proposes patches; a separate binary, not a blocking control.
        PatternKind::Refinery => RuntimeMonitored,
        // The reproducible bundle itself.
        PatternKind::Playbook => StaticallyChecked,
    }
}

/// The capabilities a compiler back-end advertises to the checker.
pub trait Binding {
    /// The canonical platform name this binding targets (matched against a
    /// spec's `platform.type`).
    fn platform(&self) -> &str;

    /// Whether this binding can enforce the Law with the given id. A Law the
    /// binding cannot enforce is rejected rather than stubbed, so the compiler
    /// never pretends a guarantee it does not provide.
    fn supports_law(&self, law_id: &str) -> bool;

    /// The obligation ids this binding's kernel knows how to discharge (e.g.
    /// via a validation step gated at a commit boundary). Used to check that an
    /// Obligation Law is actually dischargeable, not merely recorded.
    fn dischargeable_obligations(&self) -> &[&str] {
        &[]
    }

    /// How strongly this binding actually enforces `pattern`. Defaults to the
    /// shared, honest map; a richer backend may override.
    fn enforcement_level(&self, pattern: PatternKind) -> EnforcementLevel {
        default_enforcement_level(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_is_honest_about_scaffolds_vs_kernel() {
        // A scaffold must never claim to be enforced.
        assert_eq!(
            default_enforcement_level(PatternKind::Specialist),
            EnforcementLevel::Scaffolded
        );
        assert_eq!(
            default_enforcement_level(PatternKind::Delegate),
            EnforcementLevel::Scaffolded
        );
        // Genuinely enforced/kernel-mediated patterns rank strictly higher.
        assert!(
            default_enforcement_level(PatternKind::Gate)
                > default_enforcement_level(PatternKind::Specialist)
        );
        assert_eq!(
            default_enforcement_level(PatternKind::Law),
            EnforcementLevel::RuntimeEnforced
        );
        assert_eq!(
            default_enforcement_level(PatternKind::Gate),
            EnforcementLevel::KernelMediated
        );
        assert_eq!(
            default_enforcement_level(PatternKind::Hive),
            EnforcementLevel::KernelMediated
        );
    }
}
