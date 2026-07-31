//! Platform-binding capabilities.
//!
//! The front-end is platform-agnostic, but *whether a given Law can actually be
//! enforced* is a property of the target platform's binding, not of the pattern
//! language. So the checker takes a [`Binding`] and asks it. This is what lets
//! the same spec compile to more than one platform: each backend supplies its
//! own capabilities, and the front-end logic is identical.

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
}
