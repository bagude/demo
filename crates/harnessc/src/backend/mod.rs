//! Compiler back-ends.
//!
//! The front-end (`spec`) produces a validated model; a back-end turns it into
//! files for one platform. Every back-end also *is* a [`spec::Binding`], so it
//! advertises which Laws it can enforce — the same spec is checked against the
//! capabilities of whatever target it is compiled for. This is the concrete
//! payoff of the portable pattern language: one spec, many bindings.

pub mod claude_code;
pub mod portable;

use spec::{Binding, CompiledSpec};

use crate::common::Generated;

/// A platform back-end: capabilities (via [`Binding`]) plus generation.
pub trait Backend: Binding {
    /// Generate the files for a compiled harness.
    fn generate(&self, compiled: &CompiledSpec, spec_hash: &str) -> Generated;

    /// This back-end viewed as a checker capability.
    fn as_binding(&self) -> &dyn Binding;
}

/// The back-end targets this compiler knows.
pub fn available() -> &'static [&'static str] {
    &["claude-code", "portable"]
}

/// Select a back-end by target name.
pub fn select(target: &str) -> Option<Box<dyn Backend>> {
    match target {
        "claude-code" => Some(Box::new(claude_code::ClaudeCode)),
        "portable" => Some(Box::new(portable::Portable)),
        _ => None,
    }
}
