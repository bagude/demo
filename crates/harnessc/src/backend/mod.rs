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

#[cfg(test)]
mod tests {
    use super::*;

    const RESEARCH_ORG: &str = include_str!("../../../../examples/research-org.patterns.yaml");
    const SAFE_DEPLOY: &str = include_str!("../../../../examples/safe-deploy.patterns.yaml");

    fn compile_and_generate(yaml: &str) -> Vec<String> {
        let backend = select("claude-code").unwrap();
        let compiled = spec::compile(yaml, backend.as_binding())
            .unwrap_or_else(|e| panic!("example must compile: {e}"));
        backend
            .generate(&compiled, "sha256:test")
            .files
            .into_iter()
            .map(|f| f.path)
            .collect()
    }

    #[test]
    fn research_org_compiles_and_generates_delegate_hive_port_artifacts() {
        let paths = compile_and_generate(RESEARCH_ORG);
        for expected in [
            ".claude/agents/researcher.md",
            ".claude/agents/reviewer.md",
            ".claude/commands/research.md",
            "harness/schemas/researcher.result.schema.json",
            ".mcp.json",
            "harness/ports.json",
            "harness/playbook.json",
        ] {
            assert!(paths.iter().any(|p| p == expected), "missing {expected}");
        }
    }

    #[test]
    fn safe_deploy_compiles_and_generates_the_pipeline_command() {
        let paths = compile_and_generate(SAFE_DEPLOY);
        assert!(paths.iter().any(|p| p == ".claude/commands/release.md"));
    }

    #[test]
    fn both_examples_also_compile_portable() {
        let backend = select("portable").unwrap();
        for yaml in [RESEARCH_ORG, SAFE_DEPLOY] {
            let compiled = spec::compile(yaml, backend.as_binding()).expect("compiles portable");
            let files = backend.generate(&compiled, "sha256:test").files;
            assert!(files.iter().any(|f| f.path == "harness.manifest.json"));
        }
    }
}
