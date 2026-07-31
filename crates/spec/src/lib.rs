//! # spec — the pattern-language compiler front-end
//!
//! Turns a `harness.patterns.yaml` into a validated model, or a set of
//! diagnostics explaining why it cannot be compiled. It does not generate
//! anything — that is the back-end's job (`harnessc`). Keeping the front-end
//! platform-agnostic is what lets the same specification target a different
//! binding later.
//!
//! The pipeline is: **parse YAML → parse the composition algebra → check**.
//! A spec compiles only if it is structurally complete *and* every safety
//! pattern it declares is fully specified.

pub mod binding;
pub mod check;
pub mod compose;
pub mod model;

pub use binding::Binding;
pub use check::{check, Diagnostic, Severity};
pub use compose::Expr;
pub use model::SpecFile;

/// A successfully compiled specification: the typed model, its parsed
/// composition tree, and any non-fatal warnings.
#[derive(Debug, Clone)]
pub struct CompiledSpec {
    pub spec: SpecFile,
    pub composition: Expr,
    pub warnings: Vec<Diagnostic>,
}

/// Why a specification could not be compiled.
#[derive(Debug, Clone)]
pub enum CompileError {
    /// The YAML did not deserialize into the metamodel.
    Yaml(String),
    /// The composition expression did not parse.
    Composition(String),
    /// The spec parsed but failed one or more checks.
    Rejected(Vec<Diagnostic>),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::Yaml(e) => write!(f, "spec does not parse: {e}"),
            CompileError::Composition(e) => write!(f, "composition does not parse: {e}"),
            CompileError::Rejected(diags) => {
                let errors = diags
                    .iter()
                    .filter(|d| d.severity == Severity::Error)
                    .count();
                writeln!(f, "specification rejected: {errors} error(s)")?;
                for diag in diags {
                    writeln!(f, "  {diag}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for CompileError {}

/// Parse a spec into its typed model without running the checker. Used by
/// tools (like the Refinery) that inspect a spec but do not compile it.
pub fn parse_model(yaml: &str) -> Result<SpecFile, CompileError> {
    serde_yaml::from_str(yaml).map_err(|e| CompileError::Yaml(e.to_string()))
}

/// Peek the declared `platform.type` without running the full checker. Used to
/// choose a default compiler back-end before a binding is selected.
pub fn platform_of(yaml: &str) -> Result<String, CompileError> {
    Ok(parse_model(yaml)?.platform.kind)
}

/// Parse and validate a `harness.patterns.yaml` from text against a target
/// [`Binding`]'s capabilities.
///
/// Returns the compiled model on success (carrying any warnings), or a
/// [`CompileError`] describing every reason it was rejected.
pub fn compile(yaml: &str, binding: &dyn Binding) -> Result<CompiledSpec, CompileError> {
    let spec: SpecFile =
        serde_yaml::from_str(yaml).map_err(|e| CompileError::Yaml(e.to_string()))?;
    let composition =
        compose::parse(&spec.composition.expression).map_err(CompileError::Composition)?;

    let diagnostics = check(&spec, &composition, binding);
    let errors: Vec<Diagnostic> = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .cloned()
        .collect();
    if !errors.is_empty() {
        return Err(CompileError::Rejected(diagnostics));
    }

    let warnings = diagnostics
        .into_iter()
        .filter(|d| d.severity == Severity::Warning)
        .collect();
    Ok(CompiledSpec {
        spec,
        composition,
        warnings,
    })
}
