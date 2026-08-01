//! `harnessc` — compile a `harness.patterns.yaml` into a governed harness.
//!
//! - `harnessc check` parses and validates the spec against the target
//!   binding's capabilities, statically rejecting any incomplete or unsafe
//!   composition.
//! - `harnessc show`  prints the compiled model: patterns, `within` relations,
//!   and bindings — the harness made inspectable *before* execution.
//! - `harnessc build` does `check`, then writes the generated files, each
//!   stamped with the spec hash.
//!
//! The target platform is taken from the spec's `platform.type`, or overridden
//! with `--target`. The same spec can compile to more than one target.

mod backend;
mod common;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::backend::Backend;
use crate::common::GENERATOR_VERSION;

#[derive(Parser)]
#[command(name = "harnessc", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse and validate the spec; reject incomplete or unsafe compositions.
    Check {
        #[arg(long, default_value = "harness.patterns.yaml")]
        spec: PathBuf,
        /// Target binding (default: the spec's platform.type).
        #[arg(long)]
        target: Option<String>,
    },
    /// Print the compiled model without generating anything.
    Show {
        #[arg(long, default_value = "harness.patterns.yaml")]
        spec: PathBuf,
        #[arg(long)]
        target: Option<String>,
    },
    /// Validate, then generate the harness.
    Build {
        #[arg(long, default_value = "harness.patterns.yaml")]
        spec: PathBuf,
        /// Directory to write the output into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Target binding (default: the spec's platform.type).
        #[arg(long)]
        target: Option<String>,
        /// Print the files that would be written without touching disk.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Check { spec, target } => {
            let (text, _) = read_spec(&spec)?;
            let backend = resolve_backend(target.as_deref(), &text)?;
            match spec::compile(&text, backend.as_binding()) {
                Ok(compiled) => {
                    println!(
                        "ok: '{}' compiles for target '{}'",
                        compiled.spec.harness.name,
                        backend.platform()
                    );
                    for w in &compiled.warnings {
                        println!("  {w}");
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprint!("{e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Show { spec, target } => {
            let (text, _) = read_spec(&spec)?;
            let backend = resolve_backend(target.as_deref(), &text)?;
            let compiled = spec::compile(&text, backend.as_binding())?;
            print_model(&compiled, backend.as_binding());
            Ok(ExitCode::SUCCESS)
        }
        Command::Build {
            spec,
            out,
            target,
            dry_run,
        } => {
            let (text, hash) = read_spec(&spec)?;
            let backend = resolve_backend(target.as_deref(), &text)?;
            let compiled = match spec::compile(&text, backend.as_binding()) {
                Ok(c) => c,
                Err(e) => {
                    eprint!("{e}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            for w in &compiled.warnings {
                eprintln!("{w}");
            }

            let generated = backend.generate(&compiled, &hash);
            println!(
                "compiled '{}' for '{}' (spec {}) with harnessc {GENERATOR_VERSION}",
                compiled.spec.harness.name,
                backend.platform(),
                hash
            );
            for file in &generated.files {
                let target_path = out.join(&file.path);
                if dry_run {
                    println!("  would write {}", target_path.display());
                    continue;
                }
                if let Some(parent) = target_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&target_path, &file.content)?;
                make_executable_if_hook(&target_path)?;
                println!("  wrote {}", target_path.display());
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Choose a back-end from an explicit `--target` or the spec's `platform.type`.
fn resolve_backend(
    target: Option<&str>,
    text: &str,
) -> Result<Box<dyn Backend>, Box<dyn std::error::Error>> {
    let name = match target {
        Some(t) => t.to_string(),
        None => spec::platform_of(text).map_err(|e| e.to_string())?,
    };
    backend::select(&name).ok_or_else(|| {
        format!(
            "unknown target '{name}'; available: {}",
            backend::available().join(", ")
        )
        .into()
    })
}

/// Read the spec text and compute its content hash (the identity stamped into
/// every generated artifact).
fn read_spec(path: &Path) -> Result<(String, String), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    let mut hash = String::from("sha256:");
    for b in digest {
        hash.push_str(&format!("{b:02x}"));
    }
    let text = String::from_utf8(bytes)?;
    Ok((text, hash))
}

fn make_executable_if_hook(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.extension().and_then(|e| e.to_str()) == Some("sh") {
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms)?;
        }
    }
    let _ = path;
    Ok(())
}

fn print_model(compiled: &spec::CompiledSpec, binding: &dyn spec::Binding) {
    let s = &compiled.spec;
    println!("harness: {} v{}", s.harness.name, s.harness.version);
    println!("target: {}", binding.platform());
    println!("composition: {}", s.composition.expression);

    // Patterns with their honest enforcement level (weakest first is fine;
    // sorted by name for stable output).
    let mut patterns: Vec<spec::model::PatternKind> =
        compiled.composition.patterns().into_iter().collect();
    patterns.sort_by_key(|p| p.to_string());
    println!("patterns (with enforcement):");
    for p in &patterns {
        println!(
            "  {:<12} {}",
            p.to_string(),
            binding.enforcement_level(*p).as_str()
        );
    }

    for (inner, outer) in compiled.composition.within_relations() {
        let i: Vec<String> = inner.iter().map(|p| p.to_string()).collect();
        let o: Vec<String> = outer.iter().map(|p| p.to_string()).collect();
        println!("  within: {{{}}} within {{{}}}", i.join(", "), o.join(", "));
    }

    println!("bindings:");
    if s.bindings.intake.is_some() {
        println!("  intake: bound");
    }
    if let Some(v) = &s.bindings.verb {
        println!("  verb: /{}", v.name);
    }
    for law in &s.bindings.laws {
        println!("  law: {} ({:?}@{:?})", law.id, law.kind, law.event);
    }
    if let Some(g) = &s.bindings.gate {
        let obl = if g.requires_obligations.is_empty() {
            String::new()
        } else {
            format!(" requires[{}]", g.requires_obligations.join(", "))
        };
        println!("  gate: {} @ {}{}", g.id, g.boundary, obl);
    }
    if let Some(l) = &s.bindings.ledger {
        println!("  ledger: {}", l.destination);
    }
    if !compiled.warnings.is_empty() {
        println!("warnings:");
        for w in &compiled.warnings {
            println!("  {w}");
        }
    }
}
