//! `harnessc` — compile a `harness.patterns.yaml` into a Claude Code Playbook.
//!
//! - `harnessc check` parses and validates the spec, statically rejecting any
//!   incomplete or unsafe composition.
//! - `harnessc show`  prints the compiled model: patterns, `within` relations,
//!   and bindings — the harness made inspectable *before* execution.
//! - `harnessc build` does `check`, then writes the generated files, each
//!   stamped with the spec hash.

mod generate;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use spec::compile;

use crate::generate::{generate, GENERATOR_VERSION};

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
    },
    /// Print the compiled model without generating anything.
    Show {
        #[arg(long, default_value = "harness.patterns.yaml")]
        spec: PathBuf,
    },
    /// Validate, then generate the Playbook.
    Build {
        #[arg(long, default_value = "harness.patterns.yaml")]
        spec: PathBuf,
        /// Directory to write the Playbook into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
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
        Command::Check { spec } => {
            let (text, _) = read_spec(&spec)?;
            match compile(&text) {
                Ok(compiled) => {
                    println!("ok: '{}' compiles", compiled.spec.harness.name);
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
        Command::Show { spec } => {
            let (text, _) = read_spec(&spec)?;
            let compiled = compile(&text)?;
            print_model(&compiled);
            Ok(ExitCode::SUCCESS)
        }
        Command::Build { spec, out, dry_run } => {
            let (text, hash) = read_spec(&spec)?;
            let compiled = match compile(&text) {
                Ok(c) => c,
                Err(e) => {
                    eprint!("{e}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            for w in &compiled.warnings {
                eprintln!("{w}");
            }

            let generated = generate(&compiled, &hash);
            println!(
                "compiled '{}' (spec {}) with harnessc {GENERATOR_VERSION}",
                compiled.spec.harness.name, hash
            );
            for file in &generated.files {
                let target = out.join(&file.path);
                if dry_run {
                    println!("  would write {}", target.display());
                    continue;
                }
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&target, &file.content)?;
                make_executable_if_hook(&target)?;
                println!("  wrote {}", target.display());
            }
            Ok(ExitCode::SUCCESS)
        }
    }
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

fn print_model(compiled: &spec::CompiledSpec) {
    let s = &compiled.spec;
    println!("harness: {} v{}", s.harness.name, s.harness.version);
    println!("platform: {}", s.platform.kind);
    println!("composition: {}", s.composition.expression);

    let mut patterns: Vec<String> = compiled
        .composition
        .patterns()
        .iter()
        .map(|p| p.to_string())
        .collect();
    patterns.sort();
    println!("patterns: {}", patterns.join(", "));

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
        println!("  gate: {} @ {}", g.id, g.boundary);
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
