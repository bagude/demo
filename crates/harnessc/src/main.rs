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
    /// Check that the generated tree on disk matches what this compiler would
    /// produce — a freshness proof for the checked-in Playbook.
    Verify {
        #[arg(long, default_value = "harness.patterns.yaml")]
        spec: PathBuf,
        /// Directory the generated tree lives in.
        #[arg(long, default_value = ".")]
        out: PathBuf,
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
        Command::Verify { spec, out, target } => {
            let (text, hash) = read_spec(&spec)?;
            let backend = resolve_backend(target.as_deref(), &text)?;
            let compiled = match spec::compile(&text, backend.as_binding()) {
                Ok(c) => c,
                Err(e) => {
                    eprint!("{e}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let refs = common::refs(&compiled, &hash, backend.platform());
            let generated = backend.generate(&compiled, &refs);
            let problems = verify_bundle(&generated, &out);
            if problems.is_empty() {
                println!(
                    "fresh: {} generated file(s) match playbook {}",
                    generated.files.len(),
                    refs.playbook_ref
                );
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!(
                    "stale: the generated tree does not match this compiler (playbook {})",
                    refs.playbook_ref
                );
                for p in &problems {
                    eprintln!("  {p}");
                }
                eprintln!("run `harnessc build --out {}` to regenerate", out.display());
                Ok(ExitCode::FAILURE)
            }
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

            let refs = common::refs(&compiled, &hash, backend.platform());
            let generated = backend.generate(&compiled, &refs);
            println!(
                "compiled '{}' for '{}' with harnessc {GENERATOR_VERSION}\n  source   {}\n  compiler {}\n  ir       {}\n  playbook {}",
                compiled.spec.harness.name,
                backend.platform(),
                refs.source_ref,
                refs.compiler_ref,
                refs.ir_ref,
                refs.playbook_ref,
            );

            // The previous build's manifest names the paths it managed;
            // whatever fell out of the generated set since then is retired
            // during promotion, so a hook or command this compiler no longer
            // emits does not remain live behavior in the harness.
            let expected: std::collections::BTreeSet<&str> =
                generated.files.iter().map(|f| f.path.as_str()).collect();
            let obsolete: Vec<String> = bundle_manifest_file(&generated)
                .and_then(|m| common::read_manifest_paths(&out.join(&m.path)))
                .unwrap_or_default()
                .into_iter()
                .filter(|p| !expected.contains(p.as_str()))
                .filter(|p| is_safe_bundle_path(p))
                .filter(|p| out.join(p).symlink_metadata().is_ok())
                .collect();

            if dry_run {
                for file in &generated.files {
                    println!("  would write {}", out.join(&file.path).display());
                }
                for p in &obsolete {
                    println!("  would remove {}", out.join(p).display());
                }
                return Ok(ExitCode::SUCCESS);
            }

            promote_bundle(&generated, &out, &obsolete)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The bundle manifest within a generated set (the backend appends it last).
fn bundle_manifest_file(generated: &common::Generated) -> Option<&common::GenFile> {
    generated
        .files
        .iter()
        .find(|f| f.path.ends_with(common::BUNDLE_MANIFEST_FILENAME))
}

/// Prove the tree at `out` is exactly this bundle. Byte comparison of the
/// expected files proves each present file is right; it cannot see a stale
/// artifact an older compiler emitted, a hook whose executable bit was
/// stripped (which silently stops running), or a path replaced by a symlink.
/// Each of those is a behavioral divergence, so each is a verification
/// failure: path set, bytes, type, and mode are all part of the proof.
fn verify_bundle(generated: &common::Generated, out: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let expected: std::collections::BTreeSet<&str> =
        generated.files.iter().map(|f| f.path.as_str()).collect();

    // Obsolete detection: the previous build's manifest records the path set
    // it managed. Anything it lists that this compiler no longer generates —
    // but still exists on disk — is live behavior no current Playbook
    // accounts for.
    if let Some(manifest) = bundle_manifest_file(generated) {
        if let Some(old_paths) = common::read_manifest_paths(&out.join(&manifest.path)) {
            for p in old_paths {
                if !expected.contains(p.as_str())
                    && is_safe_bundle_path(&p)
                    && out.join(&p).symlink_metadata().is_ok()
                {
                    problems.push(format!(
                        "obsolete: {p} (formerly generated; not part of this Playbook)"
                    ));
                }
            }
        }
    }

    for file in &generated.files {
        let path = out.join(&file.path);
        let md = match std::fs::symlink_metadata(&path) {
            Err(_) => {
                problems.push(format!("missing:  {}", file.path));
                continue;
            }
            Ok(md) => md,
        };
        if !md.file_type().is_file() {
            problems.push(format!("type:     {} is not a regular file", file.path));
            continue;
        }
        match std::fs::read(&path) {
            Err(e) => problems.push(format!("unreadable: {} ({e})", file.path)),
            Ok(bytes) if bytes != file.content.as_bytes() => {
                problems.push(format!("differs:  {}", file.path))
            }
            Ok(_) => {}
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let is_exec = md.permissions().mode() & 0o111 != 0;
            let want_exec = common::file_mode(&file.path) == "0755";
            if is_exec != want_exec {
                problems.push(format!(
                    "mode:     {} is {}executable but must be mode {}",
                    file.path,
                    if is_exec { "" } else { "not " },
                    common::file_mode(&file.path)
                ));
            }
        }
    }
    problems
}

/// Write the bundle without ever presenting a torn Playbook as current:
///
/// 1. **Stage** every file as a `.harnessc-tmp` sibling with its final mode,
///    fsynced — the live tree is untouched until the whole bundle exists on
///    disk.
/// 2. **Promote** everything except the manifest by atomic rename.
/// 3. **Retire** obsolete files (in the previous manifest, absent from this
///    set) — before the manifest stops listing them, so an interrupted
///    cleanup is still visible to `verify` through the old manifest.
/// 4. **Promote the manifest last** — the commit point at which the tree
///    describes itself as the new bundle.
///
/// Crash windows: during (1) the old bundle is fully intact (only tmp litter
/// remains, overwritten by the next build); during (2)–(4) the tree can be
/// mixed, but the not-yet-replaced manifest still describes the OLD set, so
/// `harnessc verify` reports the exact divergence instead of trusting either
/// version. At no point is a half-written file at a live path.
fn promote_bundle(
    generated: &common::Generated,
    out: &Path,
    obsolete: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    // Stage the complete bundle first; on any failure, unstage and abort with
    // the live tree untouched.
    let mut staged: Vec<(PathBuf, PathBuf)> = Vec::new();
    for file in &generated.files {
        let target = out.join(&file.path);
        match stage_file(&target, &file.content, common::file_mode(&file.path)) {
            Ok(tmp) => staged.push((tmp, target)),
            Err(e) => {
                for (tmp, _) in &staged {
                    let _ = std::fs::remove_file(tmp);
                }
                return Err(format!("staging {}: {e}", file.path).into());
            }
        }
    }

    // The manifest is generated last, so it is the last staged pair.
    let Some(((manifest_tmp, manifest_target), files)) = staged.split_last() else {
        return Ok(());
    };
    for (tmp, target) in files {
        std::fs::rename(tmp, target).map_err(|e| format!("promoting {}: {e}", target.display()))?;
        fsync_dir(target.parent());
        println!("  wrote {}", target.display());
    }
    for p in obsolete {
        let target = out.join(p);
        match std::fs::remove_file(&target) {
            Ok(()) => println!("  removed {} (no longer generated)", target.display()),
            Err(e) => eprintln!(
                "warning: could not remove obsolete {}: {e}",
                target.display()
            ),
        }
    }
    std::fs::rename(manifest_tmp, manifest_target)
        .map_err(|e| format!("promoting {}: {e}", manifest_target.display()))?;
    fsync_dir(manifest_target.parent());
    println!("  wrote {}", manifest_target.display());
    Ok(())
}

/// Stage `content` for `target` as a `.harnessc-tmp` sibling: full bytes,
/// final mode, fsynced — ready to be atomically renamed into place.
fn stage_file(target: &Path, content: &str, mode: &str) -> std::io::Result<PathBuf> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(".harnessc-tmp");
    let tmp = target.with_file_name(name);
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bits = if mode == "0755" { 0o755 } else { 0o644 };
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(bits))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(tmp)
}

/// Durably record a rename by fsyncing the containing directory (Unix; other
/// platforms lack the primitive).
fn fsync_dir(dir: Option<&Path>) {
    #[cfg(unix)]
    if let Some(dir) = dir {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// A previously-managed path is touchable only if it is relative and contains
/// no traversal: the manifest is data, and `build` must not be steerable into
/// deleting outside the output tree by a doctored one.
fn is_safe_bundle_path(p: &str) -> bool {
    use std::path::Component;
    !p.is_empty()
        && Path::new(p)
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
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

fn print_model(compiled: &spec::CompiledSpec, binding: &dyn spec::Binding) {
    let s = &compiled.spec;
    println!("harness: {} v{}", s.harness.name, s.harness.version);
    println!("target: {}", binding.platform());
    println!("composition: {}", s.composition.expression);

    // Patterns with their honest enforcement level, derived from the RESOLVED
    // architecture (a Law activated via a `uses` edge or `always_on` is in the
    // system even with no surface occurrence). Sorted for stable output.
    let mut patterns: Vec<spec::model::PatternKind> = compiled
        .graph
        .active_kinds(&s.bindings)
        .into_iter()
        .collect();
    patterns.sort_by_key(|p| p.to_string());
    println!("patterns (with enforcement):");
    for p in &patterns {
        println!(
            "  {:<12} {}",
            p.to_string(),
            binding.enforcement_level(*p).as_str()
        );
    }

    // The resolved IR — the exact instance that was checked and generated
    // from: positions, operator edges, binding-sourced uses edges, and what
    // the composition does NOT activate.
    let g = &compiled.graph;
    println!("graph:");
    for n in g.nodes() {
        let inst = match (n.instance.as_deref(), n.alias.as_deref()) {
            (Some(i), Some(a)) => format!("[{i} as {a}]"),
            (Some(i), None) => format!("[{i}]"),
            (None, Some(a)) => format!("[as {a}]"),
            (None, None) => String::new(),
        };
        let repl = match n.multiplicity {
            spec::graph::Multiplicity::One => String::new(),
            spec::graph::Multiplicity::Exact(k) => format!("  (× {k})"),
        };
        println!(
            "  node {}: {}{}  bindings[{}]{}",
            n.id.0,
            n.kind,
            inst,
            n.bindings.join(", "),
            repl
        );
    }
    for e in g.edges() {
        println!("  edge: {} -{}-> {}", e.from.0, e.relation.as_str(), e.to.0);
    }
    for u in g.uses() {
        println!(
            "  uses: {}[{}] -{}-> {}[{}]  (from {})",
            u.from.0,
            u.from.1,
            u.kind.as_str(),
            u.to.0,
            u.to.1,
            u.kind.origin()
        );
    }
    for c in g.component_inventory(&s.bindings) {
        let origins: Vec<String> = c.origins.iter().map(|o| o.as_str()).collect();
        let name = match c.key.id() {
            Some(id) => format!("{}[{}]", c.key.kind(), id),
            None => format!("{} (singleton)", c.key.kind()),
        };
        if c.active {
            println!("  active:   {name}  via {}", origins.join(", "));
        } else {
            println!("  inactive: {name}  (not activated; excluded from generation)");
        }
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
