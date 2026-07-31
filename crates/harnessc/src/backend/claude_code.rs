//! The Claude Code back-end.
//!
//! Binds the seven roles to Claude Code: CLAUDE.md (Boot Context), `.claude/`
//! commands and settings (Invocable Workflow + hook registration), and
//! `harness/` hooks that shell out to the trusted `kernel`.

use serde_json::{json, Value};
use spec::model::{GateBinding, LawBinding, LawEvent, SpecFile};
use spec::{Binding, CompiledSpec};

use crate::backend::Backend;
use crate::common::{
    self, active_packet_path, ledger_destination, runtime_dirs, schema_files, GenFile, Generated,
    Prov,
};

/// The commit-boundary hook path (the Gate's enforcement point).
const APPROVE_COMMIT_HOOK: &str = "harness/hooks/approve_commit.sh";

pub struct ClaudeCode;

impl Binding for ClaudeCode {
    fn platform(&self) -> &str {
        "claude-code"
    }
    fn supports_law(&self, law_id: &str) -> bool {
        matches!(law_id, "enforce-file-scope" | "require-validation")
    }
    fn dischargeable_obligations(&self) -> &[&str] {
        &["require-validation"]
    }
}

impl Backend for ClaudeCode {
    fn as_binding(&self) -> &dyn Binding {
        self
    }

    fn generate(&self, compiled: &CompiledSpec, spec_hash: &str) -> Generated {
        let spec = &compiled.spec;
        let prov = Prov { spec_hash };
        let mut files = Vec::new();

        files.push(claude_md(&prov, spec));
        files.push(settings_json(&prov, spec));
        if let Some(verb) = &spec.bindings.verb {
            files.push(command_md(
                &prov,
                &verb.command,
                &verb.name,
                &verb.accepts,
                &verb.produces,
            ));
        }
        files.extend(schema_files(&prov, spec));
        files.extend(hook_files(&prov, spec));
        if let Some(gate) = &spec.bindings.gate {
            files.push(gate_file(&prov, gate));
        }
        for dir in runtime_dirs(spec) {
            files.push(prov.gitkeep(&dir));
        }
        files.push(harness_readme(&prov, spec_hash));

        Generated { files }
    }
}

fn hook_path(law: &LawBinding) -> String {
    law.implementation
        .clone()
        .unwrap_or_else(|| format!("harness/hooks/{}.sh", law.id.replace('-', "_")))
}

/// The obligations the commit Gate enforces, if any.
fn gate_obligations(spec: &SpecFile) -> Vec<String> {
    spec.bindings
        .gate
        .as_ref()
        .map(|g| g.requires_obligations.clone())
        .unwrap_or_default()
}

fn claude_md(prov: &Prov, spec: &SpecFile) -> GenFile {
    let mut body = String::new();
    body.push_str(&prov.md_header());
    body.push('\n');
    body.push_str(&format!(
        "# {} — harness boot context\n\n",
        spec.harness.name
    ));
    body.push_str(&format!(
        "This CLAUDE.md is a compiled artifact of the **{}** pattern harness \
         (version {}). It is the Boot Context role, bound to Claude Code.\n\n",
        spec.harness.name, spec.harness.version
    ));
    body.push_str("## Composition in force\n\n");
    body.push_str(&format!("```\n{}\n```\n\n", spec.composition.expression));
    body.push_str(
        "Work enters this system **only** as a typed task packet admitted through \
         the Intake. Loose conversation is not an entry path.\n\n",
    );

    body.push_str("## Laws in force\n\n");
    if spec.bindings.laws.is_empty() {
        body.push_str("_None declared._\n\n");
    } else {
        for law in &spec.bindings.laws {
            let enforcement = match law.id.as_str() {
                "enforce-file-scope" => {
                    "**enforced** — the kernel blocks edits outside the packet's write scope"
                }
                "require-validation" => {
                    "**enforced via the Gate** — recorded after each edit and required clear before commit"
                }
                _ => "declared",
            };
            body.push_str(&format!(
                "- `{}` ({:?} at {:?}, applies to {}): {}\n",
                law.id,
                law.kind,
                law.event,
                law.applies_to.join(", "),
                enforcement
            ));
        }
        body.push('\n');
    }

    if let Some(gate) = &spec.bindings.gate {
        body.push_str("## Gate\n\n");
        body.push_str(&format!(
            "`{}` halts at **{}**. Approval binds to: {}. A change to the action \
             or any bound precondition invalidates approval.\n\n",
            gate.id,
            gate.boundary,
            gate.bind.join(", ")
        ));
        if !gate.requires_obligations.is_empty() {
            body.push_str(&format!(
                "A commit is blocked until these obligations are discharged: {}. \
                 Run the validation step (`kernel validate`) to discharge.\n\n",
                gate.requires_obligations.join(", ")
            ));
        }
    }

    if let Some(ledger) = &spec.bindings.ledger {
        body.push_str("## Ledger\n\n");
        body.push_str(&format!(
            "Governed actions and decisions are appended to `{}`. Redacted: {}.\n\n",
            ledger.destination,
            ledger.redact.join(", ")
        ));
    }

    body.push_str("## How enforcement works\n\n");
    body.push_str(
        "Hooks in `.claude/settings.json` invoke the trusted `kernel` binary. The \
         model proposes actions; the kernel disposes. Do not attempt to satisfy a \
         Law by describing compliance — the check runs in code regardless.\n",
    );

    GenFile {
        path: "CLAUDE.md".to_string(),
        content: body,
    }
}

fn settings_json(prov: &Prov, spec: &SpecFile) -> GenFile {
    let mut pre: Vec<Value> = Vec::new();
    let mut post: Vec<Value> = Vec::new();

    for law in &spec.bindings.laws {
        let entry = json!({
            "matcher": tool_matcher(&law.applies_to),
            "hooks": [ { "type": "command", "command": hook_path(law) } ]
        });
        match law.event {
            LawEvent::PreTool => pre.push(entry),
            LawEvent::PostTool => post.push(entry),
        }
    }

    // The commit Gate is a pre-tool interceptor on Bash.
    if !gate_obligations(spec).is_empty() {
        pre.push(json!({
            "matcher": "Bash",
            "hooks": [ { "type": "command", "command": APPROVE_COMMIT_HOOK } ]
        }));
    }

    let mut hooks = serde_json::Map::new();
    if !pre.is_empty() {
        hooks.insert("PreToolUse".to_string(), Value::Array(pre));
    }
    if !post.is_empty() {
        hooks.insert("PostToolUse".to_string(), Value::Array(post));
    }

    prov.json_file(
        ".claude/settings.json",
        json!({
            "permissions": { "allow": [], "deny": [] },
            "hooks": Value::Object(hooks),
        }),
    )
}

fn command_md(prov: &Prov, path: &str, name: &str, accepts: &str, produces: &str) -> GenFile {
    let mut body = String::new();
    body.push_str(&prov.md_header());
    body.push('\n');
    body.push_str(&format!("# /{name}\n\n"));
    body.push_str(&format!(
        "The Verb of this harness. Consumes a `{accepts}` and produces a `{produces}`.\n\n"
    ));
    body.push_str("## Contract\n\n");
    body.push_str(
        "1. Read the active task packet from the Intake storage. If none is active, stop and ask.\n\
         2. Do the work described by the packet's objective, staying within its constraints.\n\
         3. Every edit is checked by `enforce-file-scope`: only files the packet lists with \
            `access: write` may be edited. If you need another file, the packet is wrong — stop \
            and revise it, do not work around the Law.\n\
         4. Satisfy every acceptance criterion, then run the validation step to discharge the \
            `require-validation` obligation. Until you do, the commit Gate will block.\n\
         5. At the commit boundary the Gate halts for approval. Do not attempt to bypass it.\n",
    );
    GenFile {
        path: path.to_string(),
        content: body,
    }
}

fn hook_files(prov: &Prov, spec: &SpecFile) -> Vec<GenFile> {
    let ledger = ledger_destination(spec);
    let packet = active_packet_path(spec);
    let mut out = Vec::new();

    for law in &spec.bindings.laws {
        let path = hook_path(law);
        let body = match law.id.as_str() {
            "enforce-file-scope" => format!(
                "#!/usr/bin/env bash\n{header}# Guard Law: block edits outside the active packet's write scope.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-tool \\\n  --packet \"${{INTAKE_ACTIVE_PACKET:-{packet}}}\" \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\"\n",
                header = prov.hash_header(),
            ),
            "require-validation" => format!(
                "#!/usr/bin/env bash\n{header}# Obligation Law: record to the Ledger that validation is owed after an edit.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" post-tool \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\"\n",
                header = prov.hash_header(),
            ),
            other => format!(
                "#!/usr/bin/env bash\n{header}# Law '{other}' has no kernel binding.\necho 'law {other} is not implemented by the kernel' >&2\nexit 1\n",
                header = prov.hash_header(),
            ),
        };
        out.push(GenFile {
            path,
            content: body,
        });
    }

    // The commit-boundary Gate hook.
    let obligations = gate_obligations(spec);
    if !obligations.is_empty() {
        let requires: String = obligations
            .iter()
            .map(|o| format!(" --require {o}"))
            .collect();
        out.push(GenFile {
            path: APPROVE_COMMIT_HOOK.to_string(),
            content: format!(
                "#!/usr/bin/env bash\n{header}# Gate: block `git commit` while a required obligation is outstanding.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-commit --ledger \"{ledger}\"{requires}\n",
                header = prov.hash_header(),
            ),
        });
    }
    out
}

fn gate_file(prov: &Prov, gate: &GateBinding) -> GenFile {
    prov.json_file(
        &format!("harness/gates/{}.json", gate.id),
        json!({
            "id": gate.id,
            "boundary": gate.boundary,
            "checkpoint_schema": gate.checkpoint_schema,
            "bind": gate.bind,
            "requires_obligations": gate.requires_obligations,
        }),
    )
}

fn harness_readme(prov: &Prov, spec_hash: &str) -> GenFile {
    let mut body = String::new();
    body.push_str(&prov.md_header());
    body.push('\n');
    body.push_str("# harness/ — compiled Playbook (claude-code)\n\n");
    body.push_str(&format!(
        "Compiled from `{}` (spec hash `{}`) by `harnessc {}`.\n\n",
        common::SPEC_FILENAME,
        spec_hash,
        common::GENERATOR_VERSION
    ));
    body.push_str(
        "## Regenerating\n\n```sh\nharnessc check\nharnessc build --target claude-code\n```\n\n",
    );
    body.push_str("## Enforcement honesty\n\n");
    body.push_str(
        "- `enforce-file-scope` is **enforced**: the kernel blocks (exit 2) any edit outside the \
           packet's write scope and logs the decision.\n\
         - `require-validation` is **enforced via the Gate**: an obligation is recorded after each \
           edit, and `approve_commit.sh` blocks `git commit` (exit 2) until it is discharged by the \
           validation step.\n\
         - The `Gate` checkpoint, approval binding, and precondition revalidation are enforced by \
           the kernel's `gate` subcommands.\n\n\
         Nothing here claims a guarantee the kernel does not provide.\n",
    );
    GenFile {
        path: "harness/README.md".to_string(),
        content: body,
    }
}

/// Map a Law's abstract `applies_to` tokens to a Claude Code tool-name matcher.
fn tool_matcher(applies_to: &[String]) -> String {
    let mut names: Vec<String> = Vec::new();
    for token in applies_to {
        let mapped = match token.to_ascii_lowercase().as_str() {
            "edit" => Some("Edit"),
            "write" => Some("Write"),
            "multiedit" => Some("MultiEdit"),
            "notebookedit" => Some("NotebookEdit"),
            // `delete` has no first-class Claude Code tool; dropped rather than
            // mapped to a matcher that wouldn't fire.
            _ => None,
        };
        if let Some(m) = mapped {
            if !names.iter().any(|n| n == m) {
                names.push(m.to_string());
            }
        }
    }
    if names.is_empty() {
        "Edit|Write".to_string()
    } else {
        names.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPECIMEN: &str = include_str!("../../../../harness.patterns.yaml");

    fn build() -> Generated {
        let compiled = spec::compile(SPECIMEN, &ClaudeCode).expect("specimen compiles");
        ClaudeCode.generate(&compiled, "sha256:test")
    }

    fn find<'a>(g: &'a Generated, path: &str) -> &'a GenFile {
        g.files
            .iter()
            .find(|f| f.path == path)
            .unwrap_or_else(|| panic!("missing {path}"))
    }

    #[test]
    fn generates_the_core_playbook_files() {
        let g = build();
        for path in ["CLAUDE.md", ".claude/settings.json", "harness/README.md"] {
            let _ = find(&g, path);
        }
    }

    #[test]
    fn every_file_carries_provenance() {
        for file in &build().files {
            assert!(
                file.content.contains("sha256:test"),
                "{} lacks provenance",
                file.path
            );
        }
    }

    #[test]
    fn settings_registers_guard_and_commit_gate_hooks() {
        let g = build();
        let settings = &find(&g, ".claude/settings.json").content;
        assert!(settings.contains("PreToolUse"));
        assert!(settings.contains("enforce_file_scope.sh"));
        assert!(settings.contains("approve_commit.sh"));
    }

    #[test]
    fn commit_gate_hook_requires_the_obligation() {
        let g = build();
        let hook = &find(&g, APPROVE_COMMIT_HOOK).content;
        assert!(hook.contains("pre-commit"));
        assert!(hook.contains("--require require-validation"));
    }

    #[test]
    fn shell_hooks_start_with_a_shebang() {
        for file in &build().files {
            if file.path.ends_with(".sh") {
                assert!(
                    file.content.starts_with("#!/usr/bin/env bash\n"),
                    "{}",
                    file.path
                );
            }
        }
    }

    #[test]
    fn generated_json_is_valid() {
        for file in &build().files {
            if file.path.ends_with(".json") {
                let _: Value = serde_json::from_str(&file.content)
                    .unwrap_or_else(|e| panic!("{} invalid JSON: {e}", file.path));
            }
        }
    }
}
