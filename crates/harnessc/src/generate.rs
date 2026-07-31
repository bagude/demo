//! The Claude Code back-end: turn a compiled spec into Playbook files.
//!
//! Every file carries a provenance header naming the spec it came from and the
//! spec's hash, so the source-of-truth hierarchy stays legible: edits flow
//! *down* from the spec, never up from a generated file. The generator is a
//! pure function from (compiled spec, spec hash) to a set of files; writing
//! them to disk is the caller's job.

use serde_json::{json, Value};
use spec::model::{LawEvent, SpecFile};
use spec::CompiledSpec;

/// The generator version, stamped into every provenance header.
pub const GENERATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The spec file name generated artifacts point back to.
pub const SPEC_FILENAME: &str = "harness.patterns.yaml";

/// One generated file: a repo-relative path and its full contents.
#[derive(Debug, Clone)]
pub struct GenFile {
    pub path: String,
    pub content: String,
}

/// The complete set of files for a Playbook.
#[derive(Debug, Clone)]
pub struct Generated {
    pub files: Vec<GenFile>,
}

struct Ctx<'a> {
    spec: &'a SpecFile,
    spec_hash: &'a str,
}

/// Generate a Claude Code Playbook from a compiled spec and the hash of the
/// spec file it came from.
pub fn generate(compiled: &CompiledSpec, spec_hash: &str) -> Generated {
    let ctx = Ctx {
        spec: &compiled.spec,
        spec_hash,
    };
    let mut files = Vec::new();

    files.push(ctx.claude_md());
    files.push(ctx.settings_json());
    if let Some(verb) = &ctx.spec.bindings.verb {
        files.push(ctx.command_md(&verb.command, &verb.name, &verb.accepts, &verb.produces));
    }
    files.extend(ctx.schema_files());
    files.extend(ctx.hook_files());
    if let Some(gate) = &ctx.spec.bindings.gate {
        files.push(ctx.gate_file(gate));
    }
    files.extend(ctx.directories());
    files.push(ctx.harness_readme());

    Generated { files }
}

impl Ctx<'_> {
    fn hash_line(&self) -> String {
        format!("SPEC HASH: {}", self.spec_hash)
    }

    /// A `#`-style provenance header for shell/YAML files.
    fn hash_header(&self) -> String {
        format!(
            "# GENERATED FROM: {SPEC_FILENAME}\n# {}\n# GENERATOR: harnessc {GENERATOR_VERSION}\n# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.\n",
            self.hash_line()
        )
    }

    /// An HTML-comment provenance header for Markdown files.
    fn md_header(&self) -> String {
        format!(
            "<!--\n  GENERATED FROM: {SPEC_FILENAME}\n  {}\n  GENERATOR: harnessc {GENERATOR_VERSION}\n  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.\n-->\n",
            self.hash_line()
        )
    }

    /// The `_generated` metadata object embedded in generated JSON files.
    fn json_provenance(&self) -> Value {
        json!({
            "from": SPEC_FILENAME,
            "spec_hash": self.spec_hash,
            "generator": format!("harnessc {GENERATOR_VERSION}"),
            "note": "DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`."
        })
    }

    fn json_file(&self, path: &str, mut body: Value) -> GenFile {
        if let Value::Object(map) = &mut body {
            // Insert provenance first so it reads at the top of the file.
            let mut with_prov = serde_json::Map::new();
            with_prov.insert("_generated".to_string(), self.json_provenance());
            for (k, v) in map.iter() {
                with_prov.insert(k.clone(), v.clone());
            }
            body = Value::Object(with_prov);
        }
        GenFile {
            path: path.to_string(),
            content: format!("{}\n", serde_json::to_string_pretty(&body).unwrap()),
        }
    }

    fn claude_md(&self) -> GenFile {
        let s = self.spec;
        let mut body = String::new();
        body.push_str(&self.md_header());
        body.push('\n');
        body.push_str(&format!("# {} — harness boot context\n\n", s.harness.name));
        body.push_str(&format!(
            "This CLAUDE.md is a compiled artifact of the **{}** pattern harness \
             (version {}). It is the Boot Context role of the pattern language, \
             bound to Claude Code.\n\n",
            s.harness.name, s.harness.version
        ));
        body.push_str("## Composition in force\n\n");
        body.push_str(&format!("```\n{}\n```\n\n", s.composition.expression));
        body.push_str(
            "Work enters this system **only** as a typed task packet admitted through \
             the Intake. Loose conversation is not an entry path.\n\n",
        );

        body.push_str("## Laws in force\n\n");
        if s.bindings.laws.is_empty() {
            body.push_str("_None declared._\n\n");
        } else {
            for law in &s.bindings.laws {
                let enforcement = match law.id.as_str() {
                    "enforce-file-scope" => {
                        "**enforced** — the kernel blocks edits outside the packet's write scope"
                    }
                    "require-validation" => {
                        "**recorded** — the kernel logs the obligation to the Ledger after each edit"
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

        if let Some(gate) = &s.bindings.gate {
            body.push_str("## Gate\n\n");
            body.push_str(&format!(
                "`{}` halts at **{}**. Approval binds to: {}. A change to the action \
                 or any bound precondition invalidates approval and requires renewal.\n\n",
                gate.id,
                gate.boundary,
                gate.bind.join(", ")
            ));
        }

        if let Some(ledger) = &s.bindings.ledger {
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

    fn settings_json(&self) -> GenFile {
        let mut pre: Vec<Value> = Vec::new();
        let mut post: Vec<Value> = Vec::new();

        for law in &self.spec.bindings.laws {
            let matcher = tool_matcher(&law.applies_to);
            let command = self.hook_path(law);
            let entry = json!({
                "matcher": matcher,
                "hooks": [ { "type": "command", "command": command } ]
            });
            match law.event {
                LawEvent::PreTool => pre.push(entry),
                LawEvent::PostTool => post.push(entry),
            }
        }

        let mut hooks = serde_json::Map::new();
        if !pre.is_empty() {
            hooks.insert("PreToolUse".to_string(), Value::Array(pre));
        }
        if !post.is_empty() {
            hooks.insert("PostToolUse".to_string(), Value::Array(post));
        }

        let body = json!({
            "permissions": { "allow": [], "deny": [] },
            "hooks": Value::Object(hooks),
        });
        self.json_file(".claude/settings.json", body)
    }

    fn command_md(&self, path: &str, name: &str, accepts: &str, produces: &str) -> GenFile {
        let mut body = String::new();
        body.push_str(&self.md_header());
        body.push('\n');
        body.push_str(&format!("# /{name}\n\n"));
        body.push_str(&format!(
            "The Verb of this harness. Consumes a `{accepts}` and produces a `{produces}`.\n\n"
        ));
        body.push_str("## Contract\n\n");
        body.push_str(
            "1. Read the active task packet from the Intake storage. If none is active, stop and ask.\n\
             2. Do the work described by the packet's objective, staying within its constraints.\n\
             3. Every edit you make is checked by `enforce-file-scope`: only files the packet lists \
                with `access: write` may be edited. If you need another file, the packet is wrong — \
                stop and revise it, do not work around the Law.\n\
             4. Satisfy every acceptance criterion and record evidence to the Ledger.\n\
             5. At the commit boundary, the Gate will halt for approval. Do not attempt to bypass it.\n",
        );
        GenFile {
            path: path.to_string(),
            content: body,
        }
    }

    fn schema_files(&self) -> Vec<GenFile> {
        let mut out = Vec::new();
        if let Some(intake) = &self.spec.bindings.intake {
            out.push(self.json_file(&intake.task_schema, task_packet_schema()));
        }
        if let Some(gate) = &self.spec.bindings.gate {
            out.push(self.json_file(&gate.checkpoint_schema, checkpoint_schema()));
        }
        if let Some(ledger) = &self.spec.bindings.ledger {
            out.push(self.json_file(&ledger.event_schema, event_schema()));
        }
        out
    }

    fn hook_path(&self, law: &spec::model::LawBinding) -> String {
        law.implementation
            .clone()
            .unwrap_or_else(|| format!("harness/hooks/{}.sh", law.id.replace('-', "_")))
    }

    fn hook_files(&self) -> Vec<GenFile> {
        let ledger_dest = self
            .spec
            .bindings
            .ledger
            .as_ref()
            .map(|l| l.destination.clone())
            .unwrap_or_else(|| "evidence/events.jsonl".to_string());
        let packet = self
            .spec
            .bindings
            .intake
            .as_ref()
            .map(|i| format!("{}active.json", ensure_trailing_slash(&i.storage)))
            .unwrap_or_else(|| "tasks/active.json".to_string());

        let mut out = Vec::new();
        for law in &self.spec.bindings.laws {
            let path = self.hook_path(law);
            // The shebang must be the first line so the script is directly
            // executable by Claude Code; the provenance header follows it.
            let body = match law.id.as_str() {
                "enforce-file-scope" => format!(
                    "#!/usr/bin/env bash\n{header}# Guard Law: block edits outside the active packet's write scope.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-tool \\\n  --packet \"${{INTAKE_ACTIVE_PACKET:-{packet}}}\" \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\"\n",
                    header = self.hash_header(),
                    packet = packet,
                    ledger = ledger_dest,
                ),
                "require-validation" => format!(
                    "#!/usr/bin/env bash\n{header}# Obligation Law: record to the Ledger that validation is now owed after an edit.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" post-tool \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\"\n",
                    header = self.hash_header(),
                    ledger = ledger_dest,
                ),
                other => format!(
                    "#!/usr/bin/env bash\n{header}# Law '{other}' has no kernel binding.\necho 'law {other} is not implemented by the kernel' >&2\nexit 1\n",
                    header = self.hash_header(),
                ),
            };
            out.push(GenFile {
                path,
                content: body,
            });
        }
        out
    }

    fn gate_file(&self, gate: &spec::model::GateBinding) -> GenFile {
        let body = json!({
            "id": gate.id,
            "boundary": gate.boundary,
            "checkpoint_schema": gate.checkpoint_schema,
            "bind": gate.bind,
        });
        self.json_file(&format!("harness/gates/{}.json", gate.id), body)
    }

    fn directories(&self) -> Vec<GenFile> {
        let mut dirs = Vec::new();
        if let Some(intake) = &self.spec.bindings.intake {
            dirs.push(ensure_trailing_slash(&intake.storage));
        }
        if let Some(ledger) = &self.spec.bindings.ledger {
            if let Some((dir, _)) = ledger.destination.rsplit_once('/') {
                dirs.push(format!("{dir}/"));
            }
        }
        if self.spec.bindings.gate.is_some() {
            dirs.push("checkpoints/".to_string());
        }
        dirs.sort();
        dirs.dedup();
        dirs.into_iter()
            .map(|d| GenFile {
                path: format!("{d}.gitkeep"),
                content: format!(
                    "# GENERATED FROM: {SPEC_FILENAME}\n# {}\n# Runtime directory kept in version control; contents are runtime state.\n",
                    self.hash_line()
                ),
            })
            .collect()
    }

    fn harness_readme(&self) -> GenFile {
        let mut body = String::new();
        body.push_str(&self.md_header());
        body.push('\n');
        body.push_str("# harness/ — compiled Playbook\n\n");
        body.push_str(&format!(
            "Compiled from `{SPEC_FILENAME}` (spec hash `{}`) by `harnessc {GENERATOR_VERSION}`.\n\n",
            self.spec_hash
        ));
        body.push_str("## Regenerating\n\n");
        body.push_str("```sh\nharnessc check   # validate the spec\nharnessc build   # regenerate this Playbook\n```\n\n");
        body.push_str("## Enforcement honesty\n\n");
        body.push_str(
            "- `enforce-file-scope` is **enforced**: the kernel exits non-zero and blocks the tool \
               call for any edit outside the packet's write scope.\n\
             - `require-validation` is **recorded**: the kernel appends an obligation event after each \
               edit. Discharging that obligation (e.g. gating the commit on it) is a documented next \
               step, not yet enforced end-to-end.\n\
             - The `Gate` checkpoint, approval binding, and precondition revalidation are enforced by \
               the kernel's `gate` subcommands.\n\n\
             Nothing here claims a guarantee the kernel does not actually provide.\n",
        );
        GenFile {
            path: "harness/README.md".to_string(),
            content: body,
        }
    }
}

fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
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
            // `delete` has no first-class Claude Code tool; it is intentionally
            // dropped rather than mapped to a matcher that wouldn't fire.
            "delete" => None,
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

fn task_packet_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "TaskPacket",
        "type": "object",
        "required": ["title", "objective", "submitted_by"],
        "additionalProperties": false,
        "properties": {
            "title": { "type": "string", "minLength": 1 },
            "objective": { "type": "string", "minLength": 12 },
            "constraints": { "type": "array", "items": { "type": "string" } },
            "files": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["path"],
                    "additionalProperties": false,
                    "properties": {
                        "path": { "type": "string", "minLength": 1 },
                        "access": { "enum": ["read", "write"], "default": "read" }
                    }
                }
            },
            "acceptance_criteria": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
            "submitted_by": { "type": "string", "minLength": 1 },
            "priority": { "enum": ["low", "medium", "high", "critical"], "default": "medium" }
        }
    })
}

fn checkpoint_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Checkpoint",
        "type": "object",
        "required": ["gate_id", "run_id", "action_hash", "action_summary", "continuation", "created_at"],
        "properties": {
            "gate_id": { "type": "string" },
            "run_id": { "type": "string" },
            "task_id": { "type": "string" },
            "action_hash": { "type": "string" },
            "action_summary": { "type": "string" },
            "preconditions": { "type": "object", "additionalProperties": { "type": "string" } },
            "continuation": { "type": "string" },
            "created_at": { "type": "string" },
            "approval": {
                "type": "object",
                "required": ["approver", "action_hash", "approved_at"],
                "properties": {
                    "approver": { "type": "string" },
                    "action_hash": { "type": "string" },
                    "preconditions": { "type": "object", "additionalProperties": { "type": "string" } },
                    "approved_at": { "type": "string" },
                    "expiry": { "type": "string" }
                }
            }
        }
    })
}

fn event_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Event",
        "type": "object",
        "required": ["run_id", "action_id", "actor", "timestamp", "transition", "decision"],
        "properties": {
            "run_id": { "type": "string" },
            "task_id": { "type": "string" },
            "parent_task_id": { "type": "string" },
            "action_id": { "type": "string" },
            "actor": { "type": "string" },
            "timestamp": { "type": "string" },
            "transition": { "type": "string" },
            "input_refs": { "type": "array", "items": { "type": "string" } },
            "output_refs": { "type": "array", "items": { "type": "string" } },
            "decision": { "enum": ["allowed", "denied", "approved", "rejected", "recorded"] },
            "evidence_refs": { "type": "array", "items": { "type": "string" } }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPECIMEN: &str = include_str!("../../../harness.patterns.yaml");

    fn build() -> Generated {
        let compiled = spec::compile(SPECIMEN).expect("specimen compiles");
        generate(&compiled, "sha256:test")
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
        let g = build();
        for file in &g.files {
            assert!(
                file.content.contains("sha256:test"),
                "{} is missing its provenance header",
                file.path
            );
        }
    }

    #[test]
    fn settings_registers_the_guard_hook() {
        let g = build();
        let settings = find(&g, ".claude/settings.json");
        assert!(settings.content.contains("PreToolUse"));
        assert!(settings.content.contains("enforce_file_scope.sh"));
    }

    #[test]
    fn shell_hooks_start_with_a_shebang() {
        let g = build();
        for file in &g.files {
            if file.path.ends_with(".sh") {
                assert!(
                    file.content.starts_with("#!/usr/bin/env bash\n"),
                    "{} must start with a shebang to be directly executable",
                    file.path
                );
            }
        }
    }

    #[test]
    fn generated_json_is_valid() {
        let g = build();
        for file in &g.files {
            if file.path.ends_with(".json") {
                let _: Value = serde_json::from_str(&file.content)
                    .unwrap_or_else(|e| panic!("{} is invalid JSON: {e}", file.path));
            }
        }
    }
}
