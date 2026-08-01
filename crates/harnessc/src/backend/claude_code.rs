//! The Claude Code back-end.
//!
//! Binds the seven roles to Claude Code: CLAUDE.md (Boot Context), `.claude/`
//! commands and settings (Invocable Workflow + hook registration), and
//! `harness/` hooks that shell out to the trusted `kernel`.

use serde_json::{json, Value};
use spec::model::{
    DelegateBinding, GateBinding, HiveBinding, LawBinding, LawEvent, PipelineBinding, PortBinding,
    SpecFile, SpecialistBinding,
};
use spec::{Binding, CompiledSpec};

use crate::backend::Backend;
use crate::common::{
    self, active_packet_path, ledger_destination, runtime_dirs, schema_files, GenFile, Generated,
    Prov,
};

/// The commit-boundary hook path (the Gate's enforcement point).
const APPROVE_COMMIT_HOOK: &str = "harness/hooks/approve_commit.sh";
/// The Bash self-protection hook path.
const PROTECT_HOOK: &str = "harness/hooks/protect_enforcement.sh";
/// The file listing protected enforcement-artifact prefixes.
const PROTECTED_FILE: &str = "harness/enforcement.protected";

/// Enforcement artifacts protected from ambient amendment (constitution §4).
/// These are the paths a compiled claude-code Playbook writes, plus the spec.
fn protected_prefixes() -> [&'static str; 3] {
    ["harness.patterns.yaml", ".claude/", "harness/"]
}

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
        files.push(protected_file(&prov));
        if let Some(gate) = &spec.bindings.gate {
            files.push(gate_file(&prov, gate));
        }
        files.extend(pattern_files(&prov, spec));
        files.push(playbook_manifest(&prov, compiled));
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
                    "**enforced** — the kernel blocks edits outside the packet's write scope; \
                     enforcement artifacts additionally require an explicit `amends_enforcement` grant"
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

    // Bash pre-tool interceptors: self-protection always, plus the commit Gate
    // when the harness has obligations to discharge.
    let mut bash_hooks = vec![json!({ "type": "command", "command": PROTECT_HOOK })];
    if !gate_obligations(spec).is_empty() {
        bash_hooks.push(json!({ "type": "command", "command": APPROVE_COMMIT_HOOK }));
    }
    pre.push(json!({ "matcher": "Bash", "hooks": bash_hooks }));

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
                "#!/usr/bin/env bash\n{header}# Guard Law: block edits outside the active packet's write scope\n# (and protect enforcement artifacts unless amends_enforcement is granted).\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-tool \\\n  --packet \"${{INTAKE_ACTIVE_PACKET:-{packet}}}\" \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\" \\\n  --playbook-ref \"{playbook}\" \\\n  --protected \"{protected}\"\n",
                header = prov.hash_header(),
                playbook = prov.spec_hash,
                protected = PROTECTED_FILE,
            ),
            "require-validation" => format!(
                "#!/usr/bin/env bash\n{header}# Obligation Law: record to the Ledger that validation is owed after an edit.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" post-tool \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\" \\\n  --playbook-ref \"{playbook}\"\n",
                header = prov.hash_header(),
                playbook = prov.spec_hash,
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
                "#!/usr/bin/env bash\n{header}# Gate: block `git commit` while a required obligation is outstanding (per run).\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-commit --ledger \"{ledger}\" --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\"{requires}\n",
                header = prov.hash_header(),
            ),
        });
    }

    // Bash self-protection hook: block destructive commands against enforcement
    // artifacts unless the active packet grants amends_enforcement.
    out.push(GenFile {
        path: PROTECT_HOOK.to_string(),
        content: format!(
            "#!/usr/bin/env bash\n{header}# Self-protection: block `rm`/`mv`/redirect against enforcement artifacts.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-bash \\\n  --packet \"${{INTAKE_ACTIVE_PACKET:-{packet}}}\" \\\n  --protected \"{protected}\" \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\" \\\n  --playbook-ref \"{playbook}\"\n",
            header = prov.hash_header(),
            protected = PROTECTED_FILE,
            playbook = prov.spec_hash,
        ),
    });
    out
}

/// Generate the Claude Code artifacts for the scale/interaction patterns.
fn pattern_files(prov: &Prov, spec: &SpecFile) -> Vec<GenFile> {
    let b = &spec.bindings;
    let mut out = Vec::new();

    for s in &b.specialists {
        out.push(specialist_skill(prov, s));
    }
    for dg in &b.delegates {
        out.push(delegate_agent(prov, dg));
        out.push(prov.json_file(&dg.contract_schema, delegate_contract_schema(dg)));
    }
    for p in &b.pipelines {
        out.push(pipeline_command(prov, p));
    }
    for h in &b.hives {
        out.push(hive_orchestrator(prov, h));
    }
    if !b.ports.is_empty() {
        out.push(mcp_config(prov, &b.ports));
        out.push(ports_manifest(prov, &b.ports));
    }
    out
}

fn specialist_skill(prov: &Prov, s: &SpecialistBinding) -> GenFile {
    let mut body = prov.md_header();
    body.push('\n');
    body.push_str(&format!(
        "---\nname: {}\ndescription: {}\n---\n\n# {}\n\nDemand-loaded knowledge (a Specialist). This SKILL.md is present only when the \
         task calls for it. Fill in the domain expertise below.\n",
        s.id, s.description, s.id
    ));
    GenFile {
        path: s.skill.clone(),
        content: body,
    }
}

fn delegate_agent(prov: &Prov, dg: &DelegateBinding) -> GenFile {
    let mut body = prov.md_header();
    body.push('\n');
    let role = if dg.critic {
        "Critic (judges work it did not produce)"
    } else {
        "Delegate"
    };
    body.push_str(&format!(
        "# {} — {}\n\nA Nested Executor with a fresh context and a narrow mandate.\n\n\
         - **Delegated authority (tools):** {}\n- **Ports:** {}\n- **Return contract:** `{}` — \
         results MUST conform to this schema; narrative belongs *inside* typed fields, never as an \
         unstructured return.\n",
        dg.id,
        role,
        dg.tools.join(", "),
        if dg.ports.is_empty() {
            "none".to_string()
        } else {
            dg.ports.join(", ")
        },
        dg.contract_schema,
    ));
    GenFile {
        path: dg.agent.clone(),
        content: body,
    }
}

fn delegate_contract_schema(dg: &DelegateBinding) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("{}Result", dg.id),
        "type": "object",
        "description": "The typed contract a delegate returns against — never unstructured prose.",
        "required": ["result"],
        "properties": {
            "result": { "type": "object" },
            "sources": { "type": "array", "items": { "type": "string" } },
            "confidence": { "type": "number", "minimum": 0, "maximum": 1 }
        }
    })
}

fn pipeline_command(prov: &Prov, p: &PipelineBinding) -> GenFile {
    let mut body = prov.md_header();
    body.push('\n');
    body.push_str(&format!(
        "# /{}\n\nA Pipeline: control flow fixed at write-time; each stage \
        consumes and produces typed artifacts. The model exercises judgment *within* a stage but \
        cannot redefine the stage graph.\n\n## Stages\n\n",
        p.id
    ));
    for (i, st) in p.stages.iter().enumerate() {
        body.push_str(&format!(
            "{}. **{}** — consumes `{}`, produces `{}`\n",
            i + 1,
            st.name,
            st.consumes.as_deref().unwrap_or("—"),
            st.produces.as_deref().unwrap_or("—"),
        ));
    }
    GenFile {
        path: p.command.clone(),
        content: body,
    }
}

fn hive_orchestrator(prov: &Prov, h: &HiveBinding) -> GenFile {
    let mut body = prov.md_header();
    body.push('\n');
    body.push_str(&format!(
        "# /{} — Hive orchestrator\n\nCoordinates fan-out and merge. **{:?}** fan-out; workers are \
         `{}` delegates; results merge to `{}`.\n\n## Law of the Hive (enforced by the kernel)\n\n\
         Every spawned task must have a parent, a contract, a budget, a depth, a termination \
         condition, a merge destination, and a declared write scope. Before spawning, validate:\n\n\
         ```sh\n\
         echo \"$SPAWN_JSON\" | kernel hive-spawn --max-depth {} --budget-remaining $REMAINING\n\
         ```\n\n\
         Caps: budget {} · max depth {} · worker isolation {:?}.\n",
        h.id, h.fan_out, h.worker, h.merge, h.max_depth, h.budget, h.max_depth, h.worker_isolation,
    ));
    if let Some(scope) = h.approval_scope {
        body.push_str(&format!("\nGate approval scope: **{scope:?}**.\n"));
    }
    GenFile {
        path: h.orchestrator.clone(),
        content: body,
    }
}

fn mcp_config(prov: &Prov, ports: &[PortBinding]) -> GenFile {
    let mut servers = serde_json::Map::new();
    for p in ports {
        servers.insert(p.server.clone(), json!({ "command": p.server }));
    }
    prov.json_file(".mcp.json", json!({ "mcpServers": Value::Object(servers) }))
}

fn ports_manifest(prov: &Prov, ports: &[PortBinding]) -> GenFile {
    let entries: Vec<Value> = ports
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "server": p.server,
                "observe": p.observe,
                "write": p.write,
                "write_guard": p.write_guard,
                "credentials": p.credentials,
                "idempotent": p.idempotent,
                "sandboxed": p.sandboxed.map(|s| format!("{s:?}").to_lowercase()),
            })
        })
        .collect();
    prov.json_file("harness/ports.json", json!({ "ports": entries }))
}

/// The Playbook manifest — the reproducible harness bundle's identity: name,
/// version, spec digest, composition, and every bound pattern.
fn playbook_manifest(prov: &Prov, compiled: &CompiledSpec) -> GenFile {
    let spec = &compiled.spec;
    let mut patterns: Vec<String> = compiled
        .composition
        .patterns()
        .iter()
        .map(|p| p.to_string())
        .collect();
    patterns.sort();
    prov.json_file(
        "harness/playbook.json",
        json!({
            "name": spec.harness.name,
            "version": spec.harness.version,
            "playbook_ref": prov.spec_hash,
            "composition": spec.composition.expression,
            "patterns": patterns,
        }),
    )
}

fn protected_file(prov: &Prov) -> GenFile {
    let mut body = prov.hash_header();
    body.push_str("# Protected enforcement artifacts. A write to any of these requires a task\n");
    body.push_str(
        "# packet with amends_enforcement = true (an explicit, auditable Intake grant).\n",
    );
    for p in protected_prefixes() {
        body.push_str(p);
        body.push('\n');
    }
    GenFile {
        path: PROTECTED_FILE.to_string(),
        content: body,
    }
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
           the kernel's `gate` subcommands.\n\
         - **Self-protection**: the enforcement artifacts listed in `enforcement.protected` \
           (this tree and the spec) are default-deny like everything else; editing one requires a \
           packet with `amends_enforcement = true`, and `protect_enforcement.sh` blocks a `rm`/`mv` \
           of them via Bash. Amending enforcement is never an ambient capability.\n\n\
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
    fn emits_protected_set_and_self_protection_hook() {
        let g = build();
        let protected = &find(&g, PROTECTED_FILE).content;
        assert!(protected.contains("harness.patterns.yaml"));
        assert!(protected.contains(".claude/"));
        assert!(protected.contains("harness/"));

        let hook = &find(&g, PROTECT_HOOK).content;
        assert!(hook.contains("pre-bash"));
        assert!(hook.contains("--protected"));

        // The guard hook consults the protected set.
        assert!(find(&g, "harness/hooks/enforce_file_scope.sh")
            .content
            .contains("--protected"));
        // The Bash matcher is registered in settings.
        assert!(find(&g, ".claude/settings.json")
            .content
            .contains("protect_enforcement.sh"));
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
