//! A platform-neutral back-end.
//!
//! Proves the front-end/back-end split is real: the *same* `harness.patterns.yaml`
//! compiles here to a different shape. There is no `CLAUDE.md` and no
//! `.claude/settings.json` — those are Claude Code specifics. Instead a
//! `harness.manifest.json` declares the hook→event bindings so any runner can
//! wire the identical `kernel` invocations. The pattern program is stable; only
//! the binding changes.

use serde_json::{json, Value};
use spec::model::SpecFile;
use spec::{Binding, CompiledSpec};

use crate::backend::Backend;
use crate::common::{
    active_packet_path, checkpoint_schema, event_schema, ledger_destination, runtime_dirs,
    task_packet_schema, GenFile, Generated, Prov,
};

pub struct Portable;

impl Binding for Portable {
    fn platform(&self) -> &str {
        "portable"
    }
    fn supports_law(&self, law_id: &str) -> bool {
        // Same kernel, so the same laws are enforceable.
        matches!(law_id, "enforce-file-scope" | "require-validation")
    }
    fn dischargeable_obligations(&self) -> &[&str] {
        &["require-validation"]
    }
}

impl Backend for Portable {
    fn as_binding(&self) -> &dyn Binding {
        self
    }

    fn generate(&self, compiled: &CompiledSpec, spec_hash: &str) -> Generated {
        let spec = &compiled.spec;
        let prov = Prov { spec_hash };
        let mut files = Vec::new();

        files.push(manifest(&prov, compiled));
        files.extend(hook_files(&prov, spec));
        files.push(protected_file(&prov));
        // Schemas placed under a flat schemas/ dir — the backend owns layout.
        files.push(prov.json_file("schemas/task-packet.schema.json", task_packet_schema()));
        files.push(prov.json_file("schemas/checkpoint.schema.json", checkpoint_schema()));
        files.push(prov.json_file("schemas/event.schema.json", event_schema()));
        for dir in runtime_dirs(spec) {
            files.push(prov.gitkeep(&dir));
        }
        files.push(readme(&prov, spec_hash));

        Generated { files }
    }
}

fn gate_obligations(spec: &SpecFile) -> Vec<String> {
    spec.bindings
        .gate
        .as_ref()
        .map(|g| g.requires_obligations.clone())
        .unwrap_or_default()
}

fn manifest(prov: &Prov, compiled: &CompiledSpec) -> GenFile {
    let spec = &compiled.spec;
    let ledger = ledger_destination(spec);
    let packet = active_packet_path(spec);

    let laws: Vec<Value> = spec
        .bindings
        .laws
        .iter()
        .map(|law| {
            let (hook, invocation) = match law.id.as_str() {
                "enforce-file-scope" => (
                    "hooks/enforce_file_scope.sh",
                    format!("kernel pre-tool --packet {packet} --ledger {ledger}"),
                ),
                "require-validation" => (
                    "hooks/require_validation.sh",
                    format!("kernel post-tool --ledger {ledger}"),
                ),
                _ => ("", String::new()),
            };
            json!({
                "id": law.id,
                "kind": format!("{:?}", law.kind).to_lowercase(),
                "event": format!("{:?}", law.event),
                "applies_to": law.applies_to,
                "hook": hook,
                "invokes": invocation,
            })
        })
        .collect();

    let mut patterns: Vec<String> = compiled
        .composition
        .patterns()
        .iter()
        .map(|p| p.to_string())
        .collect();
    patterns.sort();

    let gate = spec.bindings.gate.as_ref().map(|g| {
        json!({
            "id": g.id,
            "boundary": g.boundary,
            "bind": g.bind,
            "requires_obligations": g.requires_obligations,
            "hook": "hooks/approve_commit.sh",
            "invokes": format!(
                "kernel pre-commit --ledger {ledger}{}",
                g.requires_obligations.iter().map(|o| format!(" --require {o}")).collect::<String>()
            ),
        })
    });

    prov.json_file(
        "harness.manifest.json",
        json!({
            "harness": { "name": spec.harness.name, "version": spec.harness.version },
            "composition": spec.composition.expression,
            "patterns": patterns,
            "laws": laws,
            "gate": gate,
            "ledger": spec.bindings.ledger.as_ref().map(|l| json!({
                "destination": l.destination,
                "redact": l.redact,
            })),
            "kernel": { "entrypoint": "kernel" },
        }),
    )
}

fn hook_files(prov: &Prov, spec: &SpecFile) -> Vec<GenFile> {
    let ledger = ledger_destination(spec);
    let packet = active_packet_path(spec);
    let mut out = Vec::new();

    for law in &spec.bindings.laws {
        let (path, body) = match law.id.as_str() {
            "enforce-file-scope" => (
                "hooks/enforce_file_scope.sh",
                format!(
                    "#!/usr/bin/env bash\n{header}# Guard Law: block edits outside the active packet's write scope (with self-protection).\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-tool --packet \"${{ACTIVE_PACKET:-{packet}}}\" --ledger \"{ledger}\" --run-id \"${{RUN_ID:-unknown}}\" --playbook-ref \"{playbook}\" --protected \"enforcement.protected\"\n",
                    header = prov.hash_header(),
                    playbook = prov.spec_hash,
                ),
            ),
            "require-validation" => (
                "hooks/require_validation.sh",
                format!(
                    "#!/usr/bin/env bash\n{header}# Obligation Law: record that validation is owed after an edit.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" post-tool --ledger \"{ledger}\" --run-id \"${{RUN_ID:-unknown}}\" --playbook-ref \"{playbook}\"\n",
                    header = prov.hash_header(),
                    playbook = prov.spec_hash,
                ),
            ),
            _ => continue,
        };
        out.push(GenFile {
            path: path.to_string(),
            content: body,
        });
    }

    let obligations = gate_obligations(spec);
    if !obligations.is_empty() {
        let requires: String = obligations
            .iter()
            .map(|o| format!(" --require {o}"))
            .collect();
        out.push(GenFile {
            path: "hooks/approve_commit.sh".to_string(),
            content: format!(
                "#!/usr/bin/env bash\n{header}# Gate: block a git commit while a required obligation is outstanding.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-commit --ledger \"{ledger}\"{requires}\n",
                header = prov.hash_header(),
            ),
        });
    }

    // Self-protection Bash hook.
    out.push(GenFile {
        path: "hooks/protect_enforcement.sh".to_string(),
        content: format!(
            "#!/usr/bin/env bash\n{header}# Self-protection: block destructive Bash against enforcement artifacts.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-bash --packet \"${{ACTIVE_PACKET:-{packet}}}\" --protected \"enforcement.protected\" --ledger \"{ledger}\" --run-id \"${{RUN_ID:-unknown}}\" --playbook-ref \"{playbook}\"\n",
            header = prov.hash_header(),
            playbook = prov.spec_hash,
        ),
    });
    out
}

fn protected_file(prov: &Prov) -> GenFile {
    let mut body = prov.hash_header();
    body.push_str("# Protected enforcement artifacts (portable layout). A write requires a task\n");
    body.push_str(
        "# packet with amends_enforcement = true (an explicit, auditable Intake grant).\n",
    );
    for p in [
        "harness.patterns.yaml",
        "hooks/",
        "schemas/",
        "harness.manifest.json",
    ] {
        body.push_str(p);
        body.push('\n');
    }
    GenFile {
        path: "enforcement.protected".to_string(),
        content: body,
    }
}

fn readme(prov: &Prov, spec_hash: &str) -> GenFile {
    let mut body = String::new();
    body.push_str(&prov.md_header());
    body.push('\n');
    body.push_str("# Portable harness bundle\n\n");
    body.push_str(&format!(
        "Compiled from `harness.patterns.yaml` (spec hash `{spec_hash}`).\n\n"
    ));
    body.push_str(
        "This bundle has no platform-specific launcher. `harness.manifest.json` declares, for each \
         Law and for the Gate, the tool event it intercepts and the exact `kernel` command its hook \
         runs. A runner for any platform wires those hooks to its own pre-/post-tool interception \
         points; the enforcement itself lives in the shared `kernel` binary, unchanged.\n\n\
         Contrast with the claude-code target, which additionally emits `CLAUDE.md` and \
         `.claude/settings.json`. Same spec, same kernel, different binding.\n",
    );
    GenFile {
        path: "README.md".to_string(),
        content: body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPECIMEN: &str = include_str!("../../../../harness.patterns.yaml");

    fn build() -> Generated {
        let compiled = spec::compile(SPECIMEN, &Portable).expect("specimen compiles");
        Portable.generate(&compiled, "sha256:test")
    }

    fn has(g: &Generated, path: &str) -> bool {
        g.files.iter().any(|f| f.path == path)
    }

    #[test]
    fn emits_a_manifest_not_claude_files() {
        let g = build();
        assert!(has(&g, "harness.manifest.json"));
        // The claude-code specifics are absent — this is a different binding.
        assert!(!has(&g, "CLAUDE.md"));
        assert!(!has(&g, ".claude/settings.json"));
    }

    #[test]
    fn manifest_is_valid_json_with_laws_and_gate() {
        let g = build();
        let m = g
            .files
            .iter()
            .find(|f| f.path == "harness.manifest.json")
            .unwrap();
        let v: Value = serde_json::from_str(&m.content).unwrap();
        assert!(v["laws"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["id"] == "enforce-file-scope"));
        assert_eq!(v["gate"]["requires_obligations"][0], "require-validation");
    }

    #[test]
    fn hooks_call_the_same_kernel() {
        let g = build();
        let hook = g
            .files
            .iter()
            .find(|f| f.path == "hooks/enforce_file_scope.sh")
            .unwrap();
        assert!(hook.content.contains("kernel"));
        assert!(hook.content.starts_with("#!/usr/bin/env bash\n"));
    }
}
