//! A platform-neutral back-end.
//!
//! Proves the front-end/back-end split is real: the *same* `harness.patterns.yaml`
//! compiles here to a different shape. There is no `CLAUDE.md` and no
//! `.claude/settings.json` — those are Claude Code specifics. Instead a
//! `harness.manifest.json` declares the hook→event bindings so any runner can
//! wire the identical `kernel` invocations. The pattern program is stable; only
//! the binding changes.

use serde_json::{json, Value};
use spec::{Binding, CompiledSpec};

use crate::backend::Backend;
use crate::common::{
    active_packet_path, checkpoint_schema, event_schema, ledger_destination, runtime_dirs,
    task_packet_schema, GenFile, Generated, Prov, Refs,
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

    fn generate(&self, compiled: &CompiledSpec, refs: &Refs) -> Generated {
        let prov = Prov { refs };
        let mut files = Vec::new();

        files.push(manifest(&prov, compiled));
        files.extend(hook_files(&prov, compiled));
        files.push(protected_file(&prov));
        // Schemas placed under a flat schemas/ dir — the backend owns layout.
        // These three describe the KERNEL's own types (invariant across
        // compositions), not any one component, so they are unconditional —
        // unlike the claude-code target, where each schema's path is named by
        // a component binding and so follows that component's activation.
        files.push(prov.json_file("schemas/task-packet.schema.json", task_packet_schema()));
        files.push(prov.json_file("schemas/checkpoint.schema.json", checkpoint_schema()));
        files.push(prov.json_file("schemas/event.schema.json", event_schema()));
        for dir in runtime_dirs(compiled) {
            files.push(prov.gitkeep(&dir));
        }
        files.push(readme(&prov, refs));
        // Always last: the manifest inventories every file above it (path,
        // digest, mode, type), and `build` promotes it as the commit point.
        let manifest =
            crate::common::bundle_manifest(&prov, crate::common::BUNDLE_MANIFEST_FILENAME, &files);
        files.push(manifest);

        Generated { files }
    }
}

/// The commit Gate's obligations (`id:scope` encoded) — only when the Gate is
/// an active component.
fn gate_obligations(compiled: &CompiledSpec) -> Vec<String> {
    crate::common::encoded_gate_requirements(compiled)
}

fn manifest(prov: &Prov, compiled: &CompiledSpec) -> GenFile {
    use spec::PatternKind;
    let spec = &compiled.spec;
    let graph = &compiled.graph;
    let ledger = ledger_destination(spec);
    let packet = active_packet_path(spec);

    let laws: Vec<Value> = spec
        .bindings
        .laws
        .iter()
        .filter(|law| graph.is_active(PatternKind::Law, &law.id))
        .map(|law| {
            let (hook, invocation) = match law.id.as_str() {
                "enforce-file-scope" => (
                    "hooks/enforce_file_scope.sh",
                    format!("kernel pre-tool --packet {packet} --ledger {ledger}"),
                ),
                "require-validation" => (
                    "hooks/require_validation.sh",
                    format!(
                        "kernel post-tool --ledger {ledger} --scope {}",
                        law.scope.as_str()
                    ),
                ),
                _ => ("", String::new()),
            };
            json!({
                "id": law.id,
                "kind": format!("{:?}", law.kind).to_lowercase(),
                "event": format!("{:?}", law.event),
                "applies_to": law.applies_to,
                "scope": law.scope.as_str(),
                "hook": hook,
                "invokes": invocation,
            })
        })
        .collect();

    let patterns = crate::common::pattern_inventory(compiled, &Portable);

    let gate = spec
        .bindings
        .gate
        .as_ref()
        .filter(|g| graph.is_active(PatternKind::Gate, &g.id))
        .map(|g| {
            json!({
                "id": g.id,
                "boundary": g.boundary,
                "bind": g.bind,
                "requires_obligations": g.requires_obligations,
                "hook": "hooks/approve_commit.sh",
                "invokes": format!(
                    "kernel pre-commit --ledger {ledger}{}",
                    gate_obligations(compiled)
                        .iter()
                        .map(|o| format!(" --require {o}"))
                        .collect::<String>()
                ),
            })
        });

    // The manifest declares the compiled architecture, so it lists only the
    // bindings the composition *activates* — same active set as generation.
    let g = graph;
    let delegates: Vec<Value> = spec
        .bindings
        .delegates
        .iter()
        .filter(|dg| g.is_active(PatternKind::Delegate, &dg.id))
        .map(|dg| json!({ "id": dg.id, "tools": dg.tools, "ports": dg.ports, "critic": dg.critic, "contract": dg.contract_schema }))
        .collect();
    let pipelines: Vec<Value> = spec
        .bindings
        .pipelines
        .iter()
        .filter(|p| g.is_active(PatternKind::Pipeline, &p.id))
        .map(|p| json!({ "id": p.id, "stages": p.stages.iter().map(|s| &s.name).collect::<Vec<_>>() }))
        .collect();
    let ports: Vec<Value> = spec
        .bindings
        .ports
        .iter()
        .filter(|p| g.is_active(PatternKind::Port, &p.id))
        .map(|p| json!({ "id": p.id, "server": p.server, "observe": p.observe, "write": p.write, "write_guard": p.write_guard, "idempotent": p.idempotent }))
        .collect();
    let hives: Vec<Value> = spec
        .bindings
        .hives
        .iter()
        .filter(|h| g.is_active(PatternKind::Hive, &h.id))
        .map(|h| json!({ "id": h.id, "worker": h.worker, "budget": h.budget, "max_depth": h.max_depth, "fan_out": format!("{:?}", h.fan_out).to_lowercase() }))
        .collect();
    let specialists: Vec<Value> = spec
        .bindings
        .specialists
        .iter()
        .filter(|s| g.is_active(PatternKind::Specialist, &s.id))
        .map(|s| json!({ "id": s.id, "skill": s.skill }))
        .collect();

    prov.json_file(
        "harness.manifest.json",
        json!({
            "harness": { "name": spec.harness.name, "version": spec.harness.version },
            "composition": spec.composition.expression,
            "patterns": patterns,
            "laws": laws,
            "gate": gate,
            "ledger": spec
                .bindings
                .ledger
                .as_ref()
                .filter(|_| graph.is_singleton_active(PatternKind::Ledger))
                .map(|l| json!({
                    "destination": l.destination,
                    "redact": l.redact,
                })),
            "specialists": specialists,
            "delegates": delegates,
            "pipelines": pipelines,
            "ports": ports,
            "hives": hives,
            "graph": crate::common::graph_json(compiled),
            "kernel": { "entrypoint": "kernel" },
        }),
    )
}

fn hook_files(prov: &Prov, compiled: &CompiledSpec) -> Vec<GenFile> {
    let spec = &compiled.spec;
    let ledger = ledger_destination(spec);
    let packet = active_packet_path(spec);
    let mut out = Vec::new();

    for law in spec
        .bindings
        .laws
        .iter()
        .filter(|law| compiled.graph.is_active(spec::PatternKind::Law, &law.id))
    {
        let (path, body) = match law.id.as_str() {
            "enforce-file-scope" => (
                "hooks/enforce_file_scope.sh",
                format!(
                    "#!/usr/bin/env bash\n{header}# Guard Law: block edits outside the active packet's write scope (with self-protection).\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-tool --packet \"${{ACTIVE_PACKET:-{packet}}}\" --ledger \"{ledger}\" --run-id \"${{RUN_ID:-unknown}}\" --playbook-ref \"{playbook}\" --protected \"enforcement.protected\"\n",
                    header = prov.hash_header(),
                    playbook = prov.refs.playbook_ref,
                ),
            ),
            "require-validation" => (
                "hooks/require_validation.sh",
                format!(
                    "#!/usr/bin/env bash\n{header}# Obligation Law: record that validation is owed after an edit (scope '{scope}').\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" post-tool --ledger \"{ledger}\" --run-id \"${{RUN_ID:-unknown}}\" --playbook-ref \"{playbook}\" --scope {scope}{packet_arg}\n",
                    scope = law.scope.as_str(),
                    packet_arg = if law.scope == spec::model::ObligationScope::Task {
                        format!(" --packet \"${{ACTIVE_PACKET:-{packet}}}\"")
                    } else {
                        String::new()
                    },
                    header = prov.hash_header(),
                    playbook = prov.refs.playbook_ref,
                ),
            ),
            _ => continue,
        };
        out.push(GenFile {
            path: path.to_string(),
            content: body,
        });
    }

    let obligations = gate_obligations(compiled);
    if !obligations.is_empty() {
        let requires: String = obligations
            .iter()
            .map(|o| format!(" --require {o}"))
            .collect();
        out.push(GenFile {
            path: "hooks/approve_commit.sh".to_string(),
            content: format!(
                "#!/usr/bin/env bash\n{header}# Gate: block a git commit while a required obligation is outstanding, each at\n# its declared scope. Every commit evaluation is recorded to the Ledger.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-commit --ledger \"{ledger}\" --run-id \"${{RUN_ID:-unknown}}\" --playbook-ref \"{playbook}\" --packet \"${{ACTIVE_PACKET:-{packet}}}\"{requires}\n",
                header = prov.hash_header(),
                playbook = prov.refs.playbook_ref,
            ),
        });
    }

    // Self-protection Bash hook.
    out.push(GenFile {
        path: "hooks/protect_enforcement.sh".to_string(),
        content: format!(
            "#!/usr/bin/env bash\n{header}# Self-protection: block destructive Bash against enforcement artifacts.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-bash --packet \"${{ACTIVE_PACKET:-{packet}}}\" --protected \"enforcement.protected\" --ledger \"{ledger}\" --run-id \"${{RUN_ID:-unknown}}\" --playbook-ref \"{playbook}\"\n",
            header = prov.hash_header(),
            playbook = prov.refs.playbook_ref,
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
        // The bundle inventory: tampering it would hide an obsolete artifact
        // from verification, so it is protected like the hooks themselves.
        "bundle.manifest.json",
    ] {
        body.push_str(p);
        body.push('\n');
    }
    GenFile {
        path: "enforcement.protected".to_string(),
        content: body,
    }
}

fn readme(prov: &Prov, refs: &Refs) -> GenFile {
    let mut body = String::new();
    body.push_str(&prov.md_header());
    body.push('\n');
    body.push_str("# Portable harness bundle\n\n");
    body.push_str(&format!(
        "Compiled from `harness.patterns.yaml` (source `{}`, playbook `{}`).\n\n",
        refs.source_ref, refs.playbook_ref
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
        Portable.generate(
            &compiled,
            &crate::common::refs(&compiled, "sha256:test", "test"),
        )
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
