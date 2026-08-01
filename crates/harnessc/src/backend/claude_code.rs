//! The Claude Code back-end.
//!
//! Binds the seven roles to Claude Code: CLAUDE.md (Boot Context), `.claude/`
//! commands and settings (Invocable Workflow + hook registration), and
//! `harness/` hooks that shell out to the trusted `kernel`.

use serde_json::{json, Value};
use spec::model::{
    DelegateBinding, GateBinding, HiveBinding, LawBinding, LawEvent, PipelineBinding, PortBinding,
    SpecialistBinding,
};
use spec::{Binding, CompiledSpec};

use crate::backend::Backend;
use crate::common::{
    self, active_packet_path, ledger_destination, runtime_dirs, schema_files, GenFile, Generated,
    Prov, Refs,
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

    fn generate(&self, compiled: &CompiledSpec, refs: &Refs) -> Generated {
        // Membership is the resolved graph's call: every component-specific
        // artifact below is emitted only for a component the graph activates.
        // The bindings block supplies *configuration* (paths, names, caps);
        // it never decides *presence* — a binding the composition ignores is
        // not architecture, and generation must not resurrect it.
        use spec::PatternKind;
        let spec = &compiled.spec;
        let g = &compiled.graph;
        let prov = Prov { refs };
        let mut files = Vec::new();

        files.push(claude_md(&prov, compiled));
        files.push(settings_json(&prov, compiled));
        if let Some(verb) = spec
            .bindings
            .verb
            .as_ref()
            .filter(|_| g.is_singleton_active(PatternKind::Verb))
        {
            files.push(command_md(
                &prov,
                &verb.command,
                &verb.name,
                &verb.accepts,
                &verb.produces,
            ));
        }
        files.extend(schema_files(&prov, compiled));
        files.extend(hook_files(&prov, compiled));
        files.push(protected_file(&prov));
        if let Some(gate) = spec
            .bindings
            .gate
            .as_ref()
            .filter(|gate| g.is_active(PatternKind::Gate, &gate.id))
        {
            files.push(gate_file(&prov, gate));
        }
        files.extend(pattern_files(&prov, compiled));
        files.push(playbook_manifest(&prov, compiled));
        for dir in runtime_dirs(compiled) {
            files.push(prov.gitkeep(&dir));
        }
        files.push(harness_readme(&prov, refs));
        // Always last: the manifest inventories every file above it (path,
        // digest, mode, type), and `build` promotes it as the commit point.
        let manifest = common::bundle_manifest(
            &prov,
            &format!("harness/{}", common::BUNDLE_MANIFEST_FILENAME),
            &files,
        );
        files.push(manifest);

        Generated { files }
    }
}

fn hook_path(law: &LawBinding) -> String {
    law.implementation
        .clone()
        .unwrap_or_else(|| format!("harness/hooks/{}.sh", law.id.replace('-', "_")))
}

/// The Laws that are part of the compiled architecture — active in the
/// resolved graph (surface occurrence, `uses` edge, or `always_on`). The
/// checker rejects a bound-but-inactive enforcement Law outright, so for a
/// valid spec this filter drops nothing; it exists so generation *derives*
/// from the resolved architecture instead of restating the checker's theorem.
fn active_laws(compiled: &CompiledSpec) -> Vec<&LawBinding> {
    compiled
        .spec
        .bindings
        .laws
        .iter()
        .filter(|law| compiled.graph.is_active(spec::PatternKind::Law, &law.id))
        .collect()
}

/// The obligations the commit Gate enforces (`id:scope` encoded) — only when
/// the Gate itself is an active component of the resolved architecture.
fn gate_obligations(compiled: &CompiledSpec) -> Vec<String> {
    common::encoded_gate_requirements(compiled)
}

fn claude_md(prov: &Prov, compiled: &CompiledSpec) -> GenFile {
    use spec::PatternKind;
    let spec = &compiled.spec;
    let g = &compiled.graph;
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
    let laws = active_laws(compiled);
    if laws.is_empty() {
        body.push_str("_None declared._\n\n");
    } else {
        for law in laws {
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
                "- `{}` ({:?} at {:?}, applies to {}{}): {}\n",
                law.id,
                law.kind,
                law.event,
                law.applies_to.join(", "),
                match law.kind {
                    spec::model::LawKind::Obligation => format!("; scope {}", law.scope.as_str()),
                    _ => String::new(),
                },
                enforcement
            ));
        }
        body.push('\n');
    }

    if let Some(gate) = spec
        .bindings
        .gate
        .as_ref()
        .filter(|gate| g.is_active(PatternKind::Gate, &gate.id))
    {
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

    if let Some(ledger) = spec
        .bindings
        .ledger
        .as_ref()
        .filter(|_| g.is_singleton_active(PatternKind::Ledger))
    {
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

fn settings_json(prov: &Prov, compiled: &CompiledSpec) -> GenFile {
    let mut pre: Vec<Value> = Vec::new();
    let mut post: Vec<Value> = Vec::new();

    for law in active_laws(compiled) {
        let entry = json!({
            "matcher": tool_matcher(&law.applies_to),
            "hooks": [ { "type": "command", "command": hook_path(law) } ]
        });
        match law.event {
            LawEvent::PreTool => pre.push(entry),
            LawEvent::PostTool => post.push(entry),
        }
    }

    // Bash pre-tool interceptors: self-protection always (it guards the
    // Playbook itself, not any one component), plus the commit Gate when an
    // active Gate has obligations to discharge.
    let mut bash_hooks = vec![json!({ "type": "command", "command": PROTECT_HOOK })];
    if !gate_obligations(compiled).is_empty() {
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

fn hook_files(prov: &Prov, compiled: &CompiledSpec) -> Vec<GenFile> {
    let spec = &compiled.spec;
    let ledger = ledger_destination(spec);
    let packet = active_packet_path(spec);
    let mut out = Vec::new();

    for law in active_laws(compiled) {
        let path = hook_path(law);
        let body = match law.id.as_str() {
            "enforce-file-scope" => format!(
                "#!/usr/bin/env bash\n{header}# Guard Law: block edits outside the active packet's write scope\n# (and protect enforcement artifacts unless amends_enforcement is granted).\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-tool \\\n  --packet \"${{INTAKE_ACTIVE_PACKET:-{packet}}}\" \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\" \\\n  --playbook-ref \"{playbook}\" \\\n  --protected \"{protected}\"\n",
                header = prov.hash_header(),
                playbook = prov.refs.playbook_ref,
                protected = PROTECTED_FILE,
            ),
            "require-validation" => format!(
                "#!/usr/bin/env bash\n{header}# Obligation Law: record to the Ledger that validation is owed after an edit\n# (debt scoped '{scope}', as the spec declares).\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" post-tool \\\n  --ledger \"{ledger}\" \\\n  --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\" \\\n  --playbook-ref \"{playbook}\" \\\n  --scope {scope}{packet_arg}\n",
                header = prov.hash_header(),
                playbook = prov.refs.playbook_ref,
                scope = law.scope.as_str(),
                packet_arg = if law.scope == spec::model::ObligationScope::Task {
                    format!(" \\\n  --packet \"${{INTAKE_ACTIVE_PACKET:-{packet}}}\"")
                } else {
                    String::new()
                },
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

    // The commit-boundary Gate hook (only for an active Gate).
    let obligations = gate_obligations(compiled);
    if !obligations.is_empty() {
        let requires: String = obligations
            .iter()
            .map(|o| format!(" --require {o}"))
            .collect();
        out.push(GenFile {
            path: APPROVE_COMMIT_HOOK.to_string(),
            content: format!(
                "#!/usr/bin/env bash\n{header}# Gate: block `git commit` while a required obligation is outstanding, each\n# at its declared scope. Every commit evaluation is recorded to the Ledger.\nset -euo pipefail\nexec \"${{KERNEL_BIN:-kernel}}\" pre-commit --ledger \"{ledger}\" --run-id \"${{CLAUDE_SESSION_ID:-unknown}}\" --playbook-ref \"{playbook}\" --packet \"${{INTAKE_ACTIVE_PACKET:-{packet}}}\"{requires}\n",
                header = prov.hash_header(),
                playbook = prov.refs.playbook_ref,
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
            playbook = prov.refs.playbook_ref,
        ),
    });
    out
}

/// Generate the Claude Code artifacts for the scale/interaction patterns.
///
/// Generation consumes the resolved graph's **active set**, not the raw
/// bindings block: a binding the composition never activates is not an
/// architectural node and produces no artifact. A `production` Port bound
/// beside `Port[staging] within Sandbox` is therefore *not* wired into the
/// Playbook — connectivity the architecture does not declare is not emitted.
fn pattern_files(prov: &Prov, compiled: &CompiledSpec) -> Vec<GenFile> {
    use spec::PatternKind;
    let b = &compiled.spec.bindings;
    let g = &compiled.graph;
    let mut out = Vec::new();

    for s in b
        .specialists
        .iter()
        .filter(|s| g.is_active(PatternKind::Specialist, &s.id))
    {
        out.push(specialist_skill(prov, s));
    }
    for dg in b
        .delegates
        .iter()
        .filter(|dg| g.is_active(PatternKind::Delegate, &dg.id))
    {
        out.push(delegate_agent(prov, dg));
        out.push(prov.json_file(&dg.contract_schema, delegate_contract_schema(dg)));
    }
    for p in b
        .pipelines
        .iter()
        .filter(|p| g.is_active(PatternKind::Pipeline, &p.id))
    {
        out.push(pipeline_command(prov, p));
    }
    for h in b
        .hives
        .iter()
        .filter(|h| g.is_active(PatternKind::Hive, &h.id))
    {
        out.push(hive_orchestrator(
            prov,
            h,
            &ledger_destination(&compiled.spec),
        ));
    }
    let active_ports: Vec<_> = b
        .ports
        .iter()
        .filter(|p| g.is_active(PatternKind::Port, &p.id))
        .cloned()
        .collect();
    if !active_ports.is_empty() {
        out.push(mcp_config(prov, &active_ports));
        out.push(ports_manifest(prov, &active_ports));
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

fn hive_orchestrator(prov: &Prov, h: &HiveBinding, ledger: &str) -> GenFile {
    let mut body = prov.md_header();
    body.push('\n');
    body.push_str(&format!(
        "# /{id} — Hive orchestrator\n\nCoordinates fan-out and merge. **{:?}** fan-out; workers are \
         `{}` delegates; results merge to `{}`.\n\n## Law of the Hive (kernel-validated when invoked)\n\n\
         Every spawned task must have a parent, a contract, a budget, a depth, a termination \
         condition, a merge destination, and a declared write scope. Nothing forces this \
         invocation — the enforcement level is statically-checked, not mediated — so the required \
         flow is **transactional against the durable budget pool** (racing spawns serialize on \
         the pool's lock and can never jointly overshoot the total):\n\n\
         ```sh\n\
         # once, before fan-out: create the pool\n\
         kernel hive init --store hive --hive {id} --budget {budget}\n\n\
         # per spawn: validate AND atomically reserve the spawn's budget\n\
         echo \"$SPAWN_JSON\" | kernel hive-spawn --max-depth {max_depth} \\\n  --store hive --hive {id} --spawn-id \"$SPAWN_ID\" --ledger {ledger}\n\n\
         # per worker completion: record actual spend, return the remainder\n\
         kernel hive settle --store hive --hive {id} --spawn-id \"$SPAWN_ID\" \\\n  --spent \"$TOKENS_SPENT\" --ledger {ledger}\n\
         ```\n\n\
         A failed worker settles with `--spent 0` so its whole reservation returns to the pool.\n\n\
         Caps: budget {budget} · max depth {max_depth} · worker isolation {:?}.\n",
        h.fan_out, h.worker, h.merge, h.worker_isolation,
        id = h.id, budget = h.budget, max_depth = h.max_depth,
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
    // Derived from the resolved architecture, not surface presence: a Law
    // activated through a `uses` edge or `always_on` is in the system.
    let patterns = crate::common::pattern_inventory(compiled, &ClaudeCode);
    prov.json_file(
        "harness/playbook.json",
        json!({
            "name": spec.harness.name,
            "version": spec.harness.version,
            "refs": prov.refs.json(),
            "composition": spec.composition.expression,
            "patterns": patterns,
            // The checked IR itself: the compiled interpretation is auditable,
            // not just the source identity (playbook_ref).
            "graph": crate::common::graph_json(compiled),
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

fn harness_readme(prov: &Prov, refs: &Refs) -> GenFile {
    let mut body = String::new();
    body.push_str(&prov.md_header());
    body.push('\n');
    body.push_str("# harness/ — compiled Playbook (claude-code)\n\n");
    body.push_str(&format!(
        "Compiled from `{}` by `harnessc {}`.\n\n\
         - source `{}` — the specification bytes\n\
         - compiler `{}` — a content digest of the compiler and front-end\n\
           implementation source, dependency lock, and toolchain, folded with\n\
           the IR schema and target\n\
         - IR `{}` — the resolved composition graph\n\
         - **playbook `{}`** — all of the above; the identity of this compiled\n\
           interpretation, and what runtime evidence binds to\n\n\
         A compiled identity is not a runtime identity: every Ledger event also\n\
         records `kernel_ref`, a content digest of the kernel binary that actually\n\
         executed the transition, so the same Playbook enforced by a different\n\
         kernel is distinguishable in the evidence.\n\n",
        common::SPEC_FILENAME,
        common::GENERATOR_VERSION,
        refs.source_ref,
        refs.compiler_ref,
        refs.ir_ref,
        refs.playbook_ref,
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
           validation step. Every commit evaluation — allow or deny — is itself a run-bound Ledger \
           event, so a blocked commit is evidence, not just an exit code.\n\
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
        ClaudeCode.generate(
            &compiled,
            &crate::common::refs(&compiled, "sha256:test", "test"),
        )
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
    fn inactive_bindings_are_not_generated() {
        // Activation semantics: the composition names only Port[staging], so
        // the bound-but-unactivated `production` Port must not be wired into
        // the Playbook — a valid reference is an *active architectural node*,
        // and only active nodes generate artifacts.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "(Port[staging] within Sandbox) -> Gate + Law + Ledger"
bindings:
  sandbox: { workspace: branch, lineage: [source_revision, sandbox_id, merge_revision] }
  laws:
    - { id: enforce-file-scope, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: deploy, write: [release], write_guard: enforce-file-scope, sandboxed: propose }
    - { id: production, server: deploy-prod, write: [release], write_guard: enforce-file-scope, sandboxed: propose }
  gate:
    id: g
    boundary: before_deploy
    checkpoint_schema: harness/schemas/checkpoint.schema.json
    bind: [action_hash, repository_revision, approver]
  ledger:
    event_schema: harness/schemas/event.schema.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;
        let compiled = spec::compile(yaml, &ClaudeCode).expect("compiles");
        let g = ClaudeCode.generate(
            &compiled,
            &crate::common::refs(&compiled, "sha256:test", "test"),
        );
        let ports = &find(&g, "harness/ports.json").content;
        assert!(ports.contains("staging"), "active port is generated");
        assert!(
            !ports.contains("production"),
            "inactive port must not be wired into the Playbook: {ports}"
        );
        let mcp = &find(&g, ".mcp.json").content;
        assert!(!mcp.contains("deploy-prod"), "inactive port server absent");
    }

    #[test]
    fn bound_but_unreferenced_singletons_generate_no_artifacts() {
        // The stronger invariant: every component-specific artifact must be
        // reachable from an active component. Verb and Intake are not
        // enforcement (so the checker only warns), but a Verb the composition
        // never places must not become a live command, and an Intake the
        // composition never places must not scaffold storage — the backend
        // consults the resolved graph, never raw binding presence.
        let unreferenced = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "(Port[staging] within Sandbox) -> Gate + Law + Ledger"
bindings:
  sandbox: { workspace: branch, lineage: [source_revision, sandbox_id, merge_revision] }
  intake: { task_schema: harness/schemas/task-packet.schema.json, storage: tasks/ }
  verb: { name: deploy, command: .claude/commands/deploy.md, accepts: TaskPacket, produces: Result }
  laws:
    - { id: enforce-file-scope, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: deploy, write: [release], write_guard: enforce-file-scope, sandboxed: propose }
  gate:
    id: g
    boundary: before_deploy
    checkpoint_schema: harness/schemas/checkpoint.schema.json
    bind: [action_hash, repository_revision, approver]
  ledger:
    event_schema: harness/schemas/event.schema.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;
        let compiled = spec::compile(unreferenced, &ClaudeCode).expect("compiles with warnings");
        let warnings: Vec<String> = compiled.warnings.iter().map(|w| w.to_string()).collect();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("bound but never appears")),
            "the exclusion is warned about, never silent: {warnings:?}"
        );
        let g = ClaudeCode.generate(
            &compiled,
            &crate::common::refs(&compiled, "sha256:test", "test"),
        );
        let paths: Vec<&str> = g.files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            !paths.contains(&".claude/commands/deploy.md"),
            "an unplaced Verb must not become a live command"
        );
        assert!(
            !paths.contains(&"harness/schemas/task-packet.schema.json"),
            "an unplaced Intake emits no schema"
        );
        assert!(
            !paths.contains(&"tasks/.gitkeep"),
            "an unplaced Intake scaffolds no storage"
        );

        // The same bindings, placed in the composition: all three appear.
        let referenced = unreferenced.replace(
            "\"(Port[staging] within Sandbox) -> Gate + Law + Ledger\"",
            "\"Intake -> Verb + (Port[staging] within Sandbox) -> Gate + Law + Ledger\"",
        );
        let compiled = spec::compile(&referenced, &ClaudeCode).expect("compiles");
        let g = ClaudeCode.generate(
            &compiled,
            &crate::common::refs(&compiled, "sha256:test", "test"),
        );
        let paths: Vec<&str> = g.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&".claude/commands/deploy.md"));
        assert!(paths.contains(&"harness/schemas/task-packet.schema.json"));
        assert!(paths.contains(&"tasks/.gitkeep"));
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
    fn commit_gate_hook_requires_the_obligation_and_binds_the_run() {
        let g = build();
        let hook = &find(&g, APPROVE_COMMIT_HOOK).content;
        assert!(hook.contains("pre-commit"));
        assert!(hook.contains("--require require-validation"));
        // The commit Gate's decisions are Ledger events like any other, so the
        // hook must bake in the run binding the way the Guard hooks do.
        assert!(hook.contains("--playbook-ref"));
    }

    #[test]
    fn declared_obligation_scope_flows_into_the_generated_hooks() {
        // The spec declares the scope; the compiled hooks carry it to the
        // kernel — recording side (--scope) and gate side (--require
        // id:scope) must agree, or debt opened at one scope would be
        // evaluated at another.
        let yaml = SPECIMEN.replace(
            "    - id: require-validation\n      kind: obligation\n",
            "    - id: require-validation\n      kind: obligation\n      scope: workspace\n",
        );
        let compiled = spec::compile(&yaml, &ClaudeCode).expect("compiles");
        let g = ClaudeCode.generate(
            &compiled,
            &crate::common::refs(&compiled, "sha256:test", "test"),
        );
        let record = &find(&g, "harness/hooks/require_validation.sh").content;
        assert!(record.contains("--scope workspace"), "{record}");
        let gate = &find(&g, APPROVE_COMMIT_HOOK).content;
        assert!(
            gate.contains("--require require-validation:workspace"),
            "{gate}"
        );

        // The default is explicit too: the specimen (no scope declared)
        // compiles to `run`, spelled out rather than assumed at runtime.
        let g = build();
        assert!(find(&g, "harness/hooks/require_validation.sh")
            .content
            .contains("--scope run"));
        assert!(find(&g, APPROVE_COMMIT_HOOK)
            .content
            .contains("--require require-validation:run"));
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
    fn playbook_manifest_carries_enforcement_levels() {
        let g = build();
        let manifest = &find(&g, "harness/playbook.json").content;
        let v: Value = serde_json::from_str(manifest).unwrap();
        let patterns = v["patterns"].as_array().unwrap();
        // Every pattern entry names its enforcement level.
        assert!(patterns.iter().all(|p| p["enforcement"].is_string()));
        // The Gate is honestly runtime-enforced (a registered commit hook), not
        // kernel-mediated — nothing binds the commit action to a checkpoint.
        assert!(patterns
            .iter()
            .any(|p| p["name"] == "Gate" && p["enforcement"] == "runtime-enforced"));
    }

    #[test]
    fn generated_event_schema_mandates_the_kernel_identity() {
        // The compiled Ledger schema requires kernel_ref: a governed runtime
        // event must record which enforcement binary executed it.
        let g = build();
        let schema = &find(&g, "harness/schemas/event.schema.json").content;
        let v: Value = serde_json::from_str(schema).unwrap();
        let required: Vec<&str> = v["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert!(
            required.contains(&"kernel_ref"),
            "runtime identity must be mandatory in the event schema"
        );
        assert!(
            required.contains(&"playbook_ref"),
            "run binding must be mandatory in the event schema"
        );
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
