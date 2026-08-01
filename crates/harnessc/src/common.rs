//! Platform-neutral generation toolkit shared by every backend: the file
//! model, provenance stamping, and the JSON Schemas that describe the kernel's
//! own types (which are the same whatever platform we compile to).

use serde_json::{json, Value};

/// The generator version, stamped into every provenance header.
pub const GENERATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the serialized IR schema. Bumped whenever the shape of
/// [`graph_json`] changes, so an artifact generated against an older schema is
/// detectable even when the spec bytes and crate versions are unchanged.
pub const IR_SCHEMA_VERSION: &str = "2";

/// The spec file name generated artifacts point back to.
pub const SPEC_FILENAME: &str = "harness.patterns.yaml";

/// One generated file: a repo-relative path and its full contents.
#[derive(Debug, Clone)]
pub struct GenFile {
    pub path: String,
    pub content: String,
}

/// The complete set of files for a compiled harness.
#[derive(Debug, Clone)]
pub struct Generated {
    pub files: Vec<GenFile>,
}

/// Provenance-stamping helper bound to one spec hash. Every generated file gets
/// a header naming the spec and its hash, so edits are known to flow *down*
/// from the spec, never up from generated output.
pub struct Prov<'a> {
    pub refs: &'a Refs,
}

impl Prov<'_> {
    /// The identity a generated artifact advertises. `SOURCE` is the spec
    /// bytes; `PLAYBOOK` binds source + compiler + IR, so a rebuild by a
    /// different compiler — or against a changed IR — is detectably different
    /// even when the spec is byte-identical.
    fn hash_line(&self) -> String {
        format!(
            "SOURCE: {}\n# PLAYBOOK: {}",
            self.refs.source_ref, self.refs.playbook_ref
        )
    }

    /// A `#`-style provenance header for shell/YAML files.
    pub fn hash_header(&self) -> String {
        format!(
            "# GENERATED FROM: {SPEC_FILENAME}\n# {}\n# GENERATOR: harnessc {GENERATOR_VERSION}\n# DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.\n",
            self.hash_line()
        )
    }

    /// An HTML-comment provenance header for Markdown files.
    pub fn md_header(&self) -> String {
        format!(
            "<!--\n  GENERATED FROM: {SPEC_FILENAME}\n  SOURCE: {}\n  PLAYBOOK: {}\n  GENERATOR: harnessc {GENERATOR_VERSION}\n  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.\n-->\n",
            self.refs.source_ref, self.refs.playbook_ref
        )
    }

    fn json_provenance(&self) -> Value {
        json!({
            "from": SPEC_FILENAME,
            "source_ref": self.refs.source_ref,
            "compiler_ref": self.refs.compiler_ref,
            "ir_ref": self.refs.ir_ref,
            "playbook_ref": self.refs.playbook_ref,
            "generator": format!("harnessc {GENERATOR_VERSION}"),
            "ir_schema": IR_SCHEMA_VERSION,
            "note": "DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`."
        })
    }

    /// Build a generated JSON file with a `_generated` provenance object first.
    pub fn json_file(&self, path: &str, body: Value) -> GenFile {
        let content = if let Value::Object(map) = body {
            let mut with_prov = serde_json::Map::new();
            with_prov.insert("_generated".to_string(), self.json_provenance());
            for (k, v) in map {
                with_prov.insert(k, v);
            }
            format!(
                "{}\n",
                serde_json::to_string_pretty(&Value::Object(with_prov)).unwrap()
            )
        } else {
            format!("{}\n", serde_json::to_string_pretty(&body).unwrap())
        };
        GenFile {
            path: path.to_string(),
            content,
        }
    }

    /// A `.gitkeep` for a runtime directory.
    pub fn gitkeep(&self, dir: &str) -> GenFile {
        GenFile {
            path: format!("{dir}.gitkeep"),
            content: format!(
                "# GENERATED FROM: {SPEC_FILENAME}\n# {}\n# Runtime directory kept in version control; contents are runtime state.\n",
                self.hash_line()
            ),
        }
    }
}

/// Serialize the resolved composition graph — the checked IR — so the compiled
/// bundle carries an inspectable proof object: positions, operator edges,
/// binding-sourced `uses` edges, and the bindings the composition does NOT
/// activate. The spec hash proves *identity*; this makes the compiled
/// *interpretation* directly auditable.
pub fn graph_json(compiled: &spec::CompiledSpec) -> Value {
    let g = &compiled.graph;
    let nodes: Vec<Value> = g
        .nodes()
        .iter()
        .map(|n| {
            json!({
                "node_id": n.id.0,
                "pattern": n.kind.to_string(),
                "instance": n.instance,
                "alias": n.alias,
                "bindings": n.bindings,
                "multiplicity": n.multiplicity.count(),
                "origin": "surface",
            })
        })
        .collect();
    // Two layers, two collections. Position edges relate architectural
    // occurrences (node ids); binding edges relate implementations (kind + id).
    // A single heterogeneous array would need a tagged union to validate.
    let position_edges: Vec<Value> = g
        .edges()
        .iter()
        .map(|e| {
            json!({
                "relation": e.relation.as_str(),
                "from": e.from.0,
                "to": e.to.0,
            })
        })
        .collect();
    let binding_edges: Vec<Value> = g
        .uses()
        .iter()
        .map(|u| {
            json!({
                "relation": "uses",
                "kind": u.kind.as_str(),
                "from": { "pattern": u.from.0.to_string(), "id": u.from.1 },
                "to": { "pattern": u.to.0.to_string(), "id": u.to.1 },
                "origin": u.kind.origin(),
            })
        })
        .collect();
    // EVERY bound component — singleton and named — with why it is active. A
    // singleton `always_on` Ledger owns no binding id and occupies no position,
    // yet the backend can emit it, so it must appear here for the IR to account
    // for everything generated.
    let components: Vec<Value> = g
        .component_inventory(&compiled.spec.bindings)
        .into_iter()
        .map(|c| {
            let origins: Vec<String> = c.origins.iter().map(|o| o.as_str()).collect();
            json!({
                "pattern": c.key.kind().to_string(),
                "id": c.key.id(),
                "singleton": c.key.id().is_none(),
                "active": c.active,
                "activation_origins": origins,
            })
        })
        .collect();
    let self_relations: Vec<Value> = g
        .self_relations()
        .iter()
        .map(|sr| {
            json!({
                "node": sr.node.0,
                "relation": sr.relation.as_str(),
                "origin": sr.origin.as_str(),
            })
        })
        .collect();
    json!({
        "nodes": nodes,
        "position_edges": position_edges,
        "binding_edges": binding_edges,
        "components": components,
        "self_relations": self_relations,
    })
}

/// SHA-256 over the canonical serialization of the resolved IR — the identity
/// of the compiled *interpretation*, as distinct from the source bytes.
pub fn ir_digest(compiled: &spec::CompiledSpec) -> String {
    sha256_hex(
        serde_json::to_string(&graph_json(compiled))
            .expect("IR is serializable")
            .as_bytes(),
    )
}

/// The compiler's own implementation source — the front-end (`spec`) and this
/// back-end — embedded at compile time. Hashing these bytes is what makes
/// `compiler_ref` a genuine *implementation* reference rather than a version
/// label: two materially different source trees produce different references
/// even when neither bumped its package version, which is exactly the failure
/// mode that let a stale artifact keep calling itself `0.1.0`. Source rather
/// than the built binary keeps the digest reproducible: the same source, lock,
/// and toolchain always agree, without requiring bit-reproducible builds.
const COMPILER_SOURCE: &[&str] = &[
    // front-end (spec crate): metamodel, parser, resolver, checker
    include_str!("../../spec/src/lib.rs"),
    include_str!("../../spec/src/model.rs"),
    include_str!("../../spec/src/binding.rs"),
    include_str!("../../spec/src/compose.rs"),
    include_str!("../../spec/src/graph.rs"),
    include_str!("../../spec/src/check.rs"),
    // back-end (this crate): the code that turns the resolved IR into a bundle
    include_str!("main.rs"),
    include_str!("common.rs"),
    include_str!("backend/mod.rs"),
    include_str!("backend/claude_code.rs"),
    include_str!("backend/portable.rs"),
];

/// The workspace dependency lock, embedded at compile time. The compiler's
/// behavior is a function of its dependencies too: identical source built
/// against different serde/yaml/parser versions can generate differently, so
/// the lock is part of the compiler's identity.
const COMPILER_LOCKFILE: &str = include_str!("../../../Cargo.lock");

/// The toolchain that built this compiler (`rustc --version --verbose`:
/// release, commit hash, host triple), captured by `build.rs`. The same
/// source compiled by a different rustc is a different compiler.
const COMPILER_TOOLCHAIN: &str = env!("HARNESSC_RUSTC_VERSION");

/// The identity of the compiler that produced an artifact: a content digest of
/// the compiler and front-end **implementation source**, the **dependency
/// lock**, and the **toolchain**, folded together with the IR schema version
/// and the target binding.
///
/// Source provenance and executable provenance are different things — the same
/// `harness.patterns.yaml` compiled by a different compiler can govern a
/// materially different system. Binding only the spec bytes (or only version
/// labels, which two divergent trees can share) would let a stale or divergent
/// artifact carry a matching reference. Hashing implementation source closes
/// the source gap; hashing the lock and toolchain closes the build gap:
/// change the compiler — its code, its dependencies, or the rustc that built
/// it — and the reference changes.
pub fn compiler_digest(target: &str) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let units = COMPILER_SOURCE
        .iter()
        .copied()
        .chain([COMPILER_LOCKFILE, COMPILER_TOOLCHAIN]);
    for unit in units {
        // Length-prefix each unit so boundaries can't be shuffled into a
        // collision.
        buf.extend_from_slice(&(unit.len() as u64).to_le_bytes());
        buf.extend_from_slice(unit.as_bytes());
    }
    buf.extend_from_slice(format!(";ir_schema={IR_SCHEMA_VERSION};target={target}").as_bytes());
    sha256_hex(&buf)
}

/// The full identity chain for a compiled Playbook.
pub fn refs(compiled: &spec::CompiledSpec, source_ref: &str, target: &str) -> Refs {
    let compiler_ref = compiler_digest(target);
    let ir_ref = ir_digest(compiled);
    let playbook_ref = sha256_hex(
        format!("source={source_ref};compiler={compiler_ref};target={target};ir={ir_ref}")
            .as_bytes(),
    );
    Refs {
        source_ref: source_ref.to_string(),
        compiler_ref,
        ir_ref,
        playbook_ref,
    }
}

/// The identity a generated artifact and every runtime event carries.
#[derive(Debug, Clone)]
pub struct Refs {
    /// Hash of the specification bytes.
    pub source_ref: String,
    /// Hash of the compiler/backend/IR-schema/target identity.
    pub compiler_ref: String,
    /// Hash of the canonical resolved IR.
    pub ir_ref: String,
    /// Hash binding all of the above — the compiled interpretation's identity.
    pub playbook_ref: String,
}

impl Refs {
    pub fn json(&self) -> Value {
        json!({
            "source_ref": self.source_ref,
            "compiler_ref": self.compiler_ref,
            "ir_ref": self.ir_ref,
            "playbook_ref": self.playbook_ref,
        })
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::from("sha256:");
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// File name of the bundle manifest — the exact inventory every backend appends
/// as the **final** file of its generated set. Backends choose the directory
/// (`harness/` for claude-code, the bundle root for portable); the name is
/// shared so the driver can locate the previous build's manifest for obsolete-
/// file detection without knowing the backend's layout.
pub const BUNDLE_MANIFEST_FILENAME: &str = "bundle.manifest.json";

/// The mode a generated file is promoted with, and the mode `verify` holds it
/// to. Shell hooks are executable; everything else is not. A hook whose bytes
/// match but whose executable bit was stripped is a *behavioral* change — the
/// hook silently stops running — so mode is part of the bundle's identity, not
/// a filesystem detail.
pub fn file_mode(path: &str) -> &'static str {
    if path.ends_with(".sh") {
        "0755"
    } else {
        "0644"
    }
}

/// Build the bundle manifest over every file generated **before** it: path,
/// content digest, mode, and file type, sorted by path.
///
/// Byte comparison of the expected set proves each present file is right; it
/// cannot prove nothing else is left over. A file an *older* compiler emitted
/// and the current one no longer does — a stale hook, a retired command —
/// passes a files-I-expect scan untouched, while still being live behavior in
/// the harness. The manifest closes that hole: it is the durable record of the
/// managed path set, so `build` can delete what fell out of the set and
/// `verify` can flag it. The manifest cannot list its own digest; it is
/// instead compared byte-for-byte like any other generated file.
pub fn bundle_manifest(prov: &Prov, path: &str, files: &[GenFile]) -> GenFile {
    let mut entries: Vec<&GenFile> = files.iter().collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let files_json: Vec<Value> = entries
        .iter()
        .map(|f| {
            json!({
                "path": f.path,
                "digest": sha256_hex(f.content.as_bytes()),
                "mode": file_mode(&f.path),
                "type": "regular",
            })
        })
        .collect();
    prov.json_file(path, json!({ "files": files_json }))
}

/// The managed path set recorded by a previous build's manifest on disk, or
/// `None` when no (parseable) manifest exists — e.g. the first build into a
/// directory. Tolerant parsing is deliberate: a corrupt manifest must not
/// brick `build`, and `verify` catches the corruption as a byte mismatch.
pub fn read_manifest_paths(manifest_path: &std::path::Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(manifest_path).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    Some(
        v.get("files")?
            .as_array()?
            .iter()
            .filter_map(|f| f.get("path")?.as_str().map(String::from))
            .collect(),
    )
}

/// The pattern kinds of the compiled architecture with their enforcement
/// levels, derived from the **resolved graph** rather than from surface
/// presence: a Law activated only through a `uses` edge or `always_on` is part
/// of the system and must appear in the enforcement summary.
pub fn pattern_inventory(compiled: &spec::CompiledSpec, binding: &dyn spec::Binding) -> Vec<Value> {
    let mut kinds: Vec<_> = compiled
        .graph
        .active_kinds(&compiled.spec.bindings)
        .into_iter()
        .collect();
    kinds.sort_by_key(|p| p.to_string());
    kinds
        .iter()
        .map(|p| {
            json!({
                "name": p.to_string(),
                "enforcement": binding.enforcement_level(*p).as_str(),
            })
        })
        .collect()
}

/// The active Gate's required obligations in the form the kernel consumes:
/// `id:scope`, with the scope read from each obligation Law's declaration.
/// The encoding is explicit even for the default (`:run`) so a generated
/// artifact never depends on a runtime default staying what it was.
pub fn encoded_gate_requirements(compiled: &spec::CompiledSpec) -> Vec<String> {
    let Some(gate) = compiled
        .spec
        .bindings
        .gate
        .as_ref()
        .filter(|g| compiled.graph.is_active(spec::PatternKind::Gate, &g.id))
    else {
        return Vec::new();
    };
    gate.requires_obligations
        .iter()
        .map(|id| {
            let scope = compiled
                .spec
                .bindings
                .laws
                .iter()
                .find(|l| &l.id == id)
                .map(|l| l.scope)
                .unwrap_or_default();
            format!("{id}:{}", scope.as_str())
        })
        .collect()
}

pub fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}

/// The runtime directories a harness needs, derived from the **active
/// components** of the resolved graph. A binding the composition never
/// activates gets no runtime directory: membership in the compiled
/// architecture is the graph's call, never inferred from raw binding presence.
pub fn runtime_dirs(compiled: &spec::CompiledSpec) -> Vec<String> {
    use spec::PatternKind;
    let spec = &compiled.spec;
    let g = &compiled.graph;
    let mut dirs = Vec::new();
    if let Some(intake) = spec
        .bindings
        .intake
        .as_ref()
        .filter(|_| g.is_singleton_active(PatternKind::Intake))
    {
        dirs.push(ensure_trailing_slash(&intake.storage));
    }
    if let Some(ledger) = spec
        .bindings
        .ledger
        .as_ref()
        .filter(|_| g.is_singleton_active(PatternKind::Ledger))
    {
        if let Some((dir, _)) = ledger.destination.rsplit_once('/') {
            dirs.push(format!("{dir}/"));
        }
    }
    if spec
        .bindings
        .gate
        .as_ref()
        .is_some_and(|gate| g.is_active(PatternKind::Gate, &gate.id))
    {
        dirs.push("checkpoints/".to_string());
    }
    // An active Hive gets its durable budget-pool store: reservations must
    // survive the orchestrator's process, or the cap is caller-claimed again.
    if spec
        .bindings
        .hives
        .iter()
        .any(|h| g.is_active(PatternKind::Hive, &h.id))
    {
        dirs.push("hive/".to_string());
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

/// The default active-packet path derived from the intake storage dir.
pub fn active_packet_path(spec: &spec::SpecFile) -> String {
    spec.bindings
        .intake
        .as_ref()
        .map(|i| format!("{}active.json", ensure_trailing_slash(&i.storage)))
        .unwrap_or_else(|| "tasks/active.json".to_string())
}

pub fn ledger_destination(spec: &spec::SpecFile) -> String {
    spec.bindings
        .ledger
        .as_ref()
        .map(|l| l.destination.clone())
        .unwrap_or_else(|| "evidence/events.jsonl".to_string())
}

pub fn task_packet_schema() -> Value {
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
            "priority": { "enum": ["low", "medium", "high", "critical"], "default": "medium" },
            "amends_enforcement": { "type": "boolean", "default": false }
        }
    })
}

pub fn checkpoint_schema() -> Value {
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
            "requires_obligations": { "type": "array", "items": { "type": "string" } },
            "ledger_head": { "type": "string" },
            "approval": {
                "type": "object",
                "required": ["approver", "action_hash", "approved_at"],
                "properties": {
                    "approver": {
                        "type": "object",
                        "required": ["principal", "auth"],
                        "properties": {
                            "principal": { "type": "string" },
                            "auth": { "enum": ["claimed", "token", "signature"] },
                            "evidence": { "type": "string" }
                        }
                    },
                    "action_hash": { "type": "string" },
                    "preconditions": { "type": "object", "additionalProperties": { "type": "string" } },
                    "approved_at": { "type": "string" },
                    "expiry": { "type": "string" }
                }
            }
        }
    })
}

pub fn event_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Event",
        "type": "object",
        "required": ["seq", "prev", "run_id", "action_id", "actor", "timestamp", "transition", "decision", "playbook_ref", "kernel_ref"],
        "properties": {
            "seq": { "type": "integer", "minimum": 0 },
            "prev": { "type": "string" },
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
            "evidence_refs": { "type": "array", "items": { "type": "string" } },
            "playbook_ref": { "type": "string" },
            "kernel_ref": { "type": "string" },
            "attempt_id": { "type": "string" }
        }
    })
}

/// The kernel schemas at the paths the spec names for them — emitted only for
/// components the resolved graph activates. An Intake that is bound but never
/// enters the composition is not part of the compiled architecture, so its
/// schema is not part of the Playbook.
pub fn schema_files(prov: &Prov, compiled: &spec::CompiledSpec) -> Vec<GenFile> {
    use spec::PatternKind;
    let spec = &compiled.spec;
    let g = &compiled.graph;
    let mut out = Vec::new();
    if let Some(intake) = spec
        .bindings
        .intake
        .as_ref()
        .filter(|_| g.is_singleton_active(PatternKind::Intake))
    {
        out.push(prov.json_file(&intake.task_schema, task_packet_schema()));
    }
    if let Some(gate) = spec
        .bindings
        .gate
        .as_ref()
        .filter(|gate| g.is_active(PatternKind::Gate, &gate.id))
    {
        out.push(prov.json_file(&gate.checkpoint_schema, checkpoint_schema()));
    }
    if let Some(ledger) = spec
        .bindings
        .ledger
        .as_ref()
        .filter(|_| g.is_singleton_active(PatternKind::Ledger))
    {
        out.push(prov.json_file(&ledger.event_schema, event_schema()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_digest_is_content_addressed_not_a_version_label() {
        // Regression guard for the exact historical failure: a version-label
        // identity would collide across divergent trees at the same version.
        // The digest must NOT equal a hash of the old label string.
        let target = "claude-code";
        let old_label = sha256_hex(
            format!(
                "harnessc={GENERATOR_VERSION};spec={};ir_schema={IR_SCHEMA_VERSION};target={target}",
                spec::VERSION
            )
            .as_bytes(),
        );
        assert_ne!(
            compiler_digest(target),
            old_label,
            "compiler_ref must fold in implementation source, not just version labels"
        );
    }

    #[test]
    fn compiler_digest_embeds_the_real_implementation() {
        // The embedded corpus is genuinely the compiler's own code, so any
        // change to generation or checking changes the reference.
        assert!(!COMPILER_SOURCE.is_empty());
        let corpus: String = COMPILER_SOURCE.concat();
        assert!(corpus.contains("fn compiler_digest"));
        assert!(corpus.contains("impl Backend for ClaudeCode"));
    }

    #[test]
    fn compiler_digest_binds_the_dependency_lock_and_toolchain() {
        // Identical source built against different dependency versions or a
        // different rustc is a different compiler; the embedded lock and
        // toolchain identity are what let the digest tell them apart.
        assert!(
            COMPILER_LOCKFILE.contains("[[package]]"),
            "the embedded lockfile is the real Cargo.lock"
        );
        assert!(
            COMPILER_TOOLCHAIN.starts_with("rustc"),
            "the toolchain identity comes from the actual rustc: {COMPILER_TOOLCHAIN}"
        );
        assert!(
            COMPILER_TOOLCHAIN.contains("host:"),
            "--verbose identity includes the host triple: {COMPILER_TOOLCHAIN}"
        );
    }

    #[test]
    fn compiler_digest_distinguishes_targets() {
        assert_ne!(
            compiler_digest("claude-code"),
            compiler_digest("portable"),
            "a different target is a different compiler identity"
        );
    }

    #[test]
    fn event_schema_requires_run_binding_and_chain_fields() {
        // A governed record must carry which Playbook governed it, which
        // kernel executed it, AND its position in the hash chain; the schema
        // makes all of it mandatory rather than conventional. (Legacy records
        // are exactly the ones that fail this schema.)
        let schema = event_schema();
        let required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"playbook_ref"));
        assert!(required.contains(&"kernel_ref"));
        assert!(required.contains(&"seq"));
        assert!(required.contains(&"prev"));
    }
}
