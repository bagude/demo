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

/// The identity of the compiler that produced an artifact: this crate's
/// version, the front-end's, the IR schema version, and the target binding.
///
/// Source provenance and executable provenance are different things — the same
/// `harness.patterns.yaml` compiled by a different compiler can govern a
/// materially different system. Binding only the spec bytes would let a stale
/// or divergent artifact carry a matching reference.
pub fn compiler_digest(target: &str) -> String {
    sha256_hex(
        format!(
            "harnessc={GENERATOR_VERSION};spec={};ir_schema={IR_SCHEMA_VERSION};target={target}",
            spec::VERSION
        )
        .as_bytes(),
    )
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

pub fn ensure_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}

/// The runtime directories a harness needs, derived from its bindings.
pub fn runtime_dirs(spec: &spec::SpecFile) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Some(intake) = &spec.bindings.intake {
        dirs.push(ensure_trailing_slash(&intake.storage));
    }
    if let Some(ledger) = &spec.bindings.ledger {
        if let Some((dir, _)) = ledger.destination.rsplit_once('/') {
            dirs.push(format!("{dir}/"));
        }
    }
    if spec.bindings.gate.is_some() {
        dirs.push("checkpoints/".to_string());
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
            "evidence_refs": { "type": "array", "items": { "type": "string" } },
            "playbook_ref": { "type": "string" },
            "attempt_id": { "type": "string" }
        }
    })
}

/// The three kernel schemas at the paths the spec names for them.
pub fn schema_files(prov: &Prov, spec: &spec::SpecFile) -> Vec<GenFile> {
    let mut out = Vec::new();
    if let Some(intake) = &spec.bindings.intake {
        out.push(prov.json_file(&intake.task_schema, task_packet_schema()));
    }
    if let Some(gate) = &spec.bindings.gate {
        out.push(prov.json_file(&gate.checkpoint_schema, checkpoint_schema()));
    }
    if let Some(ledger) = &spec.bindings.ledger {
        out.push(prov.json_file(&ledger.event_schema, event_schema()));
    }
    out
}
