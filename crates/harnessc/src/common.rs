//! Platform-neutral generation toolkit shared by every backend: the file
//! model, provenance stamping, and the JSON Schemas that describe the kernel's
//! own types (which are the same whatever platform we compile to).

use serde_json::{json, Value};

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

/// The complete set of files for a compiled harness.
#[derive(Debug, Clone)]
pub struct Generated {
    pub files: Vec<GenFile>,
}

/// Provenance-stamping helper bound to one spec hash. Every generated file gets
/// a header naming the spec and its hash, so edits are known to flow *down*
/// from the spec, never up from generated output.
pub struct Prov<'a> {
    pub spec_hash: &'a str,
}

impl Prov<'_> {
    fn hash_line(&self) -> String {
        format!("SPEC HASH: {}", self.spec_hash)
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
            "<!--\n  GENERATED FROM: {SPEC_FILENAME}\n  {}\n  GENERATOR: harnessc {GENERATOR_VERSION}\n  DO NOT EDIT DIRECTLY — edit the spec and run `harnessc build`.\n-->\n",
            self.hash_line()
        )
    }

    fn json_provenance(&self) -> Value {
        json!({
            "from": SPEC_FILENAME,
            "spec_hash": self.spec_hash,
            "generator": format!("harnessc {GENERATOR_VERSION}"),
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
