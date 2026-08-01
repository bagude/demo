//! The resolved composition graph — the compiler's intermediate representation.
//!
//! The surface expression is a concise linear syntax; this module **lowers** it
//! into an explicit graph so that downstream stages operate on resolved
//! structure, not on the syntax tree:
//!
//! ```text
//! composition expression
//!         ↓ parse            (compose.rs)
//! AST
//!         ↓ resolve          (this module)
//! ResolvedGraph  — nodes, typed edges, ACTIVE binding set
//!         ↓
//! case law + backend generation
//! ```
//!
//! Two properties the AST alone cannot provide:
//!
//! 1. **Positions are preserved — and aliases identify them.** Every syntactic
//!    occurrence becomes its own node, so `Port[github] within Sandbox +
//!    Port[github] -> Gate` is two architectural positions sharing one binding.
//!    The one deliberate exception is the alias: same-alias occurrences are ONE
//!    position (`Port[github as gh] within Sandbox + gh -> Gate` collapses the
//!    declaration and its reference into a single node participating in both
//!    relations) — that collapse is exactly what makes a position referenceable
//!    and lets a linear expression declare a DAG.
//!
//! 2. **Activation is explicit.** A binding is part of the compiled system only
//!    if the composition *activates* it: an anonymous occurrence (`Port`)
//!    activates every binding of its kind; named occurrences (`Port[staging]`)
//!    activate exactly those ids; and activation closes over the references
//!    bindings make to each other (an active Hive activates its worker
//!    Delegate; an active Delegate activates its granted Ports; an active Port
//!    activates its write-guard Law; an active Gate activates its required
//!    obligation Laws). These closure edges are the binding-sourced `uses`
//!    relations — they come from the bindings block, not from the linear
//!    expression. A binding that is not activated is not an architectural node:
//!    the checker warns about it and the backends do not generate it.
//!
//! **Stated over-approximation:** an operator between grouped operands relates
//! all pairs — `(A + B) -> (C + D)` yields all four `FlowsTo` edges. This is a
//! deliberate, conservative reading of the linear syntax (declaring more data
//! paths derives more obligations, never fewer). A spec that needs finer paths
//! should split the expression rather than rely on grouping.

use std::collections::{BTreeMap, BTreeSet};

use crate::compose::Expr;
use crate::model::{Bindings, PatternInstance, PatternKind};

/// A position in the composition graph, identifying one syntactic occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeId(pub usize);

/// One architectural position: a pattern occurrence resolved to the binding
/// ids that implement it.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: NodeId,
    pub kind: PatternKind,
    /// The instance label if the occurrence was named (`Port[staging]`).
    pub instance: Option<String>,
    /// The declared position name (`Port[github as staging_deployer]` →
    /// `staging_deployer`). Distinct from the binding id: two positions sharing
    /// one binding can be named apart, and a singleton kind's position can be
    /// named even though it has no binding id (`Sandbox[as worker]`). Unique
    /// across the composition (checked).
    pub alias: Option<String>,
    /// The binding ids this position resolves to: the named id, or every
    /// binding of the kind for an anonymous occurrence. Empty for singleton
    /// kinds, which have no id namespace.
    pub bindings: Vec<String>,
    /// True when the occurrence sits under a `× N` replication.
    pub replicated: bool,
}

/// The relation an edge carries. Direction is `from → to` in the operator's
/// own sense: `Within(inner, outer)`, `FlowsTo(upstream, downstream)`,
/// `Provisions(provisioner, provisioned)`. `Coexist` is symmetric but stored
/// once, left-to-right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    Within,
    FlowsTo,
    Provisions,
    Coexist,
}

/// A typed edge between two positions.
#[derive(Debug, Clone, Copy)]
pub struct Edge {
    pub relation: Relation,
    pub from: NodeId,
    pub to: NodeId,
}

impl Relation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Relation::Within => "within",
            Relation::FlowsTo => "flows_to",
            Relation::Provisions => "provisions",
            Relation::Coexist => "coexist",
        }
    }
}

/// Why one binding depends on another — the binding-sourced dependency kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UseKind {
    /// A Hive's `worker` field names the Delegate it spawns against.
    HiveWorker,
    /// A Delegate's `ports` list grants it a capability Port.
    DelegatePort,
    /// A Port's `write_guard` names the Law governing its writes.
    PortGuard,
    /// A Gate's `requires_obligations` names the obligation Laws it discharges.
    GateObligation,
}

impl UseKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            UseKind::HiveWorker => "hive_worker",
            UseKind::DelegatePort => "delegate_port",
            UseKind::PortGuard => "port_guard",
            UseKind::GateObligation => "gate_obligation",
        }
    }

    /// The bindings-block field this dependency was read from.
    pub fn origin(&self) -> &'static str {
        match self {
            UseKind::HiveWorker => "hive.worker",
            UseKind::DelegatePort => "delegate.ports",
            UseKind::PortGuard => "port.write_guard",
            UseKind::GateObligation => "gate.requires_obligations",
        }
    }
}

/// A binding-level dependency edge: `from` uses `to`. Unlike position [`Edge`]s
/// (which relate syntactic occurrences), a `uses` edge relates *bindings* — it
/// is read from the bindings block, not from the linear expression, and it is a
/// first-class part of the IR so case law can ask "which Delegate uses this
/// Port" without returning to the raw bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseEdge {
    pub kind: UseKind,
    pub from: (PatternKind, String),
    pub to: (PatternKind, String),
}

/// Which bindings of one kind the composition activates.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Activation {
    /// An anonymous occurrence appeared: every binding of the kind is active.
    All,
    /// Exactly these binding ids are active (possibly none).
    Ids(BTreeSet<String>),
}

impl Activation {
    fn includes(&self, id: &str) -> bool {
        match self {
            Activation::All => true,
            Activation::Ids(ids) => ids.contains(id),
        }
    }

    fn insert(&mut self, id: &str) -> bool {
        match self {
            Activation::All => false,
            Activation::Ids(ids) => ids.insert(id.to_string()),
        }
    }
}

/// The lowered, resolved form of a composition: positions, typed edges, and
/// the active binding set that case law and generation consume.
#[derive(Debug, Clone)]
pub struct ResolvedGraph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    uses: Vec<UseEdge>,
    /// Relations written explicitly between one position and itself
    /// (`p -> p`). Recorded rather than dropped: an incidental self-pair from
    /// conservative all-pairs lowering is noise, but an explicitly written
    /// self-relation is syntax, and silently deleting syntax can delete a
    /// derived obligation with it. The checker reports these.
    self_relations: Vec<(NodeId, Relation)>,
    /// Aliases reached both under and outside a `× N` replication. One node
    /// cannot be both a singleton position and a replicated one; until runtime
    /// instances exist the compiler refuses the ambiguity instead of folding it
    /// into a single boolean.
    replication_conflicts: BTreeSet<String>,
    activation: BTreeMap<PatternKind, Activation>,
    /// Why each activated binding is part of the architecture. Serialized, so
    /// activation provenance is explainable rather than a private map.
    activation_origins: BTreeMap<(PatternKind, String), BTreeSet<ActivationOrigin>>,
}

/// Why a binding is active — the provenance behind [`ResolvedGraph::is_active`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActivationOrigin {
    /// Named (or covered anonymously) by a position in the composition.
    Surface,
    /// Pulled in by an active binding's declared dependency (a `uses` edge).
    Uses(UseKind),
    /// Declared `always_on` in the bindings block.
    AlwaysOn,
}

impl ActivationOrigin {
    pub fn as_str(&self) -> String {
        match self {
            ActivationOrigin::Surface => "surface".to_string(),
            ActivationOrigin::Uses(k) => format!("uses:{}", k.as_str()),
            ActivationOrigin::AlwaysOn => "always_on".to_string(),
        }
    }
}

/// Whether a binding is part of the compiled architecture, and why.
#[derive(Debug, Clone)]
pub struct ResolvedBinding {
    pub kind: PatternKind,
    pub id: String,
    pub active: bool,
    pub origins: BTreeSet<ActivationOrigin>,
}

impl ResolvedGraph {
    /// Lower a parsed composition against its bindings block.
    pub fn resolve(expr: &Expr, b: &Bindings) -> Self {
        let mut g = ResolvedGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
            uses: Vec::new(),
            self_relations: Vec::new(),
            replication_conflicts: BTreeSet::new(),
            activation: BTreeMap::new(),
            activation_origins: BTreeMap::new(),
        };
        g.lower(expr, false, b);
        // `always_on` enforcement is explicitly declared architecture: it is
        // active by declaration, and its own dependencies close like any other.
        for law in b.laws.iter().filter(|l| l.always_on) {
            g.activate_id(PatternKind::Law, &law.id);
            g.record_origin(PatternKind::Law, &law.id, ActivationOrigin::AlwaysOn);
        }
        if let Some(gate) = b.gate.as_ref().filter(|gt| gt.always_on) {
            g.activate_id(PatternKind::Gate, &gate.id);
            g.record_origin(PatternKind::Gate, &gate.id, ActivationOrigin::AlwaysOn);
        }
        g.close_over_binding_references(b);
        g
    }

    /// Every architectural position, in occurrence order.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Every typed edge.
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Every binding-level dependency edge (`from` uses `to`), recorded while
    /// closing activation over the bindings block.
    pub fn uses(&self) -> &[UseEdge] {
        &self.uses
    }

    /// Relations written explicitly between a position and itself.
    pub fn self_relations(&self) -> &[(NodeId, Relation)] {
        &self.self_relations
    }

    /// Aliases reached both inside and outside a replication.
    pub fn replication_conflicts(&self) -> &BTreeSet<String> {
        &self.replication_conflicts
    }

    /// Every addressable binding with its activation status and provenance —
    /// the IR's complete account of which components the architecture includes
    /// and *why*. Serialized, so an `always_on` Law that appears in no position
    /// and no `uses` edge is still visible in the compiled proof object.
    pub fn binding_inventory(&self, b: &Bindings) -> Vec<ResolvedBinding> {
        use PatternKind::*;
        let mut out = Vec::new();
        for kind in [Law, Gate, Specialist, Delegate, Pipeline, Port, Hive] {
            for id in resolved_bindings(b, kind, None) {
                let active = self.is_active(kind, &id);
                let origins = self
                    .activation_origins
                    .get(&(kind, id.clone()))
                    .cloned()
                    .unwrap_or_default();
                out.push(ResolvedBinding {
                    kind,
                    id,
                    active,
                    origins,
                });
            }
        }
        out
    }

    /// Every pattern kind in the compiled architecture: kinds occupying a
    /// position, plus kinds of any active binding (a Law activated only through
    /// a `uses` edge or `always_on` has no position but IS in the system).
    pub fn active_kinds(&self, b: &Bindings) -> BTreeSet<PatternKind> {
        let mut kinds: BTreeSet<PatternKind> = self.nodes.iter().map(|n| n.kind).collect();
        for rb in self.binding_inventory(b).into_iter().filter(|r| r.active) {
            kinds.insert(rb.kind);
        }
        kinds
    }

    /// The addressable bindings the composition does NOT activate, with their
    /// kinds — the components excluded from the compiled architecture. This is
    /// what the serialized IR reports as `inactive_bindings`.
    pub fn inactive_bindings(&self, b: &Bindings) -> Vec<(PatternKind, String)> {
        use PatternKind::*;
        let mut out = Vec::new();
        for kind in [Law, Gate, Specialist, Delegate, Pipeline, Port, Hive] {
            for id in resolved_bindings(b, kind, None) {
                if !self.is_active(kind, &id) {
                    out.push((kind, id));
                }
            }
        }
        out
    }

    /// Whether the composition activates the binding of `kind` with this id.
    /// Inactive bindings are not part of the compiled architecture: the checker
    /// warns about them and the backends do not generate their artifacts.
    pub fn is_active(&self, kind: PatternKind, id: &str) -> bool {
        self.activation.get(&kind).is_some_and(|a| a.includes(id))
    }

    // ---- relational queries -------------------------------------------------
    //
    // Composition case law runs on THESE, not on the syntax tree: the graph's
    // typed edges already carry the resolved binding ids per position, so a
    // rule asks "which bindings stand in this relation" and attaches the
    // derived obligation to exactly those. An anonymous occurrence resolved to
    // every binding of its kind at lowering time, so the conservative
    // all-bindings reading is materialized in the nodes rather than re-derived
    // by each rule.

    fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id.0]
    }

    /// Whether any position of `kind` exists in the composition.
    pub fn has_kind(&self, kind: PatternKind) -> bool {
        self.nodes.iter().any(|n| n.kind == kind)
    }

    /// The position declared with this alias, if any. Aliases are unique
    /// across the composition (the checker rejects duplicates), so this is at
    /// most one node.
    pub fn node_by_alias(&self, alias: &str) -> Option<&Node> {
        self.nodes
            .iter()
            .find(|n| n.alias.as_deref() == Some(alias))
    }

    /// Alias-addressed relation, position on the `from` side: does the position
    /// named `alias` stand in `relation` to some position of kind `other`?
    /// (`alias_related_to("staging_deployer", Relation::Within, Sandbox)` asks
    /// whether that one position — not its binding, not its kind — is inside a
    /// Sandbox.)
    pub fn alias_related_to(&self, alias: &str, relation: Relation, other: PatternKind) -> bool {
        let Some(node) = self.node_by_alias(alias) else {
            return false;
        };
        self.edges
            .iter()
            .any(|e| e.relation == relation && e.from == node.id && self.node(e.to).kind == other)
    }

    /// Alias-addressed relation, position on the `to` side: does some position
    /// of kind `other` stand in `relation` to the position named `alias`?
    pub fn related_to_alias(&self, other: PatternKind, relation: Relation, alias: &str) -> bool {
        let Some(node) = self.node_by_alias(alias) else {
            return false;
        };
        self.edges
            .iter()
            .any(|e| e.relation == relation && e.to == node.id && self.node(e.from).kind == other)
    }

    /// Whether some `from`-kind position stands in `relation` to some
    /// `to`-kind position (edge direction is the operator's own).
    fn kinds_related(&self, relation: Relation, from: PatternKind, to: PatternKind) -> bool {
        self.edges.iter().any(|e| {
            e.relation == relation && self.node(e.from).kind == from && self.node(e.to).kind == to
        })
    }

    /// The resolved binding ids on one side of every matching edge.
    fn edge_bindings(
        &self,
        relation: Relation,
        from: PatternKind,
        to: PatternKind,
        collect_from_side: bool,
    ) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for e in self.edges.iter().filter(|e| e.relation == relation) {
            let (f, t) = (self.node(e.from), self.node(e.to));
            if f.kind == from && t.kind == to {
                let subject = if collect_from_side { f } else { t };
                out.extend(subject.bindings.iter().cloned());
            }
        }
        out
    }

    /// Kind-level: some `inner` executes within some `outer`.
    pub fn kind_within(&self, inner: PatternKind, outer: PatternKind) -> bool {
        self.kinds_related(Relation::Within, inner, outer)
    }

    /// Kind-level: `p` runs within, or downstream of, `entry` — `p` executes in
    /// the context `entry` establishes (within | flows-into | provisioned-by).
    pub fn runs_under(&self, entry: PatternKind, p: PatternKind) -> bool {
        self.kinds_related(Relation::Within, p, entry)
            || self.kinds_related(Relation::FlowsTo, entry, p)
            || self.kinds_related(Relation::Provisions, entry, p)
    }

    /// Binding ids of the `inner`-kind positions that execute within an
    /// `outer`-kind position.
    pub fn bindings_within(&self, inner: PatternKind, outer: PatternKind) -> BTreeSet<String> {
        self.edge_bindings(Relation::Within, inner, outer, true)
    }

    /// Binding ids of the `outer`-kind positions that enclose an `inner`-kind
    /// position (the containers, rather than the contained).
    pub fn bindings_enclosing(&self, inner: PatternKind, outer: PatternKind) -> BTreeSet<String> {
        self.edge_bindings(Relation::Within, inner, outer, false)
    }

    /// Binding ids of the `subject`-kind positions that sit on a data path with
    /// an `other`-kind position — either flow direction.
    pub fn bindings_flow_connected(
        &self,
        subject: PatternKind,
        other: PatternKind,
    ) -> BTreeSet<String> {
        let mut s = self.edge_bindings(Relation::FlowsTo, subject, other, true);
        s.extend(self.edge_bindings(Relation::FlowsTo, other, subject, false));
        s
    }

    /// Binding ids of the `provisioned`-kind positions that a
    /// `provisioner`-kind position provisions.
    pub fn bindings_provisioned(
        &self,
        provisioner: PatternKind,
        provisioned: PatternKind,
    ) -> BTreeSet<String> {
        self.edge_bindings(Relation::Provisions, provisioner, provisioned, false)
    }

    // ---- lowering -----------------------------------------------------------

    /// Recursively lower `expr`, returning the node ids of the subtree's leaf
    /// occurrences so operators can draw pairwise edges between operand groups.
    fn lower(&mut self, expr: &Expr, replicated: bool, b: &Bindings) -> Vec<NodeId> {
        match expr {
            Expr::Pattern(inst) => {
                vec![self.intern_position(inst, inst.alias.as_deref(), replicated, b)]
            }
            // A reference is not a new position: it resolves to the node the
            // declaration produced (creating it if the reference was read
            // first), so every relation mentioning the alias attaches to one
            // node and a linear expression can declare a DAG.
            Expr::AliasRef { alias, target } => {
                vec![self.intern_position(target, Some(alias), replicated, b)]
            }
            Expr::Coexist(l, r) => self.lower_pair(l, r, Relation::Coexist, replicated, b),
            Expr::Seq(l, r) => self.lower_pair(l, r, Relation::FlowsTo, replicated, b),
            Expr::Provision(l, r) => self.lower_pair(l, r, Relation::Provisions, replicated, b),
            Expr::Within(l, r) => self.lower_pair(l, r, Relation::Within, replicated, b),
            Expr::Replicate(e, _) => self.lower(e, true, b),
        }
    }

    fn lower_pair(
        &mut self,
        l: &Expr,
        r: &Expr,
        relation: Relation,
        replicated: bool,
        b: &Bindings,
    ) -> Vec<NodeId> {
        let left = self.lower(l, replicated, b);
        let right = self.lower(r, replicated, b);
        // An operator written directly between one position and itself (`p -> p`)
        // is explicit syntax, not an artifact of grouping: record it so the
        // checker can report it rather than deleting it silently.
        if left.len() == 1 && right.len() == 1 && left[0] == right[0] {
            self.self_relations.push((left[0], relation));
        }
        // All-pairs between operand groups: the stated over-approximation. A
        // collapsed alias can put the SAME node in both groups (`Port[x as p]
        // within Sandbox + p -> Gate` has p on each side of the `+`); a position
        // stands in no relation to itself, so those incidental self-pairs are
        // dropped — the explicit case was recorded above.
        for &from in &left {
            for &to in &right {
                if from != to {
                    self.edges.push(Edge { relation, from, to });
                }
            }
        }
        let mut all = left;
        all.extend(right);
        all
    }

    /// Get or create the node for an occurrence. An aliased occurrence resolves
    /// to the single node bearing that alias — the declaration and every
    /// reference to it are one architectural position. Reaching that one
    /// position both under and outside a replication is contradictory, so it is
    /// recorded as a conflict rather than folded into one boolean.
    fn intern_position(
        &mut self,
        inst: &PatternInstance,
        alias: Option<&str>,
        replicated: bool,
        b: &Bindings,
    ) -> NodeId {
        if let Some(alias) = alias {
            if let Some(existing) = self
                .nodes
                .iter()
                .position(|n| n.alias.as_deref() == Some(alias))
            {
                if self.nodes[existing].replicated != replicated {
                    self.replication_conflicts.insert(alias.to_string());
                }
                return self.nodes[existing].id;
            }
        }
        let id = NodeId(self.nodes.len());
        self.nodes.push(Node {
            id,
            kind: inst.kind,
            instance: inst.id.clone(),
            alias: alias.map(str::to_string),
            bindings: resolved_bindings(b, inst.kind, inst.id.as_deref()),
            replicated,
        });
        self.activate_occurrence(inst.kind, inst.id.as_deref());
        for bid in resolved_bindings(b, inst.kind, inst.id.as_deref()) {
            self.record_origin(inst.kind, &bid, ActivationOrigin::Surface);
        }
        id
    }

    fn record_origin(&mut self, kind: PatternKind, id: &str, origin: ActivationOrigin) {
        self.activation_origins
            .entry((kind, id.to_string()))
            .or_default()
            .insert(origin);
    }

    fn activate_occurrence(&mut self, kind: PatternKind, id: Option<&str>) {
        let entry = self
            .activation
            .entry(kind)
            .or_insert_with(|| Activation::Ids(BTreeSet::new()));
        match id {
            None => *entry = Activation::All,
            Some(id) => {
                entry.insert(id);
            }
        }
    }

    /// Close activation over the references bindings make to each other — the
    /// binding-sourced `uses` edges. A component the architecture activates
    /// pulls in what it declares it depends on, even when the linear expression
    /// never names the dependency.
    fn close_over_binding_references(&mut self, b: &Bindings) {
        // Critic addresses the review-only Delegate subset: fold its activation
        // into Delegate so a single namespace answers is_active for delegates.
        if let Some(critic) = self.activation.get(&PatternKind::Critic).cloned() {
            for dg in b.delegates.iter().filter(|dg| dg.critic) {
                let applies = match &critic {
                    Activation::All => true,
                    Activation::Ids(ids) => ids.contains(&dg.id),
                };
                if applies {
                    self.activate_occurrence(PatternKind::Delegate, Some(&dg.id));
                }
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            // An active Hive activates its worker Delegate.
            for h in &b.hives {
                if self.is_active(PatternKind::Hive, &h.id) {
                    changed |= self.activate_id(PatternKind::Delegate, &h.worker);
                    self.record_use(
                        UseKind::HiveWorker,
                        (PatternKind::Hive, &h.id),
                        (PatternKind::Delegate, &h.worker),
                    );
                }
            }
            // An active Delegate activates the Ports it is granted.
            for dg in &b.delegates {
                if self.is_active(PatternKind::Delegate, &dg.id) {
                    for port in &dg.ports {
                        changed |= self.activate_id(PatternKind::Port, port);
                        self.record_use(
                            UseKind::DelegatePort,
                            (PatternKind::Delegate, &dg.id),
                            (PatternKind::Port, port),
                        );
                    }
                }
            }
            // An active Port activates its write-guard Law.
            for p in &b.ports {
                if self.is_active(PatternKind::Port, &p.id) {
                    if let Some(g) = &p.write_guard {
                        changed |= self.activate_id(PatternKind::Law, g);
                        self.record_use(
                            UseKind::PortGuard,
                            (PatternKind::Port, &p.id),
                            (PatternKind::Law, g),
                        );
                    }
                }
            }
            // An active Gate activates the obligation Laws it requires.
            if let Some(gate) = &b.gate {
                if self.is_active(PatternKind::Gate, &gate.id) {
                    for o in &gate.requires_obligations {
                        changed |= self.activate_id(PatternKind::Law, o);
                        self.record_use(
                            UseKind::GateObligation,
                            (PatternKind::Gate, &gate.id),
                            (PatternKind::Law, o),
                        );
                    }
                }
            }
        }
    }

    /// Record a binding-level dependency edge exactly once, and with it the
    /// activation provenance of the binding it pulled in.
    fn record_use(&mut self, kind: UseKind, from: (PatternKind, &str), to: (PatternKind, &str)) {
        let edge = UseEdge {
            kind,
            from: (from.0, from.1.to_string()),
            to: (to.0, to.1.to_string()),
        };
        if !self.uses.contains(&edge) {
            self.uses.push(edge);
        }
        self.record_origin(to.0, to.1, ActivationOrigin::Uses(kind));
    }

    fn activate_id(&mut self, kind: PatternKind, id: &str) -> bool {
        self.activation
            .entry(kind)
            .or_insert_with(|| Activation::Ids(BTreeSet::new()))
            .insert(id)
    }
}

/// The binding ids an occurrence resolves to: the named id alone, or every
/// binding of the kind when anonymous. Empty for singleton kinds.
fn resolved_bindings(b: &Bindings, kind: PatternKind, id: Option<&str>) -> Vec<String> {
    if let Some(id) = id {
        return vec![id.to_string()];
    }
    use PatternKind::*;
    match kind {
        Law => b.laws.iter().map(|l| l.id.clone()).collect(),
        Gate => b.gate.iter().map(|g| g.id.clone()).collect(),
        Specialist => b.specialists.iter().map(|s| s.id.clone()).collect(),
        Delegate => b.delegates.iter().map(|dg| dg.id.clone()).collect(),
        Critic => b
            .delegates
            .iter()
            .filter(|dg| dg.critic)
            .map(|dg| dg.id.clone())
            .collect(),
        Pipeline => b.pipelines.iter().map(|p| p.id.clone()).collect(),
        Port => b.ports.iter().map(|p| p.id.clone()).collect(),
        Hive => b.hives.iter().map(|h| h.id.clone()).collect(),
        Intake | Verb | Ledger | Sandbox | NightShift | Refinery | Playbook => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::parse;
    use crate::model::SpecFile;

    fn bindings(yaml: &str) -> Bindings {
        let spec: SpecFile = serde_yaml::from_str(yaml).expect("parses");
        spec.bindings
    }

    const TWO_PORTS: &str = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "unused" }
bindings:
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: a, write: [x], write_guard: guard-writes }
    - { id: production, server: b, write: [y], write_guard: guard-writes }
platform: { type: claude-code }
"#;

    #[test]
    fn positions_are_preserved_not_collapsed() {
        // The same binding in two architectural positions stays two nodes.
        let expr = parse("Port[staging] within Sandbox + Port[staging] -> Gate").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let port_nodes: Vec<_> = g
            .nodes()
            .iter()
            .filter(|n| n.kind == PatternKind::Port)
            .collect();
        assert_eq!(port_nodes.len(), 2, "two positions, one binding");
        assert!(port_nodes
            .iter()
            .all(|n| n.bindings == vec!["staging".to_string()]));
    }

    #[test]
    fn named_only_usage_activates_only_named_bindings() {
        let expr = parse("Port[staging] within Sandbox").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        assert!(g.is_active(PatternKind::Port, "staging"));
        assert!(!g.is_active(PatternKind::Port, "production"));
    }

    #[test]
    fn anonymous_occurrence_activates_every_binding_of_the_kind() {
        let expr = parse("Port within Sandbox").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        assert!(g.is_active(PatternKind::Port, "staging"));
        assert!(g.is_active(PatternKind::Port, "production"));
    }

    #[test]
    fn activation_closes_over_binding_references() {
        // Hive -> worker Delegate -> granted Port -> write-guard Law, without
        // any of them being named in the expression.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "unused" }
bindings:
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  delegates:
    - { id: worker, agent: a.md, contract_schema: s.json, tools: [Read], ports: [gh] }
  ports:
    - { id: gh, server: github, write: [comments], write_guard: guard-writes }
  hives:
    - id: swarm
      orchestrator: o.md
      worker: worker
      fan_out: static
      budget: 100
      max_depth: 2
      termination: done
      merge: root
      worker_isolation: disjoint
platform: { type: claude-code }
"#;
        let expr = parse("Hive[swarm]").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(yaml));
        assert!(g.is_active(PatternKind::Hive, "swarm"));
        assert!(g.is_active(PatternKind::Delegate, "worker"));
        assert!(g.is_active(PatternKind::Port, "gh"));
        assert!(g.is_active(PatternKind::Law, "guard-writes"));

        // The dependency chain is REPRESENTED, not just its activation effect:
        // each closure step is a typed `uses` edge in the IR, so case law can
        // ask "which Delegate uses this Port" without the raw bindings block.
        let has = |kind: UseKind, from: (PatternKind, &str), to: (PatternKind, &str)| {
            g.uses().iter().any(|u| {
                u.kind == kind
                    && u.from == (from.0, from.1.to_string())
                    && u.to == (to.0, to.1.to_string())
            })
        };
        assert!(has(
            UseKind::HiveWorker,
            (PatternKind::Hive, "swarm"),
            (PatternKind::Delegate, "worker")
        ));
        assert!(has(
            UseKind::DelegatePort,
            (PatternKind::Delegate, "worker"),
            (PatternKind::Port, "gh")
        ));
        assert!(has(
            UseKind::PortGuard,
            (PatternKind::Port, "gh"),
            (PatternKind::Law, "guard-writes")
        ));
    }

    #[test]
    fn aliased_positions_share_a_binding_but_are_named_apart() {
        // The reviewer's canonical case: one implementation, two positions.
        let expr =
            parse("Port[staging as deployer] within Sandbox + Port[staging as annotator] -> Gate")
                .unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let deployer = g.node_by_alias("deployer").expect("deployer exists");
        let annotator = g.node_by_alias("annotator").expect("annotator exists");
        assert_ne!(deployer.id, annotator.id, "two distinct positions");
        assert_eq!(deployer.bindings, annotator.bindings, "one shared binding");
        assert_eq!(deployer.bindings, vec!["staging".to_string()]);
        assert!(g.node_by_alias("ghost").is_none());
    }

    #[test]
    fn alias_reference_collapses_to_one_node_with_both_relations() {
        // One declared position, referenced in a second relation: ONE node,
        // participating in Within(Sandbox) and FlowsTo(Gate).
        let expr = parse("Port[staging as gh] within Sandbox + gh -> Gate").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let port_nodes = g
            .nodes()
            .iter()
            .filter(|n| n.kind == PatternKind::Port)
            .count();
        assert_eq!(port_nodes, 1, "declaration + reference = one position");
        assert!(g.alias_related_to("gh", Relation::Within, PatternKind::Sandbox));
        assert!(g.alias_related_to("gh", Relation::FlowsTo, PatternKind::Gate));
        // Direction honesty: nothing flows INTO gh from the Gate.
        assert!(!g.related_to_alias(PatternKind::Gate, Relation::FlowsTo, "gh"));
        // An unknown alias stands in no relation.
        assert!(!g.alias_related_to("ghost", Relation::Within, PatternKind::Sandbox));
        // A collapsed node appearing in both operand groups of an operator
        // never relates to itself.
        assert!(g.edges().iter().all(|e| e.from != e.to), "no self-edges");
    }

    #[test]
    fn always_on_enforcement_appears_in_the_binding_inventory() {
        // An `always_on` Law occupies no position and has no incoming `uses`
        // edge, yet it IS part of the compiled architecture — the IR must
        // account for it, or the serialized proof object would omit a
        // mechanism the backend still emits.
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "unused" }
bindings:
  laws:
    - { id: standalone, kind: guard, event: pre_tool, applies_to: [edit], always_on: true }
platform: { type: claude-code }
"#;
        let b = bindings(yaml);
        let expr = parse("Verb").unwrap();
        let g = ResolvedGraph::resolve(&expr, &b);
        assert!(g.is_active(PatternKind::Law, "standalone"));
        let inv = g.binding_inventory(&b);
        let law = inv
            .iter()
            .find(|r| r.id == "standalone")
            .expect("in inventory");
        assert!(law.active);
        assert!(law.origins.contains(&ActivationOrigin::AlwaysOn));
        // ...and the enforcement summary sees the kind even with no position.
        assert!(g.active_kinds(&b).contains(&PatternKind::Law));
        assert!(!g.nodes().iter().any(|n| n.kind == PatternKind::Law));
    }

    #[test]
    fn activation_provenance_distinguishes_surface_from_dependency() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "unused" }
bindings:
  laws:
    - { id: guard-writes, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: gh, server: github, write: [comments], write_guard: guard-writes }
platform: { type: claude-code }
"#;
        let b = bindings(yaml);
        let expr = parse("Port[gh]").unwrap();
        let g = ResolvedGraph::resolve(&expr, &b);
        let inv = g.binding_inventory(&b);
        let port = inv.iter().find(|r| r.id == "gh").unwrap();
        let law = inv.iter().find(|r| r.id == "guard-writes").unwrap();
        assert!(port.origins.contains(&ActivationOrigin::Surface));
        assert!(law
            .origins
            .contains(&ActivationOrigin::Uses(UseKind::PortGuard)));
        assert!(!law.origins.contains(&ActivationOrigin::Surface));
    }

    #[test]
    fn a_reference_is_not_a_second_position() {
        // Declaration + reference = one node; the reference does not intern a
        // new position and does not double-count the binding.
        let expr = parse("Port[staging as p] within Sandbox + p -> Gate").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        assert_eq!(
            g.nodes()
                .iter()
                .filter(|n| n.alias.as_deref() == Some("p"))
                .count(),
            1
        );
    }

    #[test]
    fn inactive_bindings_are_enumerable_from_the_ir() {
        let expr = parse("Port[staging] within Sandbox").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let inactive = g.inactive_bindings(&bindings(TWO_PORTS));
        assert!(inactive.contains(&(PatternKind::Port, "production".to_string())));
        assert!(!inactive.contains(&(PatternKind::Port, "staging".to_string())));
    }

    #[test]
    fn binding_queries_name_only_the_related_component() {
        // Case-law attachment: only the enclosed occurrence's binding stands in
        // the Within relation; its sibling outside the Sandbox does not.
        let expr = parse("Port[staging] within Sandbox + Port[production]").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let inside = g.bindings_within(PatternKind::Port, PatternKind::Sandbox);
        assert_eq!(
            inside.iter().collect::<Vec<_>>(),
            ["staging"],
            "only the enclosed port"
        );
    }

    #[test]
    fn anonymous_occurrence_relates_every_binding_of_the_kind() {
        // The conservative reading is materialized at lowering: a bare `Port`
        // node resolved to every Port binding, so the relation names them all.
        let expr = parse("Port within Sandbox").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let inside = g.bindings_within(PatternKind::Port, PatternKind::Sandbox);
        assert!(inside.contains("staging") && inside.contains("production"));
    }

    #[test]
    fn flow_and_provision_queries_are_direction_honest() {
        // Canonical `Port -> NightShift`: upstream Port is flow-connected, but
        // nothing "runs under" the Night Shift in that topology.
        let expr = parse("Port[staging] -> NightShift").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let on_path = g.bindings_flow_connected(PatternKind::Port, PatternKind::NightShift);
        assert_eq!(on_path.iter().collect::<Vec<_>>(), ["staging"]);
        assert!(!g.runs_under(PatternKind::NightShift, PatternKind::Port));

        let expr = parse("NightShift => Port[production]").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let made = g.bindings_provisioned(PatternKind::NightShift, PatternKind::Port);
        assert_eq!(made.iter().collect::<Vec<_>>(), ["production"]);
        assert!(g.runs_under(PatternKind::NightShift, PatternKind::Port));
    }

    #[test]
    fn enclosing_query_names_the_container() {
        let yaml = r#"
harness: { name: n, version: 0.1.0 }
composition: { expression: "unused" }
bindings:
  delegates:
    - { id: w, agent: a.md, contract_schema: s.json, tools: [Read] }
  hives:
    - id: research
      orchestrator: o.md
      worker: w
      fan_out: static
      budget: 100
      max_depth: 2
      termination: done
      merge: root
      worker_isolation: disjoint
    - id: deploy
      orchestrator: o.md
      worker: w
      fan_out: static
      budget: 100
      max_depth: 2
      termination: done
      merge: root
      worker_isolation: disjoint
platform: { type: claude-code }
"#;
        let expr = parse("(Gate within Hive[research]) + Hive[deploy]").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(yaml));
        let gated = g.bindings_enclosing(PatternKind::Gate, PatternKind::Hive);
        assert_eq!(gated.iter().collect::<Vec<_>>(), ["research"]);
    }

    #[test]
    fn grouped_flow_declares_all_pairwise_edges() {
        // The stated over-approximation, asserted so it stays a stated choice.
        let expr = parse("(Port + Ledger) -> (NightShift + Gate)").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let flows = g
            .edges()
            .iter()
            .filter(|e| e.relation == Relation::FlowsTo)
            .count();
        assert_eq!(flows, 4, "(A + B) -> (C + D) declares four data paths");
    }

    #[test]
    fn replication_marks_nodes() {
        let expr = parse("(Delegate × 3) + Gate").unwrap();
        let g = ResolvedGraph::resolve(&expr, &bindings(TWO_PORTS));
        let dg = g
            .nodes()
            .iter()
            .find(|n| n.kind == PatternKind::Delegate)
            .unwrap();
        let gate = g
            .nodes()
            .iter()
            .find(|n| n.kind == PatternKind::Gate)
            .unwrap();
        assert!(dg.replicated);
        assert!(!gate.replicated);
    }
}
