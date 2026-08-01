//! The composition algebra as a parseable little language.
//!
//! The constitution defines five relations: `A + B` (coexist), `A -> B` (data
//! flow), `A => B` (provision), `A within B` (isolation/control), and `A × N`
//! (replication). This module tokenizes and parses an expression like
//! `Intake -> Verb within (Law + Gate) + Ledger` into an [`Expr`] tree, so the
//! checker can ask structural questions: *which patterns are present?* and
//! *what is running within what?*
//!
//! Occurrences are **instance-addressable**. A bare `Port` is an anonymous
//! occurrence standing for every Port binding; `Port[staging]` names one. The
//! relational queries take a [`Sel`] so the checker can ask about a category
//! (*is some Port within some Sandbox?*) or one component (*is `Port[staging]`
//! within `Sandbox[worker]`?*), and the instance enumerators return the exact
//! bindings a derived obligation should attach to.

use std::collections::{BTreeSet, HashSet};

use crate::model::{PatternInstance, PatternKind};

/// A parsed composition expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A single pattern occurrence, possibly carrying an instance id.
    Pattern(PatternInstance),
    /// `A + B` — both coexist independently.
    Coexist(Box<Expr>, Box<Expr>),
    /// `A -> B` — A's output feeds B.
    Seq(Box<Expr>, Box<Expr>),
    /// `A => B` — A provisions/instantiates B.
    Provision(Box<Expr>, Box<Expr>),
    /// `A within B` — A executes under B's control or isolation.
    Within(Box<Expr>, Box<Expr>),
    /// `A × N` — bounded replication.
    Replicate(Box<Expr>, u32),
}

/// What a relational query matches: any occurrence of a kind, or one specific
/// labelled instance.
///
/// A bare [`PatternKind`] converts into `Sel::Any`, so every kind-level call
/// site (*is some Port within some Sandbox?*) keeps working unchanged.
/// [`Sel::the`] addresses one component (*is `Port[staging]` within it?*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sel<'a> {
    /// Any occurrence of this kind, labelled or not.
    Any(PatternKind),
    /// The occurrence of this kind bearing exactly this instance id.
    One(PatternKind, &'a str),
}

impl<'a> Sel<'a> {
    /// A selector for one named component, e.g. `Sel::the(Port, "staging")`.
    pub fn the(kind: PatternKind, id: &'a str) -> Self {
        Sel::One(kind, id)
    }

    /// Whether this selector matches a concrete occurrence. An `Any` selector
    /// matches every occurrence of the kind (labelled or not); a `One` selector
    /// matches only the occurrence carrying that exact id.
    fn matches(&self, inst: &PatternInstance) -> bool {
        match self {
            Sel::Any(k) => inst.kind == *k,
            Sel::One(k, id) => inst.kind == *k && inst.id.as_deref() == Some(*id),
        }
    }
}

impl From<PatternKind> for Sel<'_> {
    fn from(kind: PatternKind) -> Self {
        Sel::Any(kind)
    }
}

impl<'a> From<&'a PatternInstance> for Sel<'a> {
    fn from(inst: &'a PatternInstance) -> Self {
        match &inst.id {
            Some(id) => Sel::One(inst.kind, id),
            None => Sel::Any(inst.kind),
        }
    }
}

impl Expr {
    /// Every pattern *kind* mentioned anywhere in the expression.
    pub fn patterns(&self) -> BTreeSet<PatternKind> {
        let mut set = BTreeSet::new();
        self.collect(&mut set);
        set
    }

    fn collect(&self, set: &mut BTreeSet<PatternKind>) {
        match self {
            Expr::Pattern(i) => {
                set.insert(i.kind);
            }
            Expr::Coexist(a, b) | Expr::Seq(a, b) | Expr::Provision(a, b) | Expr::Within(a, b) => {
                a.collect(set);
                b.collect(set);
            }
            Expr::Replicate(a, _) => a.collect(set),
        }
    }

    /// True if `kind` appears anywhere in the expression.
    pub fn contains(&self, kind: PatternKind) -> bool {
        self.contains_sel(Sel::Any(kind))
    }

    /// True if any occurrence matching `sel` appears anywhere in the expression.
    fn contains_sel(&self, sel: Sel) -> bool {
        match self {
            Expr::Pattern(i) => sel.matches(i),
            Expr::Coexist(a, b) | Expr::Seq(a, b) | Expr::Provision(a, b) | Expr::Within(a, b) => {
                a.contains_sel(sel) || b.contains_sel(sel)
            }
            Expr::Replicate(a, _) => a.contains_sel(sel),
        }
    }

    /// For every `within` node, the (inner-patterns, outer-patterns) pair.
    /// `Verb within (Law + Gate)` yields `({Verb}, {Law, Gate})`.
    pub fn within_relations(&self) -> Vec<(BTreeSet<PatternKind>, BTreeSet<PatternKind>)> {
        let mut out = Vec::new();
        self.collect_within(&mut out);
        out
    }

    fn collect_within(&self, out: &mut Vec<(BTreeSet<PatternKind>, BTreeSet<PatternKind>)>) {
        match self {
            Expr::Pattern(_) => {}
            Expr::Within(a, b) => {
                out.push((a.patterns(), b.patterns()));
                a.collect_within(out);
                b.collect_within(out);
            }
            Expr::Coexist(a, b) | Expr::Seq(a, b) | Expr::Provision(a, b) => {
                a.collect_within(out);
                b.collect_within(out);
            }
            Expr::Replicate(a, _) => a.collect_within(out),
        }
    }

    // ---- relational queries -------------------------------------------------
    //
    // These ask about *topology*, not mere presence. `Gate + NightShift` (two
    // independent branches) is a different system from `NightShift -> Gate`
    // (a gate downstream of an unattended run), and the composition rules must
    // distinguish them. Each takes `impl Into<Sel>`, so it can be asked about a
    // whole kind or one named instance.

    /// True if some occurrence matching `inner` executes within some occurrence
    /// matching `outer` (`inner within outer`).
    pub fn is_within<'a>(&self, inner: impl Into<Sel<'a>>, outer: impl Into<Sel<'a>>) -> bool {
        self.is_within_sel(inner.into(), outer.into())
    }

    fn is_within_sel(&self, inner: Sel, outer: Sel) -> bool {
        match self {
            Expr::Within(l, r) => {
                (l.contains_sel(inner) && r.contains_sel(outer))
                    || l.is_within_sel(inner, outer)
                    || r.is_within_sel(inner, outer)
            }
            Expr::Coexist(l, r) | Expr::Seq(l, r) | Expr::Provision(l, r) => {
                l.is_within_sel(inner, outer) || r.is_within_sel(inner, outer)
            }
            Expr::Replicate(e, _) => e.is_within_sel(inner, outer),
            Expr::Pattern(_) => false,
        }
    }

    /// True if `from`'s output flows into `to` (`from -> to`), possibly through
    /// intermediate stages. Directional.
    pub fn flows_to<'a>(&self, from: impl Into<Sel<'a>>, to: impl Into<Sel<'a>>) -> bool {
        self.flows_to_sel(from.into(), to.into())
    }

    fn flows_to_sel(&self, from: Sel, to: Sel) -> bool {
        match self {
            Expr::Seq(l, r) => {
                (l.contains_sel(from) && r.contains_sel(to))
                    || l.flows_to_sel(from, to)
                    || r.flows_to_sel(from, to)
            }
            Expr::Coexist(l, r) | Expr::Provision(l, r) | Expr::Within(l, r) => {
                l.flows_to_sel(from, to) || r.flows_to_sel(from, to)
            }
            Expr::Replicate(e, _) => e.flows_to_sel(from, to),
            Expr::Pattern(_) => false,
        }
    }

    /// True if `provisioner` provisions `provisioned` (`provisioner => provisioned`).
    pub fn provisions<'a>(
        &self,
        provisioner: impl Into<Sel<'a>>,
        provisioned: impl Into<Sel<'a>>,
    ) -> bool {
        self.provisions_sel(provisioner.into(), provisioned.into())
    }

    fn provisions_sel(&self, provisioner: Sel, provisioned: Sel) -> bool {
        match self {
            Expr::Provision(l, r) => {
                (l.contains_sel(provisioner) && r.contains_sel(provisioned))
                    || l.provisions_sel(provisioner, provisioned)
                    || r.provisions_sel(provisioner, provisioned)
            }
            Expr::Coexist(l, r) | Expr::Seq(l, r) | Expr::Within(l, r) => {
                l.provisions_sel(provisioner, provisioned)
                    || r.provisions_sel(provisioner, provisioned)
            }
            Expr::Replicate(e, _) => e.provisions_sel(provisioner, provisioned),
            Expr::Pattern(_) => false,
        }
    }

    /// True if `a` and `b` coexist independently (under `+`).
    pub fn coexist<'a>(&self, a: impl Into<Sel<'a>>, b: impl Into<Sel<'a>>) -> bool {
        self.coexist_sel(a.into(), b.into())
    }

    fn coexist_sel(&self, a: Sel, b: Sel) -> bool {
        match self {
            Expr::Coexist(l, r) => {
                (l.contains_sel(a) && r.contains_sel(b))
                    || (l.contains_sel(b) && r.contains_sel(a))
                    || l.coexist_sel(a, b)
                    || r.coexist_sel(a, b)
            }
            Expr::Seq(l, r) | Expr::Provision(l, r) | Expr::Within(l, r) => {
                l.coexist_sel(a, b) || r.coexist_sel(a, b)
            }
            Expr::Replicate(e, _) => e.coexist_sel(a, b),
            Expr::Pattern(_) => false,
        }
    }

    /// True if `p` appears inside a replicated (`× N`) subtree.
    pub fn is_replicated<'a>(&self, p: impl Into<Sel<'a>>) -> bool {
        self.is_replicated_sel(p.into())
    }

    fn is_replicated_sel(&self, p: Sel) -> bool {
        match self {
            Expr::Replicate(e, _) => e.contains_sel(p) || e.is_replicated_sel(p),
            Expr::Coexist(l, r) | Expr::Seq(l, r) | Expr::Provision(l, r) | Expr::Within(l, r) => {
                l.is_replicated_sel(p) || r.is_replicated_sel(p)
            }
            Expr::Pattern(_) => false,
        }
    }

    /// True if `a` and `b` sit on the same data path (`a -> b` or `b -> a`,
    /// possibly through stages). This is *artifact dependency*, deliberately kept
    /// distinct from control/isolation — it says the two participate together,
    /// not that one governs the other.
    pub fn flow_connected<'a>(&self, a: impl Into<Sel<'a>>, b: impl Into<Sel<'a>>) -> bool {
        let (a, b) = (a.into(), b.into());
        self.flows_to_sel(a, b) || self.flows_to_sel(b, a)
    }

    /// True if `p` runs within, or downstream of, `entry` — i.e. `p` executes in
    /// the context that `entry` establishes (used for "a Gate downstream of an
    /// unattended entrypoint"). Note this is a *downstream/containment* test, not
    /// a claim that data flow equals control: it is asymmetric and names the
    /// direction explicitly.
    pub fn runs_under<'a>(&self, entry: impl Into<Sel<'a>>, p: impl Into<Sel<'a>>) -> bool {
        let (entry, p) = (entry.into(), p.into());
        self.is_within_sel(p, entry) || self.flows_to_sel(entry, p) || self.provisions_sel(entry, p)
    }

    /// True if `a` and `b` may execute concurrently: they coexist or share a
    /// replicated subtree, and neither is sequenced before the other.
    pub fn may_execute_concurrently<'a>(
        &self,
        a: impl Into<Sel<'a>>,
        b: impl Into<Sel<'a>>,
    ) -> bool {
        let (a, b) = (a.into(), b.into());
        (self.coexist_sel(a, b) || (self.is_replicated_sel(a) && self.is_replicated_sel(b)))
            && !self.flows_to_sel(a, b)
            && !self.flows_to_sel(b, a)
    }

    // ---- instance enumeration ----------------------------------------------
    //
    // The bool queries above answer *whether* a relation holds. These answer
    // *which components* stand in it, so the checker can attach a derived
    // obligation to `Port[staging]` alone rather than to every Port binding.

    /// The distinct occurrences of `kind`, deduplicated by identity (anonymous
    /// occurrences collapse to one).
    pub fn instances_of(&self, kind: PatternKind) -> Vec<&PatternInstance> {
        let mut v = Vec::new();
        self.collect_kind(kind, &mut v);
        dedup(v)
    }

    fn collect_kind<'e>(&'e self, kind: PatternKind, out: &mut Vec<&'e PatternInstance>) {
        match self {
            Expr::Pattern(i) => {
                if i.kind == kind {
                    out.push(i);
                }
            }
            Expr::Coexist(a, b) | Expr::Seq(a, b) | Expr::Provision(a, b) | Expr::Within(a, b) => {
                a.collect_kind(kind, out);
                b.collect_kind(kind, out);
            }
            Expr::Replicate(a, _) => a.collect_kind(kind, out),
        }
    }

    /// The `inner`-kind occurrences that execute *within* some occurrence
    /// matching `outer`. Mirrors [`Self::is_within`], but names the components.
    pub fn instances_within<'a>(
        &self,
        inner: PatternKind,
        outer: impl Into<Sel<'a>>,
    ) -> Vec<&PatternInstance> {
        let mut v = Vec::new();
        self.collect_within_instances(inner, outer.into(), &mut v);
        dedup(v)
    }

    fn collect_within_instances<'e>(
        &'e self,
        inner: PatternKind,
        outer: Sel,
        out: &mut Vec<&'e PatternInstance>,
    ) {
        match self {
            Expr::Within(l, r) => {
                if r.contains_sel(outer) {
                    l.collect_kind(inner, out);
                }
                l.collect_within_instances(inner, outer, out);
                r.collect_within_instances(inner, outer, out);
            }
            Expr::Coexist(l, r) | Expr::Seq(l, r) | Expr::Provision(l, r) => {
                l.collect_within_instances(inner, outer, out);
                r.collect_within_instances(inner, outer, out);
            }
            Expr::Replicate(e, _) => e.collect_within_instances(inner, outer, out),
            Expr::Pattern(_) => {}
        }
    }

    /// The `outer`-kind occurrences that *enclose* some occurrence matching
    /// `inner` (the containers, rather than the contained).
    pub fn instances_enclosing<'a>(
        &self,
        inner: impl Into<Sel<'a>>,
        outer: PatternKind,
    ) -> Vec<&PatternInstance> {
        let mut v = Vec::new();
        self.collect_enclosing_instances(inner.into(), outer, &mut v);
        dedup(v)
    }

    fn collect_enclosing_instances<'e>(
        &'e self,
        inner: Sel,
        outer: PatternKind,
        out: &mut Vec<&'e PatternInstance>,
    ) {
        match self {
            Expr::Within(l, r) => {
                if l.contains_sel(inner) {
                    r.collect_kind(outer, out);
                }
                l.collect_enclosing_instances(inner, outer, out);
                r.collect_enclosing_instances(inner, outer, out);
            }
            Expr::Coexist(l, r) | Expr::Seq(l, r) | Expr::Provision(l, r) => {
                l.collect_enclosing_instances(inner, outer, out);
                r.collect_enclosing_instances(inner, outer, out);
            }
            Expr::Replicate(e, _) => e.collect_enclosing_instances(inner, outer, out),
            Expr::Pattern(_) => {}
        }
    }

    /// The `subject`-kind occurrences that sit on the same data path as some
    /// occurrence matching `other` (either flow direction). Names the components
    /// behind [`Self::flow_connected`].
    pub fn instances_flow_connected<'a>(
        &self,
        subject: PatternKind,
        other: impl Into<Sel<'a>>,
    ) -> Vec<&PatternInstance> {
        let mut v = Vec::new();
        self.collect_flow_connected(subject, other.into(), &mut v);
        dedup(v)
    }

    fn collect_flow_connected<'e>(
        &'e self,
        subject: PatternKind,
        other: Sel,
        out: &mut Vec<&'e PatternInstance>,
    ) {
        match self {
            Expr::Seq(l, r) => {
                // Everything in `l` flows into everything in `r`. A subject on
                // either side of an `other` is flow-connected to it.
                if r.contains_sel(other) {
                    l.collect_kind(subject, out);
                }
                if l.contains_sel(other) {
                    r.collect_kind(subject, out);
                }
                l.collect_flow_connected(subject, other, out);
                r.collect_flow_connected(subject, other, out);
            }
            Expr::Coexist(l, r) | Expr::Provision(l, r) | Expr::Within(l, r) => {
                l.collect_flow_connected(subject, other, out);
                r.collect_flow_connected(subject, other, out);
            }
            Expr::Replicate(e, _) => e.collect_flow_connected(subject, other, out),
            Expr::Pattern(_) => {}
        }
    }

    /// The `provisioned`-kind occurrences that some occurrence matching
    /// `provisioner` provisions (`provisioner => provisioned`).
    pub fn instances_provisioned<'a>(
        &self,
        provisioner: impl Into<Sel<'a>>,
        provisioned: PatternKind,
    ) -> Vec<&PatternInstance> {
        let mut v = Vec::new();
        self.collect_provisioned(provisioner.into(), provisioned, &mut v);
        dedup(v)
    }

    fn collect_provisioned<'e>(
        &'e self,
        provisioner: Sel,
        provisioned: PatternKind,
        out: &mut Vec<&'e PatternInstance>,
    ) {
        match self {
            Expr::Provision(l, r) => {
                if l.contains_sel(provisioner) {
                    r.collect_kind(provisioned, out);
                }
                l.collect_provisioned(provisioner, provisioned, out);
                r.collect_provisioned(provisioner, provisioned, out);
            }
            Expr::Coexist(l, r) | Expr::Seq(l, r) | Expr::Within(l, r) => {
                l.collect_provisioned(provisioner, provisioned, out);
                r.collect_provisioned(provisioner, provisioned, out);
            }
            Expr::Replicate(e, _) => e.collect_provisioned(provisioner, provisioned, out),
            Expr::Pattern(_) => {}
        }
    }
}

/// Deduplicate instance references by identity `(kind, id)`, preserving a stable
/// order. Anonymous occurrences of the same kind collapse to one.
fn dedup(v: Vec<&PatternInstance>) -> Vec<&PatternInstance> {
    let mut seen = HashSet::new();
    v.into_iter()
        .filter(|i| seen.insert((i.kind, i.id.clone())))
        .collect()
}

// ---- tokenizer --------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Number(u32),
    Plus,
    Arrow,    // ->
    FatArrow, // =>
    Within,
    Times, // ×
    LParen,
    RParen,
    LBracket, // [ — opens an instance id
    RBracket, // ]
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '[' => {
                tokens.push(Token::LBracket);
                i += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                i += 1;
            }
            '+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            '×' => {
                tokens.push(Token::Times);
                i += 1;
            }
            '-' if chars.get(i + 1) == Some(&'>') => {
                tokens.push(Token::Arrow);
                i += 2;
            }
            '=' if chars.get(i + 1) == Some(&'>') => {
                tokens.push(Token::FatArrow);
                i += 2;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let n: String = chars[start..i].iter().collect();
                tokens.push(Token::Number(
                    n.parse().map_err(|_| format!("bad number '{n}'"))?,
                ));
            }
            c if c.is_alphanumeric() || c == '_' || c == '-' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '-')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if word == "within" {
                    tokens.push(Token::Within);
                } else {
                    tokens.push(Token::Ident(word));
                }
            }
            other => return Err(format!("unexpected character '{other}' in composition")),
        }
    }
    Ok(tokens)
}

// ---- parser -----------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    /// Precedence, loosest to tightest: `+`  <  `->` / `=>`  <  `within`  <  `×`.
    ///
    /// `+` is loosest because the constitution treats it as cross-cutting
    /// *instrumentation* attached to a whole pipeline ("attach them with +, not
    /// →"): `A -> B + C` therefore means `(A -> B) + C`, and the specimen
    /// `Intake -> Verb within (Law + Gate) + Ledger` means the Ledger coexists
    /// with the entire `Intake -> …` pipeline. Fixing precedence — rather than
    /// leaving `+`/`->` at the same level — is required now that topology drives
    /// safety diagnostics.
    fn parse_coexist(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_flow()?;
        while matches!(self.peek(), Some(Token::Plus)) {
            self.next();
            let right = self.parse_flow()?;
            left = Expr::Coexist(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `->` and `=>` bind tighter than `+`, left-associative.
    fn parse_flow(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_within()?;
        while let Some(tok) = self.peek() {
            let ctor: fn(Box<Expr>, Box<Expr>) -> Expr = match tok {
                Token::Arrow => Expr::Seq,
                Token::FatArrow => Expr::Provision,
                _ => break,
            };
            self.next();
            let right = self.parse_within()?;
            left = ctor(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `within` binds tighter than the flow operators.
    fn parse_within(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_postfix()?;
        while matches!(self.peek(), Some(Token::Within)) {
            self.next();
            let right = self.parse_postfix()?;
            left = Expr::Within(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// Postfix `× N` replication binds tightest.
    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_primary()?;
        while matches!(self.peek(), Some(Token::Times)) {
            self.next();
            match self.next() {
                Some(Token::Number(n)) => expr = Expr::Replicate(Box::new(expr), n),
                other => return Err(format!("expected a number after '×', got {other:?}")),
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Token::LParen) => {
                let inner = self.parse_coexist()?;
                match self.next() {
                    Some(Token::RParen) => Ok(inner),
                    other => Err(format!("expected ')', got {other:?}")),
                }
            }
            Some(Token::Ident(name)) => {
                let kind = name.parse::<PatternKind>()?;
                let id = self.parse_optional_instance_id()?;
                Ok(Expr::Pattern(PatternInstance { kind, id }))
            }
            other => Err(format!("expected a pattern or '(', got {other:?}")),
        }
    }

    /// After a pattern name, an optional `[id]` naming which binding it refers
    /// to. `Port` yields `None`; `Port[staging]` yields `Some("staging")`.
    fn parse_optional_instance_id(&mut self) -> Result<Option<String>, String> {
        if !matches!(self.peek(), Some(Token::LBracket)) {
            return Ok(None);
        }
        self.next(); // consume '['
        let id = match self.next() {
            Some(Token::Ident(s)) => s,
            Some(Token::Number(n)) => n.to_string(),
            other => return Err(format!("expected an instance id after '[', got {other:?}")),
        };
        match self.next() {
            Some(Token::RBracket) => Ok(Some(id)),
            other => Err(format!(
                "expected ']' after instance id '{id}', got {other:?}"
            )),
        }
    }
}

/// Parse a composition expression into an [`Expr`] tree.
pub fn parse(input: &str) -> Result<Expr, String> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err("empty composition expression".to_string());
    }
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_coexist()?;
    if parser.pos != parser.tokens.len() {
        return Err(format!(
            "unexpected trailing tokens after position {}",
            parser.pos
        ));
    }
    Ok(expr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_specimen() {
        let expr = parse("Intake -> Verb within (Law + Gate) + Ledger").unwrap();
        let patterns = expr.patterns();
        assert!(patterns.contains(&PatternKind::Intake));
        assert!(patterns.contains(&PatternKind::Verb));
        assert!(patterns.contains(&PatternKind::Law));
        assert!(patterns.contains(&PatternKind::Gate));
        assert!(patterns.contains(&PatternKind::Ledger));
        assert_eq!(patterns.len(), 5);
    }

    #[test]
    fn captures_the_within_relation() {
        let expr = parse("Verb within (Law + Gate)").unwrap();
        let rels = expr.within_relations();
        assert_eq!(rels.len(), 1);
        let (inner, outer) = &rels[0];
        assert!(inner.contains(&PatternKind::Verb));
        assert!(outer.contains(&PatternKind::Law));
        assert!(outer.contains(&PatternKind::Gate));
    }

    #[test]
    fn parses_replication() {
        // Delegate × N appears in real recipes (e.g. Research Org).
        let expr = parse("Delegate × 4").unwrap();
        assert!(matches!(expr, Expr::Replicate(_, 4)));
    }

    #[test]
    fn parses_the_full_v12_pattern_set() {
        // Every bindable pattern name must tokenize and resolve.
        let expr = parse(
            "(Delegate × 3) -> Critic -> Refinery -> Playbook + Hive + Port + Pipeline + Specialist",
        )
        .unwrap();
        let p = expr.patterns();
        for kind in [
            PatternKind::Delegate,
            PatternKind::Critic,
            PatternKind::Refinery,
            PatternKind::Playbook,
            PatternKind::Hive,
            PatternKind::Port,
            PatternKind::Pipeline,
            PatternKind::Specialist,
        ] {
            assert!(p.contains(&kind), "missing {kind}");
        }
    }

    #[test]
    fn relational_queries_distinguish_topology() {
        // A gate downstream of an unattended run vs. two independent branches.
        let downstream = parse("NightShift -> Gate").unwrap();
        assert!(downstream.flows_to(PatternKind::NightShift, PatternKind::Gate));
        assert!(downstream.runs_under(PatternKind::NightShift, PatternKind::Gate));

        let independent = parse("NightShift + Gate").unwrap();
        assert!(!independent.flows_to(PatternKind::NightShift, PatternKind::Gate));
        assert!(!independent.runs_under(PatternKind::NightShift, PatternKind::Gate));
        assert!(independent.coexist(PatternKind::NightShift, PatternKind::Gate));
    }

    #[test]
    fn flow_connected_is_symmetric_and_direction_stays_distinct() {
        // The canonical `Port -> Night Shift`: the Port feeds the unattended run.
        let e = parse("Port -> NightShift").unwrap();
        assert!(e.flows_to(PatternKind::Port, PatternKind::NightShift));
        assert!(!e.flows_to(PatternKind::NightShift, PatternKind::Port));
        // flow_connected is symmetric; runs_under (NightShift over Port) is NOT
        // implied by upstream flow — the two relations stay distinct.
        assert!(e.flow_connected(PatternKind::Port, PatternKind::NightShift));
        assert!(!e.runs_under(PatternKind::NightShift, PatternKind::Port));
    }

    #[test]
    fn within_and_provisions_and_replication() {
        let e = parse("Verb within (Law + Gate)").unwrap();
        assert!(e.is_within(PatternKind::Verb, PatternKind::Law));
        assert!(e.is_within(PatternKind::Verb, PatternKind::Gate));
        assert!(!e.is_within(PatternKind::Law, PatternKind::Verb));

        let p = parse("NightShift => Gate").unwrap();
        assert!(p.provisions(PatternKind::NightShift, PatternKind::Gate));
        assert!(p.runs_under(PatternKind::NightShift, PatternKind::Gate));

        let hive = parse("(Delegate × 3) + Gate").unwrap();
        assert!(hive.is_replicated(PatternKind::Delegate));
        assert!(!hive.is_replicated(PatternKind::Gate));
    }

    #[test]
    fn plus_binds_looser_than_arrow() {
        // `A -> B + C` is `(A -> B) + C`: C (instrumentation) coexists with the
        // pipeline, it is not sequenced after B.
        let e = parse("Intake -> Verb + Ledger").unwrap();
        assert!(matches!(e, Expr::Coexist(_, _)));
        assert!(e.flows_to(PatternKind::Intake, PatternKind::Verb));
        assert!(!e.flows_to(PatternKind::Verb, PatternKind::Ledger));
        assert!(e.coexist(PatternKind::Verb, PatternKind::Ledger));
    }

    #[test]
    fn flow_is_transitive_through_stages() {
        let e = parse("Port -> NightShift -> Gate").unwrap();
        // Port's output reaches the Gate through the Night Shift.
        assert!(e.flows_to(PatternKind::Port, PatternKind::Gate));
        assert!(e.flows_to(PatternKind::NightShift, PatternKind::Gate));
    }

    #[test]
    fn rejects_unknown_pattern() {
        assert!(parse("Frobnicate + Gate").is_err());
    }

    #[test]
    fn rejects_unbalanced_parens() {
        assert!(parse("Verb within (Law + Gate").is_err());
    }

    // ---- instance addressability -------------------------------------------

    #[test]
    fn parses_and_distinguishes_named_instances() {
        let e = parse("Port[staging] within Sandbox[worker] + Port[metrics]").unwrap();
        // Both Ports are the same kind but distinct instances.
        let ports = e.instances_of(PatternKind::Port);
        assert_eq!(ports.len(), 2);
        // Only the staging Port is inside the sandbox; the metrics Port is not.
        assert!(e.is_within(Sel::the(PatternKind::Port, "staging"), PatternKind::Sandbox));
        assert!(!e.is_within(Sel::the(PatternKind::Port, "metrics"), PatternKind::Sandbox));
        // Kind-level query still sees *some* Port within the Sandbox.
        assert!(e.is_within(PatternKind::Port, PatternKind::Sandbox));
    }

    #[test]
    fn instances_within_names_only_the_enclosed_component() {
        let e = parse("Port[staging] within Sandbox + Port[metrics]").unwrap();
        let inside = e.instances_within(PatternKind::Port, PatternKind::Sandbox);
        assert_eq!(inside.len(), 1);
        assert_eq!(inside[0].id.as_deref(), Some("staging"));
    }

    #[test]
    fn instances_enclosing_names_the_container() {
        let e = parse("(Gate within Hive[research]) + Hive[deploy] + Delegate").unwrap();
        let enclosing = e.instances_enclosing(PatternKind::Gate, PatternKind::Hive);
        assert_eq!(enclosing.len(), 1);
        assert_eq!(enclosing[0].id.as_deref(), Some("research"));
    }

    #[test]
    fn instances_flow_connected_and_provisioned_name_components() {
        let e = parse("Port[a] -> NightShift + Port[b]").unwrap();
        let on_path = e.instances_flow_connected(PatternKind::Port, PatternKind::NightShift);
        assert_eq!(on_path.len(), 1);
        assert_eq!(on_path[0].id.as_deref(), Some("a"));

        let p = parse("NightShift => Port[worker]").unwrap();
        let made = p.instances_provisioned(PatternKind::NightShift, PatternKind::Port);
        assert_eq!(made.len(), 1);
        assert_eq!(made[0].id.as_deref(), Some("worker"));
    }

    #[test]
    fn anonymous_occurrence_still_stands_for_every_binding() {
        // A bare `Port` names no specific instance; the enumerator returns the
        // anonymous occurrence, which the checker reads as "all Port bindings".
        let e = parse("Port within Sandbox").unwrap();
        let inside = e.instances_within(PatternKind::Port, PatternKind::Sandbox);
        assert_eq!(inside.len(), 1);
        assert!(inside[0].id.is_none());
    }
}
