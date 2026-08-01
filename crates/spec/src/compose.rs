//! The composition algebra as a parseable little language.
//!
//! The constitution defines five relations: `A + B` (coexist), `A -> B` (data
//! flow), `A => B` (provision), `A within B` (isolation/control), and `A × N`
//! (replication). This module tokenizes and parses an expression like
//! `Intake -> Verb within (Law + Gate) + Ledger` into an [`Expr`] tree, so the
//! checker can ask structural questions: *which patterns are present?* and
//! *what is running within what?*

use std::collections::BTreeSet;

use crate::model::PatternKind;

/// A parsed composition expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Pattern(PatternKind),
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

impl Expr {
    /// Every pattern kind mentioned anywhere in the expression.
    pub fn patterns(&self) -> BTreeSet<PatternKind> {
        let mut set = BTreeSet::new();
        self.collect(&mut set);
        set
    }

    fn collect(&self, set: &mut BTreeSet<PatternKind>) {
        match self {
            Expr::Pattern(p) => {
                set.insert(*p);
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
        self.patterns().contains(&kind)
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

    /// Lowest precedence: `+`, `->`, `=>`, left-associative and same level
    /// (their relative precedence is immaterial to the structural questions the
    /// checker asks).
    fn parse_binary(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_within()?;
        while let Some(tok) = self.peek() {
            let ctor: fn(Box<Expr>, Box<Expr>) -> Expr = match tok {
                Token::Plus => Expr::Coexist,
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

    /// `within` binds tighter than the binary operators.
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
                let inner = self.parse_binary()?;
                match self.next() {
                    Some(Token::RParen) => Ok(inner),
                    other => Err(format!("expected ')', got {other:?}")),
                }
            }
            Some(Token::Ident(name)) => name.parse::<PatternKind>().map(Expr::Pattern),
            other => Err(format!("expected a pattern or '(', got {other:?}")),
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
    let expr = parser.parse_binary()?;
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
    fn rejects_unknown_pattern() {
        assert!(parse("Frobnicate + Gate").is_err());
    }

    #[test]
    fn rejects_unbalanced_parens() {
        assert!(parse("Verb within (Law + Gate").is_err());
    }
}
