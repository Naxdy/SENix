//! Boolean values and the two expression languages of the policy source:
//! conditional expressions (`if`) and constraint expressions
//! (`constrain`, `mlsconstrain`, `validatetrans`, `mlsvalidatetrans`).

use std::fmt;

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::identifier::{BoolId, CategoryId, ClassId, RoleId, SensitivityId, TypeId, User};
use crate::impl_from_str;
use crate::lexer::{Delimiter, TokenTree};
use crate::parser::{ParseFromTokens, Parser};
use crate::policy::mls::MlsComparisonOp;
use crate::policy::names::IdSet;

/// A boolean literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BoolValue {
    /// `true`
    True,
    /// `false`
    False,
}

impl BoolValue {
    /// The literal's source spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::True => "true",
            Self::False => "false",
        }
    }

    /// The boolean value itself.
    #[must_use]
    pub const fn get(self) -> bool {
        matches!(self, Self::True)
    }
}

impl ParseFromTokens for BoolValue {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        if parser.eat_keyword("true") {
            return Ok(Self::True);
        }
        if parser.eat_keyword("false") {
            return Ok(Self::False);
        }
        match parser.peek() {
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                "`true` or `false`",
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "`true` or `false`",
                },
                parser.at(),
            )),
        }
    }
}

impl fmt::Display for BoolValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The binary operators of a conditional expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CondBinaryOp {
    /// `and` / `&&`
    And,
    /// `or` / `||`
    Or,
    /// `xor` / `^`
    Xor,
    /// `eq` / `==`
    Equal,
    /// `!=`
    NotEqual,
}

impl CondBinaryOp {
    /// The operator's canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::And => "&&",
            Self::Or => "||",
            Self::Xor => "^",
            Self::Equal => "==",
            Self::NotEqual => "!=",
        }
    }

    const fn precedence(self) -> u8 {
        match self {
            Self::Or => 1,
            Self::Xor => 2,
            Self::And => 3,
            Self::Equal | Self::NotEqual => 4,
        }
    }
}

impl fmt::Display for CondBinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An expression in the condition of an `if` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondExpr {
    /// A boolean identifier.
    Bool(BoolId),
    /// A parenthesised subexpression.
    Paren(Box<Self>),
    /// A negation.
    Not(Box<Self>),
    /// A binary operation.
    Binary {
        /// The operator.
        op: CondBinaryOp,
        /// The left operand.
        left: Box<Self>,
        /// The right operand.
        right: Box<Self>,
    },
}

impl ParseFromTokens for CondExpr {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Self::parse_binary(parser, 0)
    }
}

impl CondExpr {
    fn parse_binary(parser: &mut Parser<'_>, min_precedence: u8) -> Result<Self> {
        let mut left = Self::parse_unary(parser)?;
        while let Some(op) = peek_binary_op(parser, BinaryFamily::Conditional) {
            if op.precedence() < min_precedence {
                break;
            }
            consume_binary_op(parser, op);
            let right = Self::parse_binary(parser, op.precedence() + 1)?;
            left = Self::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary(parser: &mut Parser<'_>) -> Result<Self> {
        if peek_not(parser) {
            consume_not(parser);
            return Ok(Self::Not(Box::new(Self::parse_unary(parser)?)));
        }
        match parser.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                let mut inner_parser = parser.next_paren("a conditional expression")?;
                let inner = Self::parse_from_tokens(&mut inner_parser)?;
                inner_parser.finish()?;
                Ok(Self::Paren(Box::new(inner)))
            }
            Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Ident => {
                Ok(Self::Bool(parser.parse_ident("a boolean")?))
            }
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                "a boolean or `(`",
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "a boolean or `(`",
                },
                parser.at(),
            )),
        }
    }
}

impl_from_str!(CondExpr);

impl fmt::Display for CondExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(id) => fmt::Display::fmt(id, f),
            Self::Paren(inner) => write!(f, "({inner})"),
            Self::Not(inner) => write!(f, "!{inner}"),
            Self::Binary { op, left, right } => write!(f, "{left} {op} {right}"),
        }
    }
}

/// The two expression families share the boolean connective operators but not
/// their leaf syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFamily {
    /// `if` conditions.
    Conditional,
    /// Constraint bodies.
    Constraint,
}

fn peek_binary_op(parser: &Parser<'_>, family: BinaryFamily) -> Option<CondBinaryOp> {
    match parser.peek()? {
        TokenTree::Leaf(token) => {
            if token.kind == crate::lexer::TokenKind::Ident {
                return match token.text.as_str() {
                    "and" => Some(CondBinaryOp::And),
                    "or" => Some(CondBinaryOp::Or),
                    "xor" if family == BinaryFamily::Conditional => Some(CondBinaryOp::Xor),
                    "eq" => Some(CondBinaryOp::Equal),
                    "neq" if family == BinaryFamily::Constraint => Some(CondBinaryOp::NotEqual),
                    _ => None,
                };
            }
            let next = match parser.peek_second()? {
                TokenTree::Leaf(next) => next,
                TokenTree::Group(_) => return None,
            };
            match (token.kind, next.kind) {
                (crate::lexer::TokenKind::Punct('&'), crate::lexer::TokenKind::Punct('&')) => {
                    Some(CondBinaryOp::And)
                }
                (crate::lexer::TokenKind::Punct('|'), crate::lexer::TokenKind::Punct('|')) => {
                    Some(CondBinaryOp::Or)
                }
                (crate::lexer::TokenKind::Punct('='), crate::lexer::TokenKind::Punct('=')) => {
                    Some(CondBinaryOp::Equal)
                }
                (crate::lexer::TokenKind::Punct('!'), crate::lexer::TokenKind::Punct('=')) => {
                    Some(CondBinaryOp::NotEqual)
                }
                (crate::lexer::TokenKind::Punct('^'), _) if family == BinaryFamily::Conditional => {
                    Some(CondBinaryOp::Xor)
                }
                _ => None,
            }
        }
        TokenTree::Group(_) => None,
    }
}

fn consume_binary_op(parser: &mut Parser<'_>, op: CondBinaryOp) {
    match op {
        CondBinaryOp::And => {
            if !parser.eat_double_punct('&') {
                parser.eat_keyword("and");
            }
        }
        CondBinaryOp::Or => {
            if !parser.eat_double_punct('|') {
                parser.eat_keyword("or");
            }
        }
        CondBinaryOp::Xor => {
            if !parser.eat_punct('^') {
                parser.eat_keyword("xor");
            }
        }
        CondBinaryOp::Equal => {
            if !parser.eat_double_punct('=') {
                parser.eat_keyword("eq");
            }
        }
        CondBinaryOp::NotEqual => {
            let splashed = parser.peek_punct('!')
                && parser.peek_second().is_some_and(|tree| {
                    matches!(tree, TokenTree::Leaf(token) if token.kind == crate::lexer::TokenKind::Punct('='))
                });
            if splashed {
                parser.eat_punct('!');
                parser.eat_punct('=');
            } else {
                parser.eat_keyword("neq");
            }
        }
    }
}

fn peek_not(parser: &Parser<'_>) -> bool {
    parser.peek_keyword("not") || parser.peek_punct('!')
}

fn consume_not(parser: &mut Parser<'_>) {
    if !parser.eat_keyword("not") {
        parser.eat_punct('!');
    }
}

/// The equality operators of plain constraint comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EqualityOp {
    /// `==`
    Equal,
    /// `!=`
    NotEqual,
}

impl EqualityOp {
    /// The operator's spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "==",
            Self::NotEqual => "!=",
        }
    }
}

impl fmt::Display for EqualityOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The source operand of a constraint leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserOperand {
    /// `u1` — the source user.
    Source,
    /// `u2` — the target user.
    Target,
    /// `u3` — the extended (object) user.
    Object,
}

/// A role operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleOperand {
    /// `r1` — the source role.
    Source,
    /// `r2` — the target role.
    Target,
    /// `r3` — the extended (object) role.
    Object,
}

/// A type operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeOperand {
    /// `t1` — the source type.
    Source,
    /// `t2` — the target type.
    Target,
    /// `t3` — the extended (object) type.
    Object,
}

/// A level operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LevelOperand {
    /// `l1` — the low bound of the source level.
    SourceLow,
    /// `l2` — the low bound of the target level.
    TargetLow,
    /// `h1` — the high bound of the source level.
    SourceHigh,
    /// `h2` — the high bound of the target level.
    TargetHigh,
}

/// An operand in a plain attribute comparison (users, roles or types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttrOperand {
    /// A user operand.
    User(UserOperand),
    /// A role operand.
    Role(RoleOperand),
    /// A type operand.
    Type(TypeOperand),
}

impl fmt::Display for UserOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "u1",
            Self::Target => "u2",
            Self::Object => "u3",
        })
    }
}

impl fmt::Display for RoleOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "r1",
            Self::Target => "r2",
            Self::Object => "r3",
        })
    }
}

impl fmt::Display for TypeOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "t1",
            Self::Target => "t2",
            Self::Object => "t3",
        })
    }
}

impl fmt::Display for LevelOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SourceLow => "l1",
            Self::TargetLow => "l2",
            Self::SourceHigh => "h1",
            Self::TargetHigh => "h2",
        })
    }
}

impl fmt::Display for AttrOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(operand) => fmt::Display::fmt(operand, f),
            Self::Role(operand) => fmt::Display::fmt(operand, f),
            Self::Type(operand) => fmt::Display::fmt(operand, f),
        }
    }
}

/// The named right-hand side of a constraint comparison: one identifier or a
/// `{ … }` set of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintNames<T> {
    /// A single identifier.
    Single(T),
    /// A set of identifiers.
    Set(IdSet<T>),
}

impl<T: ParseFromTokens> ParseFromTokens for ConstraintNames<T> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Brace => {
                Ok(Self::Set(IdSet::parse_from_tokens(parser)?))
            }
            Some(_) => Ok(Self::Single(T::parse_from_tokens(parser)?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "an identifier",
                },
                parser.at(),
            )),
        }
    }
}

impl<T: fmt::Display> fmt::Display for ConstraintNames<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(item) => fmt::Display::fmt(item, f),
            Self::Set(set) => fmt::Display::fmt(set, f),
        }
    }
}

/// A leaf of a constraint expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintLeaf {
    /// A plain operand comparison (`u1 == u2`, `r1 dom r2`, `t1 != t2`).
    Attribute {
        /// The left operand.
        left: AttrOperand,
        /// The operator.
        op: MlsComparisonOp,
        /// The right operand.
        right: AttrOperand,
    },
    /// A named user comparison (`u1 == { alice bob }`).
    Users {
        /// The left operand.
        left: UserOperand,
        /// The operator.
        op: EqualityOp,
        /// The user set.
        users: ConstraintNames<User>,
    },
    /// A named role comparison.
    Roles {
        /// The left operand.
        left: RoleOperand,
        /// The operator.
        op: EqualityOp,
        /// The role set.
        roles: ConstraintNames<RoleId>,
    },
    /// A named type comparison.
    Types {
        /// The left operand.
        left: TypeOperand,
        /// The operator.
        op: EqualityOp,
        /// The type set.
        types: ConstraintNames<TypeId>,
    },
    /// A named class comparison.
    Classes {
        /// The left operand.
        left: TypeOperand,
        /// The operator.
        op: EqualityOp,
        /// The class set.
        classes: ConstraintNames<ClassId>,
    },
    /// A named sensitivity comparison.
    Sensitivities {
        /// The left operand.
        left: UserOperand,
        /// The operator.
        op: EqualityOp,
        /// The sensitivity set.
        sensitivities: ConstraintNames<SensitivityId>,
    },
    /// A named category comparison.
    Categories {
        /// The left operand.
        left: UserOperand,
        /// The operator.
        op: EqualityOp,
        /// The category set.
        categories: ConstraintNames<CategoryId>,
    },
    /// `sameuser` — source and target users are identical.
    SameUser,
    /// `source role { … }`.
    SourceRole(ConstraintNames<RoleId>),
    /// `target role { … }`.
    TargetRole(ConstraintNames<RoleId>),
    /// `role <mls-op>` — compares the source and target roles.
    Role(MlsComparisonOp),
    /// `source type { … }`.
    SourceType(ConstraintNames<TypeId>),
    /// `target type { … }`.
    TargetType(ConstraintNames<TypeId>),
    /// A bare macro invocation standing for the whole subexpression.
    Macro(crate::policy::m4::MacroInvocation),
    /// A level comparison (`l1 dom l2`, …).
    Levels {
        /// The left operand.
        left: LevelOperand,
        /// The operator.
        op: MlsComparisonOp,
        /// The right operand.
        right: LevelOperand,
    },
}

/// A constraint expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintExpr {
    /// A parenthesised subexpression.
    Paren(Box<Self>),
    /// A negation.
    Not(Box<Self>),
    /// A conjunction.
    And(Box<Self>, Box<Self>),
    /// A disjunction.
    Or(Box<Self>, Box<Self>),
    /// A leaf.
    Leaf(ConstraintLeaf),
}

impl ParseFromTokens for ConstraintExpr {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Self::parse_binary(parser, 0)
    }
}

impl ConstraintExpr {
    fn parse_binary(parser: &mut Parser<'_>, min_precedence: u8) -> Result<Self> {
        let mut left = Self::parse_unary(parser)?;
        while let Some(op) = peek_binary_op(parser, BinaryFamily::Constraint) {
            if op.precedence() < min_precedence {
                break;
            }
            consume_binary_op(parser, op);
            let right = Self::parse_binary(parser, op.precedence() + 1)?;
            left = match op {
                CondBinaryOp::And => Self::And(Box::new(left), Box::new(right)),
                CondBinaryOp::Or => Self::Or(Box::new(left), Box::new(right)),
                other => {
                    return Err(ParseError::invalid(format!(
                        "operator {} is not valid in a constraint",
                        other.as_str()
                    )));
                }
            };
        }
        Ok(left)
    }

    fn parse_unary(parser: &mut Parser<'_>) -> Result<Self> {
        if peek_not(parser) {
            consume_not(parser);
            return Ok(Self::Not(Box::new(Self::parse_unary(parser)?)));
        }
        match parser.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                let mut inner_parser = parser.next_paren("a constraint expression")?;
                let inner = Self::parse_from_tokens(&mut inner_parser)?;
                inner_parser.finish()?;
                Ok(Self::Paren(Box::new(inner)))
            }
            Some(_) => Ok(Self::Leaf(Self::parse_leaf(parser)?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "a constraint expression",
                },
                parser.at(),
            )),
        }
    }

    fn parse_leaf(parser: &mut Parser<'_>) -> Result<ConstraintLeaf> {
        let left_text = parser.next_ident_text("a constraint operand")?;
        match left_text {
            "sameuser" => Ok(ConstraintLeaf::SameUser),
            "role" => Ok(ConstraintLeaf::Role(parse_mls_op(parser)?)),
            "source" | "target" => {
                let kind = parser.next_ident_text("`role` or `type`")?;
                let names_parser = parser;
                match (left_text, kind) {
                    ("source", "role") => Ok(ConstraintLeaf::SourceRole(
                        ConstraintNames::parse_from_tokens(names_parser)?,
                    )),
                    ("target", "role") => Ok(ConstraintLeaf::TargetRole(
                        ConstraintNames::parse_from_tokens(names_parser)?,
                    )),
                    ("source", "type") => Ok(ConstraintLeaf::SourceType(
                        ConstraintNames::parse_from_tokens(names_parser)?,
                    )),
                    ("target", "type") => Ok(ConstraintLeaf::TargetType(
                        ConstraintNames::parse_from_tokens(names_parser)?,
                    )),
                    _ => Err(ParseError::invalid(format!(
                        "`{left_text} {kind}` is not a constraint operand"
                    ))),
                }
            }
            "u1" | "u2" | "u3" => {
                let left = user_operand(left_text)?;
                if parser.peek_punct('=') && parser.peek_second().is_some() {
                    if is_named(parser) {
                        return Ok(ConstraintLeaf::Users {
                            left,
                            op: parse_equality_op(parser)?,
                            users: ConstraintNames::parse_from_tokens(parser)?,
                        });
                    }
                    let right_text = parser.next_ident_text("a user operand")?;
                    let right = user_operand(right_text)?;
                    Ok(ConstraintLeaf::Attribute {
                        left: AttrOperand::User(left),
                        op: MlsComparisonOp::Equal,
                        right: AttrOperand::User(right),
                    })
                } else if is_named(parser) {
                    Ok(ConstraintLeaf::Users {
                        left,
                        op: parse_equality_op(parser)?,
                        users: ConstraintNames::parse_from_tokens(parser)?,
                    })
                } else {
                    let right_text = parser.next_ident_text("a user operand")?;
                    let right = user_operand(right_text)?;
                    Ok(ConstraintLeaf::Attribute {
                        left: AttrOperand::User(left),
                        op: MlsComparisonOp::Equal,
                        right: AttrOperand::User(right),
                    })
                }
            }
            "r1" | "r2" | "r3" => {
                let left = role_operand(left_text)?;
                if is_named(parser) {
                    return Ok(ConstraintLeaf::Roles {
                        left,
                        op: parse_equality_op(parser)?,
                        roles: ConstraintNames::parse_from_tokens(parser)?,
                    });
                }
                let right_text = parser.next_ident_text("a role operand")?;
                let right = role_operand(right_text)?;
                Ok(ConstraintLeaf::Attribute {
                    left: AttrOperand::Role(left),
                    op: parse_mls_op(parser)?,
                    right: AttrOperand::Role(right),
                })
            }
            "t1" | "t2" | "t3" => {
                let left = type_operand(left_text)?;
                if is_named(parser) {
                    return Ok(ConstraintLeaf::Types {
                        left,
                        op: parse_equality_op(parser)?,
                        types: ConstraintNames::parse_from_tokens(parser)?,
                    });
                }
                let right_text = parser.next_ident_text("a type operand")?;
                let right = type_operand(right_text)?;
                Ok(ConstraintLeaf::Attribute {
                    left: AttrOperand::Type(left),
                    op: MlsComparisonOp::Equal,
                    right: AttrOperand::Type(right),
                })
            }
            "l1" | "l2" | "h1" | "h2" => {
                let left = level_operand(left_text)?;
                let op = parse_mls_op(parser)?;
                let right_text = parser.next_ident_text("a level operand")?;
                Ok(ConstraintLeaf::Levels {
                    left,
                    op,
                    right: level_operand(right_text)?,
                })
            }
            _ => {
                let name = left_text.parse()?;
                let args = crate::policy::m4::MacroInvocation::parse_arguments(parser)?;
                Ok(ConstraintLeaf::Macro(crate::policy::m4::MacroInvocation {
                    name,
                    args,
                }))
            }
        }
    }
}

impl_from_str!(ConstraintExpr);

impl fmt::Display for ConstraintExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Paren(inner) => write!(f, "({inner})"),
            Self::Not(inner) => write!(f, "not {inner}"),
            Self::And(left, right) => write!(f, "{left} and {right}"),
            Self::Or(left, right) => write!(f, "{left} or {right}"),
            Self::Leaf(leaf) => fmt::Display::fmt(leaf, f),
        }
    }
}

impl fmt::Display for ConstraintLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attribute { left, op, right } => write!(f, "{left} {op} {right}"),
            Self::Users { left, op, users } => write!(f, "{left} {op} {users}"),
            Self::Roles { left, op, roles } => write!(f, "{left} {op} {roles}"),
            Self::Types { left, op, types } => write!(f, "{left} {op} {types}"),
            Self::Classes { left, op, classes } => write!(f, "{left} {op} {classes}"),
            Self::Sensitivities {
                left,
                op,
                sensitivities,
            } => write!(f, "{left} {op} {sensitivities}"),
            Self::Categories {
                left,
                op,
                categories,
            } => write!(f, "{left} {op} {categories}"),
            Self::SameUser => f.write_str("sameuser"),
            Self::SourceRole(roles) => write!(f, "source role {roles}"),
            Self::TargetRole(roles) => write!(f, "target role {roles}"),
            Self::Role(op) => write!(f, "role {op}"),
            Self::SourceType(types) => write!(f, "source type {types}"),
            Self::TargetType(types) => write!(f, "target type {types}"),
            Self::Macro(invocation) => fmt::Display::fmt(invocation, f),
            Self::Levels { left, op, right } => write!(f, "{left} {op} {right}"),
        }
    }
}

fn is_named(parser: &Parser<'_>) -> bool {
    parser.peek_keyword("eq")
        || parser.peek_keyword("neq")
        || parser.peek_punct('=')
        || parser.peek_punct('!')
}

fn parse_equality_op(parser: &mut Parser<'_>) -> Result<EqualityOp> {
    if parser.eat_keyword("eq") || parser.eat_double_punct('=') {
        return Ok(EqualityOp::Equal);
    }
    if parser.eat_keyword("neq") || (parser.eat_punct('!') && parser.eat_punct('=')) {
        return Ok(EqualityOp::NotEqual);
    }
    Err(ParseError::unexpected(
        parser.peek().map_or_else(String::new, TokenTree::describe),
        "`==` or `!=`",
        parser.at(),
    ))
}

fn parse_mls_op(parser: &mut Parser<'_>) -> Result<MlsComparisonOp> {
    if let Some(op) = ["eq", "neq", "dom", "domby", "incomp"]
        .into_iter()
        .find_map(|text| {
            parser.eat_keyword(text).then_some(match text {
                "eq" => MlsComparisonOp::Equal,
                "neq" => MlsComparisonOp::NotEqual,
                "dom" => MlsComparisonOp::Dominates,
                "domby" => MlsComparisonOp::DominatedBy,
                _ => MlsComparisonOp::Incomparable,
            })
        })
    {
        return Ok(op);
    }
    if parser.eat_double_punct('=') {
        return Ok(MlsComparisonOp::Equal);
    }
    if parser.eat_punct('!') && parser.eat_punct('=') {
        return Ok(MlsComparisonOp::NotEqual);
    }
    Err(ParseError::unexpected(
        parser.peek().map_or_else(String::new, TokenTree::describe),
        "a comparison operator",
        parser.at(),
    ))
}

fn user_operand(text: &str) -> Result<UserOperand> {
    match text {
        "u1" => Ok(UserOperand::Source),
        "u2" => Ok(UserOperand::Target),
        "u3" => Ok(UserOperand::Object),
        other => Err(ParseError::invalid(format!("not a user operand: {other}"))),
    }
}

fn role_operand(text: &str) -> Result<RoleOperand> {
    match text {
        "r1" => Ok(RoleOperand::Source),
        "r2" => Ok(RoleOperand::Target),
        "r3" => Ok(RoleOperand::Object),
        other => Err(ParseError::invalid(format!("not a role operand: {other}"))),
    }
}

fn type_operand(text: &str) -> Result<TypeOperand> {
    match text {
        "t1" => Ok(TypeOperand::Source),
        "t2" => Ok(TypeOperand::Target),
        "t3" => Ok(TypeOperand::Object),
        other => Err(ParseError::invalid(format!("not a type operand: {other}"))),
    }
}

fn level_operand(text: &str) -> Result<LevelOperand> {
    match text {
        "l1" => Ok(LevelOperand::SourceLow),
        "l2" => Ok(LevelOperand::TargetLow),
        "h1" => Ok(LevelOperand::SourceHigh),
        "h2" => Ok(LevelOperand::TargetHigh),
        other => Err(ParseError::invalid(format!("not a level operand: {other}"))),
    }
}
