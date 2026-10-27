//! Extended permissions (`allowxperm` and friends).
//!
//! The operand is a number, a `{ … }` set of numbers and `low - high` ranges,
//! and any of those complemented with `~`.

use std::fmt;

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::identifier::XPermNumber;
use crate::impl_from_str;
use crate::parser::{ParseFromTokens, Parser};

/// One element of an extended-permission set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XPermSetElem {
    /// A single permission number.
    Single(XPermNumber),
    /// An inclusive `low - high` range.
    Range(XPermNumber, XPermNumber),
    /// A nested set.
    Set(XPermSet),
}

impl ParseFromTokens for XPermSetElem {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        if let Some(crate::lexer::TokenTree::Group(group)) = parser.peek() {
            if group.delimiter == crate::lexer::Delimiter::Brace {
                return Ok(Self::Set(XPermSet::parse_from_tokens(parser)?));
            }
        }
        let low = XPermNumber::parse_from_tokens(parser)?;
        if parser.eat_punct('-') {
            return Ok(Self::Range(low, XPermNumber::parse_from_tokens(parser)?));
        }
        Ok(Self::Single(low))
    }
}

/// A `{ … }` set of extended permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XPermSet(Vec<XPermSetElem>);

impl XPermSet {
    /// The set's elements.
    #[must_use]
    pub fn elements(&self) -> &[XPermSetElem] {
        &self.0
    }
}

impl ParseFromTokens for XPermSet {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut inner = parser.next_brace("`{`")?;
        let mut elements = Vec::new();
        loop {
            inner.skip_trivia();
            if inner.is_empty() {
                break;
            }
            elements.push(XPermSetElem::parse_from_tokens(&mut inner)?);
        }
        Ok(Self(elements))
    }
}

/// The extended-permission operand of an xperm rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XPerms {
    /// A single permission number.
    Single(XPermNumber),
    /// A `{ … }` set.
    Set(XPermSet),
    /// The `~` complement of a single number or a set.
    Negated(Box<Self>),
}

impl ParseFromTokens for XPerms {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        if parser.eat_punct('~') {
            return Ok(Self::Negated(Box::new(Self::parse_from_tokens(parser)?)));
        }
        if let Some(crate::lexer::TokenTree::Group(group)) = parser.peek() {
            if group.delimiter == crate::lexer::Delimiter::Brace {
                return Ok(Self::Set(XPermSet::parse_from_tokens(parser)?));
            }
            return Err(ParseError::unexpected(
                "{",
                "an extended permission",
                group.span,
            ));
        }
        match parser.peek() {
            Some(_) => Ok(Self::Single(XPermNumber::parse_from_tokens(parser)?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "an extended permission",
                },
                parser.at(),
            )),
        }
    }
}

impl_from_str!(XPerms);

impl fmt::Display for XPerms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(number) => fmt::Display::fmt(number, f),
            Self::Set(set) => fmt::Display::fmt(set, f),
            Self::Negated(inner) => write!(f, "~{inner}"),
        }
    }
}

impl fmt::Display for XPermSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("{ ")?;
        for (index, element) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(element, f)?;
        }
        f.write_str(" }")
    }
}

impl fmt::Display for XPermSetElem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(number) => fmt::Display::fmt(number, f),
            Self::Range(low, high) => write!(f, "{low}-{high}"),
            Self::Set(set) => fmt::Display::fmt(set, f),
        }
    }
}
