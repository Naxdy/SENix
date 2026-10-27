//! Identifier sets: the `names`, `nested_id_set` and `id_comma_list` grammar
//! productions.
//!
//! `names` is the polymorphic operand language of an access-vector rule. It is
//! a single name, a `{ … }` set (which may itself nest sets and negate single
//! members with `-`), a `*` wildcard, a `~` complement of any of those, or an
//! inclusive `low - high` range.
//!
//! Everything is generic over the element identifier type, so a class set holds
//! [`ClassId`](crate::identifier::ClassId)s and a permission set holds
//! [`PermId`](crate::identifier::PermId)s.

use std::fmt;

use crate::error::{ParseError, Result};
use crate::parser::{ParseFromTokens, Parser};
use crate::span::Span;

use crate::impl_from_str;

/// One member of a `{ … }` nested set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdSetElem<T> {
    /// A plain identifier.
    Id(T),
    /// A negated identifier (`-name`).
    Negated(T),
    /// A further nested set.
    Set(IdSet<T>),
}

impl<T: ParseFromTokens> ParseFromTokens for IdSetElem<T> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        if parser.eat_punct('-') {
            return Ok(Self::Negated(T::parse_from_tokens(parser)?));
        }
        match parser.peek() {
            Some(crate::lexer::TokenTree::Group(group))
                if group.delimiter == crate::lexer::Delimiter::Brace =>
            {
                Ok(Self::Set(IdSet::parse_from_tokens(parser)?))
            }
            Some(_) => Ok(Self::Id(T::parse_from_tokens(parser)?)),
            None => Err(ParseError::at(
                crate::error::ParseErrorKind::UnexpectedEof {
                    expected: "an identifier",
                },
                parser.at(),
            )),
        }
    }
}

/// A `{ … }` nested identifier set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSet<T>(Vec<IdSetElem<T>>);

impl<T> IdSet<T> {
    /// The set's members.
    #[must_use]
    pub fn elements(&self) -> &[IdSetElem<T>] {
        &self.0
    }
}

impl<T: ParseFromTokens> ParseFromTokens for IdSet<T> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut inner = parser.next_brace("`{`")?;
        let mut elements = Vec::new();
        loop {
            inner.skip_trivia();
            if inner.is_empty() {
                break;
            }
            elements.push(IdSetElem::parse_from_tokens(&mut inner)?);
        }
        Ok(Self(elements))
    }
}

/// A whitespace-separated identifier list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdList<T>(Vec<T>);

impl<T> IdList<T> {
    /// The listed identifiers.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.0
    }
}

impl<T: ParseFromTokens> ParseFromTokens for IdList<T> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        crate::parser::parse_space_list(parser).map(Self)
    }
}

impl_from_str!(IdList<crate::identifier::PermId>);

/// A comma-separated identifier list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdCommaList<T>(Vec<T>);

impl<T> IdCommaList<T> {
    /// The listed identifiers.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.0
    }
}

impl<T: ParseFromTokens> ParseFromTokens for IdCommaList<T> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        crate::parser::parse_comma_list(parser).map(Self)
    }
}

impl_from_str!(IdCommaList<crate::identifier::AttributeId>);

/// The `names` operand language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameSet<T> {
    /// A single name.
    Single(T),
    /// A `{ … }` set.
    Set(IdSet<T>),
    /// The `*` wildcard.
    Star(Span),
    /// The `~` complement of the following operand.
    Negated(Box<Self>),
    /// The inclusive `low - high` range.
    Range(T, T),
}

impl<T: ParseFromTokens> ParseFromTokens for NameSet<T> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        if let Some(span) = parser.peek().map(crate::lexer::TokenTree::span) {
            if parser.eat_punct('*') {
                return Ok(Self::Star(span));
            }
        }
        if parser.eat_punct('~') {
            return Ok(Self::Negated(Box::new(Self::parse_from_tokens(parser)?)));
        }
        match parser.peek() {
            Some(crate::lexer::TokenTree::Group(group))
                if group.delimiter == crate::lexer::Delimiter::Brace =>
            {
                return Ok(Self::Set(IdSet::parse_from_tokens(parser)?));
            }
            Some(_) => {}
            None => {
                return Err(ParseError::at(
                    crate::error::ParseErrorKind::UnexpectedEof {
                        expected: "an identifier or name set",
                    },
                    parser.at(),
                ));
            }
        }
        let low = T::parse_from_tokens(parser)?;
        if parser.eat_punct('-') {
            return Ok(Self::Range(low, T::parse_from_tokens(parser)?));
        }
        Ok(Self::Single(low))
    }
}

impl_from_str!(NameSet<crate::identifier::ClassId>);

impl<T: fmt::Display> fmt::Display for NameSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(item) => fmt::Display::fmt(item, f),
            Self::Set(set) => fmt::Display::fmt(set, f),
            Self::Star(_) => f.write_str("*"),
            Self::Negated(item) => write!(f, "~{item}"),
            Self::Range(low, high) => write!(f, "{low}-{high}"),
        }
    }
}

impl<T: fmt::Display> fmt::Display for IdSet<T> {
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

impl<T: fmt::Display> fmt::Display for IdSetElem<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(item) => fmt::Display::fmt(item, f),
            Self::Negated(item) => write!(f, "-{item}"),
            Self::Set(set) => fmt::Display::fmt(set, f),
        }
    }
}

impl<T: fmt::Display> fmt::Display for IdList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, item) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(item, f)?;
        }
        Ok(())
    }
}

impl<T: fmt::Display> fmt::Display for IdCommaList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, item) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            fmt::Display::fmt(item, f)?;
        }
        Ok(())
    }
}
