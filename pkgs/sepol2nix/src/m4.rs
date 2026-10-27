//! Standalone `m4` files (`.spt`, `.m4`, and the `support/` helpers).
//!
//! These files are pure `m4`: macro definitions, conditionals, `dnl` and, in the
//! `support/` helpers, `divert`/`undivert`/`errprint` calls. They carry no
//! policy statements, so their items are the raw `m4` constructs.

use std::fmt;

use crate::error::{ParseError, Result};
use crate::identifier::{Comment, DocComment};
use crate::impl_from_str_m4;
use crate::lexer::{TokenKind, TokenTree};
use crate::parser::{ParseFromTokens, Parser};
use crate::policy::m4::{Conditional, Definition, Dnl, IfElse, MacroInvocation};
use std::str::FromStr;

/// One item of an `m4` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A `#` comment.
    Comment(Comment),
    /// A `##` documentation comment.
    DocComment(DocComment),
    /// A `define(...)`.
    Definition(Definition),
    /// An `ifdef`/`ifndef`.
    Conditional(Box<Conditional<ItemList>>),
    /// An `ifelse(...)`.
    IfElse(IfElse),
    /// Any other macro invocation.
    Invocation(MacroInvocation),
    /// A `dnl`.
    Dnl(Dnl),
    /// An `m4` `changequote(…)` directive.
    ChangeQuote(ChangeQuote),
    /// Any other token, kept verbatim.
    Token(TokenTree),
}

/// An `m4` `changequote(…)` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeQuote {
    /// The new opening delimiter.
    pub open: char,
    /// The new closing delimiter.
    pub close: char,
}

impl ChangeQuote {
    /// The directive text for a single-character delimiter pair.
    #[must_use]
    pub fn new(open: char, close: char) -> Self {
        Self { open, close }
    }
}

impl FromStr for ChangeQuote {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let inner = source
            .strip_prefix("changequote(")
            .and_then(|rest| rest.strip_suffix(')'))
            .ok_or_else(|| ParseError::invalid(format!("bad changequote directive: {source}")))?;
        let (open, close) = inner
            .split_once(',')
            .ok_or_else(|| ParseError::invalid(format!("bad changequote directive: {source}")))?;
        let open = open
            .chars()
            .next()
            .ok_or_else(|| ParseError::invalid("empty changequote opener"))?;
        let close = close
            .chars()
            .next()
            .ok_or_else(|| ParseError::invalid("empty changequote closer"))?;
        Ok(Self { open, close })
    }
}

impl fmt::Display for ChangeQuote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "changequote({},{}", self.open, self.close)
    }
}

impl ParseFromTokens for Item {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::Comment => {
                let text = token.text.clone();
                parser.next_tree();
                Ok(Self::Comment(Comment::new(text)))
            }
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::DocComment => {
                let text = token.text.clone();
                parser.next_tree();
                Ok(Self::DocComment(DocComment::new(text)))
            }
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::ChangeQuote => {
                let text = token.text.clone();
                parser.next_tree();
                Ok(Self::ChangeQuote(text.parse()?))
            }
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::Ident => {
                Ok(match token.text.as_str() {
                    "define" => Self::Definition(Definition::parse_from_tokens(parser)?),
                    "ifdef" | "ifndef" => Self::Conditional(Box::new(
                        Conditional::<ItemList>::parse_from_tokens(parser)?,
                    )),
                    "ifelse" => Self::IfElse(IfElse::parse_from_tokens(parser)?),
                    "dnl" => Self::Dnl(Dnl::parse_from_tokens(parser)?),
                    _ => Self::Invocation(MacroInvocation::parse_from_tokens(parser)?),
                })
            }
            Some(tree) => {
                let tree = tree.clone();
                parser.next_tree();
                Ok(Self::Token(tree))
            }
            None => Err(ParseError::at(
                crate::error::ParseErrorKind::UnexpectedEof {
                    expected: "an `m4` construct",
                },
                parser.at(),
            )),
        }
    }
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Comment(v) => writeln!(f, "{v}"),
            Self::DocComment(v) => writeln!(f, "{v}"),
            Self::Definition(v) => writeln!(f, "{v}"),
            Self::Conditional(v) => writeln!(f, "{v}"),
            Self::IfElse(v) => writeln!(f, "{v}"),
            Self::Invocation(v) => writeln!(f, "{v}"),
            Self::Dnl(_) => writeln!(f, "dnl"),
            Self::ChangeQuote(v) => writeln!(f, "{v})"),
            Self::Token(crate::lexer::TokenTree::Leaf(token)) => writeln!(f, "{}", token.text),
            Self::Token(crate::lexer::TokenTree::Group(group)) => {
                writeln!(f, "{}{}", group.delimiter.open(), group.delimiter.close())
            }
        }
    }
}

/// A list of `m4` items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemList(Vec<Item>);

impl ItemList {
    /// The items.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.0
    }
}

impl ParseFromTokens for ItemList {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut items = Vec::new();
        while !parser.is_empty() {
            items.push(Item::parse_from_tokens(parser)?);
        }
        Ok(Self(items))
    }
}

impl fmt::Display for ItemList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in &self.0 {
            fmt::Display::fmt(item, f)?;
        }
        Ok(())
    }
}

/// A whole `m4` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M4File(Vec<Item>);

impl M4File {
    /// The file's items.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.0
    }
}

impl ParseFromTokens for M4File {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(Self(ItemList::parse_from_tokens(parser)?.items().to_vec()))
    }
}

impl_from_str_m4!(M4File);

impl fmt::Display for M4File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in &self.0 {
            fmt::Display::fmt(item, f)?;
        }
        Ok(())
    }
}
