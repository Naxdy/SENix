//! The `m4` layer of the policy source.
//!
//! Refpolicy is macro-parameterised: `.if` interfaces, `.te` modules, `.spt`
//! support files and the base policy files are all `m4` input. The constructs
//! that matter syntactically are macro invocations, definitions, `dnl`,
//! conditionals and `ifelse`.
//!
//! An invocation's arguments are kept as token sequences (bare or quoted), so a
//! macro body still carries its inner policy syntax. The policy-specific macros
//! that carry structure (`gen_require`, `optional_policy`, `tunable_policy`,
//! `ifdef`, `define`, `policy_module`) are parsed into their own types by
//! [`crate::policy::statement`] rather than represented here.

use std::fmt;

use crate::error::{ParseError, Result};
use crate::identifier::Symbol;
use crate::impl_from_str;
use crate::lexer::{Delimiter, TokenTree};
use crate::m4::ChangeQuote;
use crate::parser::{ParseFromTokens, Parser};

/// A verbatim run of tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSequence(Vec<TokenTree>);

impl TokenSequence {
    /// The run's tokens.
    #[must_use]
    pub fn tokens(&self) -> &[TokenTree] {
        &self.0
    }

    /// Wraps tokens.
    #[must_use]
    pub fn new(tokens: Vec<TokenTree>) -> Self {
        Self(tokens)
    }
}

impl ParseFromTokens for TokenSequence {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(Self(parser.take_rest().to_vec()))
    }
}

impl_from_str!(TokenSequence);

/// One piece of a macro argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacroFragment {
    /// An unquoted token run.
    Bare(TokenSequence),
    /// A `` `…' ``-quoted token run.
    Quoted(TokenSequence),
}

/// One macro argument, made of one or more adjacent fragments.
///
/// `m4` concatenates an argument's pieces, so ``errprint(`text' __endline__)``
/// is a single argument with a quoted and a bare fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroArg {
    /// The argument's fragments, in source order.
    pub fragments: Vec<MacroFragment>,
}

impl MacroArg {
    /// Whether the argument consists of exactly one identifier token.
    #[must_use]
    pub fn single_ident(&self) -> Option<&crate::lexer::Token> {
        let [MacroFragment::Bare(sequence) | MacroFragment::Quoted(sequence)] = &self.fragments[..]
        else {
            return None;
        };
        match sequence.tokens() {
            [TokenTree::Leaf(token)] if token.kind == crate::lexer::TokenKind::Ident => Some(token),
            _ => None,
        }
    }
}

impl ParseFromTokens for MacroArg {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut fragments = Vec::new();
        let mut bare: Vec<TokenTree> = Vec::new();
        loop {
            match parser.peek() {
                None => break,
                Some(TokenTree::Leaf(token))
                    if token.kind == crate::lexer::TokenKind::Punct(',') =>
                {
                    break;
                }
                Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Quote => {
                    if !bare.is_empty() {
                        fragments.push(MacroFragment::Bare(TokenSequence::new(std::mem::take(
                            &mut bare,
                        ))));
                    }
                    let mut inner = parser.next_quote("a quoted macro argument")?;
                    fragments.push(MacroFragment::Quoted(TokenSequence::parse_from_tokens(
                        &mut inner,
                    )?));
                }
                Some(tree) => {
                    bare.push(tree.clone());
                    parser.next_tree();
                }
            }
        }
        if !bare.is_empty() {
            fragments.push(MacroFragment::Bare(TokenSequence::new(bare)));
        }
        Ok(Self { fragments })
    }
}

/// An invocation of a policy macro, e.g. `files_type(foo_t)` or a bare `dnl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroInvocation {
    /// The macro name.
    pub name: Symbol,
    /// The arguments, or `None` for a bare invocation without parentheses.
    pub args: Option<Vec<MacroArg>>,
}

impl MacroInvocation {
    /// Parses the argument list following an already consumed macro name.
    ///
    /// # Errors
    /// Returns an error when an argument does not parse.
    pub fn parse_arguments(parser: &mut Parser<'_>) -> Result<Option<Vec<MacroArg>>> {
        match parser.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                let mut inner = parser.next_paren("a macro argument list")?;
                let mut args = Vec::new();
                if !inner.is_empty() {
                    loop {
                        args.push(MacroArg::parse_from_tokens(&mut inner)?);
                        if !inner.eat_punct(',') {
                            break;
                        }
                    }
                }
                inner.finish()?;
                Ok(Some(args))
            }
            _ => Ok(None),
        }
    }
}

impl ParseFromTokens for MacroInvocation {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let name = parser.parse_ident("a macro name")?;
        let args = Self::parse_arguments(parser)?;
        Ok(Self { name, args })
    }
}

impl_from_str!(MacroInvocation);

impl fmt::Display for MacroInvocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.name, f)?;
        if let Some(args) = &self.args {
            f.write_str("(")?;
            for (index, arg) in args.iter().enumerate() {
                if index > 0 {
                    f.write_str(",")?;
                }
                fmt::Display::fmt(arg, f)?;
            }
            f.write_str(")")?;
        }
        Ok(())
    }
}

impl fmt::Display for MacroArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for fragment in &self.fragments {
            match fragment {
                MacroFragment::Bare(sequence) => fmt::Display::fmt(sequence, f)?,
                MacroFragment::Quoted(sequence) => write!(f, "`{sequence}'")?,
            }
        }
        Ok(())
    }
}

impl fmt::Display for TokenSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut quote_open = "`".to_owned();
        let mut quote_close = "'".to_owned();
        let mut last_line = None;
        let mut previous_ident = false;
        for (index, tree) in self.0.iter().enumerate() {
            let line = tree.span().line;
            // `m4` only recognises a macro call when `(` touches the name.
            let glued = previous_ident
                && matches!(
                    tree,
                    TokenTree::Group(group) if group.delimiter == Delimiter::Parenthesis
                );
            match last_line {
                Some(previous) if line > previous => {
                    for _ in previous..line {
                        f.write_str("\n")?;
                    }
                }
                Some(_) if !glued => f.write_str(" ")?,
                None if index > 0 && !glued => f.write_str(" ")?,
                _ => {}
            }
            previous_ident = matches!(
                tree,
                TokenTree::Leaf(token) if token.kind == crate::lexer::TokenKind::Ident
            );
            last_line = Some(line);
            match tree {
                TokenTree::Leaf(token) => {
                    if token.kind == crate::lexer::TokenKind::ChangeQuote {
                        if let Ok(directive) = token.text.parse::<ChangeQuote>() {
                            quote_open = directive.open.to_string();
                            quote_close = directive.close.to_string();
                        }
                    }
                    match token.kind {
                        crate::lexer::TokenKind::Comment => write!(f, "# {}", token.text)?,
                        crate::lexer::TokenKind::DocComment => write!(f, "## {}", token.text)?,
                        _ => f.write_str(&token.text)?,
                    }
                }
                TokenTree::Group(group) => {
                    let (open, close) = if group.delimiter == Delimiter::Quote {
                        (quote_open.as_str(), quote_close.as_str())
                    } else {
                        (group.delimiter.open(), group.delimiter.close())
                    };
                    f.write_str(open)?;
                    fmt::Display::fmt(&Self(group.tokens.clone()), f)?;
                    f.write_str(close)?;
                }
            }
        }
        Ok(())
    }
}

/// Reads a macro name, quoted or bare.
fn parse_argument_symbol(parser: &mut Parser<'_>) -> Result<Symbol> {
    if let Some(TokenTree::Group(group)) = parser.peek() {
        if group.delimiter == Delimiter::Quote {
            let mut inner = parser.next_quote("a quoted symbol")?;
            let symbol = inner.parse_ident("a symbol")?;
            inner.finish()?;
            return Ok(symbol);
        }
    }
    match parser.next_tree() {
        Some(TokenTree::Leaf(token)) => token.text.parse(),
        Some(tree) => Err(ParseError::unexpected(
            tree.describe(),
            "a symbol",
            tree.span(),
        )),
        None => Err(ParseError::at(
            crate::error::ParseErrorKind::UnexpectedEof {
                expected: "a symbol",
            },
            parser.at(),
        )),
    }
}

/// An `m4` `define(...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// The macro being defined.
    pub name: Symbol,
    /// The definition body.
    pub body: TokenSequence,
}

impl ParseFromTokens for Definition {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("define")?;
        let mut args = parser.next_paren("the `define` argument list")?;
        let name = parse_argument_symbol(&mut args)?;
        args.expect_punct(',')?;
        let body = match args.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Quote => {
                let mut body = args.next_quote_unwrapped("the quoted macro body")?;
                TokenSequence::parse_from_tokens(&mut body)?
            }
            _ => TokenSequence::parse_from_tokens(&mut args)?,
        };
        Ok(Self { name, body })
    }
}

impl_from_str!(Definition);

impl fmt::Display for Definition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "define(`{}',`{}')", self.name, self.body)
    }
}

/// Which conditional an [`Conditional`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalKind {
    /// `ifdef`
    IfDef,
    /// `ifndef`
    IfNDef,
}

impl ConditionalKind {
    /// The construct's source spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IfDef => "ifdef",
            Self::IfNDef => "ifndef",
        }
    }
}

impl fmt::Display for ConditionalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An `ifdef`/`ifndef` construct over bodies of `B`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conditional<B> {
    /// Which conditional it is.
    pub kind: ConditionalKind,
    /// The tested `m4` symbol.
    pub symbol: Symbol,
    /// The body taken when the test holds.
    pub then: B,
    /// The optional alternative body.
    pub otherwise: Option<B>,
}

impl<B: ParseFromTokens> ParseFromTokens for Conditional<B> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let kind = if parser.eat_keyword("ifdef") {
            ConditionalKind::IfDef
        } else {
            parser.expect_keyword("ifndef")?;
            ConditionalKind::IfNDef
        };
        let mut args = parser.next_paren("the conditional argument list")?;
        let mut symbol_parser = args.next_quote("the quoted tested symbol")?;
        let symbol: Symbol = symbol_parser.parse_ident("a condition symbol")?;
        symbol_parser.finish()?;
        args.expect_punct(',')?;
        let mut then_parser = args.next_quote_unwrapped("the quoted then-body")?;
        let then = B::parse_from_tokens(&mut then_parser)?;
        let otherwise = if args.eat_punct(',') {
            let mut otherwise_parser = args.next_quote_unwrapped("the quoted else-body")?;
            let otherwise = B::parse_from_tokens(&mut otherwise_parser)?;
            Some(otherwise)
        } else {
            None
        };
        args.finish()?;
        Ok(Self {
            kind,
            symbol,
            then,
            otherwise,
        })
    }
}

impl<B: fmt::Display> fmt::Display for Conditional<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(`{}',`{}'", self.kind, self.symbol, self.then)?;
        if let Some(otherwise) = &self.otherwise {
            write!(f, ",`{otherwise}'")?;
        }
        f.write_str(")")
    }
}

/// An `m4` `ifelse(...)`.
///
/// Its alternatives are ordinary macro arguments because `ifelse` conditions on
/// arbitrary expressions (`ifelse(`$2',`',…)`) that only exist per caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfElse {
    /// The raw arguments, three or more.
    pub args: Vec<MacroArg>,
}

impl ParseFromTokens for IfElse {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("ifelse")?;
        let mut inner = parser.next_paren("the `ifelse` argument list")?;
        let mut args = Vec::new();
        if !inner.is_empty() {
            loop {
                args.push(MacroArg::parse_from_tokens(&mut inner)?);
                if !inner.eat_punct(',') {
                    break;
                }
            }
        }
        inner.finish()?;
        if args.len() < 3 {
            return Err(ParseError::invalid(format!(
                "`ifelse` needs at least 3 arguments, found {}",
                args.len()
            )));
        }
        Ok(Self { args })
    }
}

impl_from_str!(IfElse);

impl fmt::Display for IfElse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ifelse(")?;
        for (index, arg) in self.args.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            fmt::Display::fmt(arg, f)?;
        }
        f.write_str(")")
    }
}

/// The `dnl` line terminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dnl;

impl fmt::Display for Dnl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dnl")
    }
}

impl ParseFromTokens for Dnl {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("dnl")?;
        Ok(Self)
    }
}
