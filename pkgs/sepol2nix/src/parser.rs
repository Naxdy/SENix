//! Recursive-descent cursor over a [`TokenTree`] slice.

use std::str::FromStr;

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::lexer::{Delimiter, Group, Token, TokenKind, TokenTree};
use crate::span::Span;

/// A syntax element that can parse itself from a token stream.
///
/// This is the primitive every grammar function is built on. It exists so that
/// nested grammars (a group's contents, a macro body, a file's whole token
/// list) can be parsed without re-lexing; [`FromStr`] is derived from it for
/// all public AST types.
pub trait ParseFromTokens: Sized {
    /// Parses the element from the cursor.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self>;
}

/// A cursor over a token-tree slice.
#[derive(Debug, Clone)]
pub struct Parser<'a> {
    tokens: &'a [TokenTree],
    pos: usize,
    fallback: Span,
}

impl<'a> Parser<'a> {
    /// Creates a parser over `tokens`.
    #[must_use]
    pub fn new(tokens: &'a [TokenTree]) -> Self {
        Self {
            tokens,
            pos: 0,
            fallback: Span::start_of_source(),
        }
    }

    /// The location to report when the cursor is at end of input.
    #[must_use]
    pub fn at(&self) -> Span {
        self.tokens
            .get(self.pos)
            .map_or(self.fallback, TokenTree::span)
    }

    /// Whether the cursor is at end of input.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    /// The next tree without consuming it.
    #[must_use]
    pub fn peek(&self) -> Option<&'a TokenTree> {
        self.tokens.get(self.pos)
    }

    /// The text of the next identifier leaf, if there is one.
    #[must_use]
    pub fn peek_ident_text(&self) -> &'a str {
        match self.peek() {
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::Ident => &token.text,
            _ => "",
        }
    }

    /// The current position, for [`Self::rewind`].
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Restores a position obtained from [`Self::position`].
    pub fn rewind(&mut self, position: usize) {
        self.pos = position;
    }

    /// The tree `offset` steps past the next one.
    #[must_use]
    pub fn peek_nth(&self, offset: usize) -> Option<&'a TokenTree> {
        self.tokens.get(self.pos + offset)
    }

    /// The tree one step past the next one.
    #[must_use]
    pub fn peek_second(&self) -> Option<&'a TokenTree> {
        self.tokens.get(self.pos + 1)
    }

    /// Consumes and returns the next tree.
    pub fn next_tree(&mut self) -> Option<&'a TokenTree> {
        let tree = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(tree)
    }

    /// All remaining trees.
    #[must_use]
    pub fn rest(&self) -> &'a [TokenTree] {
        &self.tokens[self.pos..]
    }

    /// Consumes and returns all remaining trees.
    pub fn take_rest(&mut self) -> &'a [TokenTree] {
        let rest = &self.tokens[self.pos..];
        self.pos = self.tokens.len();
        rest
    }

    /// Skips comment and documentation-comment leaves.
    pub fn skip_trivia(&mut self) {
        while matches!(
            self.peek(),
            Some(TokenTree::Leaf(token))
                if matches!(token.kind, TokenKind::Comment | TokenKind::DocComment)
        ) {
            self.pos += 1;
        }
    }

    /// Consumes a leaf of `kind`, returning it.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn next_leaf(&mut self, kind: TokenKind, expected: &'static str) -> Result<&'a Token> {
        match self.next_tree() {
            Some(TokenTree::Leaf(token)) if token.kind == kind => Ok(token),
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                expected,
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof { expected },
                self.at(),
            )),
        }
    }

    /// Consumes and returns the text of an identifier leaf.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn next_ident_text(&mut self, expected: &'static str) -> Result<&'a str> {
        Ok(&self.next_leaf(TokenKind::Ident, expected)?.text)
    }

    /// Parses an element that consumes exactly one identifier token.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn parse_ident<T>(&mut self, expected: &'static str) -> Result<T>
    where
        T: FromStr<Err = ParseError>,
    {
        let token = self.next_leaf(TokenKind::Ident, expected)?;
        token
            .text
            .parse()
            .map_err(|error: ParseError| error.with_span(token.span))
    }

    /// Parses a scalar from a word-like leaf (identifier, number or version).
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn parse_scalar<T>(&mut self, expected: &'static str) -> Result<T>
    where
        T: FromStr<Err = ParseError>,
    {
        match self.next_tree() {
            Some(TokenTree::Leaf(token))
                if matches!(
                    token.kind,
                    TokenKind::Ident | TokenKind::Number | TokenKind::Version | TokenKind::Str
                ) =>
            {
                token
                    .text
                    .parse()
                    .map_err(|error: ParseError| error.with_span(token.span))
            }
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                expected,
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof { expected },
                self.at(),
            )),
        }
    }

    /// Whether the next tree is a parenthesised group.
    #[must_use]
    pub fn peek_paren(&self) -> bool {
        matches!(
            self.peek(),
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis
        )
    }

    /// Whether the next tree is a braced group.
    #[must_use]
    pub fn peek_brace(&self) -> bool {
        matches!(
            self.peek(),
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Brace
        )
    }

    /// Whether the next tree is the punctuation `punct`.
    #[must_use]
    pub fn peek_punct(&self, punct: char) -> bool {
        matches!(
            self.peek(),
            Some(TokenTree::Leaf(Token {
                kind: TokenKind::Punct(found),
                ..
            })) if *found == punct
        )
    }

    /// Consumes the punctuation `punct` if present.
    pub fn eat_punct(&mut self, punct: char) -> bool {
        if self.peek_punct(punct) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consumes the punctuation `punct` or fails.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn expect_punct(&mut self, punct: char) -> Result<Span> {
        let expected = match punct {
            '(' => "`(`",
            ')' => "`)`",
            '{' => "`{`",
            '}' => "`}`",
            '[' => "`[`",
            ']' => "`]`",
            ',' => "`,`",
            ';' => "`;`",
            ':' => "`:`",
            '-' => "`-`",
            '.' => "`.`",
            '~' => "`~`",
            '*' => "`*`",
            '=' => "`=`",
            '!' => "`!`",
            '^' => "`^`",
            other => match other {
                '`' => "a backtick",
                '\'' => "an apostrophe",
                _ => "punctuation",
            },
        };
        match self.next_tree() {
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::Punct(punct) => Ok(token.span),
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                expected,
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof { expected },
                self.at(),
            )),
        }
    }

    /// Whether the next tree is an identifier leaf with the text `keyword`.
    #[must_use]
    pub fn peek_keyword(&self, keyword: &str) -> bool {
        matches!(
            self.peek(),
            Some(TokenTree::Leaf(Token {
                kind: TokenKind::Ident,
                text,
                ..
            })) if text == keyword
        )
    }

    /// Consumes the identifier `keyword` if present.
    pub fn eat_keyword(&mut self, keyword: &str) -> bool {
        if self.peek_keyword(keyword) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consumes `keyword` or fails.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn expect_keyword(&mut self, keyword: &'static str) -> Result<Span> {
        match self.next_tree() {
            Some(TokenTree::Leaf(token))
                if token.kind == TokenKind::Ident && token.text == keyword =>
            {
                Ok(token.span)
            }
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                keyword,
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof { expected: keyword },
                self.at(),
            )),
        }
    }

    /// Consumes one of the punctuation characters in `candidates`.
    pub fn eat_any_punct(&mut self, candidates: &[char]) -> Option<char> {
        match self.peek() {
            Some(TokenTree::Leaf(Token {
                kind: TokenKind::Punct(found),
                ..
            })) if candidates.contains(found) => {
                self.pos += 1;
                Some(*found)
            }
            _ => None,
        }
    }

    /// Consumes a doubled punctuation character (`&&`, `||`, `==`, `!=`).
    pub fn eat_double_punct(&mut self, punct: char) -> bool {
        if self.peek_punct(punct)
            && matches!(
                self.peek_second(),
                Some(TokenTree::Leaf(Token {
                    kind: TokenKind::Punct(found),
                    ..
                })) if *found == punct
            )
        {
            self.pos += 2;
            true
        } else {
            false
        }
    }

    /// Consumes a group delimited by `delimiter` and returns a parser over its
    /// contents.
    ///
    /// # Errors
    /// Returns an error when the next tree is not a group with `delimiter`.
    pub fn next_group(&mut self, delimiter: Delimiter, expected: &'static str) -> Result<Self> {
        match self.next_tree() {
            Some(TokenTree::Group(group)) if group.delimiter == delimiter => {
                let mut inner = Parser::new(&group.tokens);
                inner.fallback = group.span;
                Ok(inner)
            }
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                expected,
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof { expected },
                self.at(),
            )),
        }
    }

    /// Consumes a group without a delimiter requirement (a bare `(` group).
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn next_paren(&mut self, expected: &'static str) -> Result<Self> {
        self.next_group(Delimiter::Parenthesis, expected)
    }

    /// Consumes an `m4`-quoted group.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn next_quote(&mut self, expected: &'static str) -> Result<Self> {
        self.next_group(Delimiter::Quote, expected)
    }

    /// Consumes an `m4`-quoted group, peeling `m4` double quoting
    /// (``` `` … '' ```) down to the real body.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn next_quote_unwrapped(&mut self, expected: &'static str) -> Result<Self> {
        let mut inner = self.next_quote(expected)?;
        while inner.rest().len() == 1 {
            let Some(TokenTree::Group(group)) = inner.peek() else {
                break;
            };
            if group.delimiter != Delimiter::Quote {
                break;
            }
            inner = inner.next_quote(expected)?;
        }
        Ok(inner)
    }

    /// Consumes a `{ ... }` group.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn next_brace(&mut self, expected: &'static str) -> Result<Self> {
        self.next_group(Delimiter::Brace, expected)
    }

    /// Consumes a `[ ... ]` group.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn next_bracket(&mut self, expected: &'static str) -> Result<Self> {
        self.next_group(Delimiter::Bracket, expected)
    }

    /// Consumes a raw group and returns it, for passthrough grammars.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn next_any_group(&mut self, expected: &'static str) -> Result<Group> {
        match self.next_tree() {
            Some(TokenTree::Group(group)) => Ok(group.clone()),
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                expected,
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof { expected },
                self.at(),
            )),
        }
    }

    /// Fails unless all input has been consumed.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    /// # Errors
    /// Returns an error when the input does not match the expected grammar.
    pub fn finish(&mut self) -> Result<()> {
        match self.peek() {
            None => Ok(()),
            Some(tree) => Err(ParseError::at(
                ParseErrorKind::TrailingTokens {
                    found: tree.describe(),
                },
                tree.span(),
            )),
        }
    }
}

/// Parses `parser`'s whole remaining input as a `T`, then requires end of input.
/// # Errors
/// Returns an error when the input does not match the expected grammar.
pub fn parse_all<T: ParseFromTokens>(mut parser: Parser<'_>) -> Result<T> {
    let value = T::parse_from_tokens(&mut parser)?;
    parser.finish()?;
    Ok(value)
}

/// Parses the contents of `tokens` as a `T`, then requires end of input.
/// # Errors
/// Returns an error when the input does not match the expected grammar.
pub fn parse_tokens<T: ParseFromTokens>(tokens: &[TokenTree]) -> Result<T> {
    parse_all(Parser::new(tokens))
}

/// Parses a `( ... )` group's contents as a comma-separated list.
///
/// # Errors
/// Returns an error when the next tree is not a parenthesised group or when a
/// list element does not parse.
pub fn parse_paren_list<T: ParseFromTokens>(
    parser: &mut Parser<'_>,
    expected: &'static str,
) -> Result<Vec<T>> {
    let mut inner = parser.next_paren(expected)?;
    parse_comma_list(&mut inner)
}

/// Parses a comma-separated list until end of input.
/// # Errors
/// Returns an error when the input does not match the expected grammar.
pub fn parse_comma_list<T: ParseFromTokens>(parser: &mut Parser<'_>) -> Result<Vec<T>> {
    let mut items = Vec::new();
    if parser.is_empty() {
        return Ok(items);
    }
    loop {
        parser.skip_trivia();
        items.push(T::parse_from_tokens(parser)?);
        parser.skip_trivia();
        if !parser.eat_punct(',') {
            break;
        }
    }
    Ok(items)
}

/// Parses a whitespace-separated list until end of input.
/// # Errors
/// Returns an error when the input does not match the expected grammar.
pub fn parse_space_list<T: ParseFromTokens>(parser: &mut Parser<'_>) -> Result<Vec<T>> {
    let mut items = Vec::new();
    loop {
        parser.skip_trivia();
        if parser.is_empty() {
            break;
        }
        items.push(T::parse_from_tokens(parser)?);
    }
    Ok(items)
}

/// Implements [`FromStr`] for a type from its `ParseFromTokens` impl.
#[macro_export]
macro_rules! impl_from_str {
    ($ty:ty) => {
        impl ::core::str::FromStr for $ty {
            type Err = $crate::error::ParseError;

            fn from_str(source: &str) -> ::core::result::Result<Self, Self::Err> {
                let tokens = $crate::lexer::lex(source)?;
                $crate::parser::parse_tokens(&tokens)
            }
        }
    };
}

/// Implements [`FromStr`] for an `m4` type from its `ParseFromTokens` impl.
#[macro_export]
macro_rules! impl_from_str_m4 {
    ($ty:ty) => {
        impl ::core::str::FromStr for $ty {
            type Err = $crate::error::ParseError;

            fn from_str(source: &str) -> ::core::result::Result<Self, Self::Err> {
                let tokens = $crate::lexer::lex_m4(source)?;
                $crate::parser::parse_tokens(&tokens)
            }
        }
    };
}

/// Implements [`FromStr`] for a CIL type from its `ParseFromTokens` impl.
#[macro_export]
macro_rules! impl_from_str_cil {
    ($ty:ty) => {
        impl ::core::str::FromStr for $ty {
            type Err = $crate::error::ParseError;

            fn from_str(source: &str) -> ::core::result::Result<Self, Self::Err> {
                let tokens = $crate::lexer::lex_cil(source)?;
                $crate::parser::parse_tokens(&tokens)
            }
        }
    };
}
