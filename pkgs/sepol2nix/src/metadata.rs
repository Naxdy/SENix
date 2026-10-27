//! Layer `metadata.xml`.
//!
//! Refpolicy layers carry one `metadata.xml` with a `<summary>` that documents
//! the layer. The file is XML, but only this one element is allowed, so it is
//! parsed directly rather than through a generic XML parser.

use std::fmt;

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::identifier::DocComment;
use crate::impl_from_str;
use crate::interface::DocText;
use crate::lexer::TokenKind;
use crate::parser::{ParseFromTokens, Parser};

/// A parsed `metadata.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerMetadata {
    /// The layer summary.
    pub summary: DocText,
}

impl ParseFromTokens for LayerMetadata {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_punct('<')?;
        parser.expect_keyword("summary")?;
        parser.expect_punct('>')?;
        let mut lines = Vec::new();
        let mut current = String::new();
        loop {
            match parser.peek() {
                None => {
                    return Err(ParseError::at(
                        ParseErrorKind::UnexpectedEof {
                            expected: "`</summary>`",
                        },
                        parser.at(),
                    ));
                }
                Some(crate::lexer::TokenTree::Leaf(token)) if token.text == "<" => {
                    // `</summary>` is lexed as `<` plus the path `/summary>`;
                    // an opening `<summary>` follows with the keyword instead.
                    parser.next_tree();
                    if let Some(crate::lexer::TokenTree::Leaf(next)) = parser.peek() {
                        if next.kind == TokenKind::Path && next.text == "/summary>" {
                            parser.next_tree();
                            parser.finish()?;
                            if !current.trim().is_empty() {
                                lines.push(DocComment::new(current.trim().to_string()));
                            }
                            return Ok(Self {
                                summary: DocText::new(lines),
                            });
                        }
                    }
                    parser.expect_keyword("summary")?;
                    parser.expect_punct('>')?;
                }
                Some(_) => {
                    let text = parser.next_tree().map(crate::lexer::TokenTree::describe);
                    current.push_str(&text.unwrap_or_default());
                    current.push(' ');
                }
            }
        }
    }
}

impl_from_str!(LayerMetadata);

impl fmt::Display for LayerMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "<summary>")?;
        for line in self.summary.lines() {
            writeln!(f, "\t{}", line.text())?;
        }
        writeln!(f, "</summary>")
    }
}

/// Helper: whether a token is a `<` punctuation.
#[must_use]
pub fn is_open_angle(token: &crate::lexer::Token) -> bool {
    token.kind == TokenKind::Punct('<')
}
