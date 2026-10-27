//! Parse errors.

use std::fmt;

use crate::span::Span;

/// The kind of a [`ParseError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A delimiter was left open at end of input.
    UnterminatedDelimiter {
        /// The human-readable name of the delimiter.
        delimiter: &'static str,
    },
    /// A closing delimiter did not match the innermost opened one.
    MismatchedDelimiter {
        /// The closing delimiter that was found.
        found: &'static str,
        /// The delimiter that was expected.
        expected: &'static str,
    },
    /// A closing delimiter appeared without an opener.
    UnmatchedDelimiter {
        /// The stray closing delimiter.
        delimiter: &'static str,
    },
    /// An unexpected token was found.
    Unexpected {
        /// The offending source text.
        found: String,
        /// What the parser expected instead.
        expected: &'static str,
    },
    /// Input ended while more tokens were required.
    UnexpectedEof {
        /// What the parser expected.
        expected: &'static str,
    },
    /// Tokens remained after the parsed element.
    TrailingTokens {
        /// The first unconsumed token's source text.
        found: String,
    },
    /// The source text does not satisfy the grammar of the target type.
    Invalid {
        /// Why the text is invalid.
        reason: String,
    },
    /// The byte content is not valid UTF-8.
    NotUtf8,
}

/// A syntax error with an optional source location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// What went wrong.
    pub kind: ParseErrorKind,
    /// Where it went wrong, if a token was involved.
    pub span: Option<Span>,
}

impl ParseError {
    /// Creates an error that is not anchored to a token.
    #[must_use]
    pub fn bare(kind: ParseErrorKind) -> Self {
        Self { kind, span: None }
    }

    /// Creates a token-anchored error.
    #[must_use]
    pub fn at(kind: ParseErrorKind, span: Span) -> Self {
        Self {
            kind,
            span: Some(span),
        }
    }

    /// Creates an [`ParseErrorKind::Invalid`] error.
    #[must_use]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::bare(ParseErrorKind::Invalid {
            reason: message.into(),
        })
    }

    /// Attaches a span if the error has none yet.
    #[must_use]
    pub fn with_span(mut self, span: Span) -> Self {
        if self.span.is_none() {
            self.span = Some(span);
        }
        self
    }

    /// Creates an unexpected-token error for `found`.
    #[must_use]
    pub fn unexpected(found: impl Into<String>, expected: &'static str, span: Span) -> Self {
        Self::at(
            ParseErrorKind::Unexpected {
                found: found.into(),
                expected,
            },
            span,
        )
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.span {
            Some(span) => write!(f, "{span}: ")?,
            None => write!(f, "input: ")?,
        }
        match &self.kind {
            ParseErrorKind::UnterminatedDelimiter { delimiter } => {
                write!(f, "unterminated {delimiter}")
            }
            ParseErrorKind::MismatchedDelimiter { found, expected } => {
                write!(
                    f,
                    "mismatched delimiter: found `{found}`, expected `{expected}`"
                )
            }
            ParseErrorKind::UnmatchedDelimiter { delimiter } => {
                write!(f, "unmatched closing delimiter `{delimiter}`")
            }
            ParseErrorKind::Unexpected { found, expected } => {
                write!(f, "unexpected `{found}`, expected {expected}")
            }
            ParseErrorKind::UnexpectedEof { expected } => {
                write!(f, "unexpected end of input, expected {expected}")
            }
            ParseErrorKind::TrailingTokens { found } => {
                write!(f, "trailing tokens starting at `{found}`")
            }
            ParseErrorKind::Invalid { reason } => f.write_str(reason),
            ParseErrorKind::NotUtf8 => f.write_str("source is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<fmt::Error> for ParseError {
    fn from(_: fmt::Error) -> Self {
        Self::invalid("formatting failed")
    }
}

/// The parse result alias used throughout the crate.
pub type Result<T, E = ParseError> = std::result::Result<T, E>;
