//! Source locations.

use std::fmt;

/// A half-open byte range in the parsed source, with its start line/column.
///
/// Columns and lines are 1-based. A [`Span`] is carried by every token, group
/// and error so that diagnostics can point at the offending source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Byte offset of the first byte.
    pub start: usize,
    /// Byte offset one past the last byte.
    pub end: usize,
    /// 1-based line of `start`.
    pub line: usize,
    /// 1-based column of `start`.
    pub column: usize,
}

impl Span {
    /// Creates a span.
    #[must_use]
    pub const fn new(start: usize, end: usize, line: usize, column: usize) -> Self {
        Self {
            start,
            end,
            line,
            column,
        }
    }

    /// An empty span at the very beginning of a source.
    #[must_use]
    pub const fn start_of_source() -> Self {
        Self::new(0, 0, 1, 1)
    }

    /// Extends this span to cover `other`.
    #[must_use]
    pub fn to(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
            line: self.line,
            column: self.column,
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}
