//! Multi-level security syntax: levels, ranges and category sets.

use std::fmt;

use crate::error::Result;
use crate::identifier::{CategoryId, SensitivityId};
use crate::impl_from_str;
use crate::parser::{ParseFromTokens, Parser};

/// A single category or an inclusive category range (`c0.c1023`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CategoryRange {
    /// A single category.
    Single(CategoryId),
    /// An inclusive `low.high` range.
    Range(CategoryId, CategoryId),
}

impl ParseFromTokens for CategoryRange {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let low: CategoryId = parser.parse_ident("a category")?;
        if parser.eat_punct('.') {
            return Ok(Self::Range(low, parser.parse_ident("a category")?));
        }
        Ok(Self::Single(low))
    }
}

impl fmt::Display for CategoryRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(category) => fmt::Display::fmt(category, f),
            Self::Range(low, high) => write!(f, "{low}.{high}"),
        }
    }
}

/// A comma-separated set of categories.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CategorySet(Vec<CategoryRange>);

impl CategorySet {
    /// The set's members.
    #[must_use]
    pub fn ranges(&self) -> &[CategoryRange] {
        &self.0
    }
}

impl ParseFromTokens for CategorySet {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        crate::parser::parse_comma_list(parser).map(Self)
    }
}

impl_from_str!(CategorySet);

impl fmt::Display for CategorySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, range) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            fmt::Display::fmt(range, f)?;
        }
        Ok(())
    }
}

/// An MLS level: a sensitivity and an optional category set
/// (`s0` or `s0:c0,c2`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MlsLevel {
    /// The sensitivity.
    pub sensitivity: SensitivityId,
    /// The categories, if any.
    pub categories: Option<CategorySet>,
}

impl ParseFromTokens for MlsLevel {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let sensitivity = parser.parse_ident("a sensitivity")?;
        let categories = if parser.eat_punct(':') {
            Some(CategorySet::parse_from_tokens(parser)?)
        } else {
            None
        };
        Ok(Self {
            sensitivity,
            categories,
        })
    }
}

impl_from_str!(MlsLevel);

impl fmt::Display for MlsLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.sensitivity, f)?;
        if let Some(categories) = &self.categories {
            write!(f, ":{categories}")?;
        }
        Ok(())
    }
}

/// An MLS range: a single level or the inclusive `low - high` pair.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MlsRange {
    /// The low bound.
    pub low: MlsLevel,
    /// The high bound, when the range is not degenerate.
    pub high: Option<MlsLevel>,
}

impl ParseFromTokens for MlsRange {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let low = MlsLevel::parse_from_tokens(parser)?;
        let high = if parser.eat_punct('-') {
            Some(MlsLevel::parse_from_tokens(parser)?)
        } else {
            None
        };
        Ok(Self { low, high })
    }
}

impl_from_str!(MlsRange);

impl fmt::Display for MlsRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.low, f)?;
        if let Some(high) = &self.high {
            write!(f, "-{high}")?;
        }
        Ok(())
    }
}

/// The comparison operators available in MLS constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlsComparisonOp {
    /// `eq`
    Equal,
    /// `neq`
    NotEqual,
    /// `dom`
    Dominates,
    /// `domby`
    DominatedBy,
    /// `incomp`
    Incomparable,
}

impl MlsComparisonOp {
    /// The operator's source spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "eq",
            Self::NotEqual => "neq",
            Self::Dominates => "dom",
            Self::DominatedBy => "domby",
            Self::Incomparable => "incomp",
        }
    }
}

impl fmt::Display for MlsComparisonOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
