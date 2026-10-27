//! The type-enforcement grammar (`.te`).
//!
//! A `.te` file is a `policy_module(...)` declaration followed by the module's
//! statements. Base-policy fragments (the files under `policy/` that make up the
//! base module) use the same statement language without the module declaration.

use std::fmt;

use crate::error::Result;
use crate::impl_from_str;
use crate::parser::{ParseFromTokens, Parser};
use crate::policy::statement::{ModuleDecl, StatementList};

/// A whole `.te` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeEnforcementFile {
    /// The module declaration, absent in base-policy fragments.
    pub module: Option<ModuleDecl>,
    /// The module's statements.
    pub statements: StatementList,
}

impl ParseFromTokens for TypeEnforcementFile {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let module = if parser.peek_keyword("policy_module") {
            Some(ModuleDecl::parse_from_tokens(parser)?)
        } else {
            None
        };
        let statements = StatementList::parse_from_tokens(parser)?;
        Ok(Self { module, statements })
    }
}

impl_from_str!(TypeEnforcementFile);

impl fmt::Display for TypeEnforcementFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(module) = &self.module {
            write!(f, "policy_module({}", module.name)?;
            if let Some(version) = &module.version {
                write!(f, ",{version}")?;
            }
            writeln!(f, ")")?;
        }
        fmt::Display::fmt(&self.statements, f)
    }
}
