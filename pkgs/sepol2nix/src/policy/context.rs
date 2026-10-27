//! Security contexts, and the `gen_context(...)` macro that wraps them.

use std::fmt;

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::identifier::{RoleId, TypeId, User};
use crate::impl_from_str;
use crate::lexer::TokenTree;
use crate::parser::{ParseFromTokens, Parser};
use crate::policy::mls::MlsRange;

/// A `user:role:type[:range]` security context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityContext {
    /// The `SELinux` user.
    pub user: User,
    /// The role.
    pub role: RoleId,
    /// The type (or, for a process context, the domain).
    pub ty: TypeId,
    /// The MLS range, if the policy is MLS-enabled.
    pub range: Option<MlsRange>,
}

impl ParseFromTokens for SecurityContext {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let user = parser.parse_ident("a user")?;
        parser.expect_punct(':')?;
        let role = parser.parse_ident("a role")?;
        parser.expect_punct(':')?;
        let ty = parser.parse_ident("a type")?;
        let range = if parser.eat_punct(':') {
            Some(MlsRange::parse_from_tokens(parser)?)
        } else {
            None
        };
        Ok(Self {
            user,
            role,
            ty,
            range,
        })
    }
}

impl_from_str!(SecurityContext);

impl fmt::Display for SecurityContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.user, self.role, self.ty)?;
        if let Some(range) = &self.range {
            write!(f, ":{range}")?;
        }
        Ok(())
    }
}

/// The [`gen_context`] macro: a context plus the level that its second
/// argument contributes when MLS or MCS is enabled.
///
/// `m4` expands the call to `context:level` at build time, so both parts are
/// kept as written rather than merged.
///
/// [`gen_context`]: https://github.com/SELinuxProject/refpolicy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenContext {
    /// The context argument.
    pub context: SecurityContext,
    /// The MLS range argument, if present.
    pub range: Option<MlsRange>,
}

impl GenContext {
    /// The macro name.
    pub const NAME: &'static str = "gen_context";
}

impl ParseFromTokens for GenContext {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let name = parser.next_ident_text("`gen_context`")?;
        if name != Self::NAME {
            return Err(ParseError::unexpected(name, "`gen_context`", parser.at()));
        }
        let mut args = parser.next_paren("the `gen_context` argument list")?;
        // `.te`/`.if` sources go through `m4`, which quotes both arguments;
        // `.fc` sources do not, so both spellings are accepted.
        let context = match args.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == crate::lexer::Delimiter::Quote => {
                let mut context_parser = args.next_quote("the quoted context")?;
                let context = SecurityContext::parse_from_tokens(&mut context_parser)?;
                context_parser.finish()?;
                context
            }
            _ => SecurityContext::parse_from_tokens(&mut args)?,
        };
        let range = if args.eat_punct(',') {
            match args.peek() {
                Some(TokenTree::Group(group))
                    if group.delimiter == crate::lexer::Delimiter::Quote =>
                {
                    let mut range_parser = args.next_quote("the quoted MLS range")?;
                    let range = MlsRange::parse_from_tokens(&mut range_parser)?;
                    range_parser.finish()?;
                    Some(range)
                }
                _ => Some(MlsRange::parse_from_tokens(&mut args)?),
            }
        } else {
            None
        };
        args.finish()?;
        Ok(Self { context, range })
    }
}

impl_from_str!(GenContext);

impl fmt::Display for GenContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", Self::NAME)?;
        write!(f, "{}", self.context)?;
        if let Some(range) = &self.range {
            write!(f, ",{range}")?;
        }
        f.write_str(")")
    }
}

/// A context in a `security_context_def` position: a literal context or a
/// `gen_context(...)` call (the latter is what refpolicy uses everywhere).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextValue {
    /// A literal context.
    Literal(SecurityContext),
    /// A `gen_context(...)` call.
    Generated(GenContext),
}

impl ParseFromTokens for ContextValue {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Leaf(token))
                if token.kind == crate::lexer::TokenKind::Ident
                    && token.text == GenContext::NAME =>
            {
                Ok(Self::Generated(GenContext::parse_from_tokens(parser)?))
            }
            Some(_) => Ok(Self::Literal(SecurityContext::parse_from_tokens(parser)?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "a context",
                },
                parser.at(),
            )),
        }
    }
}

impl_from_str!(ContextValue);

impl fmt::Display for ContextValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(context) => write!(f, "{context}"),
            Self::Generated(context) => fmt::Display::fmt(context, f),
        }
    }
}

/// A context as it may appear in a file-context rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileContextValue {
    /// The `<<none>>` sentinel: no label.
    None,
    /// A literal context.
    Literal(SecurityContext),
    /// A `gen_context(...)` call.
    Generated(GenContext),
}

impl ParseFromTokens for FileContextValue {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::NoneContext => {
                parser.next_tree();
                Ok(Self::None)
            }
            Some(TokenTree::Leaf(token))
                if token.kind == crate::lexer::TokenKind::Ident
                    && token.text == GenContext::NAME =>
            {
                Ok(Self::Generated(GenContext::parse_from_tokens(parser)?))
            }
            Some(_) => Ok(Self::Literal(SecurityContext::parse_from_tokens(parser)?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "a file context",
                },
                parser.at(),
            )),
        }
    }
}

impl_from_str!(FileContextValue);

impl FileContextValue {
    /// Writes the value in the bare `gen_context(context,range)` spelling used
    /// by `.fc` files (which have no `m4` stage).
    ///
    /// # Errors
    /// Returns an error when the formatter fails.
    pub fn write_fc(&self, f: &mut dyn fmt::Write) -> fmt::Result {
        match self {
            Self::None => f.write_str("<<none>>"),
            Self::Literal(context) => write!(f, "{context}"),
            Self::Generated(context) => {
                write!(f, "{}(", GenContext::NAME)?;
                write!(f, "{}", context.context)?;
                if let Some(range) = &context.range {
                    write!(f, ",{range}")?;
                }
                f.write_str(")")
            }
        }
    }
}

impl FileContextValue {
    /// The `.fc` text of this value.
    #[must_use]
    pub fn fc_text(&self) -> String {
        let mut out = String::new();
        // Writing into a `String` never fails.
        let _ = self.write_fc(&mut out);
        out
    }
}

impl fmt::Display for FileContextValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_fc(f)
    }
}
