//! The CIL S-expression grammar (`.cil`).
//!
//! CIL is a parenthesised statement language. Every statement has its own type,
//! every keyword is matched exactly, and operands are typed by the role they
//! play. Expressions are represented by [`Expr`], constraint expressions by
//! [`ConstraintExpr`].

use std::fmt;
use std::str::FromStr;

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::identifier::{
    AbsolutePath, IbPkey, IbPort, Ioport, Ipv4Addr, Ipv4Cidr, Ipv6Addr, Ipv6Cidr, MapPermId,
    Number64, PciDevice, Pirq, Port, SelinuxUserName, UserPrefix, XPermNumber,
};
use crate::impl_from_str_cil;
use crate::lexer::{Delimiter, TokenKind, TokenTree};
use crate::parser::{ParseFromTokens, Parser};

/// A CIL symbol.
///
/// Symbols may contain letters, digits, `[]`, `@`, `=`, `/`, `*`, `-`, `_`, `$`,
/// `%`, `+`, `!`, `|`, `&`, `^`, `:`, `~`, `` ` ``, `#`, `{`, `}`, `'`, `<`,
/// `>` and `?`, and may be empty only inside a string context.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(Box<str>);

impl Name {
    /// The symbol text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for Name {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        if source.is_empty() {
            return Err(ParseError::invalid("empty symbol"));
        }
        if source.as_bytes().iter().any(|byte| {
            matches!(
                byte,
                b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' | b'(' | b')' | b'"' | b';'
            )
        }) {
            return Err(ParseError::invalid(format!("bad symbol: {source:?}")));
        }
        Ok(Self(source.into()))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

macro_rules! cil_name {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Name);

        impl $name {
            /// The symbol text.
            #[must_use]
            pub fn text(&self) -> &str {
                self.0.text()
            }

            /// Borrows the underlying symbol.
            #[must_use]
            pub const fn as_name(&self) -> &Name {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            fn from_str(source: &str) -> Result<Self> {
                Ok(Self(source.parse()?))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl ParseFromTokens for $name {
            fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
                parser.parse_ident(stringify!($name))
            }
        }
    };
}

cil_name! {
    /// A type symbol.
    Type
}
cil_name! {
    /// A type attribute symbol.
    TypeAttribute
}
cil_name! {
    /// A type attribute set name.
    TypeAttributeSet
}
cil_name! {
    /// A type alias.
    TypeAlias
}
cil_name! {
    /// A role symbol.
    Role
}
cil_name! {
    /// A role attribute.
    RoleAttribute
}
cil_name! {
    /// A role attribute set.
    RoleAttributeSet
}
cil_name! {
    /// A user symbol.
    UserRef
}
cil_name! {
    /// A user attribute.
    UserAttribute
}
cil_name! {
    /// A user attribute set.
    UserAttributeSet
}
cil_name! {
    /// A class symbol.
    Class
}
cil_name! {
    /// A permission symbol.
    PermName
}
cil_name! {
    /// A common permission set.
    Common
}
cil_name! {
    /// A boolean.
    Bool
}
cil_name! {
    /// A tunable.
    Tunable
}
cil_name! {
    /// A sensitivity.
    Sensitivity
}
cil_name! {
    /// A sensitivity alias.
    SensAlias
}
cil_name! {
    /// A category.
    Category
}
cil_name! {
    /// A category alias.
    CategoryAlias
}
cil_name! {
    /// A category set.
    CategorySet
}
cil_name! {
    /// A level name.
    LevelName
}
cil_name! {
    /// A level range.
    LevelRange
}
cil_name! {
    /// A context.
    ContextName
}
cil_name! {
    /// A class permission.
    ClassPermission
}
cil_name! {
    /// A class permission set.
    ClassPermissionSet
}
cil_name! {
    /// A map class.
    MapClass
}
cil_name! {
    /// A map permission.
    MapPerm
}
cil_name! {
    /// A block.
    Block
}
cil_name! {
    /// An optional block.
    OptionalName
}
cil_name! {
    /// A macro.
    Macro
}
cil_name! {
    /// A policy capability.
    PolicyCap
}
cil_name! {
    /// An initial SID.
    Sid
}
cil_name! {
    /// An IP address declaration.
    IpAddr
}
cil_name! {
    /// A declared string.
    DeclaredString
}

cil_name! {
    /// A filesystem in a `genfscon`/`fsuse`.
    Filesystem
}
cil_name! {
    /// A network interface.
    Interface
}
cil_name! {
    /// A device name.
    Device
}
cil_name! {
    /// A device-tree path.
    DeviceTreePath
}

/// A file-context path, quoted or bare.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilePath {
    text: Box<str>,
    quoted: bool,
}

impl FilePath {
    /// The path text, without quotes.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl FromStr for FilePath {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let (text, quoted) = match source
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
        {
            Some(inner) => (inner, true),
            None => (source, false),
        };
        if !text.starts_with('/') {
            return Err(ParseError::invalid(format!("not a path: {source:?}")));
        }
        Ok(Self {
            text: text.into(),
            quoted,
        })
    }
}

impl fmt::Display for FilePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.quoted {
            write!(f, "\"{}\"", self.text)
        } else {
            f.write_str(&self.text)
        }
    }
}

impl ParseFromTokens for FilePath {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.parse_scalar("a path")
    }
}

/// A CIL quoted string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CilString(Box<str>);

impl CilString {
    /// The string content, without quotes.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for CilString {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let inner = source
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or_else(|| ParseError::invalid(format!("not a quoted string: {source:?}")))?;
        if inner.contains(['"', '\n']) {
            return Err(ParseError::invalid(format!(
                "bad quoted string: {source:?}"
            )));
        }
        Ok(Self(inner.into()))
    }
}

impl fmt::Display for CilString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

impl ParseFromTokens for CilString {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.parse_ident("a quoted string")
    }
}

/// A CIL integer literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Integer(u32);

impl Integer {
    /// The value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl FromStr for Integer {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let (digits, radix) = match source.strip_prefix("0x") {
            Some(hex) => (hex, 16),
            None => (source, 10),
        };
        let value = u32::from_str_radix(digits, radix)
            .map_err(|_| ParseError::invalid(format!("bad integer: {source:?}")))?;
        Ok(Self(value))
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl ParseFromTokens for Integer {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.parse_ident("an integer")
    }
}

/// An inline IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddress {
    /// An IPv4 address or network.
    V4(Ipv4Addr),
    /// An IPv4 network.
    V4Cidr(Ipv4Cidr),
    /// An IPv6 address.
    V6(Ipv6Addr),
    /// An IPv6 network.
    V6Cidr(Ipv6Cidr),
}

impl FromStr for IpAddress {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        if source.contains('/') && source.contains(':') {
            return Ok(Self::V6Cidr(source.parse()?));
        }
        if source.contains('/') {
            return Ok(Self::V4Cidr(source.parse()?));
        }
        if source.contains(':') {
            return Ok(Self::V6(source.parse()?));
        }
        if source.contains('.') {
            return Ok(Self::V4(source.parse()?));
        }
        Err(ParseError::invalid(format!(
            "not an IP address: {source:?}"
        )))
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(v) => fmt::Display::fmt(v, f),
            Self::V4Cidr(v) => fmt::Display::fmt(v, f),
            Self::V6(v) => fmt::Display::fmt(v, f),
            Self::V6Cidr(v) => fmt::Display::fmt(v, f),
        }
    }
}

/// An operand that may be a declared name or an inline address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpRef {
    /// An address declaration.
    Named(IpAddr),
    /// An inline address.
    Address(IpAddress),
}

impl ParseFromTokens for IpRef {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            // CIL lexes addresses as plain symbols, so the text decides.
            Some(TokenTree::Leaf(token)) => {
                if let Ok(address) = token.text.parse::<IpAddress>() {
                    parser.next_tree();
                    Ok(Self::Address(address))
                } else {
                    Ok(Self::Named(parser.parse_ident("an address")?))
                }
            }
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                "an IP address",
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "an IP address",
                },
                parser.at(),
            )),
        }
    }
}

impl fmt::Display for IpRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(name) => fmt::Display::fmt(name, f),
            Self::Address(address) => fmt::Display::fmt(address, f),
        }
    }
}

/// A file type in a `filecon` or `genfscon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// `any`
    Any,
    /// `file`
    File,
    /// `dir`
    Dir,
    /// `char`
    Char,
    /// `block`
    Block,
    /// `socket`
    Socket,
    /// `pipe`
    Pipe,
    /// `symlink`
    Symlink,
}

impl FileType {
    /// The keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::File => "file",
            Self::Dir => "dir",
            Self::Char => "char",
            Self::Block => "block",
            Self::Socket => "socket",
            Self::Pipe => "pipe",
            Self::Symlink => "symlink",
        }
    }
}

impl FromStr for FileType {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        Ok(match source {
            "any" => Self::Any,
            "file" => Self::File,
            "dir" => Self::Dir,
            "char" => Self::Char,
            "block" => Self::Block,
            "socket" => Self::Socket,
            "pipe" => Self::Pipe,
            "symlink" => Self::Symlink,
            other => return Err(ParseError::invalid(format!("not a file type: {other}"))),
        })
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ParseFromTokens for FileType {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.parse_ident("a file type")
    }
}

/// A network protocol of a `portcon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// `tcp`
    Tcp,
    /// `udp`
    Udp,
    /// `dccp`
    Dccp,
    /// `sctp`
    Sctp,
}

impl Protocol {
    /// The keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Dccp => "dccp",
            Self::Sctp => "sctp",
        }
    }
}

impl ParseFromTokens for Protocol {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(match parser.next_ident_text("a protocol")? {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "dccp" => Self::Dccp,
            "sctp" => Self::Sctp,
            other => return Err(ParseError::invalid(format!("not a protocol: {other}"))),
        })
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The kind of an `fsuse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsUseType {
    /// `xattr`
    Xattr,
    /// `task`
    Task,
    /// `trans`
    Trans,
}

impl FsUseType {
    /// The keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xattr => "xattr",
            Self::Task => "task",
            Self::Trans => "trans",
        }
    }
}

impl ParseFromTokens for FsUseType {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(match parser.next_ident_text("an fsuse type")? {
            "xattr" => Self::Xattr,
            "task" => Self::Task,
            "trans" => Self::Trans,
            other => return Err(ParseError::invalid(format!("not an fsuse type: {other}"))),
        })
    }
}

impl fmt::Display for FsUseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `handleunknown` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleUnknown {
    /// `allow`
    Allow,
    /// `deny`
    Deny,
    /// `reject`
    Reject,
}

impl ParseFromTokens for HandleUnknown {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(
            match parser.next_ident_text("`allow`, `deny` or `reject`")? {
                "allow" => Self::Allow,
                "deny" => Self::Deny,
                "reject" => Self::Reject,
                other => {
                    return Err(ParseError::invalid(format!(
                        "not a handleunknown value: {other}"
                    )));
                }
            },
        )
    }
}

impl fmt::Display for HandleUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
        })
    }
}

/// Which side a `defaultuser`/`defaultrole`/`defaulttype` targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultObject {
    /// `source`
    Source,
    /// `target`
    Target,
}

impl ParseFromTokens for DefaultObject {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(match parser.next_ident_text("`source` or `target`")? {
            "source" => Self::Source,
            "target" => Self::Target,
            other => {
                return Err(ParseError::invalid(format!(
                    "not `source` or `target`: {other}"
                )));
            }
        })
    }
}

/// The range component of a `defaultrange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultRangeValue {
    /// `low`
    Low,
    /// `high`
    High,
    /// `low-high`
    LowHigh,
}

impl DefaultRangeValue {
    /// The keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
            Self::LowHigh => "low-high",
        }
    }
}

impl ParseFromTokens for DefaultRangeValue {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(
            match parser.next_ident_text("`low`, `high` or `low-high`")? {
                "low" => Self::Low,
                "high" => Self::High,
                "low-high" => Self::LowHigh,
                other => return Err(ParseError::invalid(format!("not a range value: {other}"))),
            },
        )
    }
}

/// The target of a `defaultrange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultRangeTarget {
    /// `source` with a value.
    Source(DefaultRangeValue),
    /// `target` with a value.
    Target(DefaultRangeValue),
    /// `glblub`
    Glblub,
}

impl fmt::Display for DefaultRangeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(value) => write!(f, "source {}", value.as_str()),
            Self::Target(value) => write!(f, "target {}", value.as_str()),
            Self::Glblub => f.write_str("glblub"),
        }
    }
}

/// A type-rule keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeRuleKind {
    /// `typetransition`
    Transition,
    /// `typemember`
    Member,
    /// `typechange`
    Change,
}

impl TypeRuleKind {
    /// The keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transition => "typetransition",
            Self::Member => "typemember",
            Self::Change => "typechange",
        }
    }
}

impl fmt::Display for TypeRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An access-vector rule keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvRuleKind {
    /// `allow`
    Allow,
    /// `auditallow`
    AuditAllow,
    /// `dontaudit`
    DontAudit,
    /// `neverallow`
    NeverAllow,
}

impl AvRuleKind {
    /// The keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AuditAllow => "auditallow",
            Self::DontAudit => "dontaudit",
            Self::NeverAllow => "neverallow",
        }
    }
}

impl fmt::Display for AvRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A class typing a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassOperand {
    /// A plain class name.
    Class(Class),
    /// A map class.
    Map(MapClass),
}

impl fmt::Display for ClassOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class(class) => fmt::Display::fmt(class, f),
            Self::Map(map) => fmt::Display::fmt(map, f),
        }
    }
}

impl ParseFromTokens for ClassOperand {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(Self::Class(parser.parse_ident("a class")?))
    }
}

impl FromStr for ClassOperand {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        Ok(Self::Class(source.parse()?))
    }
}

/// One class-and-permissions pair of an access-vector rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassPerms {
    /// A class-permission-set reference.
    Set(ClassPermissionSet),
    /// An explicit class with an explicit permission list.
    Explicit {
        /// The class.
        class: ClassOperand,
        /// The permissions.
        permissions: Vec<PermName>,
    },
}

impl fmt::Display for ClassPerms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Set(set) => fmt::Display::fmt(set, f),
            Self::Explicit { class, permissions } => {
                write!(f, "({class} (")?;
                for permission in permissions {
                    write!(f, " {permission}")?;
                }
                f.write_str("))")
            }
        }
    }
}

impl ParseFromTokens for ClassPerms {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::Ident => {
                Ok(Self::Set(parser.parse_ident("a class-permission-set")?))
            }
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                let mut inner = parser.next_paren("a class-permission pair")?;
                let class = ClassOperand::parse_from_tokens(&mut inner)?;
                let mut permissions_parser = inner.next_paren("a permission list")?;
                let mut permissions = Vec::new();
                while !permissions_parser.is_empty() {
                    permissions.push(permissions_parser.parse_ident("a permission")?);
                }
                inner.finish()?;
                Ok(Self::Explicit { class, permissions })
            }
            Some(tree) => Err(ParseError::unexpected(
                tree.describe(),
                "a class-permission pair",
                tree.span(),
            )),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "a class-permission pair",
                },
                parser.at(),
            )),
        }
    }
}

/// The class-permission operand of a rule; CIL allows exactly one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassPermsList(Vec<ClassPerms>);

impl ClassPermsList {
    /// The pairs.
    #[must_use]
    pub fn items(&self) -> &[ClassPerms] {
        &self.0
    }
}

impl ParseFromTokens for ClassPermsList {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(Self(vec![ClassPerms::parse_from_tokens(parser)?]))
    }
}

impl fmt::Display for ClassPermsList {
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

/// A CIL expression over `T`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr<T> {
    /// A single value.
    Value(T),
    /// The `*` glob.
    Glob,
    /// The `all` wildcard.
    All,
    /// A `(range low high)` expression.
    Range(Box<Self>, Box<Self>),
    /// An `(and …)` expression.
    And(Vec<Self>),
    /// An `(or …)` expression.
    Or(Vec<Self>),
    /// An `(xor …)` expression.
    Xor(Vec<Self>),
    /// A `(not …)` expression.
    Not(Box<Self>),
    /// An `(eq …)` expression.
    Eq(Box<Self>, Box<Self>),
    /// A `(neq …)` expression.
    Neq(Box<Self>, Box<Self>),
    /// An implicit list: a group without an operator (`(a b c)`).
    List(Vec<Self>),
}

impl<T: ParseFromTokens + std::str::FromStr<Err = ParseError>> ParseFromTokens for Expr<T> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        if let Some(TokenTree::Leaf(token)) = parser.peek() {
            if token.text == "*" && token.kind == TokenKind::Punct('*') {
                parser.next_tree();
                return Ok(Self::Glob);
            }
            if token.kind == TokenKind::Ident {
                if token.text == "all" {
                    parser.next_tree();
                    return Ok(Self::All);
                }
                return Ok(Self::Value(T::parse_from_tokens(parser)?));
            }
            return Ok(Self::Value(T::parse_from_tokens(parser)?));
        }
        let mut inner = parser.next_paren("an expression")?;
        let operator = inner.next_ident_text("an expression operator")?;
        let value = match operator {
            "and" | "or" | "xor" | "not" | "eq" | "neq" | "range" => {
                let mut operands = Vec::new();
                while !inner.is_empty() {
                    operands.push(Self::parse_from_tokens(&mut inner)?);
                }
                match operator {
                    "and" => Self::And(operands),
                    "or" => Self::Or(operands),
                    "xor" => Self::Xor(operands),
                    "not" => {
                        if operands.len() != 1 {
                            return Err(ParseError::invalid("`not` takes one operand"));
                        }
                        Self::Not(Box::new(operands.remove(0)))
                    }
                    "eq" | "neq" | "range" => {
                        if operands.len() != 2 {
                            return Err(ParseError::invalid(format!(
                                "`{operator}` takes two operands"
                            )));
                        }
                        let right = operands.remove(1);
                        let left = operands.remove(0);
                        match operator {
                            "eq" => Self::Eq(Box::new(left), Box::new(right)),
                            "neq" => Self::Neq(Box::new(left), Box::new(right)),
                            _ => Self::Range(Box::new(left), Box::new(right)),
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => {
                // Not an operator: the group is an implicit conjunction list.
                let mut items = vec![Self::Value(operator.parse()?)];
                while !inner.is_empty() {
                    items.push(Self::parse_from_tokens(&mut inner)?);
                }
                Self::List(items)
            }
        };
        inner.finish()?;
        Ok(value)
    }
}

impl<T: fmt::Display> fmt::Display for Expr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(value) => fmt::Display::fmt(value, f),
            Self::Glob => f.write_str("*"),
            Self::All => f.write_str("all"),
            Self::Range(low, high) => write!(f, "(range {low} {high})"),
            Self::And(items) => write_list(f, "and", items),
            Self::Or(items) => write_list(f, "or", items),
            Self::Xor(items) => write_list(f, "xor", items),
            Self::Not(item) => write!(f, "(not {item})"),
            Self::Eq(left, right) => write!(f, "(eq {left} {right})"),
            Self::Neq(left, right) => write!(f, "(neq {left} {right})"),
            Self::List(items) => write_list(f, "", items),
        }
    }
}

fn write_list<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    operator: &str,
    items: &[T],
) -> fmt::Result {
    write!(f, "({operator}")?;
    for item in items {
        write!(f, " {item}")?;
    }
    f.write_str(")")
}

/// A category operand in a category expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CategoryRef {
    /// A single category.
    Category(Category),
    /// A category set reference.
    Set(CategorySet),
}

impl ParseFromTokens for CategoryRef {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(Self::Category(parser.parse_ident("a category")?))
    }
}

impl FromStr for CategoryRef {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        Ok(Self::Category(source.parse()?))
    }
}

impl fmt::Display for CategoryRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Category(category) => fmt::Display::fmt(category, f),
            Self::Set(set) => fmt::Display::fmt(set, f),
        }
    }
}

/// An MLS level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Level {
    /// The sensitivity.
    pub sensitivity: Sensitivity,
    /// The category expression.
    pub categories: Option<Expr<CategoryRef>>,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.sensitivity, f)?;
        if let Some(categories) = &self.categories {
            write!(f, " {categories}")?;
        }
        Ok(())
    }
}

/// A level operand: a named level or an inline one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LevelRef {
    /// A named level.
    Named(LevelName),
    /// An inline level.
    Inline(Level),
}

impl ParseFromTokens for LevelRef {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                let mut inner = parser.next_paren("an inline level")?;
                let level = parse_inline_level(&mut inner)?;
                inner.finish()?;
                Ok(Self::Inline(level))
            }
            Some(_) => Ok(Self::Named(parser.parse_ident("a level")?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "a level",
                },
                parser.at(),
            )),
        }
    }
}

impl fmt::Display for LevelRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(level) => fmt::Display::fmt(level, f),
            Self::Inline(level) => write!(f, "({level})"),
        }
    }
}

fn parse_inline_level(parser: &mut Parser<'_>) -> Result<Level> {
    let sensitivity = parser.parse_ident("a sensitivity")?;
    let categories = if parser.is_empty() {
        None
    } else {
        Some(Expr::parse_from_tokens(parser)?)
    };
    Ok(Level {
        sensitivity,
        categories,
    })
}

/// A level range operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LevelRangeRef {
    /// A named range.
    Named(LevelRange),
    /// An inline low/high pair.
    Inline {
        /// The low level.
        low: LevelRef,
        /// The high level.
        high: LevelRef,
    },
}

impl ParseFromTokens for LevelRangeRef {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                let mut inner = parser.next_paren("an inline level range")?;
                let low = LevelRef::parse_from_tokens(&mut inner)?;
                let high = LevelRef::parse_from_tokens(&mut inner)?;
                inner.finish()?;
                Ok(Self::Inline { low, high })
            }
            Some(_) => Ok(Self::Named(parser.parse_ident("a level range")?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "a level range",
                },
                parser.at(),
            )),
        }
    }
}

impl fmt::Display for LevelRangeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(range) => fmt::Display::fmt(range, f),
            Self::Inline { low, high } => write!(f, "({low} {high})"),
        }
    }
}

/// A security context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// The user.
    pub user: UserRef,
    /// The role.
    pub role: Role,
    /// The type.
    pub ty: Type,
    /// The range, if any.
    pub range: Option<LevelRangeRef>,
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({} {} {}", self.user, self.role, self.ty)?;
        if let Some(range) = &self.range {
            write!(f, " {range}")?;
        }
        f.write_str(")")
    }
}

/// A context operand: a named context or an inline one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextRef {
    /// A named context.
    Named(ContextName),
    /// An inline context.
    Inline(Context),
}

impl ParseFromTokens for ContextRef {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                let mut inner = parser.next_paren("an inline context")?;
                let context = parse_inline_context(&mut inner)?;
                inner.finish()?;
                Ok(Self::Inline(context))
            }
            Some(_) => Ok(Self::Named(parser.parse_ident("a context")?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "a context",
                },
                parser.at(),
            )),
        }
    }
}

impl fmt::Display for ContextRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(context) => fmt::Display::fmt(context, f),
            Self::Inline(context) => fmt::Display::fmt(context, f),
        }
    }
}

fn parse_inline_context(parser: &mut Parser<'_>) -> Result<Context> {
    let user = parser.parse_ident("a user")?;
    let role = parser.parse_ident("a role")?;
    let ty = parser.parse_ident("a type")?;
    let range = match parser.peek() {
        None => None,
        Some(TokenTree::Group(group)) if group.tokens.is_empty() => {
            parser.next_tree();
            None
        }
        Some(_) => Some(LevelRangeRef::parse_from_tokens(parser)?),
    };
    Ok(Context {
        user,
        role,
        ty,
        range,
    })
}

/// A `permissionx` kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionXKind {
    /// `ioctl`
    Ioctl,
    /// `nlmsg`
    Nlmsg,
}

impl PermissionXKind {
    /// The keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ioctl => "ioctl",
            Self::Nlmsg => "nlmsg",
        }
    }
}

impl ParseFromTokens for PermissionXKind {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(match parser.next_ident_text("`ioctl` or `nlmsg`")? {
            "ioctl" => Self::Ioctl,
            "nlmsg" => Self::Nlmsg,
            other => {
                return Err(ParseError::invalid(format!(
                    "not a permissionx kind: {other}"
                )));
            }
        })
    }
}

/// The extended-permission operand of an `allowx`-family rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XPerms {
    /// A named permissionx.
    Named(ClassPermission),
    /// An inline permissionx.
    Inline(PermissionX),
}

impl ParseFromTokens for XPerms {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                let mut inner = parser.next_paren("an inline permissionx")?;
                let permission = parse_permission_x(&mut inner)?;
                inner.finish()?;
                Ok(Self::Inline(permission))
            }
            Some(_) => Ok(Self::Named(parser.parse_ident("a permissionx")?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof {
                    expected: "an extended permission",
                },
                parser.at(),
            )),
        }
    }
}

impl fmt::Display for XPerms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(permission) => fmt::Display::fmt(permission, f),
            Self::Inline(permission) => fmt::Display::fmt(permission, f),
        }
    }
}

fn parse_permission_x(parser: &mut Parser<'_>) -> Result<PermissionX> {
    if parser.peek_paren() {
        let mut inner = parser.next_paren("a permissionx")?;
        let permission = parse_permission_x(&mut inner)?;
        inner.finish()?;
        return Ok(permission);
    }
    let kind = PermissionXKind::parse_from_tokens(parser)?;
    let object = parser.parse_ident("an object permission")?;
    let expr = Expr::<XPermNumber>::parse_from_tokens(parser)?;
    Ok(PermissionX { kind, object, expr })
}

/// A `permissionx` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionX {
    /// The permissionx kind.
    pub kind: PermissionXKind,
    /// The object permission.
    pub object: PermName,
    /// The extended permissions.
    pub expr: Expr<XPermNumber>,
}

impl fmt::Display for PermissionX {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({} {} {})", self.kind.as_str(), self.object, self.expr)
    }
}

/// The name of a named `typetransition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionName {
    /// A quoted name (`"helper"`).
    Quoted(CilString),
    /// A bare symbol.
    Bare(Name),
}

impl ParseFromTokens for TransitionName {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::Str => {
                let name = token.text.parse()?;
                parser.next_tree();
                Ok(Self::Quoted(name))
            }
            Some(_) => Ok(Self::Bare(parser.parse_ident("a name")?)),
            None => Err(ParseError::at(
                ParseErrorKind::UnexpectedEof { expected: "a name" },
                parser.at(),
            )),
        }
    }
}

impl fmt::Display for TransitionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quoted(name) => fmt::Display::fmt(name, f),
            Self::Bare(name) => fmt::Display::fmt(name, f),
        }
    }
}

/// A constraint operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operand {
    /// `u1`
    U1,
    /// `u2`
    U2,
    /// `u3`
    U3,
    /// `r1`
    R1,
    /// `r2`
    R2,
    /// `r3`
    R3,
    /// `t1`
    T1,
    /// `t2`
    T2,
    /// `t3`
    T3,
    /// `l1`
    L1,
    /// `l2`
    L2,
    /// `h1`
    H1,
    /// `h2`
    H2,
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::U1 => "u1",
            Self::U2 => "u2",
            Self::U3 => "u3",
            Self::R1 => "r1",
            Self::R2 => "r2",
            Self::R3 => "r3",
            Self::T1 => "t1",
            Self::T2 => "t2",
            Self::T3 => "t3",
            Self::L1 => "l1",
            Self::L2 => "l2",
            Self::H1 => "h1",
            Self::H2 => "h2",
        })
    }
}

impl ParseFromTokens for Operand {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(match parser.next_ident_text("a constraint operand")? {
            "u1" => Self::U1,
            "u2" => Self::U2,
            "u3" => Self::U3,
            "r1" => Self::R1,
            "r2" => Self::R2,
            "r3" => Self::R3,
            "t1" => Self::T1,
            "t2" => Self::T2,
            "t3" => Self::T3,
            "l1" => Self::L1,
            "l2" => Self::L2,
            "h1" => Self::H1,
            "h2" => Self::H2,
            other => {
                return Err(ParseError::invalid(format!(
                    "not a constraint operand: {other}"
                )));
            }
        })
    }
}

/// A constraint expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintExpr {
    /// A conjunction.
    And(Box<Self>, Box<Self>),
    /// A disjunction.
    Or(Box<Self>, Box<Self>),
    /// A negation.
    Not(Box<Self>),
    /// A leaf comparison.
    Comparison(Comparison),
}

/// A constraint comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comparison {
    /// `eq`
    Eq(Operand, ConstraintRhs),
    /// `neq`
    Neq(Operand, ConstraintRhs),
    /// `dom`
    Dom(Operand, ConstraintRhs),
    /// `domby`
    DomBy(Operand, ConstraintRhs),
    /// `incomp`
    Incomp(Operand, ConstraintRhs),
}

/// The right-hand side of a constraint comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintRhs {
    /// Another operand.
    Operand(Operand),
    /// A name or a `( … )` list of names.
    Names(Vec<Name>),
}

impl ParseFromTokens for ConstraintExpr {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut inner = parser.next_paren("a constraint expression")?;
        let operator = inner.next_ident_text("a constraint operator")?;
        let expr = match operator {
            "and" | "or" => {
                let left = Self::parse_from_tokens(&mut inner)?;
                let right = Self::parse_from_tokens(&mut inner)?;
                if operator == "and" {
                    Self::And(Box::new(left), Box::new(right))
                } else {
                    Self::Or(Box::new(left), Box::new(right))
                }
            }
            "not" => Self::Not(Box::new(Self::parse_from_tokens(&mut inner)?)),
            "eq" | "neq" | "dom" | "domby" | "incomp" => {
                let operand = Operand::parse_from_tokens(&mut inner)?;
                let rhs = match inner.peek() {
                    Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
                        let mut list = inner.next_paren("an operand list")?;
                        let mut names = Vec::new();
                        while !list.is_empty() {
                            names.push(list.parse_ident("an operand")?);
                        }
                        ConstraintRhs::Names(names)
                    }
                    _ => ConstraintRhs::Operand(Operand::parse_from_tokens(&mut inner)?),
                };
                Self::Comparison(match operator {
                    "eq" => Comparison::Eq(operand, rhs),
                    "neq" => Comparison::Neq(operand, rhs),
                    "dom" => Comparison::Dom(operand, rhs),
                    "domby" => Comparison::DomBy(operand, rhs),
                    _ => Comparison::Incomp(operand, rhs),
                })
            }
            other => {
                return Err(ParseError::invalid(format!(
                    "not a constraint operator: {other}"
                )));
            }
        };
        inner.finish()?;
        Ok(expr)
    }
}

impl fmt::Display for ConstraintExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::And(left, right) => write!(f, "(and {left} {right})"),
            Self::Or(left, right) => write!(f, "(or {left} {right})"),
            Self::Not(inner) => write!(f, "(not {inner})"),
            Self::Comparison(comparison) => fmt::Display::fmt(comparison, f),
        }
    }
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (operator, operand, rhs) = match self {
            Self::Eq(operand, rhs) => ("eq", operand, rhs),
            Self::Neq(operand, rhs) => ("neq", operand, rhs),
            Self::Dom(operand, rhs) => ("dom", operand, rhs),
            Self::DomBy(operand, rhs) => ("domby", operand, rhs),
            Self::Incomp(operand, rhs) => ("incomp", operand, rhs),
        };
        write!(f, "({operator} {operand} {rhs})")
    }
}

impl fmt::Display for ConstraintRhs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operand(operand) => fmt::Display::fmt(operand, f),
            Self::Names(names) => {
                f.write_str("(")?;
                for name in names {
                    write!(f, " {name}")?;
                }
                f.write_str(")")
            }
        }
    }
}

/// A range of integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// The low port.
    pub low: Port,
    /// The high port.
    pub high: Port,
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.low, self.high)
    }
}

/// A pair of 64-bit integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WideRange {
    /// The low bound.
    pub low: Number64,
    /// The high bound.
    pub high: Number64,
}

impl fmt::Display for WideRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.low, self.high)
    }
}

/// A pair of 32-bit integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NarrowRange {
    /// The low bound.
    pub low: Ioport,
    /// The high bound.
    pub high: Ioport,
}

impl fmt::Display for NarrowRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.low, self.high)
    }
}

/// A pair of pkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkeyRange {
    /// The low pkey.
    pub low: IbPkey,
    /// The high pkey.
    pub high: IbPkey,
}

impl fmt::Display for PkeyRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.low, self.high)
    }
}

/// A macro parameter kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamKind {
    /// `type`
    Type,
    /// `role`
    Role,
    /// `user`
    User,
    /// `sensitivity`
    Sensitivity,
    /// `category`
    Category,
    /// `categoryset`
    CategorySet,
    /// `level`
    Level,
    /// `levelrange`
    LevelRange,
    /// `class`
    Class,
    /// `map_class`
    MapClass,
    /// `classpermission`
    ClassPermission,
    /// `boolean`
    Bool,
    /// `string` / `name`
    String,
}

impl ParamKind {
    /// The keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::Role => "role",
            Self::User => "user",
            Self::Sensitivity => "sensitivity",
            Self::Category => "category",
            Self::CategorySet => "categoryset",
            Self::Level => "level",
            Self::LevelRange => "levelrange",
            Self::Class => "class",
            Self::MapClass => "map_class",
            Self::ClassPermission => "classpermission",
            Self::Bool => "boolean",
            Self::String => "string",
        }
    }
}

impl ParseFromTokens for ParamKind {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(match parser.next_ident_text("a parameter kind")? {
            "type" => Self::Type,
            "role" => Self::Role,
            "user" => Self::User,
            "sensitivity" => Self::Sensitivity,
            "category" => Self::Category,
            "categoryset" => Self::CategorySet,
            "level" => Self::Level,
            "levelrange" => Self::LevelRange,
            "class" => Self::Class,
            "map_class" => Self::MapClass,
            "classpermission" => Self::ClassPermission,
            "boolean" => Self::Bool,
            "string" | "name" => Self::String,
            other => {
                return Err(ParseError::invalid(format!(
                    "not a parameter kind: {other}"
                )));
            }
        })
    }
}

impl fmt::Display for ParamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A macro parameter declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroParam {
    /// The kind.
    pub kind: ParamKind,
    /// The parameter name.
    pub name: DeclaredString,
}

impl fmt::Display for MacroParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({} {})", self.kind, self.name)
    }
}

/// A call argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallArg {
    /// The argument value, bound positionally to the macro's parameters.
    pub value: Name,
}

impl fmt::Display for CallArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.value, f)
    }
}

/// The kind of an `src_info` marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SrcInfoKind {
    /// `cil`
    Cil,
    /// `lms`
    Lms,
    /// `lmx`
    Lmx,
}

impl ParseFromTokens for SrcInfoKind {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(match parser.next_ident_text("an `src_info` kind")? {
            "cil" => Self::Cil,
            "lms" => Self::Lms,
            "lmx" => Self::Lmx,
            other => {
                return Err(ParseError::invalid(format!(
                    "not an `src_info` kind: {other}"
                )));
            }
        })
    }
}

/// A `classorder` list, with the optional leading `unordered` marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassOrder {
    /// Whether `unordered` was declared.
    pub unordered: bool,
    /// The ordered class groups.
    pub groups: Vec<Vec<Class>>,
}

impl ParseFromTokens for ClassOrder {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut groups: Vec<Vec<Class>> = Vec::new();
        let mut unordered = false;
        while !parser.is_empty() {
            groups.push(parse_name_list(parser, "a class")?);
        }
        if let Some(first) = groups.first_mut() {
            unordered = first
                .first()
                .is_some_and(|class| class.text() == "unordered");
            if unordered {
                first.remove(0);
            }
        }
        Ok(Self { unordered, groups })
    }
}

/// A CIL statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    /// `(block …)`
    Block {
        /// The block name.
        name: Block,
        /// Its contents.
        statements: Vec<Self>,
    },
    /// `(blockabstract …)`
    BlockAbstract {
        /// The abstract name.
        name: Block,
    },
    /// `(blockinherit …)`
    BlockInherit {
        /// The inherited block.
        name: Block,
    },
    /// `(in before|after block …)`
    In {
        /// Whether it is inserted after.
        after: bool,
        /// The target block.
        block: Block,
        /// Its contents.
        statements: Vec<Self>,
    },
    /// `(class …)`
    Class {
        /// The class name.
        name: Class,
        /// Its permissions.
        permissions: Vec<PermName>,
    },
    /// `(classorder …)`
    ClassOrder(ClassOrder),
    /// `(classmap …)`
    ClassMap {
        /// The map name.
        name: MapClass,
        /// Its permissions.
        permissions: Vec<MapPermId>,
    },
    /// `(classmapping …)`
    ClassMapping {
        /// The map class.
        map_class: MapClass,
        /// The map permission.
        map_permission: MapPermId,
        /// The target class permissions.
        class_permissions: ClassPermsList,
    },
    /// `(classpermission …)`
    ClassPermission {
        /// The name.
        name: ClassPermission,
    },
    /// `(classpermissionset …)`
    ClassPermissionSet {
        /// The set name.
        name: ClassPermissionSet,
        /// Its content.
        class_permissions: ClassPermsList,
    },
    /// `(common …)`
    Common {
        /// The common set name.
        name: Common,
        /// Its permissions.
        permissions: Vec<PermName>,
    },
    /// `(classcommon …)`
    ClassCommon {
        /// The class.
        class: Class,
        /// The common set.
        common: Common,
    },
    /// `(sid …)`
    Sid {
        /// The SID.
        name: Sid,
    },
    /// `(sidcontext …)`
    SidContext {
        /// The SID.
        sid: Sid,
        /// The context.
        context: ContextRef,
    },
    /// `(sidorder …)`
    SidOrder {
        /// The ordered SIDs.
        sids: Vec<Sid>,
    },
    /// `(user …)`
    User {
        /// The user.
        name: UserRef,
    },
    /// `(userattribute …)`
    UserAttribute {
        /// The attribute.
        name: UserAttribute,
    },
    /// `(userattributeset …)`
    UserAttributeSet {
        /// The attribute.
        attribute: UserAttribute,
        /// The member expression.
        expression: Expr<UserRef>,
    },
    /// `(userlevel …)`
    UserLevel {
        /// The user.
        user: UserRef,
        /// The level.
        level: LevelRef,
    },
    /// `(userrange …)`
    UserRange {
        /// The user.
        user: UserRef,
        /// The range.
        range: LevelRangeRef,
    },
    /// `(userbounds …)`
    UserBounds {
        /// The bounding user.
        parent: UserRef,
        /// The bounded user.
        child: UserRef,
    },
    /// `(userprefix …)`
    UserPrefix {
        /// The user.
        user: UserRef,
        /// The prefix.
        prefix: UserPrefix,
    },
    /// `(selinuxuser …)`
    SelinuxUser {
        /// The login name.
        name: SelinuxUserName,
        /// The user.
        user: UserRef,
        /// The range.
        range: LevelRangeRef,
    },
    /// `(selinuxuserdefault …)`
    SelinuxUserDefault {
        /// The user.
        user: UserRef,
        /// The range.
        range: LevelRangeRef,
    },
    /// `(type …)`
    Type {
        /// The type.
        name: Type,
    },
    /// `(typeattribute …)`
    TypeAttribute {
        /// The attribute.
        name: TypeAttribute,
    },
    /// `(typeattributeset …)`
    TypeAttributeSet {
        /// The attribute.
        attribute: TypeAttribute,
        /// The member expression.
        expression: Expr<Type>,
    },
    /// `(expandtypeattribute …)`
    ExpandTypeAttribute {
        /// The attributes.
        attributes: Vec<TypeAttribute>,
        /// Whether to expand.
        expand: bool,
    },
    /// `(typealias …)`
    TypeAlias {
        /// The alias.
        name: TypeAlias,
    },
    /// `(typealiasactual …)`
    TypeAliasActual {
        /// The alias.
        alias: TypeAlias,
        /// The aliased type.
        actual: Type,
    },
    /// `(typebounds …)`
    TypeBounds {
        /// The bounding type.
        parent: Type,
        /// The bounded type.
        child: Type,
    },
    /// `(typepermissive …)`
    TypePermissive {
        /// The type.
        ty: Type,
    },
    /// `(typeneveraudit …)`
    TypeNeverAudit {
        /// The type.
        ty: Type,
    },
    /// `(rangetransition …)`
    RangeTransition {
        /// The source type.
        source: Type,
        /// The executable type.
        executable: Type,
        /// The object class.
        class: Class,
        /// The new range.
        range: LevelRangeRef,
    },
    /// `(role …)`
    Role {
        /// The role.
        name: Role,
    },
    /// `(userrole …)`
    UserRole {
        /// The user.
        user: UserRef,
        /// The role.
        role: Role,
    },
    /// `(roletype …)`
    RoleType {
        /// The role.
        role: Role,
        /// The type.
        ty: Type,
    },
    /// `(roletransition …)`
    RoleTransition {
        /// The source role.
        source: Role,
        /// The target role.
        target: Role,
        /// The object class.
        class: Class,
        /// The resulting role.
        result: Role,
    },
    /// `(roleallow …)`
    RoleAllow {
        /// The source role.
        source: Role,
        /// The target role.
        target: Role,
    },
    /// `(roleattribute …)`
    RoleAttribute {
        /// The attribute.
        name: RoleAttribute,
    },
    /// `(roleattributeset …)`
    RoleAttributeSet {
        /// The attribute.
        attribute: RoleAttribute,
        /// The member expression.
        expression: Expr<Role>,
    },
    /// `(rolebounds …)`
    RoleBounds {
        /// The bounding role.
        parent: Role,
        /// The bounded role.
        child: Role,
    },
    /// `(boolean …)`
    Bool {
        /// The boolean.
        name: Bool,
        /// Its value.
        value: bool,
    },
    /// `(booleanif …)`
    BooleanIf {
        /// The condition.
        condition: Expr<Bool>,
        /// The true branch.
        then: Vec<Self>,
        /// The false branch.
        otherwise: Vec<Self>,
    },
    /// `(tunable …)`
    Tunable {
        /// The tunable.
        name: Tunable,
        /// Its value.
        value: bool,
    },
    /// `(tunableif …)`
    TunableIf {
        /// The condition.
        condition: Expr<Tunable>,
        /// The true branch.
        then: Vec<Self>,
        /// The false branch.
        otherwise: Vec<Self>,
    },
    /// `(true …)`
    True {
        /// The conditioned statements.
        statements: Vec<Self>,
    },
    /// `(false …)`
    False {
        /// The conditioned statements.
        statements: Vec<Self>,
    },
    /// An access-vector rule.
    AvRule {
        /// The rule kind.
        kind: AvRuleKind,
        /// The source.
        source: Type,
        /// The target.
        target: Type,
        /// The class permissions.
        class_permissions: ClassPermsList,
    },
    /// An extended access-vector rule.
    AvRuleX {
        /// The rule kind.
        kind: AvRuleKind,
        /// The source.
        source: Type,
        /// The target.
        target: Type,
        /// The extended permissions.
        permissions: XPerms,
    },
    /// `(permissionx …)`
    PermissionX {
        /// The name.
        name: ClassPermission,
        /// The declaration.
        permission: PermissionX,
    },
    /// `(deny …)`
    Deny {
        /// The source.
        source: Type,
        /// The target.
        target: Type,
        /// The class permissions.
        class_permissions: ClassPermsList,
    },
    /// A type rule.
    TypeRule {
        /// The rule kind.
        kind: TypeRuleKind,
        /// The source.
        source: Type,
        /// The target.
        target: Type,
        /// The object class.
        class: Class,
        /// The result type.
        result: Type,
    },
    /// `(typetransition …)` with a name.
    NameTypeTransition {
        /// The source.
        source: Type,
        /// The target.
        target: Type,
        /// The object class.
        class: Class,
        /// The transition name.
        name: TransitionName,
        /// The result type.
        result: Type,
    },
    /// `(sensitivity …)`
    Sensitivity {
        /// The sensitivity.
        name: Sensitivity,
    },
    /// `(sensitivityalias …)`
    SensAlias {
        /// The alias.
        name: SensAlias,
    },
    /// `(sensitivityaliasactual …)`
    SensAliasActual {
        /// The alias.
        alias: SensAlias,
        /// The actual sensitivity.
        actual: Sensitivity,
    },
    /// `(category …)`
    Category {
        /// The category.
        name: Category,
    },
    /// `(categoryalias …)`
    CatAlias {
        /// The alias.
        name: CategoryAlias,
    },
    /// `(categoryaliasactual …)`
    CatAliasActual {
        /// The alias.
        alias: CategoryAlias,
        /// The actual category.
        actual: Category,
    },
    /// `(categoryset …)`
    CatSet {
        /// The set.
        name: CategorySet,
        /// Its members.
        expression: Expr<CategoryRef>,
    },
    /// `(categoryorder …)`
    CatOrder {
        /// The ordered categories.
        categories: Vec<Category>,
    },
    /// `(sensitivityorder …)`
    SensitivityOrder {
        /// The ordered sensitivities.
        sensitivities: Vec<Sensitivity>,
    },
    /// `(sensitivitycategory …)`
    SensCat {
        /// The sensitivity.
        sensitivity: Sensitivity,
        /// The categories.
        categories: Expr<CategoryRef>,
    },
    /// `(level …)`
    Level {
        /// The level name.
        name: LevelName,
        /// Its declaration.
        level: LevelRef,
    },
    /// `(levelrange …)`
    LevelRange {
        /// The range name.
        name: LevelRange,
        /// Its declaration.
        range: LevelRangeRef,
    },
    /// `(constrain …)` / `(mlsconstrain …)`
    Constrain {
        /// Whether it is an MLS constraint.
        mls: bool,
        /// The class permissions.
        class_permissions: ClassPermsList,
        /// The expression.
        expression: ConstraintExpr,
    },
    /// `(validatetrans …)` / `(mlsvalidatetrans …)`
    ValidateTrans {
        /// Whether it is an MLS validation.
        mls: bool,
        /// The class.
        class: Class,
        /// The expression.
        expression: ConstraintExpr,
    },
    /// `(context …)`
    Context {
        /// The context name.
        name: ContextName,
        /// Its declaration.
        context: Context,
    },
    /// `(filecon …)`
    FileCon {
        /// The path.
        path: FilePath,
        /// The file type.
        file_type: FileType,
        /// The context.
        context: Option<ContextRef>,
    },
    /// `(ibpkeycon …)`
    IbPkeyCon {
        /// The subnet.
        subnet: IpRef,
        /// The pkey range.
        pkeys: Option<PkeyRange>,
        /// The context.
        context: ContextRef,
    },
    /// `(ibendportcon …)`
    IbEndPortCon {
        /// The device.
        device: Device,
        /// The port.
        port: IbPort,
        /// The context.
        context: ContextRef,
    },
    /// `(portcon …)`
    PortCon {
        /// The protocol.
        protocol: Protocol,
        /// The port range.
        ports: PortRange,
        /// The context.
        context: ContextRef,
    },
    /// `(nodecon …)`
    NodeCon {
        /// The address.
        address: IpRef,
        /// The netmask.
        netmask: IpRef,
        /// The context.
        context: ContextRef,
    },
    /// `(genfscon …)`
    GenfsCon {
        /// The filesystem.
        filesystem: Filesystem,
        /// The path.
        path: FilePath,
        /// The optional file type.
        file_type: Option<FileType>,
        /// The context.
        context: ContextRef,
    },
    /// `(netifcon …)`
    NetifCon {
        /// The interface.
        interface: Interface,
        /// The interface context.
        interface_context: ContextRef,
        /// The packet context.
        packet_context: ContextRef,
    },
    /// `(pirqcon …)`
    PirqCon {
        /// The IRQ.
        irq: Pirq,
        /// The context.
        context: ContextRef,
    },
    /// `(iomemcon …)`
    IomemCon {
        /// The memory range.
        memory: WideRange,
        /// The context.
        context: ContextRef,
    },
    /// `(ioportcon …)`
    IoportCon {
        /// The port range.
        ports: NarrowRange,
        /// The context.
        context: ContextRef,
    },
    /// `(pcidevicecon …)`
    PciDeviceCon {
        /// The device.
        device: PciDevice,
        /// The context.
        context: ContextRef,
    },
    /// `(devicetreecon …)`
    DeviceTreeCon {
        /// The path.
        path: DeviceTreePath,
        /// The context.
        context: ContextRef,
    },
    /// `(fsuse …)`
    FsUse {
        /// The fsuse kind.
        kind: FsUseType,
        /// The filesystem.
        filesystem: Filesystem,
        /// The context.
        context: ContextRef,
    },
    /// `(macro …)`
    Macro {
        /// The macro name.
        name: Macro,
        /// Its parameters.
        params: Vec<MacroParam>,
        /// Its body.
        statements: Vec<Self>,
    },
    /// `(call …)`
    Call {
        /// The macro.
        macro_: Macro,
        /// The arguments.
        arguments: Vec<CallArg>,
    },
    /// `(policycap …)`
    PolicyCap {
        /// The capability.
        name: PolicyCap,
    },
    /// `(optional …)`
    Optional {
        /// The optional name.
        name: OptionalName,
        /// Its contents.
        statements: Vec<Self>,
    },
    /// `(ipaddr …)`
    IpAddr {
        /// The declaration name.
        name: IpAddr,
        /// The address.
        address: IpAddress,
    },
    /// `(defaultuser …)`
    DefaultUser {
        /// The classes.
        classes: Vec<ClassOperand>,
        /// The object side.
        object: DefaultObject,
    },
    /// `(defaultrole …)`
    DefaultRole {
        /// The classes.
        classes: Vec<ClassOperand>,
        /// The object side.
        object: DefaultObject,
    },
    /// `(defaulttype …)`
    DefaultType {
        /// The classes.
        classes: Vec<ClassOperand>,
        /// The object side.
        object: DefaultObject,
    },
    /// `(defaultrange …)`
    DefaultRange {
        /// The classes.
        classes: Vec<ClassOperand>,
        /// The target.
        target: DefaultRangeTarget,
    },
    /// `(handleunknown …)`
    HandleUnknown(HandleUnknown),
    /// `(mls …)`
    Mls(bool),
    /// `(src_info …)`
    SrcInfo {
        /// The source kind.
        kind: SrcInfoKind,
        /// The HLL line.
        line: Integer,
        /// The source path.
        path: AbsolutePath,
    },
}

impl ParseFromTokens for Statement {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut inner = parser.next_paren("a statement")?;
        let keyword = inner.next_ident_text("a statement keyword")?;
        let statement = match keyword {
            "block" => Self::Block {
                name: inner.parse_ident("a block name")?,
                statements: parse_statements(&mut inner)?,
            },
            "blockabstract" => Self::BlockAbstract {
                name: inner.parse_ident("a block name")?,
            },
            "blockinherit" => Self::BlockInherit {
                name: inner.parse_ident("a block name")?,
            },
            "in" => {
                let after = if inner.eat_keyword("after") {
                    true
                } else {
                    inner.expect_keyword("before")?;
                    false
                };
                Self::In {
                    after,
                    block: inner.parse_ident("a block name")?,
                    statements: parse_statements(&mut inner)?,
                }
            }
            "class" => Self::Class {
                name: inner.parse_ident("a class name")?,
                permissions: parse_name_list(&mut inner, "a permission")?,
            },
            "classorder" => Self::ClassOrder(ClassOrder::parse_from_tokens(&mut inner)?),
            "classmap" => Self::ClassMap {
                name: inner.parse_ident("a map class")?,
                permissions: parse_name_list(&mut inner, "a map permission")?,
            },
            "classmapping" => Self::ClassMapping {
                map_class: inner.parse_ident("a map class")?,
                map_permission: inner.parse_ident("a map permission")?,
                class_permissions: ClassPermsList::parse_from_tokens(&mut inner)?,
            },
            "classpermission" => Self::ClassPermission {
                name: inner.parse_ident("a class-permission")?,
            },
            "classpermissionset" => Self::ClassPermissionSet {
                name: inner.parse_ident("a class-permission-set")?,
                class_permissions: ClassPermsList::parse_from_tokens(&mut inner)?,
            },
            "common" => Self::Common {
                name: inner.parse_ident("a common name")?,
                permissions: parse_name_list(&mut inner, "a permission")?,
            },
            "classcommon" => Self::ClassCommon {
                class: inner.parse_ident("a class")?,
                common: inner.parse_ident("a common")?,
            },
            "sid" => Self::Sid {
                name: inner.parse_ident("a SID")?,
            },
            "sidcontext" => Self::SidContext {
                sid: inner.parse_ident("a SID")?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "sidorder" => Self::SidOrder {
                sids: parse_name_list(&mut inner, "a SID")?,
            },
            "user" => Self::User {
                name: inner.parse_ident("a user")?,
            },
            "userattribute" => Self::UserAttribute {
                name: inner.parse_ident("a user attribute")?,
            },
            "userattributeset" => Self::UserAttributeSet {
                attribute: inner.parse_ident("a user attribute")?,
                expression: Expr::parse_from_tokens(&mut inner)?,
            },
            "userlevel" => Self::UserLevel {
                user: inner.parse_ident("a user")?,
                level: LevelRef::parse_from_tokens(&mut inner)?,
            },
            "userrange" => Self::UserRange {
                user: inner.parse_ident("a user")?,
                range: LevelRangeRef::parse_from_tokens(&mut inner)?,
            },
            "userbounds" => Self::UserBounds {
                parent: inner.parse_ident("a user")?,
                child: inner.parse_ident("a user")?,
            },
            "userprefix" => Self::UserPrefix {
                user: inner.parse_ident("a user")?,
                prefix: inner.parse_ident("a prefix")?,
            },
            "selinuxuser" => Self::SelinuxUser {
                name: inner.parse_ident("a login name")?,
                user: inner.parse_ident("a user")?,
                range: LevelRangeRef::parse_from_tokens(&mut inner)?,
            },
            "selinuxuserdefault" => Self::SelinuxUserDefault {
                user: inner.parse_ident("a user")?,
                range: LevelRangeRef::parse_from_tokens(&mut inner)?,
            },
            "type" => Self::Type {
                name: inner.parse_ident("a type")?,
            },
            "typeattribute" => Self::TypeAttribute {
                name: inner.parse_ident("a type attribute")?,
            },
            "typeattributeset" => Self::TypeAttributeSet {
                attribute: inner.parse_ident("a type attribute")?,
                expression: Expr::parse_from_tokens(&mut inner)?,
            },
            "expandtypeattribute" => {
                let attributes = parse_type_list(&mut inner)?;
                let expand = parse_bool(&mut inner)?;
                Self::ExpandTypeAttribute { attributes, expand }
            }
            "typealias" => Self::TypeAlias {
                name: inner.parse_ident("a type alias")?,
            },
            "typealiasactual" => Self::TypeAliasActual {
                alias: inner.parse_ident("a type alias")?,
                actual: inner.parse_ident("a type")?,
            },
            "typebounds" => Self::TypeBounds {
                parent: inner.parse_ident("a type")?,
                child: inner.parse_ident("a type")?,
            },
            "typepermissive" => Self::TypePermissive {
                ty: inner.parse_ident("a type")?,
            },
            "typeneveraudit" => Self::TypeNeverAudit {
                ty: inner.parse_ident("a type")?,
            },
            "rangetransition" => Self::RangeTransition {
                source: inner.parse_ident("a type")?,
                executable: inner.parse_ident("a type")?,
                class: inner.parse_ident("a class")?,
                range: LevelRangeRef::parse_from_tokens(&mut inner)?,
            },
            "role" => Self::Role {
                name: inner.parse_ident("a role")?,
            },
            "userrole" => Self::UserRole {
                user: inner.parse_ident("a user")?,
                role: inner.parse_ident("a role")?,
            },
            "roletype" => Self::RoleType {
                role: inner.parse_ident("a role")?,
                ty: inner.parse_ident("a type")?,
            },
            "roletransition" => Self::RoleTransition {
                source: inner.parse_ident("a role")?,
                target: inner.parse_ident("a role")?,
                class: inner.parse_ident("a class")?,
                result: inner.parse_ident("a role")?,
            },
            "roleallow" => Self::RoleAllow {
                source: inner.parse_ident("a role")?,
                target: inner.parse_ident("a role")?,
            },
            "roleattribute" => Self::RoleAttribute {
                name: inner.parse_ident("a role attribute")?,
            },
            "roleattributeset" => Self::RoleAttributeSet {
                attribute: inner.parse_ident("a role attribute")?,
                expression: Expr::parse_from_tokens(&mut inner)?,
            },
            "rolebounds" => Self::RoleBounds {
                parent: inner.parse_ident("a role")?,
                child: inner.parse_ident("a role")?,
            },
            "boolean" => Self::Bool {
                name: inner.parse_ident("a boolean")?,
                value: parse_bool(&mut inner)?,
            },
            "booleanif" => {
                let condition = Expr::parse_from_tokens(&mut inner)?;
                let mut blocks = parse_conditional_blocks(&mut inner)?;
                Self::BooleanIf {
                    condition,
                    then: blocks.remove(0),
                    otherwise: blocks.remove(0),
                }
            }
            "tunable" => Self::Tunable {
                name: inner.parse_ident("a tunable")?,
                value: parse_bool(&mut inner)?,
            },
            "tunableif" => {
                let condition = Expr::parse_from_tokens(&mut inner)?;
                let mut blocks = parse_conditional_blocks(&mut inner)?;
                Self::TunableIf {
                    condition,
                    then: blocks.remove(0),
                    otherwise: blocks.remove(0),
                }
            }
            "true" => Self::True {
                statements: parse_statements(&mut inner)?,
            },
            "false" => Self::False {
                statements: parse_statements(&mut inner)?,
            },
            "allow" | "auditallow" | "dontaudit" | "neverallow" => {
                let kind = av_rule_kind(keyword);
                let source = inner.parse_ident("a source type")?;
                let target = inner.parse_ident("a target type")?;
                Self::AvRule {
                    kind,
                    source,
                    target,
                    class_permissions: ClassPermsList::parse_from_tokens(&mut inner)?,
                }
            }
            "allowx" | "auditallowx" | "dontauditx" | "neverallowx" => {
                let kind = av_rule_kind(keyword.trim_end_matches('x'));
                let source = inner.parse_ident("a source type")?;
                let target = inner.parse_ident("a target type")?;
                Self::AvRuleX {
                    kind,
                    source,
                    target,
                    permissions: XPerms::parse_from_tokens(&mut inner)?,
                }
            }
            "permissionx" => Self::PermissionX {
                name: inner.parse_ident("a permissionx name")?,
                permission: parse_permission_x(&mut inner)?,
            },
            "deny" => Self::Deny {
                source: inner.parse_ident("a source type")?,
                target: inner.parse_ident("a target type")?,
                class_permissions: ClassPermsList::parse_from_tokens(&mut inner)?,
            },
            "typetransition" => {
                let source = inner.parse_ident("a source type")?;
                let target = inner.parse_ident("a target type")?;
                let class = inner.parse_ident("a class")?;
                // One remaining token is the result type; two are a name and
                // the result type.
                if inner.rest().len() == 1 {
                    Self::TypeRule {
                        kind: TypeRuleKind::Transition,
                        source,
                        target,
                        class,
                        result: inner.parse_ident("a type")?,
                    }
                } else {
                    Self::NameTypeTransition {
                        source,
                        target,
                        class,
                        name: TransitionName::parse_from_tokens(&mut inner)?,
                        result: inner.parse_ident("a type")?,
                    }
                }
            }
            "typemember" | "typechange" => {
                let kind = if keyword == "typemember" {
                    TypeRuleKind::Member
                } else {
                    TypeRuleKind::Change
                };
                Self::TypeRule {
                    kind,
                    source: inner.parse_ident("a source type")?,
                    target: inner.parse_ident("a target type")?,
                    class: inner.parse_ident("a class")?,
                    result: inner.parse_ident("a type")?,
                }
            }
            "sensitivity" => Self::Sensitivity {
                name: inner.parse_ident("a sensitivity")?,
            },
            "sensitivityalias" => Self::SensAlias {
                name: inner.parse_ident("a sensitivity alias")?,
            },
            "sensitivityaliasactual" => Self::SensAliasActual {
                alias: inner.parse_ident("a sensitivity alias")?,
                actual: inner.parse_ident("a sensitivity")?,
            },
            "category" => Self::Category {
                name: inner.parse_ident("a category")?,
            },
            "categoryalias" => Self::CatAlias {
                name: inner.parse_ident("a category alias")?,
            },
            "categoryaliasactual" => Self::CatAliasActual {
                alias: inner.parse_ident("a category alias")?,
                actual: inner.parse_ident("a category")?,
            },
            "categoryset" => Self::CatSet {
                name: inner.parse_ident("a category set")?,
                expression: Expr::parse_from_tokens(&mut inner)?,
            },
            "categoryorder" => Self::CatOrder {
                categories: parse_name_list(&mut inner, "a category")?,
            },
            "sensitivityorder" => Self::SensitivityOrder {
                sensitivities: parse_name_list(&mut inner, "a sensitivity")?,
            },
            "sensitivitycategory" => Self::SensCat {
                sensitivity: inner.parse_ident("a sensitivity")?,
                categories: Expr::parse_from_tokens(&mut inner)?,
            },
            "level" => Self::Level {
                name: inner.parse_ident::<LevelName>("a level name")?,
                level: LevelRef::parse_from_tokens(&mut inner)?,
            },
            "levelrange" => Self::LevelRange {
                name: inner.parse_ident("a level-range name")?,
                range: LevelRangeRef::parse_from_tokens(&mut inner)?,
            },
            "constrain" | "mlsconstrain" => Self::Constrain {
                mls: keyword == "mlsconstrain",
                class_permissions: ClassPermsList::parse_from_tokens(&mut inner)?,
                expression: ConstraintExpr::parse_from_tokens(&mut inner)?,
            },
            "validatetrans" | "mlsvalidatetrans" => Self::ValidateTrans {
                mls: keyword == "mlsvalidatetrans",
                class: inner.parse_ident("a class")?,
                expression: ConstraintExpr::parse_from_tokens(&mut inner)?,
            },
            "context" => Self::Context {
                name: inner.parse_ident("a context name")?,
                context: parse_context(&mut inner)?,
            },
            "filecon" => Self::FileCon {
                path: inner.parse_scalar("a path")?,
                file_type: inner.parse_ident("a file type")?,
                context: parse_optional_context(&mut inner)?,
            },
            "ibpkeycon" => Self::IbPkeyCon {
                subnet: IpRef::parse_from_tokens(&mut inner)?,
                pkeys: parse_optional_pkey_range(&mut inner)?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "ibendportcon" => Self::IbEndPortCon {
                device: inner.parse_ident("a device name")?,
                port: inner.parse_ident("an end port")?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "portcon" => Self::PortCon {
                protocol: Protocol::parse_from_tokens(&mut inner)?,
                ports: parse_port_range(&mut inner)?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "nodecon" => Self::NodeCon {
                address: IpRef::parse_from_tokens(&mut inner)?,
                netmask: IpRef::parse_from_tokens(&mut inner)?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "genfscon" => {
                let filesystem = inner.parse_ident("a filesystem")?;
                let path = inner.parse_ident("a path")?;
                let file_type = if inner.peek_ident_text().parse::<FileType>().is_ok() {
                    Some(inner.parse_ident("a file type")?)
                } else {
                    None
                };
                Self::GenfsCon {
                    filesystem,
                    path,
                    file_type,
                    context: ContextRef::parse_from_tokens(&mut inner)?,
                }
            }
            "netifcon" => Self::NetifCon {
                interface: inner.parse_ident("an interface")?,
                interface_context: ContextRef::parse_from_tokens(&mut inner)?,
                packet_context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "pirqcon" => Self::PirqCon {
                irq: inner.parse_ident("an IRQ")?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "iomemcon" => Self::IomemCon {
                memory: parse_wide_range(&mut inner)?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "ioportcon" => Self::IoportCon {
                ports: parse_narrow_range(&mut inner)?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "pcidevicecon" => Self::PciDeviceCon {
                device: inner.parse_ident("a PCI device")?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "devicetreecon" => Self::DeviceTreeCon {
                path: inner.parse_ident("a device-tree path")?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "fsuse" => Self::FsUse {
                kind: FsUseType::parse_from_tokens(&mut inner)?,
                filesystem: inner.parse_ident("a filesystem")?,
                context: ContextRef::parse_from_tokens(&mut inner)?,
            },
            "macro" => {
                let name = inner.parse_ident("a macro name")?;
                let params = parse_macro_params(&mut inner)?;
                Self::Macro {
                    name,
                    params,
                    statements: parse_statements(&mut inner)?,
                }
            }
            "call" => Self::Call {
                macro_: inner.parse_ident("a macro")?,
                arguments: parse_call_args(&mut inner)?,
            },
            "policycap" => Self::PolicyCap {
                name: inner.parse_ident("a policy capability")?,
            },
            "optional" => Self::Optional {
                name: inner.parse_ident("an optional name")?,
                statements: parse_statements(&mut inner)?,
            },
            "ipaddr" => Self::IpAddr {
                name: inner.parse_ident("an address name")?,
                address: parse_ip_address(&mut inner)?,
            },
            "defaultuser" | "defaultrole" | "defaulttype" => {
                let classes = parse_class_list(&mut inner)?;
                let object = DefaultObject::parse_from_tokens(&mut inner)?;
                match keyword {
                    "defaultuser" => Self::DefaultUser { classes, object },
                    "defaultrole" => Self::DefaultRole { classes, object },
                    _ => Self::DefaultType { classes, object },
                }
            }
            "defaultrange" => Self::DefaultRange {
                classes: parse_class_list(&mut inner)?,
                target: parse_default_range_target(&mut inner)?,
            },
            "handleunknown" => Self::HandleUnknown(HandleUnknown::parse_from_tokens(&mut inner)?),
            "mls" => Self::Mls(parse_bool(&mut inner)?),
            "src_info" => Self::SrcInfo {
                kind: SrcInfoKind::parse_from_tokens(&mut inner)?,
                line: inner.parse_ident("a line number")?,
                path: inner.parse_ident("a path")?,
            },
            other => {
                return Err(ParseError::invalid(format!(
                    "unknown CIL statement: {other}"
                )));
            }
        };
        inner.finish()?;
        Ok(statement)
    }
}

fn av_rule_kind(keyword: &str) -> AvRuleKind {
    match keyword {
        "allow" => AvRuleKind::Allow,
        "auditallow" => AvRuleKind::AuditAllow,
        "dontaudit" => AvRuleKind::DontAudit,
        _ => AvRuleKind::NeverAllow,
    }
}

fn parse_statements(parser: &mut Parser<'_>) -> Result<Vec<Statement>> {
    let mut statements = Vec::new();
    while !parser.is_empty() {
        match parser.peek() {
            Some(TokenTree::Group(_)) => statements.push(Statement::parse_from_tokens(parser)?),
            Some(TokenTree::Leaf(token))
                if matches!(token.kind, TokenKind::Comment | TokenKind::HllLineMark) =>
            {
                parser.next_tree();
            }
            Some(tree) => {
                return Err(ParseError::unexpected(
                    tree.describe(),
                    "a statement",
                    tree.span(),
                ));
            }
            None => break,
        }
    }
    Ok(statements)
}

fn parse_name_list<T: ParseFromTokens + std::str::FromStr<Err = ParseError>>(
    parser: &mut Parser<'_>,
    expected: &'static str,
) -> Result<Vec<T>> {
    let mut inner = parser.next_paren(expected)?;
    let mut items = Vec::new();
    while !inner.is_empty() {
        items.push(inner.parse_ident(expected)?);
    }
    Ok(items)
}

fn parse_type_list(parser: &mut Parser<'_>) -> Result<Vec<TypeAttribute>> {
    match parser.peek() {
        Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
            parse_name_list(parser, "a type attribute")
        }
        Some(_) => Ok(vec![parser.parse_ident("a type attribute")?]),
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof {
                expected: "a type attribute",
            },
            parser.at(),
        )),
    }
}

fn parse_class_list(parser: &mut Parser<'_>) -> Result<Vec<ClassOperand>> {
    match parser.peek() {
        Some(TokenTree::Group(group)) if group.delimiter == Delimiter::Parenthesis => {
            parse_name_list(parser, "a class")
        }
        Some(_) => Ok(vec![ClassOperand::parse_from_tokens(parser)?]),
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof {
                expected: "a class",
            },
            parser.at(),
        )),
    }
}

fn parse_bool(parser: &mut Parser<'_>) -> Result<bool> {
    if parser.eat_keyword("true") {
        return Ok(true);
    }
    parser.expect_keyword("false")?;
    Ok(false)
}

fn parse_context(parser: &mut Parser<'_>) -> Result<Context> {
    let mut inner = parser.next_paren("a context")?;
    let context = parse_inline_context(&mut inner)?;
    inner.finish()?;
    Ok(context)
}

fn parse_optional_context(parser: &mut Parser<'_>) -> Result<Option<ContextRef>> {
    match parser.peek() {
        Some(TokenTree::Group(group)) if group.tokens.is_empty() => {
            parser.next_tree();
            Ok(None)
        }
        Some(_) => Ok(Some(ContextRef::parse_from_tokens(parser)?)),
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof {
                expected: "a context",
            },
            parser.at(),
        )),
    }
}

fn parse_port_range(parser: &mut Parser<'_>) -> Result<PortRange> {
    match parser.peek() {
        Some(TokenTree::Group(_)) => {
            let mut inner = parser.next_paren("a port range")?;
            let low = inner.parse_ident("a port")?;
            let high = inner.parse_ident("a port")?;
            inner.finish()?;
            Ok(PortRange { low, high })
        }
        Some(_) => {
            let port = parser.parse_ident("a port")?;
            Ok(PortRange {
                low: port,
                high: port,
            })
        }
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof { expected: "a port" },
            parser.at(),
        )),
    }
}

fn parse_wide_range(parser: &mut Parser<'_>) -> Result<WideRange> {
    match parser.peek() {
        Some(TokenTree::Group(_)) => {
            let mut inner = parser.next_paren("an I/O memory range")?;
            let low = inner.parse_ident("an I/O memory address")?;
            let high = inner.parse_ident("an I/O memory address")?;
            inner.finish()?;
            Ok(WideRange { low, high })
        }
        Some(_) => {
            let memory: Number64 = parser.parse_ident("an I/O memory address")?;
            Ok(WideRange {
                low: memory,
                high: memory,
            })
        }
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof {
                expected: "an I/O memory address",
            },
            parser.at(),
        )),
    }
}

fn parse_narrow_range(parser: &mut Parser<'_>) -> Result<NarrowRange> {
    match parser.peek() {
        Some(TokenTree::Group(_)) => {
            let mut inner = parser.next_paren("an I/O port range")?;
            let low = inner.parse_ident("an I/O port")?;
            let high = inner.parse_ident("an I/O port")?;
            inner.finish()?;
            Ok(NarrowRange { low, high })
        }
        Some(_) => {
            let port: Ioport = parser.parse_ident("an I/O port")?;
            Ok(NarrowRange {
                low: port,
                high: port,
            })
        }
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof {
                expected: "an I/O port",
            },
            parser.at(),
        )),
    }
}

fn parse_optional_pkey_range(parser: &mut Parser<'_>) -> Result<Option<PkeyRange>> {
    match parser.peek() {
        Some(TokenTree::Group(_)) => {
            let mut inner = parser.next_paren("a pkey range")?;
            let low = inner.parse_scalar("a pkey")?;
            let high = inner.parse_scalar("a pkey")?;
            inner.finish()?;
            Ok(Some(PkeyRange { low, high }))
        }
        Some(TokenTree::Leaf(token))
            if matches!(token.kind, TokenKind::Number | TokenKind::Ident) =>
        {
            let pkey = parser.parse_scalar("a pkey")?;
            Ok(Some(PkeyRange {
                low: pkey,
                high: pkey,
            }))
        }
        Some(tok) => Err(ParseError::unexpected(tok.describe(), "a pkey", tok.span())),
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof { expected: "a pkey" },
            parser.at(),
        )),
    }
}

fn parse_ip_address(parser: &mut Parser<'_>) -> Result<IpAddress> {
    match IpRef::parse_from_tokens(parser)? {
        IpRef::Address(address) => Ok(address),
        IpRef::Named(name) => Err(ParseError::invalid(format!(
            "`{name}` is not an inline address"
        ))),
    }
}

fn parse_default_range_target(parser: &mut Parser<'_>) -> Result<DefaultRangeTarget> {
    if parser.eat_keyword("glblub") {
        return Ok(DefaultRangeTarget::Glblub);
    }
    let source = if parser.eat_keyword("source") {
        true
    } else {
        parser.expect_keyword("target")?;
        false
    };
    let value = DefaultRangeValue::parse_from_tokens(parser)?;
    Ok(if source {
        DefaultRangeTarget::Source(value)
    } else {
        DefaultRangeTarget::Target(value)
    })
}

fn parse_conditional_blocks(parser: &mut Parser<'_>) -> Result<Vec<Vec<Statement>>> {
    let mut blocks = Vec::new();
    for expected in ["true", "false"] {
        let mut inner = parser.next_paren(expected)?;
        let keyword = inner.next_ident_text(expected)?;
        if keyword != expected {
            return Err(ParseError::unexpected(
                keyword,
                if expected == "true" {
                    "`true`"
                } else {
                    "`false`"
                },
                parser.at(),
            ));
        }
        blocks.push(parse_statements(&mut inner)?);
    }
    Ok(blocks)
}

fn parse_macro_params(parser: &mut Parser<'_>) -> Result<Vec<MacroParam>> {
    let mut inner = parser.next_paren("a parameter list")?;
    let mut params = Vec::new();
    while !inner.is_empty() {
        let mut parameter = inner.next_paren("a parameter")?;
        let kind = ParamKind::parse_from_tokens(&mut parameter)?;
        let name = parameter.parse_ident("a parameter name")?;
        parameter.finish()?;
        params.push(MacroParam { kind, name });
    }
    Ok(params)
}

fn parse_call_args(parser: &mut Parser<'_>) -> Result<Vec<CallArg>> {
    let mut inner = parser.next_paren("an argument list")?;
    let mut arguments = Vec::new();
    while !inner.is_empty() {
        arguments.push(CallArg {
            value: inner.parse_ident("an argument")?,
        });
    }
    Ok(arguments)
}

/// A whole `.cil` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CilFile(Vec<Statement>);

impl CilFile {
    /// The file's statements.
    #[must_use]
    pub fn statements(&self) -> &[Statement] {
        &self.0
    }
}

impl ParseFromTokens for CilFile {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        Ok(Self(parse_statements(parser)?))
    }
}

impl_from_str_cil!(CilFile);
