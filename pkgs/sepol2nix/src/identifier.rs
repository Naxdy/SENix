//! Identifiers and scalar literals, one newtype per semantic role.
//!
//! The `SELinux` policy language uses the same lexical shape for wildly different
//! things — a type, a role, a permission and a filesystem name are all plain
//! identifiers. Giving each role its own type keeps the AST honest: passing a
//! permission where a class is expected is a type error, not a silent
//! mis-rendering.
//!
//! Identifiers additionally carry the `m4` positional-reference form (`$1`,
//! `$*`, `$@`, `$#`) used inside macro bodies and its concatenations
//! (`$1_t`), because interfaces are parsed unexpanded.

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use crate::error::{ParseError, Result};

/// An `m4` macro parameter reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamRef {
    /// `$n`, positionally indexed from 1.
    Positional(u16),
    /// `$*` — all arguments, unquoted.
    All,
    /// `$@` — all arguments, quoted.
    AllQuoted,
    /// `$#` — the argument count.
    Count,
}

impl fmt::Display for ParamRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Positional(index) => write!(f, "${index}"),
            Self::All => f.write_str("$*"),
            Self::AllQuoted => f.write_str("$@"),
            Self::Count => f.write_str("$#"),
        }
    }
}

/// An identifier: an optional [`ParamRef`] prefix plus a name fragment.
///
/// Without a prefix, `text` must start with a letter. With a prefix it may be
/// empty or start with any identifier-continuation character, which is how
/// refpolicy spells concatenations such as `$1_t`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ident {
    prefix: Option<ParamRef>,
    text: Box<str>,
}

impl Ident {
    /// Creates an identifier without validating it.
    #[must_use]
    pub fn new(text: impl Into<Box<str>>) -> Self {
        Self {
            prefix: None,
            text: text.into(),
        }
    }

    /// The `m4` parameter reference in front of the name, if any.
    #[must_use]
    pub const fn prefix(&self) -> Option<&ParamRef> {
        self.prefix.as_ref()
    }

    /// The name fragment, without the parameter reference.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Replaces the parameter reference.
    #[must_use]
    pub fn with_prefix(mut self, prefix: ParamRef) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Whether the identifier is fully static (no parameter reference).
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.prefix.is_none()
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(prefix) = &self.prefix {
            write!(f, "{prefix}")?;
        }
        f.write_str(&self.text)
    }
}

impl Deref for Ident {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl AsRef<str> for Ident {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

impl Borrow<str> for Ident {
    fn borrow(&self) -> &str {
        &self.text
    }
}

impl FromStr for Ident {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        parse_ident(source)
    }
}

fn ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

/// Accepts identifier text with embedded `m4` parameter references such as
/// `cfengine_$1_t`, which `m4` concatenates into a single name.
fn valid_ident_text(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'$' {
            index += 1;
            match bytes.get(index) {
                Some(b'*' | b'@' | b'#') => index += 1,
                Some(byte) if byte.is_ascii_digit() => {
                    while matches!(bytes.get(index), Some(byte) if byte.is_ascii_digit()) {
                        index += 1;
                    }
                }
                _ => return false,
            }
            continue;
        }
        if !ident_continue(byte) {
            return false;
        }
        index += 1;
    }
    true
}

/// Validates and splits a raw identifier into its prefix and fragment.
fn parse_ident(source: &str) -> Result<Ident> {
    let bytes = source.as_bytes();
    let mut offset = 0;
    let mut prefix = None;

    if bytes.first() == Some(&b'$') {
        let marker = bytes.get(1).copied();
        match marker {
            Some(b'*') => {
                prefix = Some(ParamRef::All);
                offset = 2;
            }
            Some(b'@') => {
                prefix = Some(ParamRef::AllQuoted);
                offset = 2;
            }
            Some(b'#') => {
                prefix = Some(ParamRef::Count);
                offset = 2;
            }
            Some(byte) if byte.is_ascii_digit() => {
                let start = offset + 1;
                offset = start;
                while matches!(bytes.get(offset), Some(byte) if byte.is_ascii_digit()) {
                    offset += 1;
                }
                let index: u16 = source[start..offset].parse().map_err(|_| {
                    ParseError::invalid(format!("parameter index out of range: {source}"))
                })?;
                prefix = Some(ParamRef::Positional(index));
            }
            _ => {}
        }
    }

    let text = &source[offset..];
    if prefix.is_none() {
        if !text.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) {
            return Err(ParseError::invalid(format!(
                "identifier must start with a letter: {source:?}"
            )));
        }
    }
    if !valid_ident_text(text) {
        return Err(ParseError::invalid(format!(
            "identifier contains an illegal character: {source:?}"
        )));
    }

    Ok(Ident {
        prefix,
        text: text.into(),
    })
}

macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Ident);

        impl $name {
            /// Creates the identifier without validating it.
            #[must_use]
            pub fn new(text: impl Into<Box<str>>) -> Self {
                Self(Ident::new(text))
            }

            /// Borrows the underlying identifier.
            #[must_use]
            pub const fn as_ident(&self) -> &Ident {
                &self.0
            }

            /// The bare name text, without any `m4` parameter reference.
            #[must_use]
            pub fn text(&self) -> &str {
                self.0.text()
            }

            /// The `m4` parameter reference, if any.
            #[must_use]
            pub const fn prefix(&self) -> Option<&ParamRef> {
                self.0.prefix()
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            #[allow(clippy::cast_lossless)]
            fn from_str(source: &str) -> Result<Self> {
                Ok(Self(source.parse()?))
            }
        }


        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &str {
                self.0.text()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.0.text()
            }
        }

        impl crate::parser::ParseFromTokens for $name {
            fn parse_from_tokens(
                parser: &mut crate::parser::Parser<'_>,
            ) -> crate::error::Result<Self> {
                parser.parse_ident(stringify!($name))
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.0.text()
            }
        }
    };
}

identifier! {
    /// A type identifier.
    TypeId
}
identifier! {
    /// A type attribute identifier (`attribute`).
    AttributeId
}
identifier! {
    /// A type alias identifier (`alias`).
    TypeAliasId
}
identifier! {
    /// A name in a `typeattribute`/`typebounds` list.
    TypeAttributeId
}
identifier! {
    /// A role identifier.
    RoleId
}
identifier! {
    /// A role attribute identifier (`attribute_role`/`roleattribute`).
    RoleAttributeId
}
identifier! {
    /// A user identifier.
    User
}
identifier! {
    /// A boolean identifier.
    BoolId
}
identifier! {
    /// A tunable identifier.
    TunableId
}
identifier! {
    /// An object class identifier.
    ClassId
}
identifier! {
    /// A common permission set identifier.
    CommonId
}
identifier! {
    /// A permission identifier.
    PermId
}
identifier! {
    /// A sensitivity identifier.
    SensitivityId
}
identifier! {
    /// A category identifier.
    CategoryId
}
identifier! {
    /// A named category set identifier.
    CategorySetId
}
identifier! {
    /// An initial SID identifier.
    SidId
}
identifier! {
    /// A policy capability identifier.
    PolicyCapId
}
identifier! {
    /// A filesystem type identifier.
    FilesystemId
}
identifier! {
    /// A network interface name.
    NetifName
}
identifier! {
    /// A module name.
    ModuleName
}
identifier! {
    /// The name of an exported `interface(...)` macro.
    InterfaceName
}
identifier! {
    /// The name of an exported `template(...)` macro.
    TemplateName
}

identifier! {
    /// A named level declaration.
    LevelId
}
identifier! {
    /// A named level-range declaration.
    LevelRangeId
}
identifier! {
    /// A named context declaration.
    ContextId
}
identifier! {
    /// A named class-permission declaration.
    ClassPermissionId
}
identifier! {
    /// A named class-permission-set declaration.
    ClassPermissionSetId
}
identifier! {
    /// A named map-class declaration.
    MapClassId
}
identifier! {
    /// A named map permission.
    MapPermId
}
identifier! {
    /// A named IP address declaration.
    IpAddrId
}
identifier! {
    /// A user attribute identifier.
    UserAttributeId
}
identifier! {
    /// A user attribute set name.
    UserAttributeSetId
}
identifier! {
    /// A role attribute set name.
    RoleAttributeSetId
}
identifier! {
    /// A type attribute set name.
    TypeAttributeSetId
}
identifier! {
    /// A sensitivity alias identifier.
    SensAliasId
}
identifier! {
    /// A category alias identifier.
    CategoryAliasId
}
identifier! {
    /// A user prefix.
    UserPrefix
}
identifier! {
    /// An `SELinux` (login) user name in a `selinuxuser` statement.
    SelinuxUserName
}

identifier! {
    /// A `genfscon` filesystem name.
    GenfsFilesystem
}

/// An absolute path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsolutePath(Box<str>);

impl AbsolutePath {
    /// Creates the path without validating it.
    #[must_use]
    pub fn new(text: impl Into<Box<str>>) -> Self {
        Self(text.into())
    }

    /// The path text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for AbsolutePath {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        if !source.starts_with('/') {
            return Err(ParseError::invalid(format!(
                "not an absolute path: {source:?}"
            )));
        }
        if source
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0c'))
        {
            return Err(ParseError::invalid(format!(
                "path contains whitespace: {source:?}"
            )));
        }
        Ok(Self(source.into()))
    }
}

impl fmt::Display for AbsolutePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for AbsolutePath {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// A non-absolute `refpolicy` macro that stands for a home directory.
///
/// `genhomedircon` resolves these at policy load, so they are carried verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HomeMacro {
    /// `HOME_DIR`
    Directory,
    /// `HOME_ROOT`
    Root,
}

impl fmt::Display for HomeMacro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Directory => "HOME_DIR",
            Self::Root => "HOME_ROOT",
        })
    }
}

impl FromStr for HomeMacro {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        match source {
            "HOME_DIR" => Ok(Self::Directory),
            "HOME_ROOT" => Ok(Self::Root),
            _ => Err(ParseError::invalid(format!(
                "not a home directory macro: {source:?}"
            ))),
        }
    }
}

/// The path of a file-context rule: an [`AbsolutePath`] or a [`HomeMacro`]
/// optionally followed by a suffix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FcPath {
    /// An absolute path.
    Absolute(AbsolutePath),
    /// A home directory macro, with an optional path-remainder suffix.
    Home {
        /// The macro.
        macro_: HomeMacro,
        /// The literal remainder after the macro.
        suffix: Box<str>,
    },
}

impl FcPath {
    /// The literal first path component, used for the NixOS relevance filter.
    #[must_use]
    pub fn first_component(&self) -> Option<&str> {
        match self {
            Self::Absolute(path) => {
                let rest = &path.text()[1..];
                let end = rest
                    .find(|char: char| char == '/' || "()[]{}|\\^$*+?".contains(char))
                    .unwrap_or(rest.len());
                Some(&rest[..end])
            }
            Self::Home { .. } => None,
        }
    }
}

impl fmt::Display for FcPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absolute(path) => fmt::Display::fmt(path, f),
            Self::Home { macro_, suffix } => write!(f, "{macro_}{suffix}"),
        }
    }
}

impl FromStr for FcPath {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        if source.starts_with('/') {
            return Ok(Self::Absolute(AbsolutePath::new(source)));
        }
        for (macro_, text) in [
            (HomeMacro::Directory, "HOME_DIR"),
            (HomeMacro::Root, "HOME_ROOT"),
        ] {
            if let Some(suffix) = source.strip_prefix(text) {
                if !suffix
                    .as_bytes()
                    .iter()
                    .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0c'))
                {
                    return Ok(Self::Home {
                        macro_,
                        suffix: suffix.into(),
                    });
                }
            }
        }
        Err(ParseError::invalid(format!(
            "not a file-context path: {source:?}"
        )))
    }
}

/// The quoted file name of a `type_transition`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileName(Box<str>);

impl FileName {
    /// The name text, without the quotes.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for FileName {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let inner = source
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or_else(|| ParseError::invalid(format!("not a quoted file name: {source:?}")))?;
        if inner.is_empty() || inner.contains(['"', '/', '\n']) {
            return Err(ParseError::invalid(format!(
                "invalid quoted file name: {source:?}"
            )));
        }
        Ok(Self(inner.into()))
    }
}

impl fmt::Display for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

macro_rules! number {
    ($(#[$meta:meta])* $name:ident, $repr:ty, $max:expr, $what:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($repr);

        impl $name {
            /// The numeric value.
            #[must_use]
            pub const fn get(self) -> $repr {
                self.0
            }

            /// The largest accepted value.
            #[allow(clippy::cast_lossless)]
            pub const MAX: $repr = $max;
        }

        impl From<$repr> for $name {
            fn from(value: $repr) -> Self {
                Self(value.min($max))
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            #[allow(clippy::cast_lossless)]
            fn from_str(source: &str) -> Result<Self> {
                let value = parse_unsigned::<$repr>(source)
                    .map_err(|reason| ParseError::invalid(format!("invalid {}: {reason}", $what)))?;
                if value > $max {
                    return Err(ParseError::invalid(format!(
                        "{} out of range: {source} > {}",
                        $what, $max
                    )));
                }
                Ok(Self(value))
            }
        }

    };
}

number! {
    /// A general unsigned 32-bit policy number.
    Number, u32, u32::MAX, "number"
}
number! {
    /// An unsigned 64-bit policy number (`iomemcon`).
    Number64, u64, u64::MAX, "number"
}
number! {
    /// A TCP/UDP/DCCP/SCTP port number.
    Port, u16, u16::MAX, "port"
}
number! {
    /// A PCI IRQ number.
    Pirq, u32, u32::MAX, "PIRQ"
}
number! {
    /// An I/O memory address.
    IomemAddr, u64, u64::MAX, "I/O memory address"
}
number! {
    /// An I/O port number.
    Ioport, u32, u16::MAX as u32, "I/O port"
}
number! {
    /// A PCI device number.
    PciDevice, u32, u32::MAX, "PCI device"
}
number! {
    /// An InfiniBand pkey.
    IbPkey, u32, u16::MAX as u32, "InfiniBand pkey"
}
number! {
    /// An InfiniBand end port.
    IbPort, u32, u32::MAX, "InfiniBand end port"
}
number! {
    /// An extended-permission number.
    XPermNumber, u32, u32::MAX, "extended permission"
}

macro_rules! display_number {
    ($($ty:ty),* $(,)?) => {
        $(
            impl fmt::Display for $ty {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::Display::fmt(&self.0, f)
                }
            }
        )*
    };
}

display_number!(
    Number, Number64, Port, Pirq, IomemAddr, Ioport, PciDevice, IbPkey, IbPort, Weight
);

impl fmt::Display for XPermNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
number! {
    /// An `infoflow` documentation weight.
    Weight, u32, u32::MAX, "infoflow weight"
}

/// Parses an unsigned integer the way `strtoul(…, 0)` does: `0x`/`0X` selects
/// hexadecimal, a leading `0` selects octal, anything else decimal.
fn parse_unsigned<T>(source: &str) -> Result<T, String>
where
    T: TryFrom<u64>,
{
    if source.is_empty() {
        return Err("empty".into());
    }
    let (digits, radix) = if let Some(hex) = source
        .strip_prefix("0x")
        .or_else(|| source.strip_prefix("0X"))
    {
        (hex, 16)
    } else if source.len() > 1 && source.starts_with('0') {
        (&source[1..], 8)
    } else {
        (source, 10)
    };
    if digits.is_empty() {
        return Err(format!("no digits after radix prefix: {source:?}"));
    }
    let value = u64::from_str_radix(digits, radix).map_err(|_| format!("{source:?}"))?;
    T::try_from(value).map_err(|_| format!("{source:?} is too large"))
}

/// An IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Addr([u8; 4]);

impl Ipv4Addr {
    /// The octets.
    #[must_use]
    pub const fn octets(self) -> [u8; 4] {
        self.0
    }
}

impl FromStr for Ipv4Addr {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let mut octets = [0u8; 4];
        let mut pieces = source.split('.');
        for octet in &mut octets {
            let piece = pieces
                .next()
                .ok_or_else(|| ParseError::invalid(format!("short IPv4 address: {source:?}")))?;
            if piece.is_empty()
                || piece.len() > 3
                || !piece.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(ParseError::invalid(format!("bad IPv4 address: {source:?}")));
            }
            *octet = piece
                .parse()
                .map_err(|_| ParseError::invalid(format!("bad IPv4 address: {source:?}")))?;
        }
        if pieces.next().is_some() {
            return Err(ParseError::invalid(format!(
                "long IPv4 address: {source:?}"
            )));
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// An IPv4 network in CIDR notation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Cidr {
    /// The network address.
    pub address: Ipv4Addr,
    /// The prefix length.
    pub prefix: u8,
}

impl FromStr for Ipv4Cidr {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let (address, prefix) = source
            .split_once('/')
            .ok_or_else(|| ParseError::invalid(format!("IPv4 CIDR without prefix: {source:?}")))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| ParseError::invalid(format!("bad IPv4 prefix length: {source:?}")))?;
        if prefix > 32 {
            return Err(ParseError::invalid(format!(
                "IPv4 prefix length > 32: {source:?}"
            )));
        }
        Ok(Self {
            address: address.parse()?,
            prefix,
        })
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// An IPv6 address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Addr(Box<str>);

impl Ipv6Addr {
    /// The address text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for Ipv6Addr {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        if !source.contains("::") && source.matches(':').count() != 7 {
            return Err(ParseError::invalid(format!("bad IPv6 address: {source:?}")));
        }
        if !source
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
        {
            return Err(ParseError::invalid(format!("bad IPv6 address: {source:?}")));
        }
        Ok(Self(source.into()))
    }
}

impl fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An IPv6 network in CIDR notation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Cidr {
    /// The network address.
    pub address: Ipv6Addr,
    /// The prefix length.
    pub prefix: u8,
}

impl FromStr for Ipv6Cidr {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let (address, prefix) = source
            .split_once('/')
            .ok_or_else(|| ParseError::invalid(format!("IPv6 CIDR without prefix: {source:?}")))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| ParseError::invalid(format!("bad IPv6 prefix length: {source:?}")))?;
        if prefix > 128 {
            return Err(ParseError::invalid(format!(
                "IPv6 prefix length > 128: {source:?}"
            )));
        }
        Ok(Self {
            address: address.parse()?,
            prefix,
        })
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// The version literal of a `module` declaration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(Box<str>);

impl Version {
    /// The version text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for Version {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let mut parts = source.split('.');
        if !parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(ParseError::invalid(format!("bad version: {source:?}")));
        }
        if !parts.all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        }) {
            return Err(ParseError::invalid(format!("bad version: {source:?}")));
        }
        Ok(Self(source.into()))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single `##` documentation-comment line, with the payload after `##`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DocComment(Box<str>);

impl DocComment {
    /// Creates a doc comment from its payload.
    #[must_use]
    pub fn new(text: impl Into<Box<str>>) -> Self {
        Self(text.into())
    }

    /// The line payload.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for DocComment {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let payload = source
            .strip_prefix("##")
            .ok_or_else(|| ParseError::invalid(format!("not a doc comment: {source:?}")))?;
        let payload = payload.strip_prefix(' ').unwrap_or(payload);
        Ok(Self(payload.trim_end().into()))
    }
}

impl fmt::Display for DocComment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "## {}", self.0)
    }
}

/// A `#` non-documentation comment line, with the payload after `#`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Comment(Box<str>);

impl Comment {
    /// Creates a comment from its payload.
    #[must_use]
    pub fn new(text: impl Into<Box<str>>) -> Self {
        Self(text.into())
    }

    /// The line payload.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for Comment {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        let payload = source
            .strip_prefix('#')
            .ok_or_else(|| ParseError::invalid(format!("not a comment: {source:?}")))?;
        let payload = payload.strip_prefix(' ').unwrap_or(payload);
        Ok(Self(payload.trim_end().into()))
    }
}

impl fmt::Display for Comment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("#")
        } else {
            write!(f, "# {}", self.0)
        }
    }
}

/// A `genfscon` path.
///
/// The policy compiler accepts both bare (`/proc/…`) and quoted (`"/proc/…"`)
/// paths; the quoting is remembered so the statement re-emits verbatim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenfsPath {
    text: Box<str>,
    quoted: bool,
}

impl GenfsPath {
    /// The path text, without quotes.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl FromStr for GenfsPath {
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
            return Err(ParseError::invalid(format!("not a genfs path: {source:?}")));
        }
        if text
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0c'))
        {
            return Err(ParseError::invalid(format!(
                "genfs path contains whitespace: {source:?}"
            )));
        }
        Ok(Self {
            text: text.into(),
            quoted,
        })
    }
}

impl fmt::Display for GenfsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.quoted {
            write!(f, "\"{}\"", self.text)
        } else {
            f.write_str(&self.text)
        }
    }
}

/// A `devicetreecon` path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceTreePath(Box<str>);

impl DeviceTreePath {
    /// The path text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for DeviceTreePath {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        if !source.starts_with('/') {
            return Err(ParseError::invalid(format!(
                "not a device-tree path: {source:?}"
            )));
        }
        Ok(Self(source.into()))
    }
}

impl fmt::Display for DeviceTreePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Implements [`ParseFromTokens`] for a scalar parsed from one token.
macro_rules! impl_parse_from_tokens {
    ($($ty:ty),* $(,)?) => {
        $(
            impl crate::parser::ParseFromTokens for $ty {
                fn parse_from_tokens(
                    parser: &mut crate::parser::Parser<'_>,
                ) -> crate::error::Result<Self> {
                    parser.parse_ident(stringify!($ty))
                }
            }
        )*
    };
}

impl_parse_from_tokens!(
    AbsolutePath,
    FileName,
    GenfsPath,
    DeviceTreePath,
    DocComment,
    Comment,
);

macro_rules! impl_parse_scalar {
    ($($ty:ty),* $(,)?) => {
        $(
            impl crate::parser::ParseFromTokens for $ty {
                fn parse_from_tokens(
                    parser: &mut crate::parser::Parser<'_>,
                ) -> crate::error::Result<Self> {
                    parser.parse_scalar(stringify!($ty))
                }
            }
        )*
    };
}

impl_parse_scalar!(
    Number,
    Number64,
    Port,
    Pirq,
    IomemAddr,
    Ioport,
    PciDevice,
    IbPkey,
    IbPort,
    XPermNumber,
    Weight,
    Version,
    Ipv4Addr,
    Ipv4Cidr,
    Ipv6Addr,
    Ipv6Cidr,
);

/// A `<param name="...">` documentation attribute.
///
/// Parameter names are documentation-only labels and may contain spaces and
/// parentheses (`objectclass(es)`, `source type`), unlike policy identifiers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParamName(Box<str>);

impl ParamName {
    /// The name text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for ParamName {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        if source.is_empty() || source.contains(['"', '\n']) {
            return Err(ParseError::invalid(format!(
                "bad parameter name: {source:?}"
            )));
        }
        Ok(Self(source.into()))
    }
}

impl fmt::Display for ParamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl crate::parser::ParseFromTokens for ParamName {
    fn parse_from_tokens(parser: &mut crate::parser::Parser<'_>) -> crate::error::Result<Self> {
        parser.parse_ident("a parameter name")
    }
}

/// An `m4` symbol: a macro name, a `define` target or a tested symbol.
///
/// `m4` allows names that the policy scanner does not (`_`, digits), so the
/// validation is laxer than [`Ident`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Symbol(Box<str>);

impl Symbol {
    /// The symbol text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl FromStr for Symbol {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self> {
        if source.is_empty() {
            return Err(ParseError::invalid("empty symbol"));
        }
        if !source
            .as_bytes()
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'$'))
        {
            return Err(ParseError::invalid(format!("bad symbol: {source:?}")));
        }
        Ok(Self(source.into()))
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl crate::parser::ParseFromTokens for Symbol {
    fn parse_from_tokens(parser: &mut crate::parser::Parser<'_>) -> crate::error::Result<Self> {
        parser.parse_ident("a symbol")
    }
}

/// The name of any policy macro invocation.
pub type MacroName = Symbol;

/// The name bound by an `m4` `define(...)`.
pub type DefineName = Symbol;
