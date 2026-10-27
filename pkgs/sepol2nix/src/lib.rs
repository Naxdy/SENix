//! Typed syntax tree for the `SELinux` policy source languages.
//!
//! The `SELinux` policy toolchain is fed five textual dialects:
//!
//! * `m4` macro files (`.spt`, `.m4`, `.if.in`, `.te.in` and the m4 layer of
//!   every `.if`/`.te`),
//! * the checkpolicy type-enforcement grammar (`.te`, and the bodies of `.if`
//!   macros),
//! * the interface documentation/macro grammar (`.if`),
//! * the file-context grammar (`.fc`),
//! * the CIL S-expression grammar (`.cil`),
//! * the layer `metadata.xml`.
//!
//! Every dialect has a dedicated module (`metadata` holds the XML subset). Each syntax element is represented by
//! its own type, every type parses itself through [`FromStr`], and identifiers
//! are split into one newtype per semantic role so that, for example, a
//! [`policy::identifier::PermId`] cannot be passed where a
//! [`policy::identifier::ClassId`] is expected.
//!
//! Parsing is purely syntactic: no symbol resolution, no macro expansion and no
//! conditional evaluation happens here. That is exactly what the checkpolicy
//! and `m4` stages downstream do, and keeping the trees unexpanded lets them be
//! re-emitted byte-for-byte.
//!
//! Rendering to Nix expressions lives in [`nix`] (`AsNixExpr`), kept separate
//! from the grammar modules.
//!
//! [`FromStr`]: std::str::FromStr

#![deny(missing_docs)]
#![deny(unsafe_code)]
// Parser code is mostly straight-line grammar; const-ness, nesting style and
// function length are not worth contorting for these lints.
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::cast_lossless)]

pub mod cil;
pub mod error;
pub mod file_context;
pub mod identifier;
pub mod interface;
pub mod lexer;
pub mod m4;
pub mod metadata;
pub mod nix;
pub mod parser;
pub mod policy;
pub mod span;
pub mod type_enforcement;

pub use error::{ParseError, ParseErrorKind};
pub use span::Span;
