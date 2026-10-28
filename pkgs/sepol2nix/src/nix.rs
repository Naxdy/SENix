//! Translation of parsed policy trees into Nix expressions.
//!
//! Each expression mirrors the option schema in `nixos/default.nix`:
//!
//! * [`InterfaceFile`] renders the `security.selinux.modules.<name>.interface`
//!   value (`summary`, `desc`, `required`, `exports`),
//! * [`TypeEnforcementFile`] renders the `typeEnforcement` string; wrapping it
//!   in `lib.mkBefore` is the caller's job.
//! * [`FileContextFile`] renders the `fileContext.rules` attribute set.
//!
//! Rendering is streaming: [`AsNixExpr::write_nix`] writes into a [`NixWriter`],
//! so no intermediate [`String`] is built for the tree itself. The only owned
//! text is the small per-line buffer used to escape indented strings and the
//! rule values whose byte lengths the `nixfmt`-compatible wrapping needs.
//!
//! Everything Nix-specific lives here; the AST modules stay parse-only.

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write as _};

use crate::cil::CilFile;
use crate::error::Result as ParseResult;
use crate::file_context::{
    CommentLine, Conditional as FcConditional, FileContextFile, FileItem, FileItems, FileTypeFlag,
    FileTypeFlags, Rule, Section, SectionItem,
};
use crate::identifier::{
    AbsolutePath, AttributeId, BoolId, CategoryAliasId, CategoryId, CategorySetId, ClassId,
    ClassPermissionId, ClassPermissionSetId, Comment, CommonId, ContextId, DeviceTreePath,
    DocComment, FcPath, FileName, FilesystemId, GenfsFilesystem, GenfsPath, HomeMacro, IbPkey,
    IbPort, Ident, InterfaceName, IomemAddr, Ioport, IpAddrId, Ipv4Addr, Ipv4Cidr, Ipv6Addr,
    Ipv6Cidr, LevelId, LevelRangeId, MapClassId, MapPermId, ModuleName, NetifName, Number,
    Number64, ParamName, PciDevice, PermId, Pirq, PolicyCapId, Port, RoleAttributeId,
    RoleAttributeSetId, RoleId, SelinuxUserName, SensAliasId, SensitivityId, SidId, Symbol,
    TemplateName, TunableId, TypeAliasId, TypeAttributeId, TypeAttributeSetId, TypeId, User,
    UserAttributeId, UserAttributeSetId, UserPrefix, Version, Weight, XPermNumber,
};
use crate::interface::{
    DocText, Infoflow, InfoflowKind, InterfaceFile, MacroBody, MacroDecl, MacroDeclName, MacroDocs,
    MacroKind, ModuleDocs, ParamDoc,
};
use crate::m4::M4File;
use crate::metadata::LayerMetadata;
use crate::policy::context::{ContextValue, FileContextValue, GenContext, SecurityContext};
use crate::policy::expr::{
    AttrOperand, BoolValue, CondBinaryOp, CondExpr, ConstraintExpr, ConstraintLeaf,
    ConstraintNames, EqualityOp, LevelOperand,
};
use crate::policy::m4::{
    Conditional, Definition, Dnl, IfElse, MacroArg, MacroFragment, MacroInvocation, TokenSequence,
};
use crate::policy::mls::{CategoryRange as MlsCategoryRange, MlsComparisonOp, MlsLevel, MlsRange};
use crate::policy::names::{IdCommaList, IdList, IdSet, IdSetElem, NameSet};
use crate::policy::statement::{
    AttributeDecl, AttributeRoleDecl, AvRuleKind, AvTabRule, BoolDecl, CategoryDecl, ClassDecl,
    ClassPermissionsDecl, CommonDecl, CondRule, CondRuleList, ConditionalBlock, ConstrainDecl,
    ConstraintStatement, ContextStatement, Declaration, DefaultRangeDecl, DefaultRangeTarget,
    DefaultRoleDecl, DefaultTarget, DefaultTypeDecl, DefaultUserDecl, DominanceDecl,
    ExpandAttributeDecl, GenBoolDecl, GenRequireBlock, GenTunableDecl, InitialSidContextDecl,
    InitialSidDecl, LevelDecl, MacroStatement, ModuleDecl, NumberRange, OptionalBlock,
    OptionalPolicyBlock, PermissiveDecl, PolicyCapDecl, RequireBlock, RequireDecl, RoleAllowRule,
    RoleAttributeDecl, RoleDecl, RoleTransitionRule, RoleTypesDecl, Semi, SensitivityDecl,
    Statement, StatementList, TransitionKind, TransitionRule, TunablePolicyBlock, TypeAliasDecl,
    TypeAttributeDecl, TypeBoundsDecl, TypeDecl, UserDecl, ValidateTransDecl, XPermRule,
    XPermRuleKind,
};
use crate::policy::xperm::{XPermSet, XPermSetElem, XPerms};
use crate::type_enforcement::TypeEnforcementFile;

/// An AST node that can be rendered as a Nix expression.
///
/// Nodes that describe policy text write that text verbatim (escaped for an
/// indented string); nodes that describe values write a Nix value. Parent
/// implementations use the child ones to stream a complete expression.
pub trait AsNixExpr {
    /// Writes `self` as a Nix expression into `nix`.
    ///
    /// # Errors
    /// Returns an error when the underlying writer fails.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result;

    /// Renders `self` into a fresh string.
    ///
    /// # Errors
    /// Returns an error when the underlying writer fails (never for a `String`).
    fn to_nix_string(&self) -> ParseResult<String> {
        let mut out = String::new();
        {
            let mut nix = NixWriter::new(&mut out);
            self.write_nix(&mut nix)?;
        }
        Ok(out)
    }
}

/// A streaming Nix writer with indentation and escaping.
pub struct NixWriter<'a> {
    out: &'a mut dyn fmt::Write,
    depth: usize,
}

impl<'a> NixWriter<'a> {
    /// Creates a writer over `out`.
    pub fn new(out: &'a mut dyn fmt::Write) -> Self {
        Self { out, depth: 0 }
    }

    /// The current indentation depth (two spaces per level).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn pad(&mut self) -> fmt::Result {
        for _ in 0..self.depth {
            self.out.write_str("  ")?;
        }
        Ok(())
    }

    /// Writes an indented code line.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn line(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        self.pad()?;
        self.out.write_fmt(args)?;
        self.out.write_str("\n")
    }

    /// Writes an indented `{`/`[` line and increases the depth.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn open(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        self.line(args)?;
        self.depth += 1;
        Ok(())
    }

    /// Decreases the depth and writes an indented closing line.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn close(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        self.depth = self.depth.saturating_sub(1);
        self.line(args)
    }

    /// Writes escaped raw text without padding or a trailing newline.
    ///
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn text_inline(&mut self, value: &str) -> fmt::Result {
        write_indented_escaped(self.out, value)
    }

    /// Writes a borrowed, already-escaped line.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn raw_line(&mut self, text: &str) -> fmt::Result {
        self.pad()?;
        self.out.write_str(text)?;
        self.out.write_str("\n")
    }

    /// Writes a Nix double-quoted string.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn string(&mut self, value: &str) -> fmt::Result {
        self.out.write_char('"')?;
        for character in value.chars() {
            match character {
                '\\' => self.out.write_str("\\\\")?,
                '"' => self.out.write_str("\\\"")?,
                '$' => self.out.write_str("\\$")?,
                other => self.out.write_char(other)?,
            }
        }
        self.out.write_char('"')
    }

    /// Writes a quoted attribute key.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn key(&mut self, value: &str) -> fmt::Result {
        self.string(value)
    }

    /// Writes `true` or `false`.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn boolean(&mut self, value: bool) -> fmt::Result {
        self.out.write_str(if value { "true" } else { "false" })
    }

    /// Writes a Nix list from the items' expressions.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn list<T: AsNixExpr>(&mut self, items: &[T]) -> fmt::Result {
        if items.is_empty() {
            return self.out.write_str("[ ]");
        }
        self.open(format_args!("["))?;
        for item in items {
            self.line_args_with(item)?;
        }
        self.close(format_args!("]"))
    }

    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn line_args_with(&mut self, item: &impl AsNixExpr) -> fmt::Result {
        self.pad()?;
        item.write_nix(self)?;
        self.out.write_str("\n")
    }

    /// Writes `{`, calls `body`, and closes with `}` on the same line.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn inline_set(
        &mut self,
        body: impl FnOnce(&mut NixWriter<'_>) -> fmt::Result,
    ) -> fmt::Result {
        self.out.write_str("{\n")?;
        self.depth += 1;
        body(self)?;
        self.depth -= 1;
        self.pad()?;
        self.out.write_str("}")
    }

    /// Runs `body` one level deeper, for a block whose delimiters the caller
    /// writes.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn block_body(
        &mut self,
        body: impl FnOnce(&mut NixWriter<'_>) -> fmt::Result,
    ) -> fmt::Result {
        self.depth += 1;
        body(self)?;
        self.depth -= 1;
        Ok(())
    }

    /// Writes the contents of a `''` string block.
    ///
    /// `body` receives a sub-writer that escapes `'`/`$` and re-indents each
    /// line; the caller writes raw policy text into it.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn indented_string(
        &mut self,
        body: impl FnOnce(&mut NixWriter<'_>) -> fmt::Result,
    ) -> fmt::Result {
        self.line(format_args!("''"))?;
        self.depth += 1;
        body(self)?;
        self.depth -= 1;
        self.line(format_args!("''"))
    }

    /// Writes `key = <value expression>;` on one line.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn field_value(&mut self, key: &str, value: &impl AsNixExpr) -> fmt::Result {
        self.pad()?;
        self.out.write_str(key)?;
        self.out.write_str(" = ")?;
        value.write_nix(self)?;
        self.out.write_str(";\n")
    }

    /// Writes `key = <raw value>;` on one line.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn field_raw(&mut self, key: &str, value: &str) -> fmt::Result {
        self.pad()?;
        self.out.write_str(key)?;
        self.out.write_str(" = ")?;
        self.out.write_str(value)?;
        self.out.write_str(";\n")
    }

    /// Writes a documentation string field, quoted or as a block if multiline
    /// (or `force_block`).
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn field_doc(&mut self, key: &str, text: &DocText, force_block: bool) -> fmt::Result {
        let block = force_block || text.lines().len() > 1;
        self.pad()?;
        self.out.write_str(key)?;
        self.out.write_str(" = ")?;
        if block {
            self.out.write_str("''\n")?;
            self.block_body(|nix| text.write_block(nix))?;
            self.line(format_args!("'';"))
        } else {
            text.write_string(self)?;
            self.out.write_str(";\n")
        }
    }

    /// Writes raw policy text (escaping `'`/`$`), padding every line.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn text(&mut self, value: &str) -> fmt::Result {
        let mut lines = value.split('\n').peekable();
        let mut line = lines.next().unwrap_or_default();
        loop {
            if !line.is_empty() {
                self.pad()?;
                write_indented_escaped(self.out, line)?;
            }
            self.out.write_str("\n")?;
            match lines.next() {
                Some(next) => line = next,
                None => return Ok(()),
            }
            if line.is_empty() && lines.peek().is_none() {
                return Ok(());
            }
        }
    }

    /// Writes `value` (from its `Display`) as raw text, padding each line.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn text_display(&mut self, value: &dyn fmt::Display) -> fmt::Result {
        let mut buffer = LineBuffer::new(self);
        write!(buffer, "{value}")?;
        buffer.finish()
    }

    /// Writes a commented line at the current depth: `# ` then `extra` spaces.
    fn comment_line(&mut self, extra: usize, args: fmt::Arguments<'_>) -> fmt::Result {
        self.pad()?;
        self.out.write_str("# ")?;
        for _ in 0..extra {
            self.out.write_str(" ")?;
        }
        self.out.write_fmt(args)?;
        self.out.write_str("\n")
    }

    /// Writes a commented-out `key = "value";` reference binding.
    ///
    /// The `#` stays at the binding indentation (nixfmt leaves such lines as
    /// they are); only the payload is indented further.
    ///
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn commented_assignment(&mut self, key: &str, values: &[String]) -> fmt::Result {
        let key_text = quoted(key);
        if values.len() == 1 {
            let value = quoted(&values[0]);
            if key_text.len() + 3 + value.len() < 100 {
                return self.comment_line(0, format_args!("{key_text} = {value};"));
            }
            self.comment_line(0, format_args!("{key_text} ="))?;
            return self.comment_line(2, format_args!("{value};"));
        }
        if key_text.len() + 3 < 100 {
            self.comment_line(0, format_args!("{key_text} = ["))?;
            for value in values {
                self.comment_line(2, format_args!("{}", quoted(value)))?;
            }
            return self.comment_line(0, format_args!("];"));
        }
        self.comment_line(0, format_args!("{key_text} ="))?;
        self.comment_line(2, format_args!("["))?;
        for value in values {
            self.comment_line(4, format_args!("{}", quoted(value)))?;
        }
        self.comment_line(2, format_args!("];"))
    }

    /// Writes a `key = lib.mkDefault "value";` binding with nixfmt-compatible
    /// wrapping.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn assignment(&mut self, key: &str, values: &[String]) -> fmt::Result {
        let mut key_text = String::new();
        {
            let mut sink = NixWriter {
                out: &mut key_text,
                depth: 0,
            };
            sink.key(key)?;
        }
        if values.len() == 1 {
            let value = format!("lib.mkDefault {}", quoted(&values[0]));
            if key_text.len() + 3 + value.len() < 100 {
                return self.line(format_args!("{key_text} = {value};"));
            }
            self.line(format_args!("{key_text} ="))?;
            self.depth += 1;
            self.line(format_args!("{value};"))?;
            self.depth -= 1;
            return Ok(());
        }
        if key_text.len() + 3 + "lib.mkDefault [".len() < 100 {
            self.line(format_args!("{key_text} = lib.mkDefault ["))?;
            self.depth += 1;
            for value in values {
                self.line(format_args!("{}", quoted(value)))?;
            }
            self.depth -= 1;
            return self.line(format_args!("];"));
        }
        self.line(format_args!("{key_text} ="))?;
        self.depth += 1;
        self.line(format_args!("lib.mkDefault"))?;
        self.open(format_args!("["))?;
        for value in values {
            self.line(format_args!("{}", quoted(value)))?;
        }
        self.close(format_args!("];"))?;
        self.depth -= 1;
        Ok(())
    }
}

impl fmt::Write for NixWriter<'_> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.out.write_str(value)
    }
}

/// Escapes `'` and `$` for an indented string.
/// # Errors
/// Returns an error when the underlying writer fails.
fn write_indented_escaped(out: &mut dyn fmt::Write, line: &str) -> fmt::Result {
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            // A lone apostrophe is literal; a pair needs the `'''` escape.
            '\'' => {
                if characters.peek() == Some(&'\'') {
                    characters.next();
                    out.write_str("'''")?;
                } else {
                    out.write_char('\'')?;
                }
            }
            '$' => out.write_str("''$")?,
            other => out.write_char(other)?,
        }
    }
    Ok(())
}

fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Buffers `Display` output and flushes it as escaped, indented lines.
struct LineBuffer<'n, 'a> {
    nix: &'n mut NixWriter<'a>,
    line: String,
    at_line_start: bool,
    wrote_anything: bool,
}

impl<'n, 'a> LineBuffer<'n, 'a> {
    fn new(nix: &'n mut NixWriter<'a>) -> Self {
        Self {
            nix,
            line: String::new(),
            at_line_start: true,
            wrote_anything: false,
        }
    }

    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn flush(&mut self) -> fmt::Result {
        if !self.line.is_empty() {
            self.nix.pad()?;
            write_indented_escaped(self.nix.out, &self.line)?;
        }
        self.nix.out.write_str("\n")?;
        self.line.clear();
        Ok(())
    }

    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn finish(mut self) -> fmt::Result {
        if !self.line.is_empty() || !self.wrote_anything {
            self.flush()?;
        }
        Ok(())
    }
}

impl fmt::Write for LineBuffer<'_, '_> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            if character == '\n' {
                self.flush()?;
                self.at_line_start = true;
            } else {
                self.line.push(character);
                self.at_line_start = false;
                self.wrote_anything = true;
            }
        }
        Ok(())
    }
}

impl DocText {
    /// Writes the documentation lines as a single quoted Nix string.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn write_string(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.out.write_str("\"")?;
        let mut first = true;
        for line in self.lines() {
            if !first {
                nix.out.write_str("\\n")?;
            }
            first = false;
            for character in line.text().chars() {
                match character {
                    '\\' => nix.out.write_str("\\\\")?,
                    '"' => nix.out.write_str("\\\"")?,
                    '$' => nix.out.write_str("\\$")?,
                    other => nix.out.write_char(other)?,
                }
            }
        }
        nix.out.write_str("\"")
    }

    /// Writes the documentation lines as `''` block contents.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn write_block(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        for line in self.lines() {
            nix.pad()?;
            write_indented_escaped(nix.out, line.text())?;
            nix.out.write_str("\n")?;
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------
// Scalar leaves
// --------------------------------------------------------------------------

macro_rules! text_ident {
    ($($ty:ty),* $(,)?) => {
        $(
            impl AsNixExpr for $ty {
                /// # Errors
                /// Returns an error when the underlying writer fails.
                fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
                    nix.string(&self.to_string())
                }
            }
        )*
    };
}

text_ident!(
    Ident,
    Symbol,
    TypeId,
    AttributeId,
    TypeAliasId,
    TypeAttributeId,
    RoleId,
    RoleAttributeId,
    User,
    BoolId,
    TunableId,
    ClassId,
    CommonId,
    PermId,
    SensitivityId,
    CategoryId,
    CategorySetId,
    SidId,
    PolicyCapId,
    FilesystemId,
    NetifName,
    ModuleName,
    InterfaceName,
    TemplateName,
    LevelId,
    LevelRangeId,
    ContextId,
    ClassPermissionId,
    ClassPermissionSetId,
    MapClassId,
    MapPermId,
    IpAddrId,
    UserAttributeId,
    UserAttributeSetId,
    RoleAttributeSetId,
    TypeAttributeSetId,
    SensAliasId,
    CategoryAliasId,
    UserPrefix,
    SelinuxUserName,
    ParamName,
    GenfsFilesystem,
    GenfsPath,
    DeviceTreePath,
    AbsolutePath,
    FileName,
    FcPath,
    DocComment,
    Comment,
    HomeMacro,
);

macro_rules! number_literal {
    ($($ty:ty),* $(,)?) => {
        $(
            impl AsNixExpr for $ty {
                /// # Errors
                /// Returns an error when the underlying writer fails.
                fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
                    nix.line(format_args!("{}", self.get()))
                }
            }
        )*
    };
}

number_literal!(
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
);

impl AsNixExpr for Ipv4Addr {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for Ipv4Cidr {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for Ipv6Addr {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.text())
    }
}

impl AsNixExpr for Ipv6Cidr {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for Version {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for BoolValue {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.boolean(self.get())
    }
}

impl AsNixExpr for Semi {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.raw_line(";")
    }
}

// --------------------------------------------------------------------------
// Sets and lists
// --------------------------------------------------------------------------

impl<T: AsNixExpr> AsNixExpr for IdSetElem<T> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Self::Id(item) => item.write_nix(nix),
            Self::Negated(item) => {
                write!(nix, "\"-\" ")?;
                item.write_nix(nix)
            }
            Self::Set(set) => set.write_nix(nix),
        }
    }
}

impl<T: AsNixExpr> AsNixExpr for IdSet<T> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.list(self.elements())
    }
}

impl<T: AsNixExpr> AsNixExpr for IdList<T> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.list(self.items())
    }
}

impl<T: AsNixExpr> AsNixExpr for IdCommaList<T> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.list(self.items())
    }
}

impl<T: AsNixExpr> AsNixExpr for NameSet<T> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Self::Single(item) => item.write_nix(nix),
            Self::Set(set) => set.write_nix(nix),
            Self::Star(_) => nix.string("*"),
            Self::Negated(item) => {
                write!(nix, "\"~\" ")?;
                item.write_nix(nix)
            }
            Self::Range(low, high) => {
                low.write_nix(nix)?;
                write!(nix, "\"-\" ")?;
                high.write_nix(nix)
            }
        }
    }
}

impl<T: AsNixExpr> AsNixExpr for ConstraintNames<T> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Self::Single(item) => item.write_nix(nix),
            Self::Set(set) => set.write_nix(nix),
        }
    }
}

impl AsNixExpr for XPermSetElem {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Self::Single(number) => number.write_nix(nix),
            Self::Range(low, high) => {
                low.write_nix(nix)?;
                write!(nix, "\"-\" ")?;
                high.write_nix(nix)
            }
            Self::Set(set) => set.write_nix(nix),
        }
    }
}

impl AsNixExpr for XPermSet {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.list(self.elements())
    }
}

impl AsNixExpr for XPerms {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Self::Single(number) => number.write_nix(nix),
            Self::Set(set) => set.write_nix(nix),
            Self::Negated(item) => {
                write!(nix, "\"~\" ")?;
                item.write_nix(nix)
            }
        }
    }
}

impl<T: AsNixExpr + PartialEq> AsNixExpr for NumberRange<T> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        if self.low == self.high {
            return self.low.write_nix(nix);
        }
        self.low.write_nix(nix)?;
        write!(nix, "\"-\" ")?;
        self.high.write_nix(nix)
    }
}

impl AsNixExpr for MlsCategoryRange {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for MlsLevel {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for MlsRange {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for SecurityContext {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for GenContext {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for ContextValue {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for FileContextValue {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

// --------------------------------------------------------------------------
// Expressions and m4
// --------------------------------------------------------------------------

impl AsNixExpr for CondExpr {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for CondBinaryOp {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.as_str())
    }
}

impl AsNixExpr for EqualityOp {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.as_str())
    }
}

impl AsNixExpr for MlsComparisonOp {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.as_str())
    }
}

impl AsNixExpr for AttrOperand {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for LevelOperand {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for ConstraintLeaf {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for ConstraintExpr {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for TokenSequence {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.text_display(&self.to_string())
    }
}

impl AsNixExpr for MacroFragment {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Self::Bare(sequence) => sequence.write_nix(nix),
            Self::Quoted(sequence) => {
                write!(nix, "`")?;
                sequence.write_nix(nix)?;
                write!(nix, "'")
            }
        }
    }
}

impl AsNixExpr for MacroArg {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        for fragment in &self.fragments {
            fragment.write_nix(nix)?;
        }
        Ok(())
    }
}

impl AsNixExpr for MacroInvocation {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.text_display(self)
    }
}

impl AsNixExpr for Definition {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.text_display(self)
    }
}

impl AsNixExpr for IfElse {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.text_display(self)
    }
}

impl<B: AsNixExpr + fmt::Display> AsNixExpr for Conditional<B> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.text_display(self)
    }
}

impl AsNixExpr for Dnl {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.text_display(self)
    }
}

// --------------------------------------------------------------------------
// Declarations and rules
// --------------------------------------------------------------------------

macro_rules! display_text {
    ($($ty:ty),* $(,)?) => {
        $(
            impl AsNixExpr for $ty {
                /// # Errors
                /// Returns an error when the underlying writer fails.
                fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
                    nix.text_display(self)
                }
            }
        )*
    };
}

display_text!(
    AvTabRule,
    XPermRule,
    TransitionRule,
    RoleAllowRule,
    RoleTransitionRule,
    Declaration,
    MacroStatement,
    Statement,
    CondRule,
    ModuleDecl,
    OptionalBlock,
    ConditionalBlock,
    RequireDecl,
    RequireBlock,
    GenRequireBlock,
    OptionalPolicyBlock,
    TunablePolicyBlock,
    GenBoolDecl,
    GenTunableDecl,
    ConstraintStatement,
    ConstrainDecl,
    ValidateTransDecl,
    ContextStatement,
    AttributeDecl,
    AttributeRoleDecl,
    BoolDecl,
    CategoryDecl,
    ClassDecl,
    ClassPermissionsDecl,
    CommonDecl,
    DefaultRangeDecl,
    DefaultRoleDecl,
    DefaultTypeDecl,
    DefaultUserDecl,
    DominanceDecl,
    ExpandAttributeDecl,
    InitialSidDecl,
    InitialSidContextDecl,
    LevelDecl,
    crate::policy::statement::NeverAuditDecl,
    PermissiveDecl,
    PolicyCapDecl,
    RoleAttributeDecl,
    RoleDecl,
    RoleTypesDecl,
    SensitivityDecl,
    TypeAliasDecl,
    TypeAttributeDecl,
    TypeBoundsDecl,
    TypeDecl,
    UserDecl,
);

impl AsNixExpr for AvRuleKind {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.as_str())
    }
}

impl AsNixExpr for XPermRuleKind {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.as_str())
    }
}

impl AsNixExpr for TransitionKind {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.as_str())
    }
}

impl AsNixExpr for DefaultTarget {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for DefaultRangeTarget {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Self::Glblub => nix.string("glblub"),
            Self::Sided { target, value } => nix.string(&format!("{target} {value}")),
        }
    }
}

impl<T: AsNixExpr> AsNixExpr for Option<T> {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Some(value) => value.write_nix(nix),
            None => Ok(()),
        }
    }
}

impl AsNixExpr for CondRuleList {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        for rule in self.rules() {
            nix.text_display(rule)?;
        }
        Ok(())
    }
}

impl AsNixExpr for StatementList {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        for statement in self.statements() {
            nix.text_display(statement)?;
        }
        Ok(())
    }
}

impl NixWriter<'_> {
    /// Writes `key = "<value>";`.
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn field_string(&mut self, key: &str, value: &str) -> fmt::Result {
        self.pad()?;
        self.out.write_str(key)?;
        self.out.write_str(" = ")?;
        self.string(value)?;
        self.out.write_str(";\n")
    }
}

// --------------------------------------------------------------------------
// Interior (`.if`)
// --------------------------------------------------------------------------

impl AsNixExpr for DocText {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        self.write_string(nix)
    }
}

impl AsNixExpr for InfoflowKind {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.as_str())
    }
}

impl AsNixExpr for Infoflow {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.inline_set(|nix| {
            nix.field_string("type", self.flow.as_str())?;
            if let Some(weight) = self.weight {
                nix.field_string("weight", &weight.to_string())?;
            }
            Ok(())
        })
    }
}

impl AsNixExpr for ParamDoc {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.inline_set(|nix| {
            nix.field_string("name", self.name.text())?;
            nix.field_doc("description", &self.summary, false)?;
            if self.optional {
                nix.field_raw("optional", "true")?;
            }
            if self.unused {
                nix.field_raw("unused", "true")?;
            }
            Ok(())
        })
    }
}

impl ModuleDocs {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_head(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.field_doc("summary", &self.summary, false)?;
        if let Some(desc) = &self.desc {
            nix.field_doc("desc", desc, true)?;
        }
        if let Some(required) = &self.required {
            nix.field_doc("required", required, true)?;
        }
        Ok(())
    }
}

impl MacroDocs {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_head(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.field_doc("summary", &self.summary, false)?;
        if let Some(desc) = &self.desc {
            nix.field_doc("desc", desc, true)?;
        }
        if !self.params.is_empty() {
            nix.open(format_args!("params = {{"))?;
            for (index, param) in self.params.iter().enumerate() {
                let key = format!("${}", index + 1);
                nix.pad()?;
                nix.key(&key)?;
                nix.out.write_str(" = ")?;
                param.write_nix(nix)?;
                nix.out.write_str(";\n")?;
            }
            nix.close(format_args!("}};"))?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_tail(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        if let Some(infoflow) = &self.infoflow {
            nix.field_value("infoflow", infoflow)?;
        }
        if self.rolecap {
            nix.field_raw("rolecap", "true")?;
        }
        if self.rolebase {
            nix.field_raw("rolebase", "true")?;
        }
        Ok(())
    }
}

impl AsNixExpr for MacroDocs {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        self.write_head(nix)?;
        self.write_tail(nix)
    }
}

impl AsNixExpr for ModuleDocs {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        self.write_head(nix)
    }
}

impl AsNixExpr for MacroKind {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(self.as_str())
    }
}

impl AsNixExpr for MacroDeclName {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for MacroBody {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        if let Some(gen_require) = &self.gen_require {
            nix.text_display(gen_require)?;
        }
        self.statements.write_nix(nix)
    }
}

impl MacroDecl {
    /// Writes the macro.
    ///
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_macro(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.pad()?;
        nix.key(&self.name.to_string())?;
        nix.out.write_str(" = {\n")?;
        nix.depth += 1;

        if self.kind == MacroKind::Template {
            nix.field_string("type", self.kind.as_str())?;
        }
        nix.field_doc("summary", &self.docs.summary, false)?;
        if let Some(desc) = self.docs.desc.as_ref() {
            nix.field_doc("desc", desc, true)?;
        }
        if !self.docs.params.is_empty() {
            nix.open(format_args!("params = {{"))?;
            for (index, param) in self.docs.params.iter().enumerate() {
                let key = format!("${}", index + 1);
                nix.pad()?;
                nix.key(&key)?;
                nix.out.write_str(" = ")?;
                param.write_nix(nix)?;
                nix.out.write_str(";\n")?;
            }
            nix.close(format_args!("}};"))?;
        }

        if let Some(gen_require) = &self.body.gen_require {
            nix.pad()?;
            nix.out.write_str("gen_require = ''")?;
            nix.out.write_str("\n")?;
            nix.block_body(|inner| {
                for declaration in &gen_require.declarations {
                    inner.text_display(declaration)?;
                }
                Ok(())
            })?;
            nix.line(format_args!("'';"))?;
        }

        let statements = self.body.statements.statements();
        nix.pad()?;
        if statements.is_empty() {
            nix.out.write_str("content = \"\";\n")?;
        } else {
            nix.out.write_str("content = ''")?;
            nix.out.write_str("\n")?;
            nix.block_body(|inner| self.body.statements.write_nix(inner))?;
            nix.line(format_args!("'';"))?;
        }

        self.docs.write_tail(nix)?;
        nix.depth -= 1;
        nix.line(format_args!("}};"))
    }
}

impl AsNixExpr for MacroDecl {
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        self.write_macro(nix)
    }
}

impl AsNixExpr for InterfaceFile {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.open(format_args!("{{"))?;
        self.docs.write_nix(nix)?;
        if !self.declarations.is_empty() {
            nix.open(format_args!("exports = {{"))?;
            for declaration in &self.declarations {
                declaration.write_nix(nix)?;
            }
            nix.close(format_args!("}};"))?;
        }
        nix.close(format_args!("}}"))
    }
}

// --------------------------------------------------------------------------
// Type enforcement (`.te`)
// --------------------------------------------------------------------------

/// `m4` symbols defined for the NixOS build; used to resolve `.fc` conditionals
/// and to drop `distro_*` blocks from `.te` text.
const ACTIVE_DEFINES: [&str; 4] = ["distro_nixos", "init_systemd", "enable_mcs", "enable_ubac"];

fn active(symbol: &Symbol) -> bool {
    ACTIVE_DEFINES.contains(&symbol.text())
}

fn chosen<'a, B>(
    conditional: &'a Conditional<B>,
    then: &'a B,
    otherwise: Option<&'a B>,
) -> Option<&'a B> {
    let truth = active(&conditional.symbol);
    let take_then = match conditional.kind {
        crate::policy::m4::ConditionalKind::IfDef => truth,
        crate::policy::m4::ConditionalKind::IfNDef => !truth,
    };
    if take_then { Some(then) } else { otherwise }
}

/// # Errors
/// Returns an error when the underlying writer fails.
fn write_te_statements(nix: &mut NixWriter<'_>, statements: &StatementList) -> fmt::Result {
    for statement in statements.statements() {
        match statement {
            Statement::Macro(MacroStatement::Conditional(conditional)) => {
                write_conditional(nix, conditional)?;
            }
            Statement::Macro(MacroStatement::OptionalPolicy(block)) => {
                nix.pad()?;
                nix.text_inline("optional_policy(`")?;
                nix.out.write_str("\n")?;
                nix.depth += 1;
                write_te_statements(nix, &block.body)?;
                nix.depth -= 1;
                nix.pad()?;
                let _ = nix.text_inline("')\n");
            }
            Statement::Macro(MacroStatement::TunablePolicy(block)) => {
                nix.pad()?;
                nix.text_inline("tunable_policy(`")?;
                nix.text_inline(&block.condition.to_string())?;
                nix.text_inline("',`\n")?;
                nix.depth += 1;
                write_te_statements(nix, &block.body)?;
                nix.depth -= 1;
                if let Some(otherwise) = &block.otherwise {
                    nix.pad()?;
                    nix.text_inline("',`\n")?;
                    nix.depth += 1;
                    write_te_statements(nix, otherwise)?;
                    nix.depth -= 1;
                }
                nix.pad()?;
                let _ = nix.text_inline("')\n");
            }
            other => nix.text_display(other)?,
        }
    }
    Ok(())
}

/// Writes an `ifdef`/`ifndef`: `distro_*` tests are resolved, every other
/// condition stays for the build's `m4` stage (with its bodies still resolved).
fn write_conditional(
    nix: &mut NixWriter<'_>,
    conditional: &Conditional<StatementList>,
) -> fmt::Result {
    if conditional.symbol.text().starts_with("distro_") {
        if let Some(branch) = chosen(
            conditional,
            &conditional.then,
            conditional.otherwise.as_ref(),
        ) {
            write_te_statements(nix, branch)?;
        }
        return Ok(());
    }
    nix.pad()?;
    nix.text_inline(&format!(
        "{}(`{}',`\n",
        conditional.kind, conditional.symbol
    ))?;
    nix.depth += 1;
    write_te_statements(nix, &conditional.then)?;
    nix.depth -= 1;
    if let Some(otherwise) = &conditional.otherwise {
        nix.pad()?;
        nix.text_inline("',`\n")?;
        nix.depth += 1;
        write_te_statements(nix, otherwise)?;
        nix.depth -= 1;
    }
    nix.pad()?;
    nix.text_inline("')\n")
}

impl AsNixExpr for TypeEnforcementFile {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.line(format_args!("''"))?;
        nix.depth += 1;
        if let Some(module) = &self.module {
            nix.text_display(module)?;
        }
        write_te_statements(nix, &self.statements)?;
        nix.depth -= 1;
        nix.line(format_args!("''"))
    }
}

// --------------------------------------------------------------------------
// File contexts (`.fc`)
// --------------------------------------------------------------------------

/// Top-level directories that exist on NixOS; rules elsewhere are dropped.
const KEEP_TOPLEVEL: [&str; 11] = [
    "boot", "dev", "etc", "home", "nix", "proc", "root", "run", "sys", "tmp", "var",
];

/// `/usr` is the FHS root that distributions install into.
const USR: &str = "/usr";

/// An extra live spelling of a commented `/usr` rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsrSubstitution {
    /// `/usr` becomes `@systemPath@` (expanded by the consuming module).
    SystemPath,
    /// `/usr` becomes the store glob `/nix/store/[^/]+`.
    NixStore,
}

impl UsrSubstitution {
    /// The replacement prefix.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::SystemPath => "@systemPath@",
            Self::NixStore => "/nix/store/[^/]+",
        }
    }
}

/// Replaces the `/usr` root of `path` with `substitution`.
fn substitute_usr(path: &FcPath, substitution: UsrSubstitution) -> String {
    let text = path.to_string();
    let prefix = substitution.prefix();
    if text == USR {
        return prefix.to_owned();
    }
    format!("{prefix}{}", &text[USR.len()..])
}

fn first_component(path: &str) -> Option<&str> {
    let rest = path.strip_prefix('/')?;
    let end = rest
        .find(|character: char| character == '/' || "()[]{}|\\^$*+?".contains(character))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

fn keep_path(path: &FcPath) -> bool {
    if !matches!(path, FcPath::Absolute(_)) {
        return matches!(path, FcPath::Home { .. });
    }
    // `/usr` rules are always kept: they are emitted commented, and any
    // requested substitution is emitted live beside them.
    if is_usr_path(path) {
        return true;
    }
    let text = path.to_string();
    let Some(rest) = text.strip_prefix('/') else {
        return false;
    };
    if !rest.contains('/') {
        return true;
    }
    first_component(&text).is_some_and(|component| KEEP_TOPLEVEL.contains(&component))
}

/// Rendering options for `.fc` sources.
#[derive(Debug, Clone, Default)]
pub struct FileContextOptions {
    /// Additional live spellings for the commented `/usr` rules.
    pub substitute_usr: Vec<UsrSubstitution>,
}

fn is_usr_path(path: &FcPath) -> bool {
    matches!(path, FcPath::Absolute(_))
        && (path.to_string() == USR || path.to_string().starts_with(&format!("{USR}/")))
}

fn is_usr(rule: &Rule) -> bool {
    is_usr_path(&rule.path)
}

/// One binding a rule contributes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Binding {
    /// The upstream `/usr` rule, kept as a reference comment.
    Commented(String),
    /// A live rule under a substitution prefix.
    Live(String),
}

/// The bindings a rule contributes, in order: the commented reference first,
/// then one live binding per requested substitution.
fn bindings(rule: &Rule, options: &FileContextOptions) -> Vec<Binding> {
    if !is_usr(rule) {
        return vec![Binding::Live(rule.path.to_string())];
    }
    let mut bindings = vec![Binding::Commented(rule.path.to_string())];
    bindings.extend(
        options
            .substitute_usr
            .iter()
            .map(|substitution| Binding::Live(substitute_usr(&rule.path, *substitution))),
    );
    bindings
}

fn rule_value(rule: &Rule) -> String {
    let mut value = String::new();
    if let Some(flags) = &rule.file_type {
        value.push_str(&flags.to_string());
        value.push(' ');
    }
    value.push_str(&rule.context.fc_text());
    value
}

impl AsNixExpr for FileTypeFlag {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self.character() {
            Some(character) => nix.string(&format!("-{character}")),
            None => nix.string("--"),
        }
    }
}

impl AsNixExpr for FileTypeFlags {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&self.to_string())
    }
}

impl AsNixExpr for Rule {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.string(&rule_value(self))
    }
}

impl AsNixExpr for CommentLine {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.raw_line(&self.to_string())
    }
}

impl AsNixExpr for SectionItem {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        match self {
            Self::Comment(comment) => comment.write_nix(nix),
            Self::Rule(rule) => {
                let values = [rule_value(rule)];
                for binding in bindings(rule, &FileContextOptions::default()) {
                    match binding {
                        Binding::Commented(key) => nix.commented_assignment(&key, &values)?,
                        Binding::Live(key) => nix.assignment(&key, &values)?,
                    }
                }
                Ok(())
            }
        }
    }
}

impl Section {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix_with(&self, nix: &mut NixWriter<'_>, options: &FileContextOptions) -> fmt::Result {
        let mut values: HashMap<Binding, Vec<String>> = HashMap::new();
        for item in &self.items {
            if let SectionItem::Rule(rule) = item
                && keep_path(&rule.path)
            {
                let value = rule_value(rule);
                for binding in bindings(rule, options) {
                    let bucket = values.entry(binding).or_default();
                    if !bucket.contains(&value) {
                        bucket.push(value.clone());
                    }
                }
            }
        }
        for comment in &self.comments {
            comment.write_nix(nix)?;
        }
        let mut emitted = HashSet::new();
        for item in &self.items {
            match item {
                SectionItem::Comment(comment) => comment.write_nix(nix)?,
                SectionItem::Rule(rule) => {
                    if !keep_path(&rule.path) {
                        continue;
                    }
                    for binding in bindings(rule, options) {
                        if !emitted.insert(binding.clone()) {
                            continue;
                        }
                        let key = match &binding {
                            Binding::Commented(key) | Binding::Live(key) => key,
                        };
                        let bucket = values.get(&binding).cloned().unwrap_or_default();
                        match binding {
                            Binding::Commented(_) => nix.commented_assignment(key, &bucket)?,
                            Binding::Live(_) => nix.assignment(key, &bucket)?,
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl AsNixExpr for Section {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        self.write_nix_with(nix, &FileContextOptions::default())
    }
}

/// A flattened `.fc` node with all conditionals resolved.
enum Flat<'a> {
    Comment(&'a CommentLine),
    Rule(&'a Rule),
}

fn resolve_items<'a>(items: &'a FileItems, out: &mut Vec<Flat<'a>>) {
    for item in items.items() {
        match item {
            FileItem::Section(section) => {
                out.extend(section.comments.iter().map(Flat::Comment));
                for entry in &section.items {
                    match entry {
                        SectionItem::Comment(comment) => out.push(Flat::Comment(comment)),
                        SectionItem::Rule(rule) => out.push(Flat::Rule(rule)),
                    }
                }
            }
            FileItem::Conditional(conditional) => {
                let branch = chosen_fc(conditional);
                if let Some(branch) = branch {
                    resolve_items(branch, out);
                }
            }
        }
    }
}

fn chosen_fc(conditional: &FcConditional) -> Option<&FileItems> {
    let truth = active(&conditional.symbol);
    let take_then = match conditional.kind {
        crate::policy::m4::ConditionalKind::IfDef => truth,
        crate::policy::m4::ConditionalKind::IfNDef => !truth,
    };
    if take_then {
        Some(&conditional.then)
    } else {
        conditional.otherwise.as_ref()
    }
}

impl FileContextFile {
    /// Renders the rules with explicit options.
    ///
    /// # Errors
    /// Returns an error when the underlying writer fails.
    pub fn write_nix_with_options(
        &self,
        nix: &mut NixWriter<'_>,
        options: &FileContextOptions,
    ) -> fmt::Result {
        let items = FileItems::from_items(self.items().to_vec());
        let mut flat = Vec::new();
        resolve_items(&items, &mut flat);

        // Rebuild comment-headed sections, then collect every value per path.
        let mut sections: Vec<(Vec<&CommentLine>, Vec<&Rule>)> = Vec::new();
        let mut current: (Vec<&CommentLine>, Vec<&Rule>) = (Vec::new(), Vec::new());
        let mut last_was_comment = false;
        for item in flat {
            match item {
                Flat::Comment(comment) => {
                    if !current.0.is_empty() && (!current.1.is_empty() || !last_was_comment) {
                        sections.push(std::mem::take(&mut current));
                    }
                    current.0.push(comment);
                    last_was_comment = true;
                }
                Flat::Rule(rule) => {
                    current.1.push(rule);
                    last_was_comment = false;
                }
            }
        }
        if !current.0.is_empty() || !current.1.is_empty() {
            sections.push(current);
        }

        let mut values: HashMap<Binding, Vec<String>> = HashMap::new();
        for (_, rules) in &sections {
            for rule in rules {
                if !keep_path(&rule.path) {
                    continue;
                }
                let value = rule_value(rule);
                for binding in bindings(rule, options) {
                    let bucket = values.entry(binding).or_default();
                    if !bucket.contains(&value) {
                        bucket.push(value.clone());
                    }
                }
            }
        }

        nix.open(format_args!("{{"))?;
        let mut emitted = HashSet::new();
        let mut wrote = false;
        for (comments, rules) in &sections {
            if !rules.iter().any(|rule| keep_path(&rule.path)) {
                continue;
            }
            if wrote {
                nix.out.write_str("\n")?;
            }
            wrote = true;
            for comment in comments {
                comment.write_nix(nix)?;
            }
            for rule in rules {
                if !keep_path(&rule.path) {
                    continue;
                }
                for binding in bindings(rule, options) {
                    if !emitted.insert(binding.clone()) {
                        continue;
                    }
                    let key = match &binding {
                        Binding::Commented(key) | Binding::Live(key) => key,
                    };
                    let bucket = values.get(&binding).cloned().unwrap_or_default();
                    match binding {
                        Binding::Commented(_) => nix.commented_assignment(key, &bucket)?,
                        Binding::Live(_) => nix.assignment(key, &bucket)?,
                    }
                }
            }
        }
        nix.close(format_args!("}}"))
    }
}

impl AsNixExpr for FileContextFile {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        self.write_nix_with_options(nix, &FileContextOptions::default())
    }
}

// --------------------------------------------------------------------------
// Ancillary sources
// --------------------------------------------------------------------------

impl AsNixExpr for LayerMetadata {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.open(format_args!("{{"))?;
        nix.field_doc("summary", &self.summary, true)?;
        nix.close(format_args!("}}"))
    }
}

impl AsNixExpr for M4File {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        nix.indented_string(|inner| inner.text_display(self))
    }
}

/// The CIL build path does not exist yet, so the tree is rendered debug-style.
impl AsNixExpr for CilFile {
    /// # Errors
    /// Returns an error when the underlying writer fails.
    fn write_nix(&self, nix: &mut NixWriter<'_>) -> fmt::Result {
        let text = format!("{self:#?}");
        nix.indented_string(|inner| inner.text(&text))
    }
}
