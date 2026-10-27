//! The interface grammar (`.if`).
//!
//! An `.if` file starts with the module's XML documentation comment header and
//! is followed by its exported `interface(...)` and `template(...)` macros. Each
//! macro carries its own documentation block, an optional `gen_require` block
//! and a body.
//!
//! Documentation is parsed into the same tags that `segenxml.py` consumes to
//! build `policy.xml`: `<summary>`, `<desc>`, `<param>`, `<infoflow>`,
//! `<rolecap/>`, `<rolebase/>` and the module-level `<required>`.

use std::fmt;

use crate::error::{ParseError, Result};
use crate::identifier::{DocComment, InterfaceName, ParamName, TemplateName, Weight};
use crate::impl_from_str;
use crate::lexer::{TokenKind, TokenTree};
use crate::parser::{ParseFromTokens, Parser};
use crate::policy::statement::{GenRequireBlock, StatementList};

/// A run of documentation text lines.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DocText(Vec<DocComment>);

impl DocText {
    /// Creates a text from its lines.
    #[must_use]
    pub fn new(lines: Vec<DocComment>) -> Self {
        Self(lines)
    }

    /// The text's lines.
    #[must_use]
    pub fn lines(&self) -> &[DocComment] {
        &self.0
    }

    /// The text with lines joined by newlines.
    #[must_use]
    pub fn joined(&self) -> String {
        self.0
            .iter()
            .map(DocComment::text)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl fmt::Display for DocText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, line) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("\n")?;
            }
            f.write_str(line.text())?;
        }
        Ok(())
    }
}

/// The module-level `##` header of an `.if` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDocs {
    /// The required `<summary>`.
    pub summary: DocText,
    /// The optional `<desc>`.
    pub desc: Option<DocText>,
    /// The optional `<required val="true">` text.
    pub required: Option<DocText>,
}

/// A `<infoflow>` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Infoflow {
    /// The information-flow kind.
    pub flow: InfoflowKind,
    /// The numeric weight, if any.
    pub weight: Option<Weight>,
}

/// The kind of an `<infoflow type="…">` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoflowKind {
    /// `none`
    None,
    /// `read`
    Read,
    /// `write`
    Write,
    /// `both`
    Both,
}

impl InfoflowKind {
    /// The kind's source spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
            Self::Both => "both",
        }
    }
}

impl fmt::Display for InfoflowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `<param>` documentation tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamDoc {
    /// The parameter name.
    pub name: ParamName,
    /// Whether the parameter is optional.
    pub optional: bool,
    /// Whether the parameter is unused by the macro.
    pub unused: bool,
    /// The parameter's `<summary>`.
    pub summary: DocText,
}

/// The macro-level `##` documentation block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MacroDocs {
    /// The required `<summary>`.
    pub summary: DocText,
    /// The optional `<desc>`.
    pub desc: Option<DocText>,
    /// The documented parameters.
    pub params: Vec<ParamDoc>,
    /// The optional `<infoflow>`.
    pub infoflow: Option<Infoflow>,
    /// Whether `<rolecap/>` is set.
    pub rolecap: bool,
    /// Whether `<rolebase/>` is set.
    pub rolebase: bool,
}

/// Which macro kind a declaration is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacroKind {
    /// `interface`
    Interface,
    /// `template`
    Template,
}

impl MacroKind {
    /// The construct's source spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interface => "interface",
            Self::Template => "template",
        }
    }
}

impl fmt::Display for MacroKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The name of a declared macro, typed by its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacroDeclName {
    /// An interface name.
    Interface(InterfaceName),
    /// A template name.
    Template(TemplateName),
}

impl fmt::Display for MacroDeclName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interface(name) => fmt::Display::fmt(name, f),
            Self::Template(name) => fmt::Display::fmt(name, f),
        }
    }
}

/// The body of an exported macro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroBody {
    /// The leading `gen_require` block, if any.
    pub gen_require: Option<GenRequireBlock>,
    /// The rest of the body.
    pub statements: StatementList,
}

/// A declared `interface(...)` or `template(...)` macro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroDecl {
    /// The macro kind.
    pub kind: MacroKind,
    /// The macro name.
    pub name: MacroDeclName,
    /// Its documentation.
    pub docs: MacroDocs,
    /// Its body.
    pub body: MacroBody,
}

/// A whole `.if` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceFile {
    /// The module header documentation.
    pub docs: ModuleDocs,
    /// The exported macros.
    pub declarations: Vec<MacroDecl>,
}

impl ParseFromTokens for MacroDecl {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let kind = match parser.next_ident_text("`interface` or `template`")? {
            "interface" => MacroKind::Interface,
            "template" => MacroKind::Template,
            other => {
                return Err(ParseError::invalid(format!(
                    "not an interface macro: {other}"
                )));
            }
        };
        let mut args = parser.next_paren("the macro argument list")?;
        let mut name_parser = args.next_quote("the quoted macro name")?;
        let name_parser_text = name_parser.next_ident_text("a macro name")?;
        let name = match kind {
            MacroKind::Interface => MacroDeclName::Interface(name_parser_text.parse()?),
            MacroKind::Template => MacroDeclName::Template(name_parser_text.parse()?),
        };
        name_parser.finish()?;
        args.expect_punct(',')?;
        let mut body_parser = args.next_quote_unwrapped("the quoted macro body")?;
        args.finish()?;

        let gen_require = if body_parser.peek_keyword("gen_require") {
            Some(GenRequireBlock::parse_from_tokens(&mut body_parser)?)
        } else {
            None
        };
        let statements = StatementList::parse_from_tokens(&mut body_parser)?;
        Ok(Self {
            kind,
            name,
            docs: MacroDocs::default(),
            body: MacroBody {
                gen_require,
                statements,
            },
        })
    }
}

/// Which tags a documentation block may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocScope {
    Module,
    Macro,
}

#[derive(Debug, Default)]
struct RawDocs {
    summary: Option<DocText>,
    desc: Option<DocText>,
    required: Option<DocText>,
    params: Vec<ParamDoc>,
    infoflow: Option<Infoflow>,
    rolecap: bool,
    rolebase: bool,
}

impl RawDocs {
    fn into_module(self) -> Result<ModuleDocs> {
        let summary = self
            .summary
            .ok_or_else(|| ParseError::invalid("module documentation lacks a `<summary>`"))?;
        Ok(ModuleDocs {
            summary,
            desc: self.desc,
            required: self.required,
        })
    }

    fn into_macro(self) -> MacroDocs {
        MacroDocs {
            summary: self.summary.unwrap_or_default(),
            desc: self.desc,
            params: self.params,
            infoflow: self.infoflow,
            rolecap: self.rolecap,
            rolebase: self.rolebase,
        }
    }
}

fn parse_docs(lines: &[DocComment], scope: DocScope) -> Result<RawDocs> {
    let mut docs = RawDocs::default();
    let mut mode = Mode::None;
    let mut buffer: Vec<DocComment> = Vec::new();
    let mut param_index: Option<usize> = None;

    for line in lines {
        // The lexer strips one marker-adjacent space; the reference parser
        // strips all remaining indentation before reading tags.
        let trimmed = line.text().trim_start();

        if let Some(rest) = inline_tag(trimmed, "summary") {
            commit(&mut docs, mode, &mut buffer, param_index, Some(rest));
            continue;
        }
        if trimmed == "<summary>" {
            mode = Mode::Summary;
            buffer.clear();
            continue;
        }
        if trimmed == "</summary>" {
            commit(&mut docs, mode, &mut buffer, param_index, None);
            mode = Mode::None;
            continue;
        }

        if let Some(param) = parse_param_open(trimmed, scope)? {
            docs.params.push(param);
            param_index = Some(docs.params.len() - 1);
            mode = Mode::Param;
            buffer.clear();
            continue;
        }
        if trimmed == "</param>" {
            mode = Mode::None;
            param_index = None;
            buffer.clear();
            continue;
        }

        if let Some(rest) = inline_tag(trimmed, "desc") {
            docs.desc = Some(DocText(vec![DocComment::new(rest)]));
            mode = Mode::None;
            continue;
        }
        if trimmed == "<desc>" {
            mode = Mode::Desc;
            buffer.clear();
            continue;
        }
        if trimmed == "</desc>" {
            docs.desc = Some(DocText(std::mem::take(&mut buffer)));
            mode = Mode::None;
            continue;
        }

        if scope == DocScope::Module {
            if trimmed.starts_with("<required") {
                mode = Mode::Required;
                buffer.clear();
                continue;
            }
            if trimmed == "</required>" {
                docs.required = Some(DocText(std::mem::take(&mut buffer)));
                mode = Mode::None;
                continue;
            }
        } else {
            if let Some(infoflow) = parse_infoflow(trimmed)? {
                docs.infoflow = Some(infoflow);
                continue;
            }
            if trimmed == "<rolecap/>" {
                docs.rolecap = true;
                continue;
            }
            if trimmed == "<rolebase/>" {
                docs.rolebase = true;
                continue;
            }
        }

        match mode {
            Mode::Summary | Mode::Desc | Mode::Required | Mode::Param => {
                buffer.push(DocComment::new(trimmed));
            }
            Mode::None => {}
        }
    }

    if !buffer.is_empty() {
        commit(&mut docs, mode, &mut buffer, param_index, None);
    }
    Ok(docs)
}

fn commit(
    docs: &mut RawDocs,
    mode: Mode,
    buffer: &mut Vec<DocComment>,
    param_index: Option<usize>,
    inline: Option<&str>,
) {
    let text = match inline {
        Some(text) => DocText(vec![DocComment::new(text)]),
        None => DocText(std::mem::take(buffer)),
    };
    match mode {
        Mode::Summary | Mode::Param | Mode::None => {
            if let Some(index) = param_index {
                docs.params[index].summary = text;
            } else if docs.summary.is_none() {
                docs.summary = Some(text);
            }
        }
        Mode::Desc => docs.desc = Some(text),
        Mode::Required => docs.required = Some(text),
    }
    buffer.clear();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    None,
    Summary,
    Desc,
    Required,
    Param,
}

fn inline_tag<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    text.strip_prefix(&format!("<{tag}>"))
        .and_then(|rest| rest.strip_suffix(&format!("</{tag}>")))
}

fn parse_param_open(text: &str, scope: DocScope) -> Result<Option<ParamDoc>> {
    if scope != DocScope::Macro || !text.starts_with("<param ") {
        return Ok(None);
    }
    let attributes = text
        .strip_prefix("<param ")
        .and_then(|rest| rest.strip_suffix('>'))
        .ok_or_else(|| ParseError::invalid(format!("malformed `<param>` tag: {text}")))?;
    // Attribute values may contain spaces (`name="source type"`), so they are
    // scanned between their quotes rather than split on whitespace.
    let name_start = attributes
        .find("name=\"")
        .ok_or_else(|| ParseError::invalid("`<param>` lacks a name"))?
        + "name=\"".len();
    let name_end = attributes[name_start..]
        .find('"')
        .ok_or_else(|| ParseError::invalid("unterminated `name` attribute"))?
        + name_start;
    let name: ParamName = attributes[name_start..name_end].parse()?;
    let optional = attributes.contains("optional=\"true\"");
    let unused = attributes.contains("unused=\"true\"");
    Ok(Some(ParamDoc {
        name,
        optional,
        unused,
        summary: DocText::default(),
    }))
}

fn parse_infoflow(text: &str) -> Result<Option<Infoflow>> {
    let Some(rest) = text.strip_prefix("<infoflow") else {
        return Ok(None);
    };
    let attributes = rest
        .strip_suffix("/>")
        .ok_or_else(|| ParseError::invalid(format!("malformed `<infoflow>` tag: {text}")))?
        .trim();
    let mut flow = InfoflowKind::None;
    let mut weight = None;
    for attribute in attributes.split_whitespace() {
        if let Some(value) = attribute.strip_prefix("type=\"") {
            flow = match value.trim_end_matches('"') {
                "none" => InfoflowKind::None,
                "read" => InfoflowKind::Read,
                "write" => InfoflowKind::Write,
                "both" => InfoflowKind::Both,
                other => {
                    return Err(ParseError::invalid(format!(
                        "unknown infoflow type: {other}"
                    )));
                }
            };
        } else if let Some(value) = attribute.strip_prefix("weight=\"") {
            weight = Some(value.trim_end_matches('"').parse::<Weight>()?);
        } else {
            return Err(ParseError::invalid(format!(
                "unknown `<infoflow>` attribute: {attribute}"
            )));
        }
    }
    Ok(Some(Infoflow { flow, weight }))
}

/// Skips plain `#` comment lines.
fn skip_comments(parser: &mut Parser<'_>) {
    while let Some(TokenTree::Leaf(token)) = parser.peek() {
        if token.kind != TokenKind::Comment {
            break;
        }
        parser.next_tree();
    }
}

/// Collects the doc lines starting at `parser` until a non-doc token.
///
/// Bare `##` lines are structural, not text: the reference generator treats an
/// empty doc line in the header as the header's end, and ignores them elsewhere.
/// Whether another doc line follows before any non-comment token.
fn docs_follow(parser: &Parser<'_>) -> bool {
    let mut offset = 1;
    loop {
        match parser.peek_nth(offset) {
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::DocComment => return true,
            Some(TokenTree::Leaf(token)) if token.kind == TokenKind::Comment => offset += 1,
            _ => return false,
        }
    }
}

fn take_docs(parser: &mut Parser<'_>) -> Vec<DocComment> {
    let mut docs = Vec::new();
    while let Some(TokenTree::Leaf(token)) = parser.peek() {
        match token.kind {
            TokenKind::DocComment if token.text.is_empty() => {
                parser.next_tree();
            }
            TokenKind::DocComment => {
                docs.push(DocComment::new(token.text.clone()));
                parser.next_tree();
            }
            TokenKind::Comment => {
                // Comment lines interleave with documentation; keep skipping
                // them while more doc lines follow.
                if !docs_follow(parser) {
                    break;
                }
                parser.next_tree();
            }
            _ => break,
        }
    }
    docs
}

impl ParseFromTokens for InterfaceFile {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        skip_comments(parser);
        // The header ends at the first bare `##` line: anything documented after
        // it belongs to the first macro.
        let mut header_lines = Vec::new();
        while let Some(TokenTree::Leaf(token)) = parser.peek() {
            match token.kind {
                TokenKind::DocComment if token.text.is_empty() => {
                    parser.next_tree();
                    break;
                }
                TokenKind::DocComment => {
                    header_lines.push(DocComment::new(token.text.clone()));
                    parser.next_tree();
                }
                _ => break,
            }
        }
        skip_comments(parser);
        if header_lines.is_empty() {
            return Err(ParseError::invalid("`.if` file lacks its module header"));
        }
        let docs = parse_docs(&header_lines, DocScope::Module)?.into_module()?;

        let mut declarations = Vec::new();
        loop {
            skip_comments(parser);
            let pending = take_docs(parser);
            skip_comments(parser);
            if parser.is_empty() {
                break;
            }
            let kind = parser.peek_ident_text();
            if kind != "interface" && kind != "template" {
                return Err(ParseError::unexpected(
                    parser.peek().map_or_else(String::new, TokenTree::describe),
                    "`interface` or `template`",
                    parser.at(),
                ));
            }
            if pending.is_empty() {
                return Err(ParseError::invalid(format!(
                    "{kind} at {} lacks a documentation block",
                    parser.at()
                )));
            }
            let macro_docs = parse_docs(&pending, DocScope::Macro)?.into_macro();
            let mut declaration = MacroDecl::parse_from_tokens(parser)?;
            declaration.docs = macro_docs;
            declarations.push(declaration);
        }
        Ok(Self { docs, declarations })
    }
}

impl_from_str!(InterfaceFile);

impl fmt::Display for InterfaceFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_docs(f, &self.docs.summary, "summary")?;
        if let Some(desc) = &self.docs.desc {
            write_docs(f, desc, "desc")?;
        }
        if let Some(required) = &self.docs.required {
            writeln!(f, "## <required val=\"true\">")?;
            for line in required.lines() {
                writeln!(f, "##\t{}", line.text())?;
            }
            writeln!(f, "## </required>")?;
        }
        for declaration in &self.declarations {
            writeln!(f, "########################################")?;
            write_docs(f, &declaration.docs.summary, "summary")?;
            if let Some(desc) = &declaration.docs.desc {
                write_docs(f, desc, "desc")?;
            }
            for param in &declaration.docs.params {
                writeln!(
                    f,
                    "## <param name=\"{}\"{}{}>",
                    param.name,
                    if param.optional {
                        " optional=\"true\""
                    } else {
                        ""
                    },
                    if param.unused { " unused=\"true\"" } else { "" }
                )?;
                write_docs(f, &param.summary, "summary")?;
                writeln!(f, "## </param>")?;
            }
            if let Some(infoflow) = &declaration.docs.infoflow {
                write!(f, "## <infoflow type=\"{}\"", infoflow.flow)?;
                if let Some(weight) = infoflow.weight {
                    write!(f, " weight=\"{weight}\"")?;
                }
                writeln!(f, "/>")?;
            }
            if declaration.docs.rolecap {
                writeln!(f, "## <rolecap/>")?;
            }
            if declaration.docs.rolebase {
                writeln!(f, "## <rolebase/>")?;
            }
            writeln!(f, "#")?;
            writeln!(f, "{}(`{}',`", declaration.kind, declaration.name)?;
            if let Some(gen_require) = &declaration.body.gen_require {
                writeln!(f, "\tgen_require(`")?;
                for declaration in &gen_require.declarations {
                    writeln!(f, "\t\t{declaration}")?;
                }
                writeln!(f, "\t')")?;
            }
            for statement in declaration.body.statements.statements() {
                writeln!(f, "\t{statement}")?;
            }
            writeln!(f, "')")?;
        }
        Ok(())
    }
}

fn write_docs(f: &mut fmt::Formatter<'_>, text: &DocText, tag: &str) -> fmt::Result {
    writeln!(f, "## <{tag}>")?;
    for line in text.lines() {
        writeln!(f, "##\t{}", line.text())?;
    }
    writeln!(f, "## </{tag}>")
}
