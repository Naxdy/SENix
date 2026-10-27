//! The file-context grammar (`.fc`).
//!
//! A `.fc` file is a sequence of comment-headed sections of
//! `pathname [file_type] context` rules, with `ifdef`/`ifndef` blocks around
//! them. The path is a regular expression (or a `HOME_DIR`/`HOME_ROOT` macro),
//! the optional file type restricts the inode kind, and the context is either a
//! literal, a `gen_context(...)` call or the `<<none>>` sentinel.

use std::fmt;

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::identifier::{Comment, DocComment, FcPath, HomeMacro};
use crate::impl_from_str;
use crate::lexer::{Delimiter, TokenKind, TokenTree};
use crate::parser::{ParseFromTokens, Parser};
use crate::policy::context::FileContextValue;
use crate::policy::m4::ConditionalKind;

/// The inode kind a rule is restricted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileTypeFlag {
    /// `-b` — block device.
    Block,
    /// `-c` — character device.
    Char,
    /// `-d` — directory.
    Directory,
    /// `-p` — named pipe.
    Pipe,
    /// `-l` — symbolic link.
    Symlink,
    /// `-s` — socket.
    Socket,
    /// `--` — ordinary file.
    Ordinary,
}

impl FileTypeFlag {
    /// The flag's source character, or `None` for `--`.
    #[must_use]
    pub const fn character(self) -> Option<char> {
        match self {
            Self::Block => Some('b'),
            Self::Char => Some('c'),
            Self::Directory => Some('d'),
            Self::Pipe => Some('p'),
            Self::Symlink => Some('l'),
            Self::Socket => Some('s'),
            Self::Ordinary => None,
        }
    }

    fn from_character(character: char) -> Option<Self> {
        Some(match character {
            'b' => Self::Block,
            'c' => Self::Char,
            'd' => Self::Directory,
            'p' => Self::Pipe,
            'l' => Self::Symlink,
            's' => Self::Socket,
            _ => return None,
        })
    }
}

/// A run of file-type flags (`--`, `-d`, `-bc`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTypeFlags(Vec<FileTypeFlag>);

impl FileTypeFlags {
    /// The flags.
    #[must_use]
    pub fn flags(&self) -> &[FileTypeFlag] {
        &self.0
    }
}

impl ParseFromTokens for FileTypeFlags {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_punct('-')?;
        if parser.eat_punct('-') {
            return Ok(Self(vec![FileTypeFlag::Ordinary]));
        }
        let text = parser.next_ident_text("a file type flag")?;
        let mut flags = Vec::new();
        for character in text.chars() {
            let flag = FileTypeFlag::from_character(character).ok_or_else(|| {
                ParseError::invalid(format!("unknown file type flag: -{character}"))
            })?;
            flags.push(flag);
        }
        if flags.is_empty() {
            return Err(ParseError::invalid("empty file type flags".to_string()));
        }
        Ok(Self(flags))
    }
}

impl fmt::Display for FileTypeFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for flag in &self.0 {
            f.write_str("-")?;
            match flag.character() {
                Some(character) => write!(f, "{character}")?,
                None => f.write_str("-")?,
            }
        }
        Ok(())
    }
}

/// One `pathname [file_type] context` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The path regular expression (or home-directory macro).
    pub path: FcPath,
    /// The optional file-type restriction.
    pub file_type: Option<FileTypeFlags>,
    /// The context or `<<none>>`.
    pub context: FileContextValue,
}

impl ParseFromTokens for Rule {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let path = match parser.peek() {
            Some(TokenTree::Leaf(token))
                if token.kind == TokenKind::Path
                    || (token.kind == TokenKind::Ident
                        && (token.text.starts_with("HOME_DIR")
                            || token.text.starts_with("HOME_ROOT"))) =>
            {
                let path = token.text.parse()?;
                parser.next_tree();
                path
            }
            Some(tree) => {
                return Err(ParseError::unexpected(
                    tree.describe(),
                    "a path",
                    tree.span(),
                ));
            }
            None => {
                return Err(ParseError::at(
                    ParseErrorKind::UnexpectedEof { expected: "a path" },
                    parser.at(),
                ));
            }
        };
        let file_type = if parser.peek_punct('-') {
            Some(FileTypeFlags::parse_from_tokens(parser)?)
        } else {
            None
        };
        let context = FileContextValue::parse_from_tokens(parser)?;
        Ok(Self {
            path,
            file_type,
            context,
        })
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)?;
        if let Some(flags) = &self.file_type {
            write!(f, " {flags}")?;
        }
        f.write_str(" ")?;
        self.context.write_fc(f)
    }
}

/// A comment line, either a `#` or a `##` one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentLine {
    /// A plain comment.
    Plain(Comment),
    /// A documentation comment.
    Doc(DocComment),
}

impl fmt::Display for CommentLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(comment) => fmt::Display::fmt(comment, f),
            Self::Doc(comment) => fmt::Display::fmt(comment, f),
        }
    }
}

/// A rule or a comment within a section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionItem {
    /// A comment line.
    Comment(CommentLine),
    /// A rule.
    Rule(Rule),
}

/// A comment-headed block of rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The section's leading comments.
    pub comments: Vec<CommentLine>,
    /// The section's items.
    pub items: Vec<SectionItem>,
}

/// An `ifdef`/`ifndef` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conditional {
    /// Which conditional it is.
    pub kind: ConditionalKind,
    /// The tested `m4` symbol.
    pub symbol: crate::identifier::Symbol,
    /// The body taken when the test holds.
    pub then: FileItems,
    /// The optional alternative body.
    pub otherwise: Option<FileItems>,
}

/// A node of a file-context file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileItem {
    /// A section of rules and comments.
    Section(Section),
    /// A conditional block.
    Conditional(Conditional),
}

/// A list of file-context nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileItems(Vec<FileItem>);

impl FileItems {
    /// Creates a node list.
    #[must_use]
    pub fn from_items(items: Vec<FileItem>) -> Self {
        Self(items)
    }

    /// The nodes.
    #[must_use]
    pub fn items(&self) -> &[FileItem] {
        &self.0
    }
}

/// A whole `.fc` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileContextFile(Vec<FileItem>);

impl FileContextFile {
    /// The file's top-level nodes.
    #[must_use]
    pub fn items(&self) -> &[FileItem] {
        &self.0
    }
}

impl ParseFromTokens for FileItems {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut items = Vec::new();
        let mut section = Section {
            comments: Vec::new(),
            items: Vec::new(),
        };
        let mut last_was_comment = false;

        let finish = |section: &mut Section, items: &mut Vec<FileItem>| {
            if !section.comments.is_empty() || !section.items.is_empty() {
                items.push(FileItem::Section(std::mem::replace(
                    section,
                    Section {
                        comments: Vec::new(),
                        items: Vec::new(),
                    },
                )));
            }
        };

        while let Some(tree) = parser.peek() {
            match tree {
                TokenTree::Leaf(token)
                    if token.kind == TokenKind::Comment || token.kind == TokenKind::DocComment =>
                {
                    let doc = token.kind == TokenKind::DocComment;
                    let text = token.text.clone();
                    parser.next_tree();
                    if !section.comments.is_empty()
                        && (!section.items.is_empty() || !last_was_comment)
                    {
                        finish(&mut section, &mut items);
                    }
                    section.comments.push(if doc {
                        CommentLine::Doc(DocComment::new(text))
                    } else {
                        CommentLine::Plain(Comment::new(text))
                    });
                    last_was_comment = true;
                }
                TokenTree::Leaf(token)
                    if token.kind == TokenKind::Ident
                        && (token.text == "ifdef" || token.text == "ifndef") =>
                {
                    finish(&mut section, &mut items);
                    items.push(FileItem::Conditional(parse_conditional(parser)?));
                    last_was_comment = false;
                }
                TokenTree::Leaf(token) if token.kind == TokenKind::Ident && token.text == "dnl" => {
                    let line = token.span.line;
                    parser.next_tree();
                    while let Some(TokenTree::Leaf(next)) = parser.peek() {
                        if next.span.line != line {
                            break;
                        }
                        parser.next_tree();
                    }
                }
                TokenTree::Leaf(token)
                    if token.kind == TokenKind::Path
                        || (token.kind == TokenKind::Ident
                            && (token.text.starts_with("HOME_DIR")
                                || token.text.starts_with("HOME_ROOT"))) =>
                {
                    section
                        .items
                        .push(SectionItem::Rule(Rule::parse_from_tokens(parser)?));
                    last_was_comment = false;
                }
                other => {
                    return Err(ParseError::unexpected(
                        other.describe(),
                        "a rule, a comment or a conditional",
                        other.span(),
                    ));
                }
            }
        }
        finish(&mut section, &mut items);
        Ok(Self(items))
    }
}

fn parse_conditional(parser: &mut Parser<'_>) -> Result<Conditional> {
    let kind = if parser.eat_keyword("ifdef") {
        ConditionalKind::IfDef
    } else {
        parser.expect_keyword("ifndef")?;
        ConditionalKind::IfNDef
    };
    let mut args = parser.next_paren("the conditional argument list")?;
    let mut symbol_parser = args.next_quote("the quoted tested symbol")?;
    let symbol: crate::identifier::Symbol = symbol_parser.parse_ident("a condition symbol")?;
    symbol_parser.finish()?;
    args.expect_punct(',')?;
    let mut then = args.next_quote_unwrapped("the quoted then-body")?;
    let then = FileItems::parse_from_tokens(&mut then)?;
    let otherwise = if args.eat_punct(',') {
        let mut otherwise = args.next_quote_unwrapped("the quoted else-body")?;
        let otherwise = FileItems::parse_from_tokens(&mut otherwise)?;
        Some(otherwise)
    } else {
        None
    };
    args.finish()?;
    Ok(Conditional {
        kind,
        symbol,
        then,
        otherwise,
    })
}

impl ParseFromTokens for FileContextFile {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let items = FileItems::parse_from_tokens(parser)?;
        Ok(Self(items.items().to_vec()))
    }
}

impl_from_str!(FileContextFile);

impl fmt::Display for FileContextFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in &self.0 {
            match item {
                FileItem::Section(section) => {
                    for comment in &section.comments {
                        writeln!(f, "{comment}")?;
                    }
                    for item in &section.items {
                        match item {
                            SectionItem::Comment(comment) => writeln!(f, "{comment}")?,
                            SectionItem::Rule(rule) => writeln!(f, "{rule}")?,
                        }
                    }
                }
                FileItem::Conditional(conditional) => {
                    write!(
                        f,
                        "{}(`{}',`{}'",
                        conditional.kind, conditional.symbol, conditional.then
                    )?;
                    if let Some(otherwise) = &conditional.otherwise {
                        write!(f, ",`{otherwise}'")?;
                    }
                    writeln!(f, ")")?;
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for FileItems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&FileContextFile(self.0.clone()), f)
    }
}

impl fmt::Display for Conditional {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = Delimiter::Quote;
        write!(f, "{}(`{}'", self.kind, self.symbol)?;
        write!(f, ",`{}'", self.then)?;
        if let Some(otherwise) = &self.otherwise {
            write!(f, ",`{otherwise}'")?;
        }
        f.write_str(")")
    }
}

/// The `HOME_DIR`/`HOME_ROOT` macros as an [`FcPath`]-level helper.
impl FcPath {
    /// The home macro backing a [`FcPath::Home`], if any.
    #[must_use]
    pub const fn home_macro(&self) -> Option<HomeMacro> {
        match self {
            Self::Home { macro_, .. } => Some(*macro_),
            Self::Absolute(_) => None,
        }
    }
}
