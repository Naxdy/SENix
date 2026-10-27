//! Tokenizer and token-tree builder.
//!
//! The lexer deliberately mirrors the checkpolicy scanner
//! (`policy_scan.l`) so that the token boundaries are the ones the policy
//! compiler itself sees, and the CIL lexer (`cil_lexer.l`) for `.cil`.
//!
//! Nesting delimiters become [`Group`]s. `m4` quoting (`` ` `` … `'`) is a
//! delimiter too, so a macro body is a group and its contents can be parsed by
//! the ordinary recursive-descent parser without a second, quoting-aware pass.

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::span::Span;

/// A nesting delimiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delimiter {
    /// `(` … `)`
    Parenthesis,
    /// `{` … `}`
    Brace,
    /// `[` … `]`
    Bracket,
    /// `` ` `` … `'` — the `m4` quote.
    Quote,
}

impl Delimiter {
    /// The opening text of the delimiter.
    #[must_use]
    pub const fn open(self) -> &'static str {
        match self {
            Self::Parenthesis => "(",
            Self::Brace => "{",
            Self::Bracket => "[",
            Self::Quote => "`",
        }
    }

    /// The closing text of the delimiter.
    #[must_use]
    pub const fn close(self) -> &'static str {
        match self {
            Self::Parenthesis => ")",
            Self::Brace => "}",
            Self::Bracket => "]",
            Self::Quote => "'",
        }
    }
}

/// The lexical class of a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A policy identifier (letters/digits/`_`/`-`/`.`, optionally prefixed
    /// with an `m4` positional parameter reference such as `$1`).
    Ident,
    /// A decimal or hexadecimal number.
    Number,
    /// An absolute path.
    Path,
    /// A quoted absolute path (`"/..."`).
    QPath,
    /// A quoted file name (`"name"`), used by `type_transition`.
    Filename,
    /// A dotted-quad IPv4 address.
    Ipv4Addr,
    /// An IPv4 address with prefix length.
    Ipv4Cidr,
    /// An IPv6 address.
    Ipv6Addr,
    /// An IPv6 address with prefix length.
    Ipv6Cidr,
    /// A module version literal, or an IPv4 address in `module ... ;`.
    Version,
    /// A network interface name (possibly with `*`/`?` globs).
    NetifName,
    /// A filesystem name.
    Filesystem,
    /// The `<<none>>` file-context sentinel.
    NoneContext,
    /// A single punctuation character.
    Punct(char),
    /// A `##` documentation-comment line.
    DocComment,
    /// A `#` comment or a `;` CIL comment, including the marker.
    Comment,
    /// A `;;*` CIL high-level-language line marker.
    HllLineMark,
    /// A CIL quoted string.
    Str,
    /// An `m4` `changequote(…)` directive.
    ChangeQuote,
}

impl TokenKind {
    /// Whether the kind is a bare word literal (no punctuation).
    #[must_use]
    pub const fn is_word(self) -> bool {
        matches!(
            self,
            Self::Ident
                | Self::Number
                | Self::Path
                | Self::QPath
                | Self::Filename
                | Self::Ipv4Addr
                | Self::Ipv4Cidr
                | Self::Ipv6Addr
                | Self::Ipv6Cidr
                | Self::Version
                | Self::NetifName
                | Self::Filesystem
                | Self::NoneContext
                | Self::HllLineMark
                | Self::Str
        )
    }
}

/// A lexical token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The lexical class.
    pub kind: TokenKind,
    /// The verbatim source text.
    pub text: String,
    /// Source location.
    pub span: Span,
}

impl Token {
    /// Creates a token.
    #[must_use]
    pub fn new(kind: TokenKind, text: impl Into<String>, span: Span) -> Self {
        Self {
            kind,
            text: text.into(),
            span,
        }
    }
}

/// A token or a nested group of tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenTree {
    /// A single token.
    Leaf(Token),
    /// A delimited sequence.
    Group(Group),
}

impl TokenTree {
    /// Source location of the tree, leaf or group alike.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Leaf(token) => token.span,
            Self::Group(group) => group.span,
        }
    }

    /// A short description for diagnostics.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Leaf(token) => token.text.clone(),
            Self::Group(group) => format!("{}{}", group.delimiter.open(), group.delimiter.close()),
        }
    }
}

/// A delimited token sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Which delimiter ranges this group.
    pub delimiter: Delimiter,
    /// Everything between the delimiters.
    pub tokens: Vec<TokenTree>,
    /// Location of the opening delimiter.
    pub span: Span,
}

/// Which lexical dialect to scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// The checkpolicy policy language (`m4` quoting included).
    Policy,
    /// The CIL S-expression language.
    Cil,
    /// Standalone `m4`, where `m4` quoting wins over grouping.
    M4,
}

/// Tokenizes `source` in the policy dialect and builds the token tree.
/// # Errors
/// Returns an error on an unterminated or mismatched delimiter.
pub fn lex(source: &str) -> Result<Vec<TokenTree>> {
    Lexer::new(source, Dialect::Policy).run()
}

/// Tokenizes `source` in the CIL dialect and builds the token tree.
/// # Errors
/// Returns an error on an unterminated or mismatched delimiter.
pub fn lex_cil(source: &str) -> Result<Vec<TokenTree>> {
    Lexer::new(source, Dialect::Cil).run()
}

/// Tokenizes `source` as standalone `m4`.
///
/// Unlike the policy dialect, an `m4` quoted region is authoritative: a quote
/// closer that arrives while a parenthesis is still open ends that parenthesis
/// (m4 sees the parentheses inside quotes as plain text), and a stray closer
/// becomes a plain punctuation token. This keeps the `support/` helpers, which
/// rely on that behaviour, lexable.
/// # Errors
/// Returns an error on an unterminated or mismatched delimiter.
pub fn lex_m4(source: &str) -> Result<Vec<TokenTree>> {
    Lexer::new(source, Dialect::M4).run()
}

struct Frame {
    delimiter: Option<Delimiter>,
    tokens: Vec<TokenTree>,
    span: Option<Span>,
}

impl Frame {
    fn new(delimiter: Option<Delimiter>) -> Self {
        Self {
            delimiter,
            tokens: Vec::new(),
            span: None,
        }
    }

    fn at(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }
}

struct Lexer<'a> {
    bytes: &'a [u8],
    source: &'a str,
    pos: usize,
    line: usize,
    column: usize,
    dialect: Dialect,
    at_line_start: bool,
    quote_open: u8,
    quote_close: u8,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str, dialect: Dialect) -> Self {
        Self {
            bytes: source.as_bytes(),
            source,
            pos: 0,
            line: 1,
            column: 1,
            dialect,
            at_line_start: true,
            quote_open: b'`',
            quote_close: b'\'',
        }
    }

    fn run(mut self) -> Result<Vec<TokenTree>> {
        let mut stack: Vec<Frame> = vec![Frame::new(None)];
        while let Some(byte) = self.current() {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\x0c' | b'\n') {
                self.advance(1);
                continue;
            }

            if let Some(delimiter) = self.closer_for(byte) {
                let top = stack.last().and_then(|frame| frame.delimiter);
                if top == Some(delimiter) {
                    let span = self.span_at(self.pos, self.pos + 1);
                    self.advance(1);
                    self.pop_frame(&mut stack, span);
                    continue;
                }
                if self.dialect == Dialect::M4 {
                    if delimiter == Delimiter::Quote {
                        while stack
                            .last()
                            .and_then(|frame| frame.delimiter)
                            .is_some_and(|open| open != Delimiter::Quote)
                        {
                            let span = self.span_at(self.pos, self.pos + 1);
                            self.pop_frame(&mut stack, span);
                        }
                        if stack.last().and_then(|frame| frame.delimiter) == Some(Delimiter::Quote)
                        {
                            let span = self.span_at(self.pos, self.pos + 1);
                            self.advance(1);
                            self.pop_frame(&mut stack, span);
                            continue;
                        }
                    }
                    let span = self.span_at(self.pos, self.pos + 1);
                    let close = delimiter.close();
                    self.advance(1);
                    push_token(
                        &mut stack,
                        TokenTree::Leaf(Token::new(
                            TokenKind::Punct(close.as_bytes()[0] as char),
                            close,
                            span,
                        )),
                    );
                    continue;
                }
                if matches!(
                    delimiter,
                    Delimiter::Parenthesis | Delimiter::Brace | Delimiter::Quote
                ) {
                    return Err(ParseError::at(
                        ParseErrorKind::MismatchedDelimiter {
                            found: delimiter.close(),
                            expected: top.map_or("", Delimiter::close),
                        },
                        self.span_at(self.pos, self.pos + 1),
                    ));
                }
                let span = self.span_at(self.pos, self.pos + 1);
                let close = delimiter.close();
                self.advance(1);
                push_token(
                    &mut stack,
                    TokenTree::Leaf(Token::new(
                        TokenKind::Punct(close.as_bytes()[0] as char),
                        close,
                        span,
                    )),
                );
                continue;
            }

            if let Some(delimiter) = self.opener_for(byte) {
                let span = self.span_at(self.pos, self.pos + 1);
                self.advance(1);
                stack.push(Frame::new(Some(delimiter)).at(span));
                continue;
            }

            let token = self.token()?;
            push_token(&mut stack, token);
        }

        if stack.len() > 1 {
            if self.dialect != Dialect::M4 {
                let delimiter = stack
                    .last()
                    .and_then(|frame| frame.delimiter)
                    .unwrap_or(Delimiter::Parenthesis);
                return Err(ParseError::at(
                    ParseErrorKind::UnterminatedDelimiter {
                        delimiter: delimiter.open(),
                    },
                    self.span_at(self.pos, self.pos),
                ));
            }
            while stack.len() > 1 {
                let span = self.span_at(self.pos, self.pos);
                self.pop_frame(&mut stack, span);
            }
        }

        Ok(stack.remove(0).tokens)
    }

    #[allow(clippy::unused_self)]
    fn pop_frame(&self, stack: &mut Vec<Frame>, span: Span) {
        let Some(frame) = stack.pop() else {
            return;
        };
        let Some(parent) = stack.last_mut() else {
            stack.push(frame);
            return;
        };
        match frame.delimiter {
            Some(delimiter) => parent.tokens.push(TokenTree::Group(Group {
                delimiter,
                tokens: frame.tokens,
                span: frame.span.unwrap_or(span),
            })),
            None => parent.tokens.extend(frame.tokens),
        }
    }

    fn span_at(&self, start: usize, end: usize) -> Span {
        Span::new(start, end, self.line, self.column)
    }

    fn peek(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    fn current(&self) -> Option<u8> {
        self.peek(0)
    }

    fn advance(&mut self, count: usize) {
        for _ in 0..count {
            match self.current() {
                Some(b'\n') => {
                    self.line += 1;
                    self.column = 1;
                    self.at_line_start = true;
                }
                Some(_) => {
                    self.column += 1;
                }
                None => break,
            }
            self.pos += 1;
        }
    }

    fn sequence(
        &mut self,
        until: Option<Delimiter>,
    ) -> Result<(Vec<TokenTree>, Option<Delimiter>)> {
        let mut tokens = Vec::new();
        loop {
            let Some(byte) = self.current() else {
                return match until {
                    Some(delimiter) => Err(ParseError::at(
                        ParseErrorKind::UnterminatedDelimiter {
                            delimiter: delimiter.open(),
                        },
                        self.span_at(self.pos, self.pos),
                    )),
                    None => Ok((tokens, None)),
                };
            };

            if matches!(byte, b' ' | b'\t' | b'\r' | b'\x0c' | b'\n') {
                self.advance(1);
                continue;
            }

            if let Some(delimiter) = self.closer_for(byte) {
                if let Some(expected) = until {
                    if delimiter == expected {
                        self.advance(1);
                        return Ok((tokens, Some(delimiter)));
                    }
                    if self.dialect != Dialect::M4
                        && matches!(
                            delimiter,
                            Delimiter::Parenthesis | Delimiter::Brace | Delimiter::Quote
                        )
                    {
                        return Err(ParseError::at(
                            ParseErrorKind::MismatchedDelimiter {
                                found: delimiter.close(),
                                expected: expected.close(),
                            },
                            self.span_at(self.pos, self.pos + 1),
                        ));
                    }
                }
                let span = self.span_at(self.pos, self.pos + 1);
                let close = delimiter.close();
                self.advance(1);
                tokens.push(TokenTree::Leaf(Token::new(
                    TokenKind::Punct(close.as_bytes()[0] as char),
                    close,
                    span,
                )));
                continue;
            }

            if let Some(delimiter) = self.opener_for(byte) {
                let span = self.span_at(self.pos, self.pos + 1);
                self.advance(1);
                let (inner, closing) = self.sequence(Some(delimiter))?;
                debug_assert_eq!(closing, Some(delimiter));
                tokens.push(TokenTree::Group(Group {
                    delimiter,
                    tokens: inner,
                    span,
                }));
                continue;
            }

            tokens.push(self.token()?);
        }
    }

    fn opener_for(&self, byte: u8) -> Option<Delimiter> {
        if self.dialect == Dialect::Cil {
            return (byte == b'(').then_some(Delimiter::Parenthesis);
        }
        if self.dialect == Dialect::M4 {
            if byte == self.quote_open {
                return Some(Delimiter::Quote);
            }
            return match byte {
                b'(' => Some(Delimiter::Parenthesis),
                b'{' => Some(Delimiter::Brace),
                _ => None,
            };
        }
        if byte == self.quote_open {
            return Some(Delimiter::Quote);
        }
        match byte {
            b'(' => Some(Delimiter::Parenthesis),
            b'{' => Some(Delimiter::Brace),
            b'[' if self.quote_open != b'[' => Some(Delimiter::Bracket),
            _ => None,
        }
    }

    fn closer_for(&self, byte: u8) -> Option<Delimiter> {
        if self.dialect == Dialect::Cil {
            return (byte == b')').then_some(Delimiter::Parenthesis);
        }
        if self.dialect == Dialect::M4 {
            if byte == self.quote_close {
                return Some(Delimiter::Quote);
            }
            return match byte {
                b')' => Some(Delimiter::Parenthesis),
                b'}' => Some(Delimiter::Brace),
                _ => None,
            };
        }
        if byte == self.quote_close {
            return Some(Delimiter::Quote);
        }
        match byte {
            b')' => Some(Delimiter::Parenthesis),
            b'}' => Some(Delimiter::Brace),
            b']' if self.quote_close != b']' => Some(Delimiter::Bracket),
            _ => None,
        }
    }

    fn token(&mut self) -> Result<TokenTree> {
        let start = self.pos;
        let line = self.line;
        let column = self.column;
        self.at_line_start = false;

        if self.dialect == Dialect::Cil {
            return self.cil_token(start, line, column);
        }

        if self.current() == Some(b'#') {
            return Ok(self.comment(start, line, column));
        }

        if self.starts_with(b"<<none>>") {
            self.advance(8);
            return Ok(self.leaf(TokenKind::NoneContext, start, line, column));
        }

        if self.starts_with(b"changequote(") && self.dialect != Dialect::Cil {
            return self.changequote(start, line, column);
        }

        if self.starts_with(b"HOME_DIR/") || self.starts_with(b"HOME_ROOT/") {
            let mut len = 8;
            while matches!(self.peek(len), Some(byte) if !matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0c'))
            {
                len += 1;
            }
            self.advance(len);
            return Ok(self.leaf(TokenKind::Path, start, line, column));
        }

        let (kind, len) = self.scan_word();
        if len > 0 {
            self.advance(len);
            return Ok(self.leaf(kind, start, line, column));
        }

        let byte = self.current().unwrap_or_default();
        self.advance(1);
        Ok(self.leaf(TokenKind::Punct(byte as char), start, line, column))
    }

    fn leaf(&self, kind: TokenKind, start: usize, line: usize, column: usize) -> TokenTree {
        let end = self.pos;
        TokenTree::Leaf(Token::new(
            kind,
            &self.source[start..end],
            Span::new(start, end, line, column),
        ))
    }

    fn comment(&mut self, start: usize, line: usize, column: usize) -> TokenTree {
        // A two-hash marker followed by whitespace starts a documentation
        // comment. Longer hash runs (`########…`) are plain separators.
        let mut hashes = 0;
        while self.current() == Some(b'#') {
            self.advance(1);
            hashes += 1;
        }
        let doc = hashes == 2 && self.current() != Some(b'#');
        let mut body_start = if doc { self.pos } else { start + 1 };
        if matches!(self.current(), Some(b' ' | b'\t')) {
            self.advance(1);
            body_start += 1;
        }
        while let Some(byte) = self.current() {
            if byte == b'\n' {
                break;
            }
            self.advance(1);
        }
        let mut body_end = self.pos;
        while body_end > body_start && matches!(self.bytes[body_end - 1], b' ' | b'\t' | b'\r') {
            body_end -= 1;
        }
        let kind = if doc {
            TokenKind::DocComment
        } else {
            TokenKind::Comment
        };
        TokenTree::Leaf(Token::new(
            kind,
            &self.source[body_start..body_end],
            Span::new(start, self.pos, line, column),
        ))
    }

    /// Consumes an `m4` `changequote(…)` directive and updates the quote
    /// delimiters. Emitted as a `changequote` identifier followed by a
    /// parenthesised group of the two delimiter leaves.
    fn changequote(&mut self, start: usize, line: usize, column: usize) -> Result<TokenTree> {
        self.advance("changequote(".len());
        let open = self.current().unwrap_or(b'`');
        self.advance(1);
        if self.current() != Some(b',') {
            return Err(ParseError::at(
                ParseErrorKind::Invalid {
                    reason: "`changequote` expects two delimiters".into(),
                },
                self.span_at(start, self.pos),
            ));
        }
        self.advance(1);
        let close = self.current().unwrap_or(b'\'');
        self.advance(1);
        if self.current() != Some(b')') {
            return Err(ParseError::at(
                ParseErrorKind::Invalid {
                    reason: "`changequote` expects two delimiters".into(),
                },
                self.span_at(start, self.pos),
            ));
        }
        self.advance(1);
        self.quote_open = open;
        self.quote_close = close;

        Ok(self.leaf(TokenKind::ChangeQuote, start, line, column))
    }

    fn starts_with(&self, needle: &[u8]) -> bool {
        self.bytes[self.pos..].starts_with(needle)
    }

    /// Scans the longest word-token match at the cursor.
    ///
    /// Returns the lexical class and length. The rule order is the scanner's
    /// rule order, which breaks ties for equal-length matches.
    fn scan_word(&self) -> (TokenKind, usize) {
        let mut best: (TokenKind, usize, usize) = (TokenKind::Ident, 0, usize::MAX);
        let mut consider = |kind: TokenKind, len: usize, rule: usize| {
            if len > best.1 || (len == best.1 && rule < best.2) {
                best = (kind, len, rule);
            }
        };

        consider(TokenKind::Path, self.path_len(), 0);
        consider(TokenKind::QPath, self.quoted_len(true), 1);
        consider(TokenKind::Filename, self.quoted_len(false), 2);
        consider(TokenKind::Ident, self.ident_len(), 3);
        consider(TokenKind::Number, self.number_len(), 4);
        consider(TokenKind::Filesystem, self.filesystem_len(), 5);
        consider(TokenKind::Ipv4Cidr, self.ipv4_len(true), 6);
        consider(TokenKind::Ipv4Addr, self.ipv4_len(false), 7);
        consider(TokenKind::Ipv6Addr, self.ipv6_len(false), 8);
        consider(TokenKind::Ipv6Cidr, self.ipv6_len(true), 9);
        consider(TokenKind::Version, self.version_len(), 10);
        consider(TokenKind::NetifName, self.netif_len(), 11);

        (best.0, best.1)
    }

    fn path_len(&self) -> usize {
        if self.current() != Some(b'/') {
            return 0;
        }
        let mut len = 1;
        while let Some(byte) = self.peek(len) {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0c') {
                break;
            }
            len += 1;
        }
        len
    }

    fn quoted_len(&self, path: bool) -> usize {
        if self.current() != Some(b'"') {
            return 0;
        }
        let mut len = 1;
        if path {
            if self.peek(1) != Some(b'/') {
                return 0;
            }
        } else if self.peek(1) == Some(b'/') {
            return 0;
        }
        while let Some(byte) = self.peek(len) {
            match byte {
                b'"' => return len + 1,
                b'\n' => return 0,
                b'/' if !path => return 0,
                _ => len += 1,
            }
        }
        0
    }

    fn ident_len(&self) -> usize {
        let mut len;
        if self.current() == Some(b'$') {
            len = 1;
            match self.peek(1) {
                Some(b'*' | b'@' | b'#') => len += 1,
                Some(byte) if byte.is_ascii_digit() => {
                    while matches!(self.peek(len), Some(byte) if byte.is_ascii_digit()) {
                        len += 1;
                    }
                }
                _ => return 0,
            }
            while matches!(self.peek(len), Some(byte) if is_ident_continue(byte)) {
                len += 1;
            }
            return len;
        }
        let Some(first) = self.current() else {
            return 0;
        };
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return 0;
        }
        let mut len = 1;
        while matches!(self.peek(len), Some(byte) if is_ident_continue(byte)) {
            len += 1;
        }
        len
    }

    fn number_len(&self) -> usize {
        match (self.current(), self.peek(1)) {
            (Some(b'0'), Some(b'x' | b'X')) => {
                let mut len = 2;
                while matches!(self.peek(len), Some(byte) if byte.is_ascii_hexdigit()) {
                    len += 1;
                }
                if len > 2 { len } else { 0 }
            }
            (Some(byte), _) if byte.is_ascii_digit() => {
                let mut len = 1;
                while matches!(self.peek(len), Some(byte) if byte.is_ascii_digit()) {
                    len += 1;
                }
                len
            }
            _ => 0,
        }
    }

    fn filesystem_len(&self) -> usize {
        let mut len = 0;
        while matches!(self.peek(len), Some(byte) if byte.is_ascii_alphanumeric()) {
            len += 1;
        }
        if len == 0 {
            return 0;
        }
        if self.bytes[self.pos..self.pos + len]
            .iter()
            .any(u8::is_ascii_alphabetic)
        {
            len
        } else {
            0
        }
    }

    fn dotted_quad(&self) -> Option<(usize, usize)> {
        let mut len = 0;
        for group in 0..4 {
            let mut digits = 0;
            while matches!(self.peek(len), Some(byte) if byte.is_ascii_digit()) {
                len += 1;
                digits += 1;
                if digits == 3 {
                    break;
                }
            }
            if digits == 0 {
                return None;
            }
            if group < 3 {
                if self.peek(len) != Some(b'.') {
                    return None;
                }
                len += 1;
            }
        }
        Some((len, 0))
    }

    fn ipv4_len(&self, cidr: bool) -> usize {
        let Some((mut len, _)) = self.dotted_quad() else {
            return 0;
        };
        if !cidr {
            return len;
        }
        if self.peek(len) != Some(b'/') {
            return 0;
        }
        len += 1;
        let mut digits = 0;
        while matches!(self.peek(len), Some(byte) if byte.is_ascii_digit()) {
            len += 1;
            digits += 1;
            if digits == 2 {
                break;
            }
        }
        if digits > 0 { len } else { 0 }
    }

    fn ipv6_len(&self, cidr: bool) -> usize {
        let mut len = 0;
        for group in 0..2 {
            let mut digits = 0;
            while matches!(self.peek(len), Some(byte) if byte.is_ascii_hexdigit()) {
                len += 1;
                digits += 1;
                if digits == 4 {
                    break;
                }
            }
            if self.peek(len) != Some(b':') {
                return 0;
            }
            len += 1;
            let _ = group;
        }
        while matches!(self.peek(len), Some(byte) if byte.is_ascii_hexdigit() || byte == b':' || byte == b'.')
        {
            len += 1;
        }
        if !cidr {
            return len;
        }
        if self.peek(len) != Some(b'/') {
            return 0;
        }
        len += 1;
        let mut digits = 0;
        while matches!(self.peek(len), Some(byte) if byte.is_ascii_digit()) {
            len += 1;
            digits += 1;
            if digits == 3 {
                break;
            }
        }
        if digits > 0 { len } else { 0 }
    }

    fn version_len(&self) -> usize {
        let mut len = 0;
        while matches!(self.peek(len), Some(byte) if byte.is_ascii_digit()) {
            len += 1;
        }
        if len == 0 {
            return 0;
        }
        if self.peek(len) != Some(b'.') {
            return len;
        }
        len += 1;
        while matches!(self.peek(len), Some(byte) if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        {
            len += 1;
        }
        len
    }

    fn netif_len(&self) -> usize {
        let mut len;
        match self.current() {
            Some(byte) if byte.is_ascii_alphanumeric() => {
                len = 1;
                while len < 16
                    && matches!(self.peek(len), Some(byte) if byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'?' | b'_'))
                {
                    len += 1;
                }
                len
            }
            Some(b'*' | b'?') => {
                len = 1;
                while len < 16
                    && matches!(self.peek(len), Some(byte) if byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'?' | b'_'))
                {
                    len += 1;
                }
                if len > 1 { len } else { 0 }
            }
            _ => 0,
        }
    }

    fn cil_token(&mut self, start: usize, line: usize, column: usize) -> Result<TokenTree> {
        match self.current() {
            Some(b';') => {
                if self.starts_with(b";;*") {
                    self.advance(3);
                    while let Some(byte) = self.current() {
                        if byte == b'\n' {
                            break;
                        }
                        self.advance(1);
                    }
                    return Ok(self.leaf(TokenKind::HllLineMark, start, line, column));
                }
                self.advance(1);
                while let Some(byte) = self.current() {
                    if byte == b'\n' {
                        break;
                    }
                    self.advance(1);
                }
                Ok(self.leaf(TokenKind::Comment, start, line, column))
            }
            Some(b'"') => {
                let mut len = 1;
                while let Some(byte) = self.peek(len) {
                    if byte == b'"' {
                        len += 1;
                        break;
                    }
                    if byte == b'\n' {
                        return Err(ParseError::at(
                            ParseErrorKind::Invalid {
                                reason: "unterminated string literal".into(),
                            },
                            self.span_at(start, start + len),
                        ));
                    }
                    len += 1;
                }
                if self.peek(len - 1) != Some(b'"') {
                    return Err(ParseError::at(
                        ParseErrorKind::Invalid {
                            reason: "unterminated string literal".into(),
                        },
                        self.span_at(start, self.pos + len),
                    ));
                }
                self.advance(len);
                Ok(self.leaf(TokenKind::Str, start, line, column))
            }
            Some(b'(') => {
                let span = self.span_at(start, start + 1);
                self.advance(1);
                let (inner, _) = self.sequence(Some(Delimiter::Parenthesis))?;
                Ok(TokenTree::Group(Group {
                    delimiter: Delimiter::Parenthesis,
                    tokens: inner,
                    span,
                }))
            }
            Some(b')') => {
                self.advance(1);
                Ok(self.leaf(TokenKind::Punct(')'), start, line, column))
            }
            Some(_) => {
                let mut len = 0;
                while matches!(self.peek(len), Some(byte) if is_cil_symbol(byte)) {
                    len += 1;
                }
                if len == 0 {
                    let byte = self.current().unwrap_or_default();
                    self.advance(1);
                    return Ok(self.leaf(TokenKind::Punct(byte as char), start, line, column));
                }
                self.advance(len);
                Ok(self.leaf(TokenKind::Ident, start, line, column))
            }
            None => Ok(self.leaf(TokenKind::Comment, start, line, column)),
        }
    }
}

fn push_token(stack: &mut [Frame], token: TokenTree) {
    if let Some(frame) = stack.last_mut() {
        frame.tokens.push(token);
    }
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'$')
}

fn is_cil_symbol(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'[' | b']'
                | b'.'
                | b'@'
                | b'='
                | b'/'
                | b'*'
                | b'-'
                | b'_'
                | b'$'
                | b'%'
                | b'+'
                | b'!'
                | b'|'
                | b'&'
                | b'^'
                | b':'
                | b'~'
                | b'`'
                | b'#'
                | b'{'
                | b'}'
                | b'\''
                | b'<'
                | b'>'
                | b'?'
                | b','
        )
}
