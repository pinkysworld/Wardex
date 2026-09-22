//! Compiler for genuine `.yar` YARA source into [`crate::yara_engine`] rules.
//!
//! This implements a well-defined, documented *subset* of the YARA
//! language — see `docs/YARA_COMPATIBILITY.md` for exactly what is and is
//! not supported. Anything outside that subset is a compile error carrying
//! a line/column, never a silently-mismatched rule: Wardex would rather
//! refuse to load a `.yar` file than pretend to enforce a detection it
//! cannot actually evaluate.
//!
//! Pipeline: [`lex`] tokenizes the source (tracking line/column and
//! special-casing hex-string bodies and regex literals, which are not
//! representable with the generic token set), then [`Parser`] performs
//! recursive-descent parsing straight into [`crate::yara_engine`] types
//! (`YaraRule`, `StringPattern`, `BoolExpr`, `NumExpr`, ...).

use crate::yara_engine::{
    BoolExpr, CmpOp, HexToken, NumExpr, OfQuantifier, RuleCondition, RuleMeta, RuleString,
    StringPattern, StringSet, YaraRule,
};

/// YARA modules Wardex recognises well enough to safely ignore. Anything
/// else in an `import` statement is a hard compile error, since we cannot
/// guarantee condition expressions referencing an unknown module's fields
/// would be rejected rather than silently mis-evaluated.
const IGNORED_IMPORTS: &[&str] = &["pe", "elf", "math", "hash", "time", "string"];

/// A `.yar` compile error with source position, so a bad rule file fails
/// loudly instead of loading a mis-parsed detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for CompileError {}

/// The result of compiling a `.yar` source file: the rules it defines, plus
/// any non-fatal warnings (currently: ignored `import` statements).
#[derive(Debug, Clone, Default)]
pub struct CompiledRules {
    pub rules: Vec<YaraRule>,
    pub warnings: Vec<String>,
}

/// Compile `.yar` source into rules for [`crate::yara_engine::YaraEngine`].
pub fn compile(source: &str) -> Result<CompiledRules, CompileError> {
    let tokens = lex(source)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        rule_names: std::collections::HashSet::new(),
        warnings: Vec::new(),
    };
    let rules = parser.parse_source()?;
    Ok(CompiledRules {
        rules,
        warnings: parser.warnings,
    })
}

// ── Lexer ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    /// Raw text between the `{` and `}` of a hex string, unparsed.
    HexBody(String),
    Regex {
        source: String,
        case_insensitive: bool,
        dotall: bool,
    },
    Int(i64),
    StrId(String),   // `$name` or `$name*`
    CountId(String), // `#name`
    AtId(String),    // `@name`
    Colon,
    Semicolon,
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Assign,
    Star,
    Dot,
    DotDot,
    Minus,
    Plus,
    Eq2,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Eof,
}

#[derive(Debug, Clone)]
struct STok {
    tok: Tok,
    line: usize,
    col: usize,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    col: usize,
}

impl Lexer {
    fn new(src: &str) -> Self {
        Self {
            chars: src.chars().collect(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn err(&self, message: impl Into<String>) -> CompileError {
        CompileError {
            message: message.into(),
            line: self.line,
            column: self.col,
        }
    }

    fn skip_trivia(&mut self) -> Result<(), CompileError> {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some('/') if self.peek_at(1) == Some('/') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                Some('/') if self.peek_at(1) == Some('*') => {
                    self.bump();
                    self.bump();
                    loop {
                        match self.peek() {
                            None => return Err(self.err("unterminated block comment")),
                            Some('*') if self.peek_at(1) == Some('/') => {
                                self.bump();
                                self.bump();
                                break;
                            }
                            _ => {
                                self.bump();
                            }
                        }
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    /// Read raw text up to (and consuming) the matching `}` — used for hex
    /// string bodies, which have their own mini-grammar (`??`, nibble
    /// wildcards, `[n-m]` jumps, `(a|b)` alternatives) that does not fit
    /// the general token set.
    fn read_hex_body(&mut self) -> Result<String, CompileError> {
        let mut body = String::new();
        loop {
            match self.bump() {
                None => return Err(self.err("unterminated hex string, expected '}'")),
                Some('}') => break,
                Some(c) => body.push(c),
            }
        }
        Ok(body)
    }

    fn read_string_literal(&mut self) -> Result<String, CompileError> {
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(self.err("unterminated string literal")),
                Some('"') => break,
                Some('\\') => match self.bump() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('x') => {
                        let hi = self.bump().ok_or_else(|| self.err("bad \\x escape"))?;
                        let lo = self.bump().ok_or_else(|| self.err("bad \\x escape"))?;
                        let byte = u8::from_str_radix(&format!("{hi}{lo}"), 16)
                            .map_err(|_| self.err("bad \\x escape"))?;
                        out.push(byte as char);
                    }
                    Some(other) => out.push(other),
                    None => return Err(self.err("unterminated string literal")),
                },
                Some(c) => out.push(c),
            }
        }
        Ok(out)
    }

    fn read_regex_literal(&mut self) -> Result<Tok, CompileError> {
        let mut pattern = String::new();
        loop {
            match self.bump() {
                None => return Err(self.err("unterminated regex literal, expected '/'")),
                Some('\\') => {
                    let next = self
                        .bump()
                        .ok_or_else(|| self.err("unterminated regex escape"))?;
                    pattern.push('\\');
                    pattern.push(next);
                }
                Some('/') => break,
                Some(c) => pattern.push(c),
            }
        }
        let mut case_insensitive = false;
        let mut dotall = false;
        while let Some(c) = self.peek() {
            match c {
                'i' => {
                    case_insensitive = true;
                    self.bump();
                }
                's' => {
                    dotall = true;
                    self.bump();
                }
                _ => break,
            }
        }
        Ok(Tok::Regex {
            source: pattern,
            case_insensitive,
            dotall,
        })
    }

    fn read_ident(&mut self) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' {
                out.push(c);
                self.bump();
            } else {
                break;
            }
        }
        out
    }

    fn read_number(&mut self) -> Result<i64, CompileError> {
        let mut digits = String::new();
        if self.peek() == Some('0') && matches!(self.peek_at(1), Some('x') | Some('X')) {
            self.bump();
            self.bump();
            let mut hex = String::new();
            while let Some(c) = self.peek() {
                if c.is_ascii_hexdigit() {
                    hex.push(c);
                    self.bump();
                } else {
                    break;
                }
            }
            let value = i64::from_str_radix(&hex, 16)
                .map_err(|_| self.err("invalid hex integer literal"))?;
            return Ok(value);
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                digits.push(c);
                self.bump();
            } else {
                break;
            }
        }
        let mut value: i64 = digits
            .parse()
            .map_err(|_| self.err("invalid integer literal"))?;
        // KB/MB size suffixes, case-insensitive.
        if matches!(self.peek(), Some('K') | Some('k'))
            && matches!(self.peek_at(1), Some('B') | Some('b'))
        {
            self.bump();
            self.bump();
            value = value.saturating_mul(1024);
        } else if matches!(self.peek(), Some('M') | Some('m'))
            && matches!(self.peek_at(1), Some('B') | Some('b'))
        {
            self.bump();
            self.bump();
            value = value.saturating_mul(1024 * 1024);
        }
        Ok(value)
    }
}

fn lex(source: &str) -> Result<Vec<STok>, CompileError> {
    let mut lexer = Lexer::new(source);
    let mut out = Vec::new();
    let mut prev_was_assign = false;
    loop {
        lexer.skip_trivia()?;
        let (line, col) = (lexer.line, lexer.col);
        let Some(c) = lexer.peek() else {
            out.push(STok {
                tok: Tok::Eof,
                line,
                col,
            });
            break;
        };
        let tok = match c {
            '{' if prev_was_assign => {
                lexer.bump();
                Tok::HexBody(lexer.read_hex_body()?)
            }
            '{' => {
                lexer.bump();
                Tok::LBrace
            }
            '}' => {
                lexer.bump();
                Tok::RBrace
            }
            '(' => {
                lexer.bump();
                Tok::LParen
            }
            ')' => {
                lexer.bump();
                Tok::RParen
            }
            '[' => {
                lexer.bump();
                Tok::LBracket
            }
            ']' => {
                lexer.bump();
                Tok::RBracket
            }
            ':' => {
                lexer.bump();
                Tok::Colon
            }
            ';' => {
                lexer.bump();
                Tok::Semicolon
            }
            ',' => {
                lexer.bump();
                Tok::Comma
            }
            '*' => {
                lexer.bump();
                Tok::Star
            }
            '+' => {
                lexer.bump();
                Tok::Plus
            }
            '-' => {
                lexer.bump();
                Tok::Minus
            }
            '.' => {
                lexer.bump();
                if lexer.peek() == Some('.') {
                    lexer.bump();
                    Tok::DotDot
                } else {
                    Tok::Dot
                }
            }
            '=' => {
                lexer.bump();
                if lexer.peek() == Some('=') {
                    lexer.bump();
                    Tok::Eq2
                } else {
                    Tok::Assign
                }
            }
            '!' if lexer.peek_at(1) == Some('=') => {
                lexer.bump();
                lexer.bump();
                Tok::Ne
            }
            '<' => {
                lexer.bump();
                if lexer.peek() == Some('=') {
                    lexer.bump();
                    Tok::Le
                } else {
                    Tok::Lt
                }
            }
            '>' => {
                lexer.bump();
                if lexer.peek() == Some('=') {
                    lexer.bump();
                    Tok::Ge
                } else {
                    Tok::Gt
                }
            }
            '"' => {
                lexer.bump();
                Tok::Str(lexer.read_string_literal()?)
            }
            '/' => {
                lexer.bump();
                lexer.read_regex_literal()?
            }
            '$' => {
                lexer.bump();
                let name = lexer.read_ident();
                if name.is_empty() {
                    return Err(lexer.err("expected string identifier after '$'"));
                }
                let wildcard = lexer.peek() == Some('*');
                if wildcard {
                    lexer.bump();
                }
                Tok::StrId(if wildcard { format!("{name}*") } else { name })
            }
            '#' => {
                lexer.bump();
                let name = lexer.read_ident();
                if name.is_empty() {
                    return Err(lexer.err("expected string identifier after '#'"));
                }
                Tok::CountId(name)
            }
            '@' => {
                lexer.bump();
                let name = lexer.read_ident();
                if name.is_empty() {
                    return Err(lexer.err("expected string identifier after '@'"));
                }
                Tok::AtId(name)
            }
            c if c.is_ascii_digit() => Tok::Int(lexer.read_number()?),
            c if c.is_alphabetic() || c == '_' => Tok::Ident(lexer.read_ident()),
            other => return Err(lexer.err(format!("unexpected character '{other}'"))),
        };
        prev_was_assign = matches!(tok, Tok::Assign);
        out.push(STok { tok, line, col });
    }
    Ok(out)
}

// ── Parser ─────────────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<STok>,
    pos: usize,
    rule_names: std::collections::HashSet<String>,
    warnings: Vec<String>,
}

impl Parser {
    fn cur(&self) -> &Tok {
        &self.tokens[self.pos.min(self.tokens.len() - 1)].tok
    }

    fn pos_info(&self) -> (usize, usize) {
        let t = &self.tokens[self.pos.min(self.tokens.len() - 1)];
        (t.line, t.col)
    }

    fn err(&self, message: impl Into<String>) -> CompileError {
        let (line, column) = self.pos_info();
        CompileError {
            message: message.into(),
            line,
            column,
        }
    }

    fn advance(&mut self) -> Tok {
        let t = self.tokens[self.pos.min(self.tokens.len() - 1)].tok.clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, expected: &Tok) -> Result<(), CompileError> {
        if self.cur() == expected {
            self.advance();
            Ok(())
        } else {
            Err(self.err(format!("expected {expected:?}, found {:?}", self.cur())))
        }
    }

    fn ident_is(&self, name: &str) -> bool {
        matches!(self.cur(), Tok::Ident(id) if id == name)
    }

    fn eat_ident(&mut self, name: &str) -> Result<(), CompileError> {
        if self.ident_is(name) {
            self.advance();
            Ok(())
        } else {
            Err(self.err(format!("expected '{name}', found {:?}", self.cur())))
        }
    }

    fn take_ident(&mut self) -> Result<String, CompileError> {
        match self.advance() {
            Tok::Ident(id) => Ok(id),
            other => Err(CompileError {
                message: format!("expected identifier, found {other:?}"),
                line: self.tokens[self.pos.saturating_sub(1)].line,
                column: self.tokens[self.pos.saturating_sub(1)].col,
            }),
        }
    }

    // ── Top level ────────────────────────────────────────────────────

    fn parse_source(&mut self) -> Result<Vec<YaraRule>, CompileError> {
        let mut rules = Vec::new();
        loop {
            match self.cur().clone() {
                Tok::Eof => break,
                Tok::Ident(id) if id == "import" => {
                    self.advance();
                    let module = match self.advance() {
                        Tok::Str(s) => s,
                        other => {
                            return Err(self.err(format!(
                                "expected a quoted module name after 'import', found {other:?}"
                            )));
                        }
                    };
                    if matches!(self.cur(), Tok::Semicolon) {
                        self.advance();
                    }
                    if IGNORED_IMPORTS.contains(&module.as_str()) {
                        self.warnings.push(format!(
                            "import \"{module}\" is not evaluated (no module fields are \
                             implemented); rules relying on {module}.* condition fields will not \
                             behave as in real YARA"
                        ));
                    } else {
                        return Err(self.err(format!(
                            "unsupported import module \"{module}\" — only {IGNORED_IMPORTS:?} \
                             are recognised (and ignored)"
                        )));
                    }
                }
                Tok::Ident(id) if id == "private" || id == "global" || id == "rule" => {
                    rules.push(self.parse_rule()?);
                }
                other => {
                    return Err(self.err(format!(
                        "expected 'import' or 'rule' at top level, found {other:?}"
                    )));
                }
            }
        }
        Ok(rules)
    }

    fn parse_rule(&mut self) -> Result<YaraRule, CompileError> {
        let mut is_private = false;
        let mut is_global = false;
        loop {
            if self.ident_is("private") {
                is_private = true;
                self.advance();
            } else if self.ident_is("global") {
                is_global = true;
                self.advance();
            } else {
                break;
            }
        }
        self.eat_ident("rule")?;
        let name = self.take_ident()?;
        if !self.rule_names.insert(name.clone()) {
            return Err(self.err(format!("duplicate rule name '{name}'")));
        }

        let mut tags = Vec::new();
        if matches!(self.cur(), Tok::Colon) {
            self.advance();
            while let Tok::Ident(tag) = self.cur().clone() {
                tags.push(tag);
                self.advance();
            }
        }

        self.eat(&Tok::LBrace)?;

        let mut meta = RuleMeta::default();
        let mut strings: Vec<RuleString> = Vec::new();
        let mut condition: Option<BoolExpr> = None;

        loop {
            if matches!(self.cur(), Tok::RBrace) {
                break;
            }
            if self.ident_is("meta") {
                self.advance();
                self.eat(&Tok::Colon)?;
                self.parse_meta(&mut meta)?;
            } else if self.ident_is("strings") {
                self.advance();
                self.eat(&Tok::Colon)?;
                self.parse_strings(&mut strings)?;
            } else if self.ident_is("condition") {
                self.advance();
                self.eat(&Tok::Colon)?;
                condition = Some(self.parse_bool_expr()?);
            } else {
                return Err(self.err(format!(
                    "expected 'meta:', 'strings:', 'condition:' or '}}', found {:?}",
                    self.cur()
                )));
            }
        }
        self.eat(&Tok::RBrace)?;

        let condition =
            condition.ok_or_else(|| self.err(format!("rule '{name}' has no condition: block")))?;
        validate_condition_refs(&condition, &strings, &self.rule_names, &name)
            .map_err(|message| self.err(message))?;

        Ok(YaraRule {
            name,
            meta,
            strings,
            condition: RuleCondition::Expr(condition),
            enabled: true,
            tags,
            is_private,
            is_global,
        })
    }

    fn parse_meta(&mut self, meta: &mut RuleMeta) -> Result<(), CompileError> {
        loop {
            let key = match self.cur().clone() {
                Tok::Ident(id) if id != "strings" && id != "condition" => id,
                _ => break,
            };
            // A bare `strings`/`condition` identifier ends the meta block;
            // any other identifier is a meta key.
            self.advance();
            self.eat(&Tok::Assign)?;
            let value = match self.advance() {
                Tok::Str(s) => serde_json::Value::String(s),
                Tok::Int(n) => serde_json::Value::Number(n.into()),
                Tok::Ident(id) if id == "true" => serde_json::Value::Bool(true),
                Tok::Ident(id) if id == "false" => serde_json::Value::Bool(false),
                Tok::Minus => match self.advance() {
                    Tok::Int(n) => serde_json::Value::Number((-n).into()),
                    other => {
                        return Err(self.err(format!("expected number after '-', found {other:?}")));
                    }
                },
                other => {
                    return Err(self.err(format!("invalid meta value for '{key}': {other:?}")));
                }
            };
            match key.as_str() {
                "author" => meta.author = value.as_str().unwrap_or_default().to_string(),
                "description" => meta.description = value.as_str().unwrap_or_default().to_string(),
                "severity" => meta.severity = value.as_str().unwrap_or_default().to_string(),
                "created" | "date" => meta.created = value.as_str().unwrap_or_default().to_string(),
                "mitre_ids" | "att&ck_id" | "attack_id" => {
                    if let Some(s) = value.as_str() {
                        meta.mitre_ids = s
                            .split(',')
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                            .map(str::to_string)
                            .collect();
                    }
                }
                _ => {
                    meta.extra.insert(key, value);
                }
            }
        }
        Ok(())
    }

    fn parse_strings(&mut self, strings: &mut Vec<RuleString>) -> Result<(), CompileError> {
        while let Tok::StrId(id) = self.cur().clone() {
            self.advance();
            self.eat(&Tok::Assign)?;
            let mut rs = RuleString {
                id: format!("${id}"),
                ..RuleString::default()
            };
            match self.advance() {
                Tok::Str(text) => {
                    rs.pattern = StringPattern::Text(text);
                    let mut explicit_ascii = false;
                    loop {
                        if self.ident_is("nocase") {
                            rs.nocase = true;
                            self.advance();
                        } else if self.ident_is("wide") {
                            rs.wide = true;
                            self.advance();
                        } else if self.ident_is("ascii") {
                            rs.ascii = true;
                            explicit_ascii = true;
                            self.advance();
                        } else if self.ident_is("fullword") {
                            rs.fullword = true;
                            self.advance();
                        } else if self.ident_is("private") {
                            self.advance(); // string-level `private` — parsed, no engine effect
                        } else {
                            break;
                        }
                    }
                    if rs.wide && !explicit_ascii {
                        rs.ascii = false;
                    }
                }
                Tok::HexBody(body) => {
                    rs.pattern = StringPattern::HexTokens(parse_hex_body(&body, self)?);
                }
                Tok::Regex {
                    source,
                    case_insensitive,
                    dotall,
                } => {
                    regex::bytes::RegexBuilder::new(&source)
                        .case_insensitive(case_insensitive)
                        .dot_matches_new_line(dotall)
                        .build()
                        .map_err(|e| self.err(format!("invalid regex /{source}/: {e}")))?;
                    rs.pattern = StringPattern::Regex {
                        source,
                        case_insensitive,
                        dotall,
                    };
                }
                other => {
                    return Err(self.err(format!(
                        "expected a string, hex, or regex pattern for ${id}, found {other:?}"
                    )));
                }
            }
            strings.push(rs);
        }
        Ok(())
    }

    // ── Condition expressions ────────────────────────────────────────
    //
    // Grammar (lowest to highest precedence):
    //   or_expr  := and_expr ('or' and_expr)*
    //   and_expr := not_expr ('and' not_expr)*
    //   not_expr := 'not' not_expr | primary
    //   primary  := '(' or_expr ')' | 'true' | 'false' | of_expr
    //             | numexpr cmp numexpr | strid 'at' numexpr
    //             | strid 'in' '(' numexpr '..' numexpr ')' | strid | ident

    fn parse_bool_expr(&mut self) -> Result<BoolExpr, CompileError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<BoolExpr, CompileError> {
        let mut lhs = self.parse_and()?;
        while self.ident_is("or") {
            self.advance();
            let rhs = self.parse_and()?;
            lhs = BoolExpr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<BoolExpr, CompileError> {
        let mut lhs = self.parse_not()?;
        while self.ident_is("and") {
            self.advance();
            let rhs = self.parse_not()?;
            lhs = BoolExpr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<BoolExpr, CompileError> {
        if self.ident_is("not") {
            self.advance();
            return Ok(BoolExpr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary_bool()
    }

    fn parse_primary_bool(&mut self) -> Result<BoolExpr, CompileError> {
        match self.cur().clone() {
            Tok::LParen => {
                self.advance();
                let inner = self.parse_or()?;
                self.eat(&Tok::RParen)?;
                Ok(inner)
            }
            Tok::Ident(id) if id == "true" => {
                self.advance();
                Ok(BoolExpr::Bool(true))
            }
            Tok::Ident(id) if id == "false" => {
                self.advance();
                Ok(BoolExpr::Bool(false))
            }
            Tok::Ident(id) if id == "all" || id == "any" => {
                self.advance();
                self.eat_ident("of")?;
                let quantifier = if id == "all" {
                    OfQuantifier::All
                } else {
                    OfQuantifier::Any
                };
                let set = self.parse_string_set()?;
                Ok(BoolExpr::OfThem(quantifier, set))
            }
            Tok::StrId(id) => {
                self.advance();
                if self.ident_is("at") {
                    self.advance();
                    let offset = self.parse_num_expr()?;
                    Ok(BoolExpr::StringAt(format!("${id}"), Box::new(offset)))
                } else if self.ident_is("in") {
                    self.advance();
                    self.eat(&Tok::LParen)?;
                    let lo = self.parse_num_expr()?;
                    self.eat(&Tok::DotDot)?;
                    let hi = self.parse_num_expr()?;
                    self.eat(&Tok::RParen)?;
                    Ok(BoolExpr::StringInRange(
                        format!("${id}"),
                        Box::new(lo),
                        Box::new(hi),
                    ))
                } else {
                    Ok(BoolExpr::StringRef(format!("${id}")))
                }
            }
            Tok::Ident(id) if id == "filesize" || is_uint_fn(&id) => self.parse_comparison_or_of(),
            Tok::Ident(id) => {
                // A bare identifier not recognised as a numeric primary is
                // a reference to another rule.
                self.advance();
                Ok(BoolExpr::RuleRef(id))
            }
            Tok::Int(_) | Tok::AtId(_) | Tok::CountId(_) | Tok::Minus => {
                self.parse_comparison_or_of()
            }
            other => Err(self.err(format!("unexpected token in condition: {other:?}"))),
        }
    }

    /// Parses either `N of <set>` (a numeric quantifier) or a numeric
    /// comparison `numexpr cmp numexpr`.
    fn parse_comparison_or_of(&mut self) -> Result<BoolExpr, CompileError> {
        let lhs = self.parse_num_expr()?;
        if self.ident_is("of") {
            self.advance();
            let set = self.parse_string_set()?;
            return Ok(BoolExpr::OfThem(OfQuantifier::Exactly(Box::new(lhs)), set));
        }
        let op = match self.cur() {
            Tok::Eq2 => CmpOp::Eq,
            Tok::Ne => CmpOp::Ne,
            Tok::Lt => CmpOp::Lt,
            Tok::Le => CmpOp::Le,
            Tok::Gt => CmpOp::Gt,
            Tok::Ge => CmpOp::Ge,
            other => {
                return Err(self.err(format!(
                    "expected a comparison operator or 'of', found {other:?}"
                )));
            }
        };
        self.advance();
        let rhs = self.parse_num_expr()?;
        Ok(BoolExpr::Cmp(lhs, op, rhs))
    }

    fn parse_string_set(&mut self) -> Result<StringSet, CompileError> {
        if self.ident_is("them") {
            self.advance();
            return Ok(StringSet::Them);
        }
        self.eat(&Tok::LParen)?;
        let mut ids = Vec::new();
        loop {
            match self.advance() {
                Tok::StrId(id) => ids.push(format!("${id}")),
                other => return Err(self.err(format!("expected a string id, found {other:?}"))),
            }
            if matches!(self.cur(), Tok::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        self.eat(&Tok::RParen)?;
        Ok(StringSet::Ids(ids))
    }

    fn parse_num_expr(&mut self) -> Result<NumExpr, CompileError> {
        let mut lhs = self.parse_num_term()?;
        loop {
            match self.cur() {
                Tok::Plus => {
                    self.advance();
                    let rhs = self.parse_num_term()?;
                    lhs = NumExpr::Add(Box::new(lhs), Box::new(rhs));
                }
                Tok::Minus => {
                    self.advance();
                    let rhs = self.parse_num_term()?;
                    lhs = NumExpr::Sub(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_num_term(&mut self) -> Result<NumExpr, CompileError> {
        match self.advance() {
            Tok::Int(n) => Ok(NumExpr::Int(n)),
            Tok::Minus => {
                let inner = self.parse_num_term()?;
                Ok(NumExpr::Sub(Box::new(NumExpr::Int(0)), Box::new(inner)))
            }
            Tok::CountId(id) => Ok(NumExpr::Count(format!("${id}"))),
            Tok::AtId(id) => {
                self.eat(&Tok::LBracket)?;
                let idx = self.parse_num_expr()?;
                self.eat(&Tok::RBracket)?;
                Ok(NumExpr::OffsetOf(format!("${id}"), Box::new(idx)))
            }
            Tok::Ident(id) if id == "filesize" => Ok(NumExpr::FileSize),
            Tok::Ident(id) if is_uint_fn(&id) => {
                self.eat(&Tok::LParen)?;
                let offset = self.parse_num_expr()?;
                self.eat(&Tok::RParen)?;
                let (width, big_endian) = uint_fn_spec(&id);
                Ok(NumExpr::UintAt {
                    width,
                    big_endian,
                    offset: Box::new(offset),
                })
            }
            Tok::LParen => {
                let inner = self.parse_num_expr()?;
                self.eat(&Tok::RParen)?;
                Ok(inner)
            }
            other => Err(self.err(format!("expected a numeric expression, found {other:?}"))),
        }
    }
}

fn is_uint_fn(id: &str) -> bool {
    matches!(
        id,
        "uint8" | "uint16" | "uint32" | "uint8be" | "uint16be" | "uint32be"
    )
}

fn uint_fn_spec(id: &str) -> (u8, bool) {
    match id {
        "uint8" => (1, false),
        "uint16" => (2, false),
        "uint32" => (4, false),
        "uint8be" => (1, true),
        "uint16be" => (2, true),
        "uint32be" => (4, true),
        _ => (4, false),
    }
}

/// Reject conditions that reference string ids the rule never declares —
/// this is exactly the class of "silently mismatched" mistake the task
/// calls out, so it is caught at compile time rather than always
/// evaluating false at scan time.
fn validate_condition_refs(
    expr: &BoolExpr,
    strings: &[RuleString],
    known_rules: &std::collections::HashSet<String>,
    rule_name: &str,
) -> Result<(), String> {
    let declared: std::collections::HashSet<&str> = strings.iter().map(|s| s.id.as_str()).collect();
    fn check_id(
        id: &str,
        declared: &std::collections::HashSet<&str>,
        rule_name: &str,
    ) -> Result<(), String> {
        if let Some(prefix) = id.strip_suffix('*') {
            if declared.iter().any(|d| d.starts_with(prefix)) {
                Ok(())
            } else {
                Err(format!(
                    "rule '{rule_name}': no declared string matches wildcard '{id}'"
                ))
            }
        } else if declared.contains(id) {
            Ok(())
        } else {
            Err(format!(
                "rule '{rule_name}': condition references undeclared string '{id}'"
            ))
        }
    }
    fn walk_num(
        n: &NumExpr,
        declared: &std::collections::HashSet<&str>,
        rule_name: &str,
    ) -> Result<(), String> {
        match n {
            NumExpr::Int(_) | NumExpr::FileSize => Ok(()),
            NumExpr::Count(id) => check_id(id, declared, rule_name),
            NumExpr::OffsetOf(id, idx) => {
                check_id(id, declared, rule_name)?;
                walk_num(idx, declared, rule_name)
            }
            NumExpr::UintAt { offset, .. } => walk_num(offset, declared, rule_name),
            NumExpr::Add(a, b) | NumExpr::Sub(a, b) => {
                walk_num(a, declared, rule_name)?;
                walk_num(b, declared, rule_name)
            }
        }
    }
    fn walk(
        expr: &BoolExpr,
        declared: &std::collections::HashSet<&str>,
        known_rules: &std::collections::HashSet<String>,
        rule_name: &str,
    ) -> Result<(), String> {
        match expr {
            BoolExpr::Bool(_) => Ok(()),
            BoolExpr::RuleRef(referenced) => {
                if known_rules.contains(referenced) {
                    Ok(())
                } else {
                    Err(format!(
                        "rule '{rule_name}': condition references unknown rule '{referenced}' \
                         (it must be defined earlier in the same file)"
                    ))
                }
            }
            BoolExpr::StringRef(id) => check_id(id, declared, rule_name),
            BoolExpr::Not(inner) => walk(inner, declared, known_rules, rule_name),
            BoolExpr::And(a, b) | BoolExpr::Or(a, b) => {
                walk(a, declared, known_rules, rule_name)?;
                walk(b, declared, known_rules, rule_name)
            }
            BoolExpr::Cmp(l, _, r) => {
                walk_num(l, declared, rule_name)?;
                walk_num(r, declared, rule_name)
            }
            BoolExpr::StringAt(id, off) => {
                check_id(id, declared, rule_name)?;
                walk_num(off, declared, rule_name)
            }
            BoolExpr::StringInRange(id, lo, hi) => {
                check_id(id, declared, rule_name)?;
                walk_num(lo, declared, rule_name)?;
                walk_num(hi, declared, rule_name)
            }
            BoolExpr::OfThem(quantifier, set) => {
                if let OfQuantifier::Exactly(n) = quantifier {
                    walk_num(n, declared, rule_name)?;
                }
                match set {
                    StringSet::Them => Ok(()),
                    StringSet::Ids(ids) => {
                        for id in ids {
                            check_id(id, declared, rule_name)?;
                        }
                        Ok(())
                    }
                }
            }
        }
    }
    walk(expr, &declared, known_rules, rule_name)
}

// ── Hex string body parsing ─────────────────────────────────────────────

/// Parse the raw text between `{` and `}` of a hex string into
/// [`HexToken`]s: byte pairs, `??` wildcards, nibble wildcards (`A?`/`?A`),
/// `[n]`/`[n-m]`/`[n-]` jumps, and `( .. | .. )` alternatives (which may
/// themselves contain any of the above, recursively).
/// Hex bodies longer than this are rejected at compile time. This is a
/// generous limit for real signatures, and it bounds the worst-case cost of
/// the backtracking hex-token matcher (jumps and alternatives can combine
/// combinatorially in a pathological, e.g. fuzzer-generated, hex string).
const MAX_HEX_BODY_LEN: usize = 2048;

fn parse_hex_body(body: &str, parser: &Parser) -> Result<Vec<HexToken>, CompileError> {
    if body.len() > MAX_HEX_BODY_LEN {
        return Err(parser.err(format!(
            "hex string exceeds the {MAX_HEX_BODY_LEN}-character limit"
        )));
    }
    let chars: Vec<char> = body.chars().collect();
    let mut pos = 0usize;
    let tokens = parse_hex_tokens(&chars, &mut pos, parser)?;
    skip_hex_ws(&chars, &mut pos);
    if pos != chars.len() {
        return Err(parser.err(format!(
            "unexpected character in hex string near position {pos}"
        )));
    }
    if tokens.is_empty() {
        return Err(parser.err("hex string must not be empty"));
    }
    Ok(tokens)
}

fn skip_hex_ws(chars: &[char], pos: &mut usize) {
    while chars.get(*pos).is_some_and(|c| c.is_whitespace()) {
        *pos += 1;
    }
}

fn parse_hex_tokens(
    chars: &[char],
    pos: &mut usize,
    parser: &Parser,
) -> Result<Vec<HexToken>, CompileError> {
    let mut tokens = Vec::new();
    loop {
        skip_hex_ws(chars, pos);
        match chars.get(*pos) {
            None | Some(')') | Some('|') => break,
            Some('[') => {
                *pos += 1;
                let (min, max) = parse_hex_jump(chars, pos, parser)?;
                tokens.push(HexToken::Jump(min, max));
            }
            Some('(') => {
                *pos += 1;
                let mut branches = vec![parse_hex_tokens(chars, pos, parser)?];
                loop {
                    skip_hex_ws(chars, pos);
                    match chars.get(*pos) {
                        Some('|') => {
                            *pos += 1;
                            branches.push(parse_hex_tokens(chars, pos, parser)?);
                        }
                        Some(')') => {
                            *pos += 1;
                            break;
                        }
                        _ => return Err(parser.err("expected '|' or ')' in hex alternative")),
                    }
                }
                tokens.push(HexToken::Alternative(branches));
            }
            Some(c) if c.is_ascii_hexdigit() || *c == '?' => {
                let hi = chars[*pos];
                *pos += 1;
                let lo = *chars
                    .get(*pos)
                    .ok_or_else(|| parser.err("hex string byte is missing its second nibble"))?;
                if !(lo.is_ascii_hexdigit() || lo == '?') {
                    return Err(parser.err(format!("invalid hex string nibble '{lo}'")));
                }
                *pos += 1;
                tokens.push(match (hi, lo) {
                    ('?', '?') => HexToken::Wildcard,
                    ('?', lo) => HexToken::LowNibble(lo.to_digit(16).unwrap_or(0) as u8),
                    (hi, '?') => HexToken::HighNibble(hi.to_digit(16).unwrap_or(0) as u8),
                    (hi, lo) => {
                        let byte = (hi.to_digit(16).unwrap_or(0) as u8) << 4
                            | lo.to_digit(16).unwrap_or(0) as u8;
                        HexToken::Byte(byte)
                    }
                });
            }
            Some(other) => {
                return Err(parser.err(format!("unexpected character '{other}' in hex string")));
            }
        }
    }
    Ok(tokens)
}

fn parse_hex_jump(
    chars: &[char],
    pos: &mut usize,
    parser: &Parser,
) -> Result<(usize, Option<usize>), CompileError> {
    skip_hex_ws(chars, pos);
    let min = read_hex_int(chars, pos).unwrap_or(0);
    skip_hex_ws(chars, pos);
    let result = if chars.get(*pos) == Some(&'-') {
        *pos += 1;
        skip_hex_ws(chars, pos);
        if chars.get(*pos) == Some(&']') {
            (min, None)
        } else {
            let max = read_hex_int(chars, pos)
                .ok_or_else(|| parser.err("expected a number after '-' in hex jump"))?;
            (min, Some(max))
        }
    } else {
        (min, Some(min))
    };
    skip_hex_ws(chars, pos);
    if chars.get(*pos) != Some(&']') {
        return Err(parser.err("expected ']' to close hex jump"));
    }
    *pos += 1;
    Ok(result)
}

fn read_hex_int(chars: &[char], pos: &mut usize) -> Option<usize> {
    let start = *pos;
    while chars.get(*pos).is_some_and(char::is_ascii_digit) {
        *pos += 1;
    }
    if *pos == start {
        return None;
    }
    chars[start..*pos].iter().collect::<String>().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yara_engine::YaraEngine;

    fn compile_ok(src: &str) -> CompiledRules {
        compile(src).unwrap_or_else(|e| panic!("compile error: {e}"))
    }

    #[test]
    fn parses_minimal_text_rule() {
        let rules = compile_ok(
            r#"
            rule hello {
                strings:
                    $a = "hello"
                condition:
                    $a
            }
            "#,
        );
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.rules[0].name, "hello");
    }

    #[test]
    fn matches_text_condition_against_buffer() {
        let rules = compile_ok(
            r#"
            rule hello {
                strings:
                    $a = "hello" nocase
                condition:
                    $a
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        let report = engine.scan(b"say HELLO world");
        assert!(report.results[0].matched);
        let report = engine.scan(b"say goodbye");
        assert!(!report.results[0].matched);
    }

    #[test]
    fn wide_and_fullword_modifiers() {
        let rules = compile_ok(
            r#"
            rule wide_test {
                strings:
                    $a = "cmd" wide fullword
                condition:
                    $a
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        let mut data = vec![0u8; 2];
        data.extend("cmd".encode_utf16().flat_map(u16::to_le_bytes));
        data.extend(vec![0u8; 2]);
        assert!(engine.scan(&data).results[0].matched);

        // No wide encoding present at all → no match.
        assert!(!engine.scan(b"xcmd").results[0].matched);
    }

    #[test]
    fn hex_string_with_wildcard_and_jump() {
        let rules = compile_ok(
            r"
            rule hex_test {
                strings:
                    $a = { 4D 5A ?? ?? [2-4] 90 }
                condition:
                    $a
            }
            ",
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        let data = vec![0x4D, 0x5A, 0x01, 0x02, 0x00, 0x00, 0x00, 0x90];
        assert!(engine.scan(&data).results[0].matched);
        // Only 0 bytes between the wildcards and 0x90 — below the [2-4] minimum.
        let too_short = vec![0x4D, 0x5A, 0x01, 0x02, 0x90];
        assert!(!engine.scan(&too_short).results[0].matched);
    }

    #[test]
    fn hex_jump_lower_bound_enforced() {
        let rules = compile_ok(
            r"
            rule hex_jump {
                strings:
                    $a = { AA [2-4] BB }
                condition:
                    $a
            }
            ",
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        // Only 1 byte between AA and BB — below the minimum jump of 2.
        assert!(!engine.scan(&[0xAA, 0x00, 0xBB]).results[0].matched);
        // 2 bytes between — satisfies [2-4].
        assert!(engine.scan(&[0xAA, 0x00, 0x00, 0xBB]).results[0].matched);
    }

    #[test]
    fn hex_alternative() {
        let rules = compile_ok(
            r"
            rule hex_alt2 {
                strings:
                    $a = { ( AA BB | CC DD ) }
                condition:
                    $a
            }
            ",
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(engine.scan(&[0xAA, 0xBB]).results[0].matched);
        assert!(engine.scan(&[0xCC, 0xDD]).results[0].matched);
        assert!(!engine.scan(&[0x11, 0x22]).results[0].matched);
    }

    #[test]
    fn regex_string_with_case_insensitive_flag() {
        let rules = compile_ok(
            r"
            rule regex_test {
                strings:
                    $a = /ev[ai]l\(/i
                condition:
                    $a
            }
            ",
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(engine.scan(b"EVAL(").results[0].matched);
        assert!(engine.scan(b"evil(").results[0].matched);
        assert!(!engine.scan(b"eval[").results[0].matched);
    }

    #[test]
    fn count_and_comparison_condition() {
        let rules = compile_ok(
            r#"
            rule count_test {
                strings:
                    $a = "x"
                condition:
                    #a >= 3
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(!engine.scan(b"xx").results[0].matched);
        assert!(engine.scan(b"xxx").results[0].matched);
    }

    #[test]
    fn string_at_and_in_range() {
        let rules = compile_ok(
            r#"
            rule at_test {
                strings:
                    $a = "MZ"
                condition:
                    $a at 0
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(engine.scan(b"MZ....").results[0].matched);
        assert!(!engine.scan(b"...MZ.").results[0].matched);

        let rules = compile_ok(
            r#"
            rule in_range_test {
                strings:
                    $a = "MZ"
                condition:
                    $a in (2..5)
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(engine.scan(b"..MZ..").results[0].matched);
        assert!(!engine.scan(b"MZ....").results[0].matched);
    }

    #[test]
    fn filesize_condition_with_kb_suffix() {
        let rules = compile_ok(
            r#"
            rule small_file {
                strings:
                    $a = "x"
                condition:
                    $a and filesize < 1KB
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(engine.scan(b"x").results[0].matched);
        let big = vec![b'x'; 2048];
        assert!(!engine.scan(&big).results[0].matched);
    }

    #[test]
    fn all_any_and_n_of_them() {
        let rules = compile_ok(
            r#"
            rule of_test {
                strings:
                    $a = "aaa"
                    $b = "bbb"
                    $c = "ccc"
                condition:
                    2 of them
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(!engine.scan(b"aaa").results[0].matched);
        assert!(engine.scan(b"aaa bbb").results[0].matched);
        assert!(engine.scan(b"aaa bbb ccc").results[0].matched);
    }

    #[test]
    fn n_of_wildcard_set() {
        let rules = compile_ok(
            r#"
            rule of_wild {
                strings:
                    $mz1 = "aaa"
                    $mz2 = "bbb"
                    $other = "zzz"
                condition:
                    1 of ($mz*)
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(engine.scan(b"aaa").results[0].matched);
        assert!(!engine.scan(b"zzz").results[0].matched);
    }

    #[test]
    fn uint_offset_reads() {
        let rules = compile_ok(
            r#"
            rule mz_header {
                strings:
                    $dummy = "unused_marker_string"
                condition:
                    uint16(0) == 0x5A4D
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(engine.scan(&[0x4D, 0x5A, 0, 0]).results[0].matched);
        assert!(!engine.scan(&[0x00, 0x00]).results[0].matched);
    }

    #[test]
    fn rule_reference_between_rules() {
        let rules = compile_ok(
            r#"
            private rule base {
                strings:
                    $a = "marker"
                condition:
                    $a
            }
            rule derived {
                condition:
                    base
            }
            "#,
        );
        let mut engine = YaraEngine::new();
        for r in rules.rules {
            engine.add_rule(r);
        }
        let report = engine.scan(b"has marker inside");
        // `base` is private and excluded from the report; `derived` should
        // still see it matched.
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].rule_name, "derived");
        assert!(report.results[0].matched);
    }

    #[test]
    fn tags_and_and_or_not_parentheses() {
        let rules = compile_ok(
            r#"
            rule tagged : malware suspicious {
                strings:
                    $a = "aaa"
                    $b = "bbb"
                condition:
                    not (not $a and not $b)
            }
            "#,
        );
        assert_eq!(rules.rules[0].tags, vec!["malware", "suspicious"]);
        let mut engine = YaraEngine::new();
        engine.add_rule(rules.rules.into_iter().next().unwrap());
        assert!(engine.scan(b"aaa").results[0].matched);
        assert!(!engine.scan(b"neither").results[0].matched);
    }

    #[test]
    fn ignored_import_produces_warning_not_error() {
        let rules = compile_ok(
            r#"
            import "pe"
            rule ok {
                strings:
                    $a = "x"
                condition:
                    $a
            }
            "#,
        );
        assert_eq!(rules.rules.len(), 1);
        assert!(!rules.warnings.is_empty());
    }

    #[test]
    fn unsupported_import_is_a_compile_error() {
        let err = compile(
            r#"
            import "totally_unsupported_module"
            rule ok {
                strings:
                    $a = "x"
                condition:
                    $a
            }
            "#,
        )
        .unwrap_err();
        assert!(err.message.contains("unsupported import"));
    }

    #[test]
    fn undeclared_string_reference_is_a_compile_error() {
        let err = compile(
            r#"
            rule bad {
                strings:
                    $a = "x"
                condition:
                    $b
            }
            "#,
        )
        .unwrap_err();
        assert!(err.message.contains("undeclared string"));
    }

    #[test]
    fn malformed_hex_string_reports_line_and_column() {
        let err = compile(
            r"
            rule bad_hex {
                strings:
                    $a = { 4D 5 }
                condition:
                    $a
            }
            ",
        )
        .unwrap_err();
        assert!(err.line > 0 && err.column > 0);
    }

    #[test]
    fn missing_condition_block_is_an_error() {
        let err = compile(
            r#"
            rule no_condition {
                strings:
                    $a = "x"
            }
            "#,
        )
        .unwrap_err();
        assert!(err.message.contains("no condition"));
    }

    #[test]
    fn bundled_example_yar_file_compiles_and_loads() {
        let source = include_str!("../rules/yara/wardex_examples.yar");
        let compiled = compile_ok(source);
        assert_eq!(compiled.rules.len(), 4);
        let mut engine = YaraEngine::new();
        for rule in compiled.rules {
            engine.add_rule(rule);
        }
        // Private helper rule is evaluated but excluded from the report.
        assert_eq!(engine.rule_count(), 4);
        let report = engine.scan(b"dummy");
        assert_eq!(report.results.len(), 3);
    }

    #[test]
    fn json_rules_still_load_after_yar_support_was_added() {
        let mut engine = YaraEngine::new();
        let json = serde_json::to_string(&crate::yara_engine::builtin_rules()).unwrap();
        let count = engine.load_rules_json(&json).unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn two_realistic_small_rules_compile_and_match() {
        // Loosely styled after common open-source community rule patterns
        // (author's own text, not vendored from any ruleset).
        let src = r#"
            rule Suspicious_Base64_PowerShell : downloader
            {
                meta:
                    author = "wardex-tests"
                    description = "Base64-encoded PowerShell download cradle"
                    severity = "High"
                strings:
                    $ps = "powershell" nocase
                    $enc = "-EncodedCommand" nocase
                    $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
                condition:
                    $ps and $enc and $b64
            }

            rule Tiny_ELF_UPX : packer
            {
                strings:
                    $elf = { 7F 45 4C 46 }
                    $upx = "UPX!"
                condition:
                    $elf at 0 and $upx
            }
        "#;
        let compiled = compile_ok(src);
        assert_eq!(compiled.rules.len(), 2);
        let mut engine = YaraEngine::new();
        for r in compiled.rules {
            engine.add_rule(r);
        }
        let ps_sample =
            b"powershell.exe -EncodedCommand aGVsbG8gd29ybGQhaGVsbG8gd29ybGQhaGVsbG8gd29ybGQh==";
        let report = engine.scan(ps_sample);
        assert!(
            report
                .results
                .iter()
                .any(|r| r.rule_name == "Suspicious_Base64_PowerShell" && r.matched)
        );

        let mut elf = vec![0x7F, 0x45, 0x4C, 0x46];
        elf.extend_from_slice(b"...UPX!...");
        let report = engine.scan(&elf);
        assert!(
            report
                .results
                .iter()
                .any(|r| r.rule_name == "Tiny_ELF_UPX" && r.matched)
        );
    }
}
