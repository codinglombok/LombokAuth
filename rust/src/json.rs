//! Minimal JSON value, parser and serializer whose text output is identical to
//! ECMAScript `JSON.stringify` (number formatting, string escaping and the
//! array-index-first key order of ECMAScript objects).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Maximum nesting accepted by [`parse_json`].
pub const MAX_JSON_DEPTH: usize = 512;

/// Dynamic JSON value. Objects keep insertion order; duplicate keys keep the
/// position of the first occurrence and the value of the last (as `JSON.parse`).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    /// Value under key `k` of an object.
    pub fn get(&self, k: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.iter().find(|(kk, _)| kk == k).map(|(_, v)| v),
            _ => None,
        }
    }
    /// String content, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    /// Number, if this is a number.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            _ => None,
        }
    }
    /// Boolean, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    /// Array items, if this is an array.
    pub fn as_arr(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    /// Object entries, if this is an object.
    pub fn as_obj(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Obj(m) => Some(m),
            _ => None,
        }
    }
    /// Insert or replace `k` (replacing keeps the original position).
    pub fn set(&mut self, k: &str, v: Value) {
        if let Value::Obj(m) = self {
            if let Some(e) = m.iter_mut().find(|(kk, _)| kk == k) {
                e.1 = v;
            } else {
                m.push((k.to_string(), v));
            }
        }
    }
    /// Compact JSON text, identical to `JSON.stringify(value)`.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        self.write_json(&mut s);
        s
    }
    fn write_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Num(n) => out.push_str(&js_number(*n)),
            Value::Str(s) => write_json_str(s, out),
            Value::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_json(out);
                }
                out.push(']');
            }
            Value::Obj(_) => {
                out.push('{');
                for (i, (k, v)) in self.js_entries().into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_str(k, out);
                    out.push(':');
                    v.write_json(out);
                }
                out.push('}');
            }
        }
    }
    /// Object entries in ECMAScript property order: array-index keys ascending, then the
    /// remaining keys in insertion order.
    pub fn js_entries(&self) -> Vec<(&String, &Value)> {
        let m = match self {
            Value::Obj(m) => m,
            _ => return Vec::new(),
        };
        let mut idx: Vec<(u64, &String, &Value)> = Vec::new();
        let mut rest: Vec<(&String, &Value)> = Vec::new();
        for (k, v) in m {
            match array_index(k) {
                Some(n) => idx.push((n, k, v)),
                None => rest.push((k, v)),
            }
        }
        idx.sort_by_key(|e| e.0);
        let mut all: Vec<(&String, &Value)> = idx.into_iter().map(|(_, k, v)| (k, v)).collect();
        all.extend(rest);
        all
    }
}

fn array_index(k: &str) -> Option<u64> {
    if k.is_empty() || k.len() > 10 || !k.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if k.len() > 1 && k.starts_with('0') {
        return None;
    }
    let n: u64 = k.parse().ok()?;
    if n < 4294967295 {
        Some(n)
    } else {
        None
    }
}

/// `JSON.stringify` for one string.
pub fn write_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript `Number.prototype.toString()` for finite numbers; `null` for NaN and infinities
/// (as `JSON.stringify`).
pub fn js_number(n: f64) -> String {
    if !n.is_finite() {
        return "null".to_string();
    }
    if n == 0.0 {
        return "0".to_string();
    }
    // `{:e}` yields the shortest round-trip digits, e.g. "-1.2345e-7".
    let e = format!("{:e}", n);
    let (mant, exp) = match e.split_once('e') {
        Some(p) => p,
        None => return e,
    };
    let neg = mant.starts_with('-');
    let mant = mant.trim_start_matches('-');
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i64;
    let n10: i64 = exp.parse::<i64>().unwrap_or(0) + 1;
    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if k <= n10 && n10 <= 21 {
        s.push_str(&digits);
        for _ in 0..(n10 - k) {
            s.push('0');
        }
    } else if 0 < n10 && n10 <= 21 {
        s.push_str(&digits[..n10 as usize]);
        s.push('.');
        s.push_str(&digits[n10 as usize..]);
    } else if -6 < n10 && n10 <= 0 {
        s.push_str("0.");
        for _ in 0..(-n10) {
            s.push('0');
        }
        s.push_str(&digits);
    } else {
        s.push_str(&digits[..1]);
        if k > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        s.push('e');
        let ee = n10 - 1;
        s.push(if ee >= 0 { '+' } else { '-' });
        s.push_str(&format!("{}", ee.abs()));
    }
    s
}

/// JSON syntax error (byte offset and reason).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub offset: usize,
    pub reason: &'static str,
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

/// Parse RFC 8259 JSON text (nesting limit [`MAX_JSON_DEPTH`]).
pub fn parse_json(s: &str) -> Result<Value, JsonError> {
    let mut p = Parser {
        b: s.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return p.err("trailing characters");
    }
    Ok(v)
}

impl Parser<'_> {
    fn err<T>(&self, reason: &'static str) -> Result<T, JsonError> {
        Err(JsonError {
            offset: self.i,
            reason,
        })
    }
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn lit(&mut self, word: &str, v: Value) -> Result<Value, JsonError> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            self.err("invalid literal")
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_JSON_DEPTH {
            return self.err("nesting too deep");
        }
        match self.peek() {
            None => self.err("unexpected end"),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Value::Arr(a));
                }
                loop {
                    self.ws();
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Arr(a));
                        }
                        _ => return self.err("expected , or ]"),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut m: Vec<(String, Value)> = Vec::new();
                // key -> position, so duplicate handling stays O(log n) per key
                let mut index: BTreeMap<String, usize> = BTreeMap::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Value::Obj(m));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return self.err("expected string key");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.peek() != Some(b':') {
                        return self.err("expected :");
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    match index.get(&k) {
                        Some(&pos) => m[pos].1 = v,
                        None => {
                            index.insert(k.clone(), m.len());
                            m.push((k, v));
                        }
                    }
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Obj(m));
                        }
                        _ => return self.err("expected , or }"),
                    }
                }
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => self.err("unexpected character"),
        }
    }
    fn digits(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
    }
    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => self.digits(),
            _ => return self.err("invalid number"),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return self.err("invalid number");
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return self.err("invalid number");
            }
            self.digits();
        }
        let text = core::str::from_utf8(&self.b[start..self.i]).unwrap_or("0");
        match text.parse::<f64>() {
            Ok(n) => Ok(Value::Num(n)),
            Err(_) => self.err("invalid number"),
        }
    }
    fn hex4(&mut self) -> Result<u32, JsonError> {
        if self.i + 4 > self.b.len() {
            return self.err("bad \\u escape");
        }
        let mut n = 0u32;
        for k in 0..4 {
            let c = self.b[self.i + k];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return self.err("bad \\u escape"),
            };
            n = n * 16 + d as u32;
        }
        self.i += 4;
        Ok(n)
    }
    fn string(&mut self) -> Result<String, JsonError> {
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = match self.peek() {
                None => return self.err("unterminated string"),
                Some(c) => c,
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = match self.peek() {
                        None => return self.err("unterminated escape"),
                        Some(e) => e,
                    };
                    self.i += 1;
                    let ch: char = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if !self.b[self.i..].starts_with(b"\\u") {
                                    return self.err("lone surrogate");
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return self.err("invalid surrogate pair");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return self.err("lone surrogate");
                            } else {
                                hi
                            };
                            match char::from_u32(cp) {
                                Some(c) => c,
                                None => return self.err("invalid code point"),
                            }
                        }
                        _ => return self.err("invalid escape"),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c if c < 0x20 => return self.err("control character in string"),
                c => out.push(c),
            }
        }
        String::from_utf8(out).or_else(|_| self.err("invalid UTF-8"))
    }
}
