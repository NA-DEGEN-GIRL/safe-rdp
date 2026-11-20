//! Small strict JSON parser (RFC 8259) for the output of local tools such as
//! `tailscale status --json`.
//!
//! Strict: exactly one value, no trailing commas, comments, BOM, NaN/Infinity, leading zeros,
//! raw control characters or lone surrogates; duplicate object keys are rejected. Bounded:
//! input size and nesting depth are limited, so hostile input cannot exhaust the stack.
//! Numbers keep their literal text, so 64-bit IDs survive without rounding.

use crate::util::{Error, Result};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    /// Members in document order; keys are unique.
    Object(Vec<(String, Value)>),
}

/// A number exactly as written in the document (validated against the JSON grammar).
#[derive(Clone, Debug, PartialEq)]
pub struct Number(String);

// A general-purpose API: not every caller needs every accessor.
#[allow(dead_code)]
impl Number {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.0.parse().ok().filter(|f: &f64| f.is_finite())
    }

    /// The value if it is an integer literal that fits (no fraction or exponent).
    pub fn as_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Largest accepted document in bytes.
    pub max_len: usize,
    /// Deepest accepted nesting of arrays and objects.
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_len: 16 << 20, max_depth: 64 }
    }
}

#[allow(dead_code)]
impl Value {
    /// Member `key` of an object (None for other types or a missing key).
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// Parses one JSON document with the default limits.
pub fn parse(input: &[u8]) -> Result<Value> {
    parse_with(input, Limits::default())
}

pub fn parse_with(input: &[u8], limits: Limits) -> Result<Value> {
    if input.len() > limits.max_len {
        return Err(Error::msg(format!("JSON document too large ({} bytes, limit {})", input.len(), limits.max_len)));
    }
    if let Err(e) = std::str::from_utf8(input) {
        return Err(Error::msg(format!("invalid JSON at byte {}: not UTF-8", e.valid_up_to())));
    }
    let mut p = Parser { b: input, pos: 0, depth: 0, max_depth: limits.max_depth };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.b.len() {
        return Err(p.err("unexpected data after the value"));
    }
    Ok(v)
}

/// Objects with more members than this switch from a linear duplicate check to a hash set.
const LINEAR_KEYS: usize = 16;

struct Parser<'a> {
    /// Valid UTF-8 (checked up front).
    b: &'a [u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
}

impl Parser<'_> {
    fn err(&self, what: &str) -> Error {
        Error::msg(format!("invalid JSON at byte {}: {what}", self.pos))
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.pos += 1;
        }
    }

    fn expect(&mut self, c: u8) -> Result<()> {
        if self.peek() != Some(c) {
            return Err(self.err(&format!("expected '{}'", c as char)));
        }
        self.pos += 1;
        Ok(())
    }

    fn value(&mut self) -> Result<Value> {
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn literal(&mut self, word: &str, v: Value) -> Result<Value> {
        if !self.b[self.pos..].starts_with(word.as_bytes()) {
            return Err(self.err("invalid literal"));
        }
        self.pos += word.len();
        Ok(v)
    }

    fn enter(&mut self) -> Result<()> {
        if self.depth >= self.max_depth {
            return Err(self.err("nested too deeply"));
        }
        self.depth += 1;
        self.pos += 1;
        Ok(())
    }

    fn array(&mut self) -> Result<Value> {
        self.enter()?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
        } else {
            loop {
                self.skip_ws();
                items.push(self.value()?);
                self.skip_ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b']') => {
                        self.pos += 1;
                        break;
                    }
                    _ => return Err(self.err("expected ',' or ']'")),
                }
            }
        }
        self.depth -= 1;
        Ok(Value::Array(items))
    }

    fn object(&mut self) -> Result<Value> {
        self.enter()?;
        let mut members: Vec<(String, Value)> = Vec::new();
        let mut seen: Option<HashSet<String>> = None;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
        } else {
            loop {
                self.skip_ws();
                let key_pos = self.pos;
                if self.peek() != Some(b'"') {
                    return Err(self.err("expected a string key"));
                }
                let key = self.string()?;
                let duplicate = match &mut seen {
                    Some(set) => !set.insert(key.clone()),
                    None => members.iter().any(|(k, _)| *k == key),
                };
                if duplicate {
                    self.pos = key_pos;
                    return Err(self.err("duplicate key"));
                }
                self.skip_ws();
                self.expect(b':')?;
                self.skip_ws();
                let v = self.value()?;
                members.push((key, v));
                if seen.is_none() && members.len() >= LINEAR_KEYS {
                    seen = Some(members.iter().map(|(k, _)| k.clone()).collect());
                }
                self.skip_ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b'}') => {
                        self.pos += 1;
                        break;
                    }
                    _ => return Err(self.err("expected ',' or '}'")),
                }
            }
        }
        self.depth -= 1;
        Ok(Value::Object(members))
    }

    fn hex4(&mut self) -> Result<u32> {
        let digits = self.b.get(self.pos..self.pos + 4).ok_or_else(|| self.err("truncated \\u escape"))?;
        let mut v = 0u32;
        for &d in digits {
            let n = (d as char).to_digit(16).ok_or_else(|| self.err("invalid \\u escape"))?;
            v = v << 4 | n;
        }
        self.pos += 4;
        Ok(v)
    }

    /// Parses a string starting at the opening quote.
    fn string(&mut self) -> Result<String> {
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let start = self.pos;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            out.extend_from_slice(&self.b[start..self.pos]);
            match self.peek() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let esc = self.peek().ok_or_else(|| self.err("unterminated string"))?;
                    self.pos += 1;
                    let ch = match esc {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode_escape()?,
                        _ => {
                            self.pos -= 1;
                            return Err(self.err("invalid escape"));
                        }
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                Some(_) => return Err(self.err("control character in string")),
            }
        }
        // Raw runs were copied whole from valid UTF-8 and escapes encode whole chars.
        String::from_utf8(out).map_err(|_| self.err("invalid UTF-8 in string"))
    }

    /// Decodes the code point after `\u`, combining a UTF-16 surrogate pair.
    fn unicode_escape(&mut self) -> Result<char> {
        let at = self.pos - 2;
        let hi = self.hex4()?;
        let cp = match hi {
            0xd800..=0xdbff => {
                if !self.b[self.pos..].starts_with(b"\\u") {
                    self.pos = at;
                    return Err(self.err("unpaired surrogate"));
                }
                self.pos += 2;
                let lo = self.hex4()?;
                if !(0xdc00..=0xdfff).contains(&lo) {
                    self.pos = at;
                    return Err(self.err("unpaired surrogate"));
                }
                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
            }
            0xdc00..=0xdfff => {
                self.pos = at;
                return Err(self.err("unpaired surrogate"));
            }
            c => c,
        };
        char::from_u32(cp).ok_or_else(|| self.err("invalid code point"))
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<Value> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if let Some(b'0'..=b'9') = self.peek() {
                    return Err(self.err("leading zero in number"));
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.err("expected a digit")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if self.digits() == 0 {
                return Err(self.err("expected a digit after '.'"));
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(self.err("expected a digit in the exponent"));
            }
        }
        // ASCII only, so the slice is valid UTF-8.
        let text = String::from_utf8_lossy(&self.b[start..self.pos]).into_owned();
        Ok(Value::Number(Number(text)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Value> {
        parse(s.as_bytes())
    }

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }

    #[test]
    fn scalars() {
        assert_eq!(p("null").unwrap(), Value::Null);
        assert_eq!(p(" true ").unwrap(), Value::Bool(true));
        assert_eq!(p("\t\r\nfalse\n").unwrap(), Value::Bool(false));
        assert_eq!(p("\"hi\"").unwrap(), s("hi"));
        assert_eq!(p("0").unwrap().as_number().unwrap().as_i64(), Some(0));
        assert_eq!(p("-12").unwrap().as_number().unwrap().as_i64(), Some(-12));
        assert_eq!(p("1.5e3").unwrap().as_number().unwrap().as_f64(), Some(1500.0));
        assert_eq!(p("-0.25E-2").unwrap().as_number().unwrap().as_f64(), Some(-0.0025));
        assert_eq!(p("2e+2").unwrap().as_number().unwrap().as_str(), "2e+2");
    }

    #[test]
    fn big_integers_are_exact() {
        let v = p("[4503599627370497, 18446744073709551615, -9223372036854775808]").unwrap();
        let a = v.as_array().unwrap();
        assert_eq!(a[0].as_number().unwrap().as_u64(), Some(4503599627370497));
        assert_eq!(a[1].as_number().unwrap().as_u64(), Some(u64::MAX));
        assert_eq!(a[2].as_number().unwrap().as_i64(), Some(i64::MIN));
        assert_eq!(a[1].as_number().unwrap().as_i64(), None);
        assert_eq!(p("1.0").unwrap().as_number().unwrap().as_i64(), None);
        assert_eq!(p("1e400").unwrap().as_number().unwrap().as_f64(), None);
    }

    #[test]
    fn containers() {
        let v = p(r#"{"a": [1, {"b": null}, []], "c": {}, "d": "x"}"#).unwrap();
        assert_eq!(v.get("d"), Some(&s("x")));
        assert!(v.get("c").unwrap().as_object().unwrap().is_empty());
        let a = v.get("a").unwrap().as_array().unwrap();
        assert_eq!(a.len(), 3);
        assert!(a[1].get("b").unwrap().is_null());
        assert!(a[2].as_array().unwrap().is_empty());
        assert_eq!(v.get("missing"), None);
        assert_eq!(s("x").get("a"), None);
        let keys: Vec<&str> = v.as_object().unwrap().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["a", "c", "d"]);
    }

    #[test]
    fn string_escapes() {
        assert_eq!(p(r#""a\"b\\c\/d\b\f\n\r\t""#).unwrap(), s("a\"b\\c/d\u{8}\u{c}\n\r\t"));
        assert_eq!(p(r#""Aé가""#).unwrap(), s("Aé가"));
        assert_eq!(p(r#""😀""#).unwrap(), s("😀"));
        assert_eq!(p(r#""x𝄞y""#).unwrap(), s("x𝄞y"));
        assert_eq!(p(r#""\u0000""#).unwrap(), s("\0"));
        assert_eq!(p("\"한글 ✓\"").unwrap(), s("한글 ✓"));
    }

    #[test]
    fn rejects_bad_strings() {
        for bad in [
            r#""abc"#,
            r#""\x41""#,
            r#""\u12""#,
            r#""\u12g4""#,
            r#""\ud83d""#,
            r#""\ud83dx""#,
            r#""\ud83dA""#,
            r#""\ude00""#,
            r#""\ude00\ud83d""#,
            "\"tab\there\"",
            "\"line\nbreak\"",
            "'single'",
        ] {
            assert!(p(bad).is_err(), "accepted {bad:?}");
        }
        assert!(parse(b"\"\xff\"").is_err());
        assert!(parse(b"\"\xc3\"").is_err());
    }

    #[test]
    fn rejects_bad_numbers() {
        for bad in ["01", "-", "-a", "1.", ".5", "1e", "1e+", "+1", "0x10", "NaN", "Infinity", "-Infinity", "1.e3", "--1"] {
            assert!(p(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rejects_bad_structure() {
        for bad in [
            "",
            "   ",
            "[1,]",
            "[,1]",
            "[1 2]",
            "{\"a\":1,}",
            "{\"a\" 1}",
            "{a:1}",
            "{\"a\":1 \"b\":2}",
            "[1]]",
            "{} {}",
            "nul",
            "truex",
            "[",
            "{\"a\":",
            "// c\n1",
            "\u{feff}1",
            "1\u{a0}",
        ] {
            assert!(p(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert!(p(r#"{"a":1,"a":2}"#).is_err());
        assert!(p(r#"{"a":1,"b":{"a":2}}"#).is_ok());
        // Past the linear threshold the hash set takes over.
        let mut doc = String::from("{");
        for i in 0..40 {
            doc.push_str(&format!("\"k{i}\":{i},"));
        }
        assert!(p(&format!("{doc}\"k39\":0}}")).is_err());
        assert!(p(&format!("{doc}\"k3\":0}}")).is_err());
        assert!(p(&format!("{doc}\"k40\":0}}")).is_ok());
        // Escaped and literal spellings of the same key are the same key.
        assert!(p(r#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn limits() {
        let deep = |n: usize| "[".repeat(n) + &"]".repeat(n);
        let lim = Limits { max_len: 1 << 20, max_depth: 8 };
        assert!(parse_with(deep(8).as_bytes(), lim).is_ok());
        assert!(parse_with(deep(9).as_bytes(), lim).is_err());
        assert!(parse_with(b"{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{}}}}}}}}}", lim).is_err());
        // Very deep input fails cleanly instead of overflowing the stack.
        assert!(parse("[".repeat(1_000_000).as_bytes()).is_err());
        let small = Limits { max_len: 4, max_depth: 8 };
        assert!(parse_with(b"1234", small).is_ok());
        assert!(parse_with(b"12345", small).is_err());
    }

    #[test]
    fn error_reports_offset() {
        let e = p("[1, 2, x]").unwrap_err().to_string();
        assert!(e.contains("byte 7"), "{e}");
        let e = p(r#"{"a":1,"a":2}"#).unwrap_err().to_string();
        assert!(e.contains("byte 7") && e.contains("duplicate"), "{e}");
    }

    #[test]
    fn accessors_on_wrong_types() {
        let v = p("[true]").unwrap();
        assert_eq!(v.as_str(), None);
        assert_eq!(v.as_bool(), None);
        assert_eq!(v.as_object(), None);
        assert_eq!(v.as_number(), None);
        assert!(!v.is_null());
        assert_eq!(v.as_array().unwrap()[0].as_bool(), Some(true));
    }
}
