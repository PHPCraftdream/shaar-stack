# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact source-recipe edits for bounded serde_bencode deserialization."""


def edits() -> dict[str, list[tuple[str, str]]]:
    return {
        'src/de.rs': [
            (
                '''pub struct Deserializer<R: Read> {
    reader: R,
    next: Option<ParseResult>,
}''',
                '''pub struct Deserializer<R: Read> {
    reader: R,
    next: Option<ParseResult>,
    remaining: Option<usize>,
    max_depth: Option<usize>,
    depth: usize,
}''',
            ),
            (
                '''    pub fn new(reader: R) -> Deserializer<R> {
        Deserializer { reader, next: None }
    }''',
                '''    pub fn new(reader: R) -> Deserializer<R> {
        Deserializer { reader, next: None, remaining: None, max_depth: None, depth: 0 }
    }

    fn account(&mut self, amount: usize) -> Result<()> {
        if let Some(remaining) = &mut self.remaining {
            *remaining = remaining.checked_sub(amount).ok_or(Error::EndOfStream)?;
        }
        Ok(())
    }''',
            ),
            (
                '''    fn parse_int(&mut self) -> Result<i64> {
        let mut buf = [0; 1];
        let mut result = Vec::new();
        loop {
            if 1 != self.reader.read(&mut buf).map_err(Error::IoError)? {
                return Err(Error::EndOfStream);
            }
            match buf[0] {''',
                '''    fn parse_int(&mut self) -> Result<i64> {
        let mut buf = [0; 1];
        let mut result = Vec::new();
        loop {
            if 1 != self.reader.read(&mut buf).map_err(Error::IoError)? {
                return Err(Error::EndOfStream);
            }
            self.account(1)?;
            match buf[0] {''',
            ),
            (
                '''    fn parse_bytes_len(&mut self, len_char: u8) -> Result<usize> {
        let mut buf = [0; 1];
        let mut len = Vec::new();
        len.push(len_char);
        loop {
            if 1 != self.reader.read(&mut buf).map_err(Error::IoError)? {
                return Err(Error::EndOfStream);
            }
            match buf[0] {''',
                '''    fn parse_bytes_len(&mut self, len_char: u8) -> Result<usize> {
        let mut buf = [0; 1];
        let mut len = Vec::new();
        len.push(len_char);
        loop {
            if 1 != self.reader.read(&mut buf).map_err(Error::IoError)? {
                return Err(Error::EndOfStream);
            }
            self.account(1)?;
            match buf[0] {''',
            ),
            (
                '''        let len = self.parse_bytes_len(len_char)?;
        let mut buf = Vec::new();''',
                '''        let len = self.parse_bytes_len(len_char)?;
        if self.remaining.is_some_and(|remaining| len > remaining) {
            return Err(Error::EndOfStream);
        }
        let mut buf = Vec::new();''',
            ),
            (
                '''        if len != actual_len {
            return Err(Error::EndOfStream);
        }
        Ok(buf)''',
                '''        self.account(actual_len)?;
        if len != actual_len {
            return Err(Error::EndOfStream);
        }
        Ok(buf)''',
            ),
            (
                '''    fn parse(&mut self) -> Result<ParseResult> {
        if let Some(t) = self.next.take() {
            return Ok(t);
        }
        let mut buf = [0; 1];
        if 1 != self.reader.read(&mut buf).map_err(Error::IoError)? {
            return Err(Error::EndOfStream);
        }
        match buf[0] {
            b'i' => Ok(ParseResult::Int(self.parse_int()?)),
            n @ b'0'..=b'9' => Ok(ParseResult::Bytes(self.parse_bytes(n)?)),
            b'l' => Ok(ParseResult::List),
            b'd' => Ok(ParseResult::Map),
            b'e' => Ok(ParseResult::End),''',
                '''    fn parse(&mut self) -> Result<ParseResult> {
        if let Some(t) = self.next.take() {
            return Ok(t);
        }
        let mut buf = [0; 1];
        if 1 != self.reader.read(&mut buf).map_err(Error::IoError)? {
            return Err(Error::EndOfStream);
        }
        self.account(1)?;
        match buf[0] {
            b'i' => Ok(ParseResult::Int(self.parse_int()?)),
            n @ b'0'..=b'9' => Ok(ParseResult::Bytes(self.parse_bytes(n)?)),
            b'l' | b'd' if self.max_depth.is_some() => {
                let depth = self.depth.checked_add(1).ok_or(Error::EndOfStream)?;
                if self.max_depth.is_some_and(|maximum| depth > maximum) {
                    return Err(Error::InvalidValue("maximum bencode nesting depth exceeded".to_string()));
                }
                self.depth = depth;
                if buf[0] == b'l' { Ok(ParseResult::List) } else { Ok(ParseResult::Map) }
            }
            b'l' => Ok(ParseResult::List),
            b'd' => Ok(ParseResult::Map),
            b'e' if self.max_depth.is_some() => {
                self.depth = self.depth.checked_sub(1).ok_or_else(|| Error::InvalidValue("unexpected bencode terminator".to_string()))?;
                Ok(ParseResult::End)
            }
            b'e' => Ok(ParseResult::End),''',
            ),
            (
                '''pub fn from_bytes<'de, T>(b: &'de [u8]) -> Result<T>
where
    T: de::Deserialize<'de>,
{
    de::Deserialize::deserialize(&mut Deserializer::new(b))
}''',
                '''pub fn from_bytes<'de, T>(b: &'de [u8]) -> Result<T>
where
    T: de::Deserialize<'de>,
{
    de::Deserialize::deserialize(&mut Deserializer::new(b))
}

/// Deserialize with explicit input-byte and recursive nesting limits.
///
/// The caller owns these policy limits. The parser accounts input as consumed, rejects
/// excess bytes before parsing, and rejects trailing bytes after one decoded value.
pub fn from_bytes_bounded<'de, T>(b: &'de [u8], max_bytes: usize, max_depth: usize) -> Result<T>
where
    T: de::Deserialize<'de>,
{
    if b.len() > max_bytes {
        return Err(Error::InvalidLength("bencode input exceeds configured byte limit".to_string()));
    }
    let mut deserializer = Deserializer::new(b);
    deserializer.remaining = Some(b.len());
    deserializer.max_depth = Some(max_depth);
    let value: T = de::Deserialize::deserialize(&mut deserializer)?;
    if deserializer.remaining != Some(0) || !deserializer.reader.is_empty() || deserializer.next.is_some() || deserializer.depth != 0 {
        return Err(Error::InvalidValue("trailing or incomplete bencode input".to_string()));
    }
    Ok(value)
}''',
            ),
        ],
    }
