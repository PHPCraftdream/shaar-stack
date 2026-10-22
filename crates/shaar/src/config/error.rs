//! Redacted configuration errors.
//!
//! [`ConfigError`] never embeds raw input, key material, or unknown
//! field names from the parsed document. Parser errors keep only a
//! static error class and safe numeric location (1-based line and a
//! byte offset); serde-level messages (which may contain field names
//! or values from the document) are reduced to the static class
//! `"schema"`.
//!
//! Classification is written against the real ktav 0.8.0 API
//! (`ktav::Error`, upstream `src/error/error.rs`): the `from_str`
//! deserialization path never produces a `Syntax` variant — the parser
//! emits `Error::Structured(ErrorKind)` (`Error::Syntax(String)` is a
//! kept legacy variant that the parser no longer constructs) and the
//! serde bridge reports deserialize failures as `Error::Message(String)`.
//! Accessors: `Error::line() -> Option<u32>` (1-based, structured
//! errors only) and `Error::span() -> Option<Span>` with
//! `Span { start: u32, end: u32 }` byte offsets. Here only `Structured`
//! maps to class `"syntax"`; everything else (`Message`, legacy
//! `Syntax`, `Io`, writer rejections) maps to `"schema"`, and none of
//! their text is retained. Limitation: ktav's structured envelope
//! (`ErrorEnvelope::from_error`) recovers canonical key `path` info
//! only for parse-time `DuplicateKey` / `KeyPathConflict` /
//! `InvalidKey` kinds — for serde-level (`Message`) schema errors the
//! upstream API offers no safe field-name recovery, so this layer does
//! not attempt to attribute a schema error to a specific known field
//! and does not parse upstream error strings.

use std::fmt;
use std::path::PathBuf;

/// How a configuration file failed to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadKind {
    /// Open or read failed (kind reported, underlying OS message dropped).
    Io,
    /// The file exceeds [`crate::config::MAX_CONFIG_BYTES`].
    TooLarge,
    /// The file is not valid UTF-8.
    InvalidUtf8,
}

/// Semantic validation failure kinds; `field` names a schema field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationKind {
    /// A required field is absent in both file and overrides.
    MissingRequired,
    /// The value is not a syntactically valid address or key.
    InvalidAddress,
    /// The address must be loopback but is not.
    NotLoopback,
    /// The port is not permitted for this field.
    InvalidPort,
    /// The value is not a valid endpoint public key.
    InvalidKey,
    /// The value is not one of the permitted enum spellings.
    InvalidEnum,
    /// A path value was present but empty.
    EmptyPath,
}

/// Configuration error: loading, parsing, or validation.
pub enum ConfigError {
    /// The configuration file could not be loaded.
    Loading { path: PathBuf, kind: LoadKind },
    /// The file text is not a valid configuration document.
    Parsing {
        /// Static class: `"syntax"` for structured parser errors,
        /// `"schema"` for serde-level errors (unknown fields, types).
        kind: &'static str,
        /// 1-based source line, when the parser reported one.
        line: Option<u32>,
        /// Byte offset into the source, when the parser reported one.
        offset: Option<u32>,
    },
    /// A known schema field failed semantic validation.
    Validation {
        field: &'static str,
        kind: ValidationKind,
    },
}

impl ConfigError {
    pub(crate) fn from_ktav(err: &ktav::Error) -> ConfigError {
        // Only numeric location is retained; neither Display nor Debug
        // of the upstream error is embedded (it can echo key names or
        // scalar bodies from the document). `Structured` is the only
        // parser-produced class; `Syntax`/`Message` carry upstream
        // text and are reduced to the static `"schema"` class. The
        // enum is `#[non_exhaustive]`, so unknown variants also land
        // in `"schema"`.
        let kind = match err {
            ktav::Error::Structured(_) => "syntax",
            _ => "schema",
        };
        ConfigError::Parsing {
            kind,
            line: err.line(),
            offset: err.span().map(|s| s.start),
        }
    }

    pub(crate) fn loading(path: PathBuf, kind: LoadKind) -> ConfigError {
        ConfigError::Loading { path, kind }
    }

    pub(crate) fn validation(field: &'static str, kind: ValidationKind) -> ConfigError {
        ConfigError::Validation { field, kind }
    }

    /// Source line, when this is a parsing error with location.
    pub fn line(&self) -> Option<u32> {
        match self {
            ConfigError::Parsing { line, .. } => *line,
            _ => None,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Loading { kind, .. } => {
                write!(f, "configuration file loading failed ({kind:?})")
            }
            ConfigError::Parsing { kind, line, offset } => {
                write!(f, "configuration parse error ({kind}")?;
                if let Some(line) = line {
                    write!(f, ", line {line}")?;
                }
                if let Some(offset) = offset {
                    write!(f, ", offset {offset}")?;
                }
                write!(f, ")")
            }
            ConfigError::Validation { field, kind } => {
                write!(
                    f,
                    "invalid configuration value for field `{field}` ({kind:?})"
                )
            }
        }
    }
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately identical redaction to Display: no raw input,
        // no key material, no unknown field names.
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ConfigError {}
