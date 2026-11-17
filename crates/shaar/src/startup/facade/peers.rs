//! `PeerKey` (the public Ed25519 identity of a Server or a Client) and `AllowList`
//! (the client keys a Server admits, with the allowlist file format).
//!
//! Allowlist file format: one client public key per line, 64 hexadecimal characters
//! (either case); blank lines and lines whose trimmed text starts with `#` are ignored.

use std::fmt;
use std::net::Ipv6Addr;
use std::path::Path;
use std::str::FromStr;

use iroh_base::PublicKey;
use libp2p_identity::PeerId;
use tokio::io::AsyncReadExt;

use crate::identity::Identity;
use crate::network::Allowlist;

/// A public Ed25519 key. For a Server it is the whole address: a Client that
/// knows it can find and reach the Server; for a Client it is the entry in a
/// Server's [`AllowList`](super::AllowList).
///
/// Text form: 64 hexadecimal characters; parsing accepts either case and the
/// base32 form of the underlying key type, printing is lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerKey([u8; 32]);

/// Why a key could not be built or parsed; never carries the rejected text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The text is not a valid encoding of a 32-byte key.
    InvalidEncoding,
    /// The 32 bytes are not a valid Ed25519 public key.
    NotAPublicKey,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEncoding => "invalid public key encoding",
            Self::NotAPublicKey => "bytes are not an Ed25519 public key",
        })
    }
}

impl std::error::Error for KeyError {}

impl PeerKey {
    /// The public key of `identity`.
    pub fn of(identity: &Identity) -> Self {
        Self(identity.public_key_bytes())
    }

    /// Validates 32 raw bytes as an Ed25519 public key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, KeyError> {
        PublicKey::from_bytes(&bytes)
            .map(|key| Self(*key.as_bytes()))
            .map_err(|_| KeyError::NotAPublicKey)
    }

    /// The 32 raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The three lines the command line prints for a key: its text, the derived libp2p
    /// `PeerId` and the derived Yggdrasil address.
    pub fn summary_lines(&self) -> [String; 3] {
        [
            format!("public_key={self}"),
            format!("peer_id={}", self.peer_id()),
            format!("ygg_ip={}", self.ygg_ip()),
        ]
    }

    /// The libp2p `PeerId` text (base58) derived from this key.
    pub fn peer_id(&self) -> String {
        let mut bytes = [0u8; 38];
        bytes[..6].copy_from_slice(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
        bytes[6..].copy_from_slice(&self.0);
        PeerId::from_bytes(&bytes)
            .expect("an identity multihash over 32 bytes is a valid PeerId")
            .to_string()
    }

    /// The Yggdrasil address derived from this key (one-way).
    pub fn ygg_ip(&self) -> Ipv6Addr {
        crate::identity::ygg_address_of(&self.0)
    }

    pub(crate) fn to_iroh(self) -> PublicKey {
        PublicKey::from_bytes(&self.0).expect("a PeerKey always holds a valid public key")
    }

    pub(crate) fn from_iroh(key: PublicKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl fmt::Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey({self})")
    }
}

impl FromStr for PeerKey {
    type Err = KeyError;

    fn from_str(text: &str) -> Result<Self, KeyError> {
        // 64 hex digits in either case; any other length goes to the key type's own
        // text forms.
        if text.len() == 64 {
            return parse_hex_key(text).ok_or(KeyError::InvalidEncoding);
        }
        text.parse::<PublicKey>()
            .map(Self::from_iroh)
            .map_err(|_| KeyError::InvalidEncoding)
    }
}

impl From<&Identity> for PeerKey {
    fn from(identity: &Identity) -> Self {
        Self::of(identity)
    }
}

/// Most entries a list may be built from, counted before deduplication.
pub const MAX_ENTRIES: usize = 256;
/// Most bytes an allowlist file or text may have.
pub const MAX_BYTES: usize = MAX_ENTRIES * 66;

/// Why an allowlist could not be built; messages never print key text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowListError {
    /// The file could not be opened or read.
    Read,
    /// The file or text exceeds [`MAX_BYTES`].
    TooLarge,
    /// More than [`MAX_ENTRIES`] entries.
    TooMany,
    /// The entry on this 1-based line (comments and blank lines count) is not a key.
    InvalidLine(usize),
}

impl fmt::Display for AllowListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("could not read allowlist"),
            Self::TooLarge => write!(f, "allowlist file exceeds {MAX_BYTES} bytes"),
            Self::TooMany => write!(f, "allowlist exceeds {MAX_ENTRIES} entries"),
            Self::InvalidLine(line) => write!(f, "invalid allowlist key on line {line}"),
        }
    }
}

impl std::error::Error for AllowListError {}

/// Distinct client keys, sorted. An empty list admits nobody.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList {
    keys: Vec<PeerKey>,
}

impl AllowList {
    /// The empty list.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a list from keys; duplicates are merged. At most [`MAX_ENTRIES`]
    /// items may be supplied, duplicates included.
    pub fn new(keys: impl IntoIterator<Item = PeerKey>) -> Result<Self, AllowListError> {
        let mut collected = Vec::new();
        for key in keys {
            if collected.len() == MAX_ENTRIES {
                return Err(AllowListError::TooMany);
            }
            collected.push(key);
        }
        Ok(Self::from_raw(collected))
    }

    /// Parses allowlist text.
    pub fn parse(text: &str) -> Result<Self, AllowListError> {
        if text.len() > MAX_BYTES {
            return Err(AllowListError::TooLarge);
        }
        let mut keys = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let value = line.trim();
            if value.is_empty() || value.starts_with('#') {
                continue;
            }
            if keys.len() == MAX_ENTRIES {
                return Err(AllowListError::TooMany);
            }
            keys.push(parse_hex_key(value).ok_or(AllowListError::InvalidLine(index + 1))?);
        }
        Ok(Self::from_raw(keys))
    }

    /// Reads and parses an allowlist file with a bounded read.
    /// cancel-safe: YES — nothing is retained when the future is dropped.
    pub async fn read(path: impl AsRef<Path>) -> Result<Self, AllowListError> {
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|_| AllowListError::Read)?;
        let mut text = String::new();
        file.take((MAX_BYTES + 1) as u64)
            .read_to_string(&mut text)
            .await
            .map_err(|_| AllowListError::Read)?;
        Self::parse(&text)
    }

    /// The allowlist text with `key` appended as its own line (comments and other lines are
    /// kept); `None` when the key is already listed. The result must still be a valid list.
    pub fn text_with(text: &str, key: &PeerKey) -> Result<Option<String>, AllowListError> {
        if Self::parse(text)?.contains(key) {
            return Ok(None);
        }
        let mut out = text.to_owned();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("{key}\n"));
        Self::parse(&out)?;
        Ok(Some(out))
    }

    /// The allowlist text without the lines that list `key`; `None` when it is not listed.
    pub fn text_without(text: &str, key: &PeerKey) -> Result<Option<String>, AllowListError> {
        Self::parse(text)?;
        let mut out = String::with_capacity(text.len());
        let mut removed = false;
        for line in text.split_inclusive('\n') {
            let value = line.trim();
            if !value.starts_with('#') && parse_hex_key(value) == Some(*key) {
                removed = true;
            } else {
                out.push_str(line);
            }
        }
        Ok(removed.then_some(out))
    }

    fn from_raw(mut keys: Vec<PeerKey>) -> Self {
        keys.sort_unstable();
        keys.dedup();
        Self { keys }
    }

    /// The distinct keys in ascending order.
    pub fn keys(&self) -> &[PeerKey] {
        &self.keys
    }

    /// Number of distinct keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether nobody is admitted.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether `key` is admitted.
    pub fn contains(&self, key: &PeerKey) -> bool {
        self.keys.binary_search(key).is_ok()
    }

    pub(crate) fn to_network(&self) -> Allowlist {
        let keys: Vec<_> = self.keys.iter().map(|key| key.to_iroh()).collect();
        Allowlist::new(&keys).expect("a list holds at most 256 keys")
    }
}

/// Exactly 64 hex digits of either case that form a valid public key.
fn parse_hex_key(text: &str) -> Option<PeerKey> {
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (slot, pair) in bytes
        .iter_mut()
        .zip(text.as_bytes().as_chunks::<2>().0.iter())
    {
        let digit = |value: u8| char::from(value).to_digit(16);
        *slot = u8::try_from(digit(pair[0])? * 16 + digit(pair[1])?).ok()?;
    }
    PeerKey::from_bytes(bytes).ok()
}

/// One `allow` subcommand of the Server binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowAction {
    /// List the admitted keys.
    List,
    /// Admit these keys.
    Add(Vec<PeerKey>),
    /// Stop admitting these keys.
    Remove(Vec<PeerKey>),
}

/// Runs one `allow` subcommand on the allowlist file at `path` and returns the lines to
/// print; the file is rewritten once, keeping its comments and the previous content as
/// `<path>.bak`. A running Server reads the file only at startup.
/// cancel-safe: NO — a write that already started completes after cancellation.
pub async fn allowlist_command(path: &Path, action: AllowAction) -> Result<Vec<String>, String> {
    let mut text = tokio::fs::read_to_string(path)
        .await
        .map_err(|_| AllowListError::Read.to_string())?;
    let (keys, adding) = match action {
        AllowAction::List => {
            let list = AllowList::parse(&text).map_err(|error| error.to_string())?;
            let mut lines: Vec<String> = list.keys().iter().map(ToString::to_string).collect();
            lines.push(format!("clients={}", list.len()));
            return Ok(lines);
        }
        AllowAction::Add(keys) => (keys, true),
        AllowAction::Remove(keys) => (keys, false),
    };
    let mut lines = Vec::new();
    let mut changed = false;
    for key in &keys {
        let edited = if adding {
            AllowList::text_with(&text, key)
        } else {
            AllowList::text_without(&text, key)
        }
        .map_err(|error| error.to_string())?;
        let verb = match (&edited, adding) {
            (Some(_), true) => "added",
            (Some(_), false) => "removed",
            (None, true) => "already listed",
            (None, false) => "not listed",
        };
        lines.push(format!("{verb}: {key}"));
        if let Some(edited) = edited {
            text = edited;
            changed = true;
        }
    }
    if changed {
        crate::identity::write_replacing(path, text, true)
            .await
            .map_err(|_| "could not write the allowlist".to_owned())?;
        lines.push(format!(
            "note: restart the server to apply; previous content kept as {}.bak",
            path.display()
        ));
    }
    Ok(lines)
}
