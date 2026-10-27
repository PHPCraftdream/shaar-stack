use iroh_base::PublicKey;
use std::path::Path;
use tokio::io::AsyncReadExt;

pub async fn read_allowlist(path: &Path) -> Result<Vec<PublicKey>, String> {
    const MAX_ALLOWLIST_BYTES: usize = 256 * 66;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| "could not read allowlist".to_owned())?;
    let mut text = String::new();
    file.take((MAX_ALLOWLIST_BYTES + 1) as u64)
        .read_to_string(&mut text)
        .await
        .map_err(|_| "could not read allowlist".to_owned())?;
    if text.len() > MAX_ALLOWLIST_BYTES {
        return Err(format!(
            "allowlist file exceeds {MAX_ALLOWLIST_BYTES} bytes"
        ));
    }
    let mut keys = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        if keys.len() == 256 {
            return Err("allowlist exceeds 256 entries".to_owned());
        }
        let bytes = decode_hex(value)
            .ok_or_else(|| format!("invalid allowlist key on line {}", line_number + 1))?;
        keys.push(
            PublicKey::from_bytes(&bytes)
                .map_err(|_| format!("invalid allowlist key on line {}", line_number + 1))?,
        );
    }
    Ok(keys)
}

fn decode_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |value: u8| match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        };
        bytes[index] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Some(bytes)
}
