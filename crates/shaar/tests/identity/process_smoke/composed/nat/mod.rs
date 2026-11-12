//! Explicit Linux CI helper roles; normal Server/Client products are separate binaries.

#![forbid(unsafe_code)]

use super::*;

mod wan;

#[tokio::test]
#[ignore = "explicit owned namespace helper, not a product process scenario"]
async fn fixture_child() {
    run().await.unwrap();
}

/// cancel-safe: NO — the CI supervisor owns this process and verifies bounded reaping.
async fn run() -> Result<(), String> {
    let nonce = std::env::var("SHAAR_NAT_NONCE").map_err(|e| e.to_string())?;
    check_nonce(&nonce)?;
    match std::env::var("SHAAR_NAT_ROLE")
        .map_err(|e| e.to_string())?
        .as_str()
    {
        "keys" => keys(&nonce).await,
        "wan" => wan::run(&nonce).await,
        _ => Err("unreviewed namespace helper role".to_owned()),
    }
}

fn check_nonce(value: &str) -> Result<(), String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("namespace nonce must be exactly 32 lowercase hex characters".to_owned());
    }
    Ok(())
}

fn public_key(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("namespace public key must be exactly 64 lowercase hex characters".to_owned());
    }
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    iroh_base::PublicKey::from_bytes(&key).map_err(|_| "invalid namespace service public key")?;
    Ok(key)
}

async fn keys(nonce: &str) -> Result<(), String> {
    let directory = PathBuf::from(std::env::var("SHAAR_NAT_DIRECTORY").map_err(|e| e.to_string())?);
    let metadata = tokio::fs::symlink_metadata(&directory)
        .await
        .map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(
            "namespace identity directory must already be an owned real directory".to_owned(),
        );
    }
    // Secure fsync provisioning is blocking; keep it off the async executor.
    tokio::task::spawn_blocking(move || {
        key_file(&directory.join("server.key"), [0xd1; 32])?;
        key_file(&directory.join("client.key"), [0xd2; 32])
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    let server = hex(&Identity::from_seed([0xd1; 32]).public_key_bytes());
    let client = hex(&Identity::from_seed([0xd2; 32]).public_key_bytes());
    // Every string field is closed-role text or validated hex, never an arbitrary path.
    println!(
        "SHAAR_NAT_READY {{\"role\":\"keys\",\"nonce\":\"{nonce}\",\"pid\":{},\"server_key\":\"{server}\",\"client_key\":\"{client}\"}}",
        std::process::id()
    );
    Ok(())
}

/// cancel-safe: NO — an incomplete control frame fails the helper; the supervisor reaps it.
async fn stop_command(mut stream: TcpStream, nonce: &str) -> Result<(), String> {
    timeout(Duration::from_secs(3), async {
        let mut frame = Vec::with_capacity(65);
        (&mut stream)
            .take(65)
            .read_to_end(&mut frame)
            .await
            .map_err(|e| e.to_string())?;
        if frame != format!("STOP {nonce}\n").as_bytes() {
            return Err("namespace control frame mismatch".to_owned());
        }
        Ok(())
    })
    .await
    .map_err(|_| "namespace control frame deadline".to_owned())?
}

#[test]
fn nonce_shape_excludes_escaping_and_unowned_control_tokens() {
    assert!(check_nonce(&"a".repeat(32)).is_ok());
    for value in [
        "".to_owned(),
        "a".repeat(31),
        "a".repeat(33),
        "A".repeat(32),
        format!("{}\"", "a".repeat(31)),
        format!("{}\n", "a".repeat(31)),
    ] {
        assert!(check_nonce(&value).is_err());
    }
}

#[test]
fn service_key_shape_is_validated_before_a_role_uses_it() {
    let expected = Identity::from_seed([0xd1; 32]).public_key_bytes();
    assert_eq!(public_key(&hex(&expected)).unwrap(), expected);
    for value in [
        "".to_owned(),
        "g".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
    ] {
        assert!(public_key(&value).is_err());
    }
}
