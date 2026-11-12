#![forbid(unsafe_code)]
//! Creates or inspects an identity key file with the public SDK.
//!
//! Usage: `keygen create <key-file>` or `keygen show <key-file>`.
//! Both print the 64-character lowercase hex public key.

use std::error::Error;
use std::process::ExitCode;

use shaar::identity::Identity;

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Creates `path` exclusively (never overwrites) and returns its public key.
pub async fn create_key(path: &str) -> Result<String, Box<dyn Error>> {
    let identity = Identity::create_new(path).await?;
    Ok(hex(&identity.public_key_bytes()))
}

/// Loads an existing key file (permission checked) and returns its public key.
pub async fn show_key(path: &str) -> Result<String, Box<dyn Error>> {
    let identity = Identity::load(path).await?;
    Ok(hex(&identity.public_key_bytes()))
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["create", path] => create_key(path).await,
        ["show", path] => show_key(path).await,
        _ => {
            eprintln!("usage: keygen create|show <key-file>");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(public_key) => {
            println!("{public_key}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("keygen: {error}");
            ExitCode::FAILURE
        }
    }
}
