use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use shaar::identity::Identity;

use crate::test_support::read_allowlist;

static NEXT: AtomicU64 = AtomicU64::new(0);
fn file(text: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "shaar-server-allowlist-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, text).unwrap();
    path
}
fn key_line(seed: u16) -> String {
    let identity = Identity::from_seed([
        seed as u8,
        (seed >> 8) as u8,
        0x5a,
        0xa5,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xf0,
        0x0f,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf1,
        0x21,
        0x43,
        0x65,
        0x87,
    ]);
    format!(
        "{}\n",
        identity
            .public_key_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[tokio::test]
async fn rejects_malformed_key() {
    let path = file(&format!("{}\n", "zz".repeat(32)));
    assert!(read_allowlist(&path).await.unwrap_err().contains("line 1"));
    fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn accepts_exactly_256_and_rejects_257_entries() {
    let accepted = file(&(0..256).map(key_line).collect::<String>());
    assert_eq!(read_allowlist(&accepted).await.unwrap().len(), 256);
    fs::remove_file(accepted).unwrap();
    let rejected = file(&(0..257).map(key_line).collect::<String>());
    assert!(read_allowlist(&rejected).await.unwrap_err().contains("256"));
    fs::remove_file(rejected).unwrap();
}
