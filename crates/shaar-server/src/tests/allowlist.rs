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
async fn empty_and_comment_only_files_produce_an_empty_allowlist() {
    for text in ["", "\n  \n# no admitted peers\n  # still empty\n"] {
        let path = file(text);
        let result = read_allowlist(&path).await;
        fs::remove_file(path).unwrap();
        assert!(result.unwrap().is_empty());
    }
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

/// The example of docs/guide/ is read verbatim by the production parser.
const GUIDE_ALLOWLIST: &str = include_str!("../../../../docs/guide/examples/allowlist.txt");

#[tokio::test]
async fn documented_example_allowlist_is_accepted_verbatim() {
    let path = file(GUIDE_ALLOWLIST);
    let keys = read_allowlist(&path).await.unwrap();
    fs::remove_file(path).unwrap();
    let hex: Vec<String> = keys
        .iter()
        .map(|key| key.as_bytes().iter().map(|b| format!("{b:02x}")).collect())
        .collect();
    assert_eq!(
        hex,
        [
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
        ]
    );
}

#[tokio::test]
async fn documented_allowlist_error_messages() {
    let cases = [
        (
            format!("{}\n", "ab".repeat(31)),
            "invalid allowlist key on line 1",
        ),
        (
            format!("# c\n\n{}0\n", "ab".repeat(32)),
            "invalid allowlist key on line 3",
        ),
        (
            format!("02{}\n", "00".repeat(31)),
            "invalid allowlist key on line 1",
        ),
    ];
    for (text, expected) in cases {
        let path = file(&text);
        let error = read_allowlist(&path).await.unwrap_err();
        fs::remove_file(path).unwrap();
        assert_eq!(error, expected);
    }
    let oversized = file(&"#".repeat(256 * 66 + 1));
    let error = read_allowlist(&oversized).await.unwrap_err();
    fs::remove_file(oversized).unwrap();
    assert_eq!(error, "allowlist file exceeds 16896 bytes");
    let missing = std::env::temp_dir().join("shaar-guide-no-such-allowlist");
    assert_eq!(
        read_allowlist(&missing).await.unwrap_err(),
        "could not read allowlist"
    );
}
