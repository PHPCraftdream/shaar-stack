//! `PeerKey` and `AllowList`: encodings, bounds and the allowlist file contract.

use libp2p_identity::PeerId;

use super::{FixtureDir, identity};
use crate::startup::facade::peers::{MAX_BYTES, MAX_ENTRIES};
use crate::startup::facade::{AllowList, AllowListError, KeyError, PeerKey};

// RFC 8032 section 7.1 test-vector 1 public key.
const RFC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn key(seed: u8) -> PeerKey {
    PeerKey::of(&identity(seed))
}

#[test]
fn a_key_prints_as_lowercase_hex_and_parses_in_either_case() {
    let lower: PeerKey = RFC_HEX.parse().unwrap();
    let upper: PeerKey = RFC_HEX.to_uppercase().parse().unwrap();
    assert_eq!(lower, upper);
    assert_eq!(lower.to_string(), RFC_HEX);
    assert_eq!(format!("{lower:?}"), format!("PeerKey({RFC_HEX})"));
    assert_eq!(lower.as_bytes()[0], 0xd7);
    assert_eq!(PeerKey::from_bytes(*lower.as_bytes()), Ok(lower));
}

#[test]
fn malformed_text_is_refused_without_echo() {
    for text in [
        "",
        "zz",
        &RFC_HEX[..63],
        &format!("{RFC_HEX}0"),
        "not a key at all",
    ] {
        let error = text.parse::<PeerKey>().unwrap_err();
        assert_eq!(error, KeyError::InvalidEncoding, "{text:?}");
        assert_eq!(error.to_string(), "invalid public key encoding");
    }
    assert_eq!(
        KeyError::NotAPublicKey.to_string(),
        "bytes are not an Ed25519 public key"
    );
}

#[test]
fn derived_forms_match_the_identity() {
    let identity = identity(7);
    let key = PeerKey::of(&identity);
    assert_eq!(PeerKey::from(&identity), key);
    assert_eq!(key.as_bytes(), &identity.public_key_bytes());
    let expected = PeerId::from_bytes(&identity.peer_id_bytes()).unwrap();
    assert_eq!(key.peer_id(), expected.to_string());
    assert_eq!(key.ygg_ip(), identity.ygg_address());
}

#[test]
fn keys_order_and_hash_by_their_bytes() {
    let mut keys = vec![key(3), key(1), key(2), key(1)];
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 3);
    assert!(
        keys.windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    );
    let set: std::collections::HashSet<_> = keys.iter().copied().collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn the_allowlist_file_format_is_parsed_with_comments_blanks_and_case() {
    let (a, b) = (key(1), key(2));
    let text = format!(
        "# clients\n\n  {a}  \n{}\n   # indented comment\n{b}\n{a}\n",
        b.to_string().to_uppercase()
    );
    let list = AllowList::parse(&text).unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.contains(&a) && list.contains(&b) && !list.contains(&key(3)));
    assert!(list.keys().windows(2).all(|pair| pair[0] < pair[1]));
    assert!(!list.is_empty());
    assert!(AllowList::parse("# nobody\n").unwrap().is_empty());
    assert_eq!(AllowList::empty(), AllowList::default());
}

#[test]
fn an_invalid_line_is_named_by_its_number_without_the_key_text() {
    let a = key(1);
    let text = format!("# one\n\n{a}\n{}\n", &RFC_HEX[..63]);
    let error = AllowList::parse(&text).unwrap_err();
    assert_eq!(error, AllowListError::InvalidLine(4));
    assert_eq!(error.to_string(), "invalid allowlist key on line 4");
    for bad in [format!("{a} trailing"), format!("{}g", &RFC_HEX[..63])] {
        assert_eq!(AllowList::parse(&bad), Err(AllowListError::InvalidLine(1)));
    }
}

#[test]
fn entry_and_byte_bounds_are_inclusive() {
    let keys: Vec<PeerKey> = (0..=255u8).map(key).collect();
    assert_eq!(keys.len(), MAX_ENTRIES);
    let lines: Vec<String> = keys.iter().map(ToString::to_string).collect();
    let text = lines.join(
        "
",
    );
    assert!(text.len() < MAX_BYTES);
    assert_eq!(AllowList::parse(&text).unwrap().len(), MAX_ENTRIES);
    assert_eq!(
        AllowList::new(keys.iter().copied()).unwrap().len(),
        MAX_ENTRIES
    );
    // A 257th entry exceeds the bound even when it repeats a key.
    let over = format!(
        "{text}
{}",
        lines[0]
    );
    assert_eq!(AllowList::parse(&over), Err(AllowListError::TooMany));
    assert_eq!(
        AllowList::new(keys.iter().copied().chain([keys[0]])),
        Err(AllowListError::TooMany)
    );
    assert_eq!(
        AllowListError::TooMany.to_string(),
        format!("allowlist exceeds {MAX_ENTRIES} entries")
    );
    assert_eq!(
        AllowList::parse(&"#".repeat(MAX_BYTES + 1)),
        Err(AllowListError::TooLarge)
    );
    assert!(AllowList::parse(&"#".repeat(MAX_BYTES)).unwrap().is_empty());
    assert_eq!(
        AllowListError::TooLarge.to_string(),
        format!("allowlist file exceeds {MAX_BYTES} bytes")
    );
}

#[tokio::test]
async fn reading_a_file_applies_the_same_rules_and_reports_a_missing_file() {
    let dir = FixtureDir::new();
    let a = key(1);
    let file = dir.0.join("allowed.txt");
    std::fs::write(&file, format!("# one client\n{a}\n")).unwrap();
    assert_eq!(AllowList::read(&file).await.unwrap().keys(), [a]);
    let big = dir.0.join("big.txt");
    std::fs::write(&big, "#".repeat(MAX_BYTES + 5)).unwrap();
    assert_eq!(AllowList::read(&big).await, Err(AllowListError::TooLarge));
    let error = AllowList::read(dir.0.join("missing.txt"))
        .await
        .unwrap_err();
    assert_eq!(error, AllowListError::Read);
    assert_eq!(error.to_string(), "could not read allowlist");
}

#[test]
fn the_network_list_carries_every_distinct_key() {
    let list = AllowList::new([key(2), key(1), key(2)]).unwrap();
    assert_eq!(list.len(), 2);
    let network = list.to_network();
    let again = AllowList::new(network.keys().map(PeerKey::from_iroh)).unwrap();
    assert_eq!(again, list);
}

#[test]
fn a_key_summary_has_the_three_derived_forms() {
    let key = key(9);
    let [public, peer, ygg] = key.summary_lines();
    assert_eq!(public, format!("public_key={key}"));
    assert_eq!(peer, format!("peer_id={}", key.peer_id()));
    assert_eq!(ygg, format!("ygg_ip={}", key.ygg_ip()));
}

#[test]
fn adding_a_key_appends_one_line_and_keeps_everything_else() {
    let (a, b) = (key(1), key(2));
    let text = format!("# clients\n{a}");
    let added = AllowList::text_with(&text, &b).unwrap().unwrap();
    assert_eq!(added, format!("# clients\n{a}\n{b}\n"));
    // Already listed, in either case: nothing to change.
    assert_eq!(AllowList::text_with(&added, &b), Ok(None));
    assert_eq!(
        AllowList::text_with(&format!("{}\n", a.to_string().to_uppercase()), &a),
        Ok(None)
    );
    // An empty file gets the key as its first line.
    assert_eq!(
        AllowList::text_with("", &a).unwrap().unwrap(),
        format!("{a}\n")
    );
    // A file that is already invalid is refused instead of being extended.
    assert_eq!(
        AllowList::text_with("not a key\n", &a),
        Err(AllowListError::InvalidLine(1))
    );
}

#[test]
fn adding_beyond_the_entry_bound_is_refused() {
    let keys: Vec<PeerKey> = (0..=255u8).map(key).collect();
    let text: String = keys.iter().map(|k| format!("{k}\n")).collect();
    assert_eq!(AllowList::parse(&text).unwrap().len(), MAX_ENTRIES);
    let one_more = PeerKey::of(&identity(255));
    assert_eq!(
        AllowList::text_with(&text, &one_more),
        Ok(None),
        "already listed"
    );
    let mut full = text.clone();
    full.push_str(&format!("{}\n", keys[0]));
    assert_eq!(
        AllowList::text_with(&full, &key(7)),
        Err(AllowListError::TooMany),
        "duplicates count as entries"
    );
}

#[test]
fn removing_a_key_drops_its_lines_only() {
    let (a, b) = (key(1), key(2));
    let text = format!(
        "# one\n{a}\n\n# two\n{}\n{b}\n{a}\n",
        b.to_string().to_uppercase()
    );
    let removed = AllowList::text_without(&text, &b).unwrap().unwrap();
    assert_eq!(removed, format!("# one\n{a}\n\n# two\n{a}\n"));
    assert_eq!(AllowList::text_without(&removed, &b), Ok(None));
    let last = AllowList::text_without(&format!("{a}"), &a)
        .unwrap()
        .unwrap();
    assert_eq!(last, "");
    // A comment that mentions the key is not a listing.
    let commented = format!("# {a}\n{b}\n");
    assert_eq!(AllowList::text_without(&commented, &a), Ok(None));
    assert_eq!(
        AllowList::text_without("garbage\n", &a),
        Err(AllowListError::InvalidLine(1))
    );
}

#[tokio::test]
async fn the_allow_command_lists_adds_and_removes_through_the_file() {
    use crate::startup::facade::{AllowAction, allowlist_command};
    let dir = FixtureDir::new();
    let path = dir.0.join("allowed.txt");
    std::fs::write(&path, "# clients\n").unwrap();
    let (a, b) = (key(1), key(2));

    let listed = allowlist_command(&path, AllowAction::List).await.unwrap();
    assert_eq!(listed, ["clients=0"]);
    let added = allowlist_command(&path, AllowAction::Add(vec![a, b, a]))
        .await
        .unwrap();
    assert_eq!(added[0], format!("added: {a}"));
    assert_eq!(added[1], format!("added: {b}"));
    assert_eq!(added[2], format!("already listed: {a}"));
    assert!(
        added[3].starts_with("note: restart the server"),
        "{added:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("# clients\n{a}\n{b}\n")
    );
    assert_eq!(
        std::fs::read_to_string(dir.0.join("allowed.txt.bak")).unwrap(),
        "# clients\n"
    );
    let listed = allowlist_command(&path, AllowAction::List).await.unwrap();
    assert_eq!(
        listed,
        [a.to_string(), b.to_string(), "clients=2".to_owned()]
    );

    let removed = allowlist_command(&path, AllowAction::Remove(vec![a, key(3)]))
        .await
        .unwrap();
    assert_eq!(removed[0], format!("removed: {a}"));
    assert_eq!(removed[1], format!("not listed: {}", key(3)));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("# clients\n{b}\n")
    );
    // Nothing to change: the file and its backup stay as they are.
    let before = std::fs::read(dir.0.join("allowed.txt.bak")).unwrap();
    let noop = allowlist_command(&path, AllowAction::Remove(vec![a]))
        .await
        .unwrap();
    assert_eq!(noop, [format!("not listed: {a}")]);
    assert_eq!(
        std::fs::read(dir.0.join("allowed.txt.bak")).unwrap(),
        before
    );

    let missing = allowlist_command(&dir.0.join("none.txt"), AllowAction::List)
        .await
        .unwrap_err();
    assert_eq!(missing, "could not read allowlist");
}
