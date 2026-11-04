#![forbid(unsafe_code)]
use libp2p::{
    Multiaddr, PeerId,
    multiaddr::{Protocol, multihash::Multihash},
};

// The emoji alphabet of the removed base256emoji crate starts with
// rocket, ringed planet, comet; its symbol values are 0, 1, 2.
const EMOJI_CODE: &str = "\u{1F680}";
const EMOJI_ONE: &str = "\u{1FA90}";

fn identity_multihash_peer() -> PeerId {
    // Identity multihash 0x0001 0x01; its base58btc text is derived in the tests.
    PeerId::from_bytes(&[0x00, 0x01, 0x01]).unwrap()
}

#[test]
fn multibase_base58btc_peer_id_text_known_answer() {
    let subject = identity_multihash_peer();
    // base58btc([0x00, 0x01, 0x01]): the leading zero byte maps to '1', and the
    // nonzero tail 0x0101 = 257 = 4*58 + 25 gives digits 4, 25 -> '5', 'S'.
    assert_eq!(subject.to_string(), "15S");
    assert_eq!("15S".parse::<PeerId>().unwrap(), subject);
}

#[test]
fn multibase_base58_p2p_multiaddr_text_and_binary_known_answer() {
    let subject = identity_multihash_peer();
    let text = format!("/p2p/{subject}");
    let address: Multiaddr = text.parse().unwrap();
    assert!(matches!(address.iter().next(), Some(Protocol::P2p(id)) if id == subject));
    assert_eq!(address.to_string(), text);
    // P2P 421 varint-encodes as [0xa5, 0x03]; the multihash is 3 bytes.
    assert_eq!(address.as_ref(), &[0xa5, 0x03, 0x03, 0x00, 0x01, 0x01]);
    assert_eq!(
        Multiaddr::empty().with(Protocol::P2p(subject)).as_ref(),
        address.as_ref()
    );
}

#[test]
fn multibase_base58_z_decode_known_answer_and_roundtrip() {
    let address: Multiaddr = "/certhash/z15TJUr".parse().unwrap();
    match address.iter().next() {
        Some(Protocol::Certhash(hash)) => {
            // base58btc("15TJUr"): leading zero -> '1'; 0x03010203 = 50397699
            // = 4*58^4 + 26*58^3 + 17*58^2 + 27*58 + 49 -> '5','T','J','U','r'.
            assert_eq!(hash.to_bytes(), vec![0x00, 0x03, 0x01, 0x02, 0x03]);
        }
        _ => panic!("MULTIBASE_Z_PAYLOAD_MUST_DECODE"),
    }
    // The interior zero byte of the payload survives the base58btc decode.
    let zeroed: Multiaddr = "/certhash/z1fxz".parse().unwrap();
    match zeroed.iter().next() {
        Some(Protocol::Certhash(hash)) => {
            assert_eq!(hash.to_bytes(), vec![0x00, 0x02, 0x00, 0x07]);
        }
        _ => panic!("MULTIBASE_ZERO_PREFIX_MUST_SURVIVE"),
    }
    // base58btc("1fxz"): leading zero -> '1'; 0x020007 = 131079
    // = 38*58^2 + 55*58 + 57 -> 'f','x','z'.
    // Canonical display re-encodes through the multibase Base64Url route and reparses.
    let canonical = address.to_string();
    assert!(canonical.starts_with("/certhash/u"));
    assert_eq!(canonical.parse::<Multiaddr>().unwrap(), address);
    assert_eq!(zeroed.to_string().parse::<Multiaddr>().unwrap(), zeroed);
    // CERTHASH 466 varint-encodes as [0xd2, 0x03]; length 5 varint-encodes as [0x05].
    assert_eq!(
        address.as_ref(),
        &[0xd2, 0x03, 0x05, 0x00, 0x03, 0x01, 0x02, 0x03]
    );
    // Arbitrary multihash bytes round-trip without a hand-computed alphabet answer.
    let arbitrary = Multihash::wrap(0x12, &(1..=32u8).collect::<Vec<u8>>()).unwrap();
    let built = Multiaddr::empty().with(Protocol::Certhash(arbitrary));
    assert_eq!(built.as_ref()[..2], [0xd2, 0x03]);
    assert_eq!(built.to_string().parse::<Multiaddr>().unwrap(), built);
}

#[test]
fn multibase_base58_rejects_empty_malformed_and_emoji_prefix() {
    // Empty base58btc payload decodes successfully upstream; the observed
    // rejection comes from the multihash layer (empty bytes are no multihash),
    // and successful empty-base58 decoding is not observable via multiaddr.
    assert!("/certhash/z".parse::<Multiaddr>().is_err());
    // Characters outside the base58btc alphabet are rejected.
    assert!("/certhash/z0OIl".parse::<Multiaddr>().is_err());
    // A payload without a known multibase code char is rejected.
    assert!("/certhash/15TJUr".parse::<Multiaddr>().is_err());
    // EMOJI_CODE + EMOJI_CODE + EMOJI_ONE + EMOJI_ONE is the rocket code char
    // followed by the payload emoji payload, which the upstream emoji alphabet
    // maps to the bytes [0x00, 0x01, 0x01] - a complete identity multihash.
    // Before the reviewed patch this string parsed successfully as a certhash;
    // removing Base256Emoji must make the prefix decisively unknown again.
    let emoji_multihash = format!("/certhash/{EMOJI_CODE}{EMOJI_CODE}{EMOJI_ONE}{EMOJI_ONE}");
    assert!(emoji_multihash.parse::<Multiaddr>().is_err());
}

#[test]
fn multibase_base58_garlic64_base64_decode_is_preserved() {
    // 420 zero bytes encode as 560 padding-free 'A' characters, inside the
    // reviewed 516..=616 length window; this exercises multiaddr's Base64 path.
    let address: Multiaddr = format!("/garlic64/{}", "A".repeat(560)).parse().unwrap();
    assert!(matches!(address.iter().next(),
        Some(Protocol::Garlic64(bytes))
        if bytes.len() == 420 && bytes.iter().all(|byte| *byte == 0)));
    // Binary form: code 446 varint [0xbe, 0x03], length 420 varint [0xa4, 0x03].
    assert_eq!(address.as_ref()[..4], [0xbe, 0x03, 0xa4, 0x03]);
    assert_eq!(address.as_ref().len(), 424);
    assert_eq!(address.to_string().parse::<Multiaddr>().unwrap(), address);
}

#[test]
fn multibase_base58_garlic32_base32_decode_is_preserved() {
    // 35 zero bytes encode as 56 'a' characters (five bits each), which the
    // reviewed parser accepts (length >= 55); this exercises Base32Lower.
    let address: Multiaddr = format!("/garlic32/{}", "a".repeat(56)).parse().unwrap();
    assert!(matches!(address.iter().next(),
        Some(Protocol::Garlic32(bytes))
        if bytes.len() == 35 && bytes.iter().all(|byte| *byte == 0)));
    // Binary form: code 447 varint [0xbf, 0x03], length 35 varint [0x23].
    assert_eq!(address.as_ref()[..3], [0xbf, 0x03, 0x23]);
    assert_eq!(address.as_ref().len(), 38);
    assert_eq!(address.to_string().parse::<Multiaddr>().unwrap(), address);
}
