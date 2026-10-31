#![forbid(unsafe_code)]
//! Generated SDK-private integration case; no raw connection API is exported by the product.

use super::*;
use futures::FutureExt;
use shaar_p2p::{DiscoveryConfig, Route, carrier_frame_probe as capture};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::File,
    io::Read,
    ops::Bound,
    path::{Path, PathBuf},
};

#[path = "wire_oracle.rs"]
mod wire_oracle;

fn parse_fin_packets(path: &Path) -> Result<(BTreeMap<Vec<u8>, Vec<bool>>, usize), &'static str> {
    const MAX_TRACE: u64 = 16 * 1024 * 1024;
    const MAX_PACKET: usize = 65535;
    const MAX_RECORDS: usize = 1024;
    let mut input = Vec::new();
    File::open(path)
        .map_err(|_| "qlog open failed")?
        .take(MAX_TRACE + 1)
        .read_to_end(&mut input)
        .map_err(|_| "qlog read failed")?;
    if input.len() as u64 > MAX_TRACE {
        return Err("qlog limit");
    }
    let mut packets = BTreeMap::new();
    let mut stream_count = 0;
    for record in input.split(|byte| *byte == 0x1e) {
        for line in record
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        {
            let event: serde_json::Value =
                serde_json::from_slice(line).map_err(|_| "invalid qlog JSON")?;
            if event["name"] != "quic:packet_sent" {
                continue;
            }
            let raw = &event["data"]["raw"];
            let encoded = raw["data"].as_str().ok_or("missing packet ciphertext")?;
            if encoded.is_empty() || encoded.len() % 2 != 0 || encoded.len() / 2 > MAX_PACKET {
                return Err("invalid packet ciphertext length");
            }
            let bytes: Vec<u8> = encoded
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let text = std::str::from_utf8(pair).map_err(|_| "invalid packet hex")?;
                    u8::from_str_radix(text, 16).map_err(|_| "invalid packet hex")
                })
                .collect::<Result<_, _>>()?;
            if raw["length"].as_u64() != Some(bytes.len() as u64) {
                return Err("packet length mismatch");
            }
            let frames = event["data"]["frames"]
                .as_array()
                .ok_or("missing decoded frames")?;
            let fins = stream_fins(frames)?;
            stream_count += fins.len();
            if packets.len() == MAX_RECORDS || packets.insert(bytes, fins).is_some() {
                return Err("duplicate or excessive qlog packet record");
            }
        }
    }
    if packets.is_empty() {
        return Err("no packet records");
    }
    Ok((packets, stream_count))
}

fn observe_fins(
    packets: &BTreeMap<Vec<u8>, Vec<bool>>,
    captured: &[&[u8]],
) -> Result<(usize, usize), &'static str> {
    const MAX_PACKET: usize = 65535;
    let mut seen = std::collections::BTreeSet::<&[u8]>::new();
    let mut observed_fin = 0usize;
    let mut observed_stream = 0usize;
    for datagram in captured {
        if datagram.is_empty() || datagram.len() > MAX_PACKET {
            return Err("invalid captured datagram");
        }
        let mut remaining = *datagram;
        while !remaining.is_empty() {
            let (packet, fins) = packets
                .range::<[u8], _>((Bound::Unbounded, Bound::Included(remaining)))
                .next_back()
                .ok_or("captured ciphertext absent from qlog")?;
            if !remaining.starts_with(packet) {
                return Err("captured ciphertext mismatch");
            }
            if !seen.insert(packet.as_slice()) {
                return Err("duplicate captured qlog packet");
            }
            observed_stream += fins.len();
            observed_fin += fins.iter().filter(|fin| **fin).count();
            remaining = &remaining[packet.len()..];
        }
    }
    Ok((observed_stream, observed_fin))
}

#[cfg(test)]
mod supplement_controls {
    use super::*;

    #[test]
    fn malformed_or_absent_fin_metadata_is_rejected() {
        for input in [
            r#"[{"frame_type":"stream"}]"#,
            r#"[{"frame_type":"stream","fin":null}]"#,
            r#"[{"frame_type":"stream","fin":1}]"#,
        ] {
            let frames: Vec<serde_json::Value> = serde_json::from_str(input).unwrap();
            assert!(stream_fins(&frames).is_err());
        }
        let frames: Vec<serde_json::Value> =
            serde_json::from_str(r#"[ {"frame_type":"stream","fin":true} ]"#).unwrap();
        let packet_identities = BTreeMap::from([(vec![1, 2], vec![true])]);
        assert!(observe_fins(&packet_identities, &[&[1, 2], &[1, 2]]).is_err());
        assert_eq!(stream_fins(&frames).unwrap(), [true]);
    }
}

fn prefix(identity: &Identity) -> String {
    let mut result = String::with_capacity(64);
    for byte in identity.public_key_bytes() {
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}

fn discovery() -> DiscoveryConfig {
    let seed = Identity::generate();
    DiscoveryConfig::new(
        vec![(
            peer_id(&public(&seed)).unwrap(),
            "/dns4/unused.example./tcp/4001".parse().unwrap(),
        )],
        vec!["127.0.0.1:53".parse().unwrap()],
    )
    .unwrap()
}

fn stream_fins(frames: &[serde_json::Value]) -> Result<Vec<bool>, &'static str> {
    let mut fins = Vec::new();
    for frame in frames {
        if frame["frame_type"] == "stream" {
            fins.push(
                frame["fin"]
                    .as_bool()
                    .ok_or("missing/nonboolean stream FIN")?,
            );
        }
    }
    Ok(fins)
}

fn trace(directory: &Path, prefix: &str) -> PathBuf {
    let files: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "qlog")
        })
        .collect();
    assert!(files.len() <= 4, "unexpected connection trace count");
    let selected: Vec<_> = files
        .into_iter()
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(prefix)
        })
        .collect();
    assert_eq!(
        selected.len(),
        1,
        "one original authenticated connection trace per endpoint"
    );
    selected.into_iter().next().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn carrier_frames_actual_relay_bootstrap_and_payload_policy() {
    let phase = std::cell::Cell::new("scenario startup");
    let input = tokio::time::timeout(Duration::from_secs(25), scenario(&phase))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "real-carrier frame phase deadline: {error}; phase={}",
                phase.get()
            )
        });
    verify(input).await;
}

struct VerificationInput {
    allowed: bool,
    directory: PathBuf,
    names: [String; 2],
    scopes: [capture::Scope; 2],
    transcript: capture::Transcript,
}

/// cancel-safe: NO — timeout fails the case; joined cleanup is required on successful completion.
async fn scenario(phase: &std::cell::Cell<&'static str>) -> VerificationInput {
    let allowed = match std::env::var("SHAAR_CARRIER_FRAME_POLICY")
        .unwrap()
        .as_str()
    {
        "strict" => false,
        "allow-all" => true,
        _ => panic!("unknown frame fixture policy"),
    };
    let directory = PathBuf::from(std::env::var_os("SHAAR_CARRIER_FRAME_TRACE").unwrap());
    let ai = Identity::generate();
    let bi = Identity::generate();
    let ap = peer_id(&public(&ai)).unwrap();
    let bp = peer_id(&public(&bi)).unwrap();
    phase.set("start relay fixture");
    let relay = relay_fixture::RelayFixture::start().await;
    phase.set("bind endpoint A");
    let a = SignaledEndpoint::bind_with_discovery(
        &ai,
        loopback(),
        loopback(),
        &[public(&bi)],
        Limits::default(),
        discovery(),
    )
    .await
    .unwrap();
    phase.set("bind endpoint B");
    let b = SignaledEndpoint::bind_with_discovery(
        &bi,
        loopback(),
        loopback(),
        &[public(&ai)],
        Limits::default(),
        discovery(),
    )
    .await
    .unwrap();
    let native = [a.local_addr(), b.local_addr()];
    let signaling = [a.signaling_addr(), b.signaling_addr()];
    phase.set("reserve relay");
    let lease = b.reserve_relay(relay.address).await.unwrap();
    assert_eq!(lease.relay(), relay.address);
    phase.set("connect via relay and wait link");
    let connection = a
        .signaling
        .handle
        .connect_via(bp, relay.address)
        .await
        .unwrap();
    let mut incoming_links = b.signaling.handle.links();
    incoming_links
        .wait_for(|links| links.iter().any(|link| link.peer == ap))
        .await
        .unwrap();
    let aa = a.signaling.factory.peer_address(bp).unwrap();
    let ba = b.signaling.factory.peer_address(ap).unwrap();
    let al = a.signaling.factory.authenticated_link(&aa).unwrap();
    let bl = b.signaling.factory.authenticated_link(&ba).unwrap();
    assert_eq!(al.connection, connection);
    assert!(
        matches!(al.route, Route::Relayed { relay: Some(peer), generation } if peer == relay.address.peer_id() && generation != 0)
    );
    assert!(
        matches!(bl.route, Route::Relayed { relay: Some(peer), generation } if peer == relay.address.peer_id() && generation != 0)
    );
    let scopes = [
        capture::Scope::observed(ap, al, &aa).unwrap(),
        capture::Scope::observed(bp, bl, &ba).unwrap(),
    ];
    capture::arm(scopes).unwrap();
    let accepted = async {
        b.endpoint
            .carrier_frame_raw()
            .accept()
            .await
            .unwrap()
            .await
            .unwrap()
    };
    phase.set("connect and accept carrier");
    let (outgoing, incoming) = tokio::join!(
        a.endpoint.carrier_frame_raw().connect(
            EndpointAddr::from_parts(b.id(), [TransportAddr::Custom(aa.clone())]),
            ALPN
        ),
        accepted,
    );
    let outgoing = outgoing.unwrap();
    assert_eq!(outgoing.remote_id(), b.id());
    assert_eq!(incoming.remote_id(), a.id());
    let original = [outgoing.stable_id(), incoming.stable_id()];
    phase.set("open streams and send payloads");
    let (mut sa, ra) = outgoing.open_bi().await.unwrap();
    let (mut sb, rb) = incoming.open_bi().await.unwrap();
    sa.write_all(b"frameapp").await.unwrap();
    sb.write_all(b"frameapp").await.unwrap();
    sa.finish().unwrap();
    sb.finish().unwrap();
    if allowed {
        // Complete both reliable deliveries before exercising DATAGRAMs.
        for (index, receiver) in [&outgoing, &incoming].into_iter().enumerate() {
            phase.set(if index == 0 {
                "allow-all accept A"
            } else {
                "allow-all accept B"
            });
            let (_send, mut receive) = receiver.accept_bi().await.unwrap();
            phase.set(if index == 0 {
                "allow-all read STREAM A"
            } else {
                "allow-all read STREAM B"
            });
            assert_eq!(receive.read_to_end(8).await.unwrap(), b"frameapp");
        }
        phase.set("allow-all send bounded DATAGRAMs");
        outgoing.send_datagram(b"frameapp".to_vec().into()).unwrap();
        incoming.send_datagram(b"frameapp".to_vec().into()).unwrap();
        for (index, receiver) in [&outgoing, &incoming].into_iter().enumerate() {
            phase.set(if index == 0 {
                "allow-all read DATAGRAM A"
            } else {
                "allow-all read DATAGRAM B"
            });
            assert_eq!(
                receiver.read_datagram().await.unwrap(),
                b"frameapp".as_slice()
            );
        }
    } else {
        // Keep strict mode adversarial: queue STREAM+FIN and DATAGRAM work
        // together, then verify policy exclusion and ongoing control traffic.
        outgoing.send_datagram(b"frameapp".to_vec().into()).unwrap();
        incoming.send_datagram(b"frameapp".to_vec().into()).unwrap();
        let before = [
            capture::count(scopes[0]).unwrap(),
            capture::count(scopes[1]).unwrap(),
        ];
        let (left, right) = tokio::join!(
            capture::wait_after(scopes[0], before[0]),
            capture::wait_after(scopes[1], before[1])
        );
        assert!(
            left.unwrap() > before[0] && right.unwrap() > before[1],
            "real custom control must continue"
        );
        assert!(outgoing.accept_bi().now_or_never().is_none());
        assert!(incoming.accept_bi().now_or_never().is_none());
        assert!(outgoing.read_datagram().now_or_never().is_none());
        assert!(incoming.read_datagram().now_or_never().is_none());
    }
    assert_eq!([outgoing.stable_id(), incoming.stable_id()], original);
    outgoing.close(0u32.into(), b"frame proof complete");
    drop((sa, sb, ra, rb));
    let retained = [a.signaling.factory.clone(), b.signaling.factory.clone()];
    let retained_addresses = [aa.clone(), ba.clone()];
    phase.set("joined endpoint close");
    let (closed_a, closed_b) = tokio::join!(a.close(), b.close());
    closed_a.unwrap();
    closed_b.unwrap();
    phase.set("relay close");
    relay.close().await;
    let transcript = capture::finish().unwrap();
    phase.set("native UDP rebind");
    for address in native {
        drop(UdpSocket::bind(address).await.unwrap());
    }
    phase.set("signaling TCP rebind");
    for address in signaling {
        drop(TcpListener::bind(address).await.unwrap());
    }
    assert!(
        retained[0]
            .authenticated_link(&retained_addresses[0])
            .is_err()
    );
    assert!(
        retained[1]
            .authenticated_link(&retained_addresses[1])
            .is_err()
    );
    drop((retained, outgoing, incoming));
    let names = [prefix(&ai), prefix(&bi)];
    VerificationInput {
        allowed,
        directory,
        names,
        scopes,
        transcript,
    }
}

async fn verify(input: VerificationInput) {
    let VerificationInput {
        allowed,
        directory,
        names,
        scopes,
        transcript,
    } = input;
    tokio::task::spawn_blocking(move || {
        for sender in 0..2 {
            let qlog = trace(&directory, &names[sender]);
            let (packets, qlog_streams) = parse_fin_packets(&qlog).unwrap();
            if allowed {
                assert!(qlog_streams > 0, "allow-all qlog must include STREAM metadata");
            } else {
                assert_eq!(qlog_streams, 0, "strict fixture qlog contains application STREAM frames");
            }
            let index = wire_oracle::Index::parse_file(&qlog).unwrap();
            let mut seen = index.seen();
            let mut frames = wire_oracle::Counts::default();
            for packet in &transcript.packets {
                let scope = transcript.scopes[packet.scope].unwrap();
                if scope.side == 1 - sender {
                    assert_eq!(scope.identity, scopes[1 - sender]);
                    frames.add(index.observe(packet.as_bytes(), &mut seen).expect("complete actual-carrier ciphertext correlation"));
                }
            }
            assert!(frames.packets > 0, "actual authenticated carrier observations required");
            let mut captured = Vec::new();
            for packet in &transcript.packets {
                let scope = transcript.scopes[packet.scope].unwrap();
                if scope.side == 1 - sender {
                    assert_eq!(scope.identity, scopes[1 - sender]);
                    captured.push(packet.as_bytes());
                }
            }
            let (streams, fins) = observe_fins(&packets, &captured).unwrap();
            if allowed {
                assert!(frames.streams > 0 && frames.datagrams > 0, "actual-carrier allow-all sensitivity required in both directions");
                assert!(streams > 0 && fins > 0, "actual-carrier STREAM and FIN sensitivity required in both directions");
            } else {
                assert_eq!(frames.streams, 0, "actual carrier STREAM escape");
                assert_eq!(frames.datagrams, 0, "actual carrier DATAGRAM escape");
                assert_eq!(streams, 0, "strict qlog metadata contains application STREAM frames");
                assert_eq!(fins, 0, "strict qlog metadata contains application FIN frames");
            }
            let missing = index.unobserved(&seen);
            assert_eq!(missing.streams, 0, "unobserved payload cannot be classified away");
            assert_eq!(missing.datagrams, 0, "unobserved payload cannot be classified away");
            eprintln!("real carrier sender={sender} allow_all={allowed} observed={frames:?} constructed_not_observed={missing:?}");
        }
    }).await.unwrap();
}
