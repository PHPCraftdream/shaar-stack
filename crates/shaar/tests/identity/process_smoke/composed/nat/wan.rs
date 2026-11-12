//! Owned WAN services using the same DHT codec, relay and safe Ygg backend as other cases.

#![forbid(unsafe_code)]

use super::*;
use std::fmt::Write as _;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// cancel-safe: NO — the supervisor owns this helper PID and classifies abnormal cleanup separately.
pub(super) async fn run(nonce: &str) -> Result<(), String> {
    let expected = public_key(&std::env::var("SHAAR_NAT_SERVICE_KEY").map_err(|e| e.to_string())?)?;
    let peer = mainline_fixture::LoopbackPeer::bind_namespace().await;
    let dht_port = peer.address.port();
    let relay = timeout(IO_TIMEOUT, relay_fixture::RelayFixture::start_namespace())
        .await
        .map_err(|_| "namespace relay startup deadline".to_owned())?;
    let peer_id = relay.address.peer_id().to_string();
    if !peer_id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        timeout(IO_TIMEOUT, relay.close())
            .await
            .map_err(|_| "namespace relay rollback deadline")?;
        return Err("unexpected relay identity encoding".to_owned());
    }
    let (transit, transit_port) = match timeout(Duration::from_secs(30), start_transit()).await {
        Ok(Ok(value)) => value,
        _ => {
            timeout(IO_TIMEOUT, relay.close())
                .await
                .map_err(|_| "namespace relay rollback deadline")?;
            return Err("namespace Ygg transit startup failed or expired".to_owned());
        }
    };
    let control = match TcpListener::bind("127.0.0.1:0").await {
        Ok(value) => value,
        Err(error) => {
            let (relay_close, transit_close) = tokio::join!(
                timeout(IO_TIMEOUT, relay.close()),
                timeout(Duration::from_secs(30), transit.close()),
            );
            relay_close.map_err(|_| format!("namespace relay rollback expired after {error}"))?;
            transit_close
                .map_err(|_| format!("namespace transit rollback expired after {error}"))?
                .map_err(|close| {
                    format!("namespace transit rollback failed after {error}: {close}")
                })?;
            return Err(error.to_string());
        }
    };
    let control_port = control.local_addr().map_err(|e| e.to_string())?.port();
    let relay_port = relay.address.socket_addr().port();
    let (record, records) = watch::channel::<Option<Arc<mainline_fixture::CapturedPut>>>(None);
    let (publications, mut observed) = mpsc::channel(8);
    let mut tasks = JoinSet::new();
    // Exactly one retained wire actor; this helper never spawns per query.
    tasks.spawn(async move {
        peer.serve_composed(records, publications, None).await;
    });
    // All strings are fixed labels, validated nonce/base58 or typed numeric fields.
    println!(
        "SHAAR_NAT_READY {{\"role\":\"wan\",\"nonce\":\"{nonce}\",\"pid\":{},\"dht_port\":{dht_port},\"relay_port\":{relay_port},\"relay_peer\":\"{peer_id}\",\"transit_port\":{transit_port},\"control_port\":{control_port}}}",
        std::process::id()
    );
    let outcome = timeout(Duration::from_secs(110), async {
        loop {
            tokio::select! {
                accepted = control.accept() => {
                    let (stream, address) = accepted.map_err(|e| e.to_string())?;
                    if !address.ip().is_loopback() {
                        return Err("namespace control source was not loopback".to_owned());
                    }
                    stop_command(stream, nonce).await?;
                    return Ok::<(), String>(());
                }
                item = observed.recv() => {
                    let item = item.ok_or("namespace publication actor ended")?;
                    if item.key == expected {
                        publication(nonce, &item)?;
                        record.send(Some(item)).map_err(|e| e.to_string())?;
                    }
                }
                result = tasks.join_next() => {
                    return Err(format!("namespace wire actor ended unexpectedly: {result:?}"));
                }
            }
        }
    })
    .await
    .map_err(|_| "namespace WAN helper lifetime deadline".to_owned())
    .and_then(|value| value);
    tasks.abort_all();
    let mut wire_error = None;
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            wire_error = Some(format!("namespace wire actor join failed: {error}"));
        }
    }
    let relay_close = timeout(IO_TIMEOUT, relay.close()).await;
    let transit_close = timeout(Duration::from_secs(30), transit.close()).await;
    outcome?;
    if let Some(error) = wire_error {
        return Err(error);
    }
    relay_close.map_err(|_| "namespace relay joined close deadline")?;
    transit_close
        .map_err(|_| "namespace Ygg joined close deadline")?
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn publication(nonce: &str, item: &mainline_fixture::CapturedPut) -> Result<(), String> {
    let packet = item.signed_packet();
    let info = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&packet)
        .map_err(|e| e.to_string())?;
    let mut addresses = String::with_capacity(256);
    for (index, address) in info.ip_addrs().take(4).enumerate() {
        if index != 0 {
            addresses.push(',');
        }
        write!(&mut addresses, "\"{address}\"").expect("bounded socket-address formatting");
    }
    let envelope = hex(&item.signed_envelope());
    // Hex and SocketAddr text cannot contain JSON escapes; no arbitrary text is encoded.
    println!(
        "SHAAR_NAT_PUBLICATION {{\"nonce\":\"{nonce}\",\"sequence\":{},\"signed_envelope_hex\":\"{envelope}\",\"native_addresses\":[{addresses}]}}",
        item.sequence
    );
    Ok(())
}

/// cancel-safe: NO — terminal startup failure is classified by the owned helper process supervisor.
async fn start_transit() -> Result<(YggTransport, u16), String> {
    for _ in 0..4 {
        let listener = TcpListener::bind("203.0.113.10:0")
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        drop(listener);
        let config = YggConfig {
            seed: [0x94; 32],
            listen: vec![format!("tcp://203.0.113.10:{port}")],
            peers: Vec::new(),
            allowed_public_keys: Vec::new(),
            group_password: None,
        };
        match YggTransport::start(config).await {
            Ok(transport) => return Ok((transport, port)),
            Err(YggError::Start { .. }) => tokio::time::sleep(Duration::from_millis(20)).await,
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("namespace transit bind retries exhausted".to_owned())
}
