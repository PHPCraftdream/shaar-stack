#![forbid(unsafe_code)]
// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{future::Future, net::SocketAddr};

use iroh_base::{EndpointId, SecretKey, TransportAddr};
use iroh_dns::endpoint_info::{EndpointData, EndpointInfo};
use iroh_mainline_address_lookup::{Builder as LookupBuilder, DhtAddressLookup};
use n0_mainline::{MutableItem, OwnedDhtHandle, OwnedPutOperation, ResourceError};
use shaar as _;

fn assert_address_lookup<T: iroh::address_lookup::AddressLookup>(_lookup: &T) {}

fn adapter_builder_uses_sdk_identity(key: SecretKey) {
    let _ = LookupBuilder::default().no_publish().secret_key(key);
}

fn endpoint_info(key: &SecretKey, address: SocketAddr) -> EndpointInfo {
    EndpointInfo::from_parts(
        EndpointId::from_bytes(key.public().as_bytes()).expect("valid public key bytes"),
        EndpointData::new(vec![TransportAddr::Ip(address)]),
    )
}

fn owned_put_type_witness(
    handle: &OwnedDhtHandle,
    item: MutableItem,
) -> impl Future<Output = Result<OwnedPutOperation, ResourceError>> + '_ {
    handle.put_mutable(item)
}

#[test]
fn timestamp_surface_accepts_boundaries_and_rejects_out_of_range() {
    let key = SecretKey::from_bytes(&[31; 32]);
    let info = endpoint_info(&key, "127.0.0.1:9000".parse().expect("socket address"));
    for timestamp in [0_u64, i64::MAX as u64] {
        let packet = info
            .to_pkarr_signed_packet_at(&key, 30, timestamp)
            .expect("in-range timestamp");
        assert_eq!(packet.timestamp().as_micros(), timestamp);
    }
    for timestamp in [i64::MAX as u64 + 1, u64::MAX] {
        assert!(info.to_pkarr_signed_packet_at(&key, 30, timestamp).is_err());
    }
    let other = SecretKey::from_bytes(&[32; 32]);
    assert!(info.to_pkarr_signed_packet_at(&other, 30, 1).is_err());
}

#[test]
fn normal_dependency_type_witnesses() {
    let key = SecretKey::from_bytes(&[31; 32]);
    adapter_builder_uses_sdk_identity(key);
    let _put_fn = owned_put_type_witness;
    let _assert_trait = assert_address_lookup::<DhtAddressLookup>;
}
