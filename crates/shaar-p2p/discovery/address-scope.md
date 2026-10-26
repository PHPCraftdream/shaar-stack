# Fixed discovery address scope and complete-address grammar

Task 112 implements the pure constructor/classification leaf of
[destination-role-context.md](destination-role-context.md), against `bff80b5`.
It does not implement the role registry, DNS/native dial guards, Kademlia,
Identify, bootstrap, discovery commands, relay handoff, or SDK integration.
Public DNS remains behind the existing `NumericOnly` barrier.

## Policy and compatibility

`DiscoveryConfig::new` now rejects numeric seeds outside the fixed conservative
scope below, before any runtime, resolver, listener, or socket is created. This
intentionally tightens the foundation's acceptance of private numeric seeds.
Application destinations, explicitly requested relays, and configured numeric
nameservers do **not** inherit this policy. Private/loopback DNS nameservers and
custom ports retain their existing validation and support.

The profile rejects **every prefix in the reviewed IANA special-purpose
snapshots**, including entries marked `Globally Reachable=True`, expired entries,
and anycast services. There are no anycast exceptions. This deliberately trades
availability of special-purpose globally reachable services for a conservative,
deterministic first policy. There is no public mode or unsafe-address override.

This is fixed address-scope filtering, not a current allocation map, a reachability
check, dynamic OS routing policy, or protection against an administrator routing
globally numbered addresses internally. An accepted literal is not proof of a
reachable or trustworthy peer. A syntactically accepted DNS name is not approval
of its future answers. Later owner, DNS-expansion, and final numeric-connect
boundaries still need role authorization, this same scope check, and revocation.

### Reviewed sources

The supplied CSV bytes were treated as untrusted data, independently hash-checked,
and reviewed row by row. No downloaded code was executed. The review identifies
exact bytes, not an assumed registry publication date or a live-update promise.

| Registry | Official CSV | SHA-256 |
| --- | --- | --- |
| IPv4 | <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv> | `cbc4b7653c8bc640ba1e8e5d4ebbf11e7c7a1d867e7f1593aad001d3f8632aac` |
| IPv6 | <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv> | `bf56772aef97fbf9b4a27c98b8511f2bb1ba96da4b9ccc12ab203a2496faba66` |

There are 25 data rows in each snapshot. The IPv4 NAT64/DNS64 discovery row
contains two `/32` prefixes. Footnote markers are metadata, not address syntax.
The code contains no CSV parsing, file loading, source refresh, or added dependency.
A later registry change requires a reviewed source, explicit policy decision, and
updated independent regression vectors; it cannot silently change runtime policy.

### IPv4

Reject these disjoint covering prefixes; allow remaining IPv4 unicast:

- `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`.
- `169.254.0.0/16`, `172.16.0.0/12`.
- `192.0.0.0/24`, `192.0.2.0/24`, `192.31.196.0/24`, `192.52.193.0/24`.
- `192.88.99.0/24`, `192.168.0.0/16`, `192.175.48.0/24`.
- `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`.
- Multicast `224.0.0.0/4` and reserved `240.0.0.0/4`.

`0/8` subsumes the unspecified `/32`. `192.0.0/24` subsumes the service-continuity
`/29`, dummy `.8`, PCP `.9`, TURN `.10`, and NAT64/DNS64 `.170`/`.171` entries.
`192.88.99/24` subsumes `.2/32`; `240/4` subsumes limited broadcast. AS112, AMT,
PCP, TURN, and direct-delegation anycasts are intentionally denied. No blanket
last-octet `.0`/`.255` ban applies to the remaining global numbers: without a
subnet/routing contract those endings alone do not identify a broadcast address.

### IPv6

Allow only `2000::/3`, minus all reviewed overlapping special-purpose entries:

- `2001::/23` (including Teredo, PCP/TURN/DNS-SD anycasts, benchmarking, AMT,
  AS112-v6, deprecated ORCHID, ORCHIDv2, and DETs subentries).
- `2001:db8::/32` documentation.
- `2002::/16` 6to4.
- `2620:4f:8000::/48` direct-delegation AS112.
- `3fff::/20` documentation.

All addresses outside `2000::/3` are denied, including unspecified, loopback,
IPv4-compatible and IPv4-mapped forms (even mapped global IPv4), both reviewed
NAT64 translation prefixes, discard-only, dummy, SRv6 SIDs, ULA, link-local,
site-local, multicast, and otherwise reserved space. Zone components are not
part of the accepted grammar. IPv6 policy does not reinterpret mapped values as
ordinary IPv4 or exempt globally reachable translation services.

`src/discovery/scope.rs` uses constant octet/segment patterns with fixed ranges.
The covering prefixes remove redundant subprefix checks without exceptions.
There is no attacker-sized table, generic CIDR parser, or routing lookup. Scope
classification is O(1) time and space, independent of platform routes.

## Borrowed complete-address classifier

`src/discovery/address.rs::classify_complete` takes a borrowed complete byte slice
and an expected `PeerId`. It uses pinned `multiaddr 0.19.1`
`Protocol::from_bytes`, never a custom varint, protocol, IP-text, or PeerId parser.
The inspected upstream archive matches Cargo.lock SHA-256
`fd707c05eadfb37577f01cbec206726feeecf0b9edea259aee6fc9bc541ee253`.
The crate uses `libp2p 0.57.1` and Hickory `0.26.3` without dependency changes.

Accepted shapes are exactly:

```text
/ip4/IP/tcp/N/p2p/EXPECTED
/ip6/IP/tcp/N/p2p/EXPECTED
/dns/absolute-name./tcp/N/p2p/EXPECTED
/dns4/absolute-name./tcp/N/p2p/EXPECTED
/dns6/absolute-name./tcp/N/p2p/EXPECTED
/dnsaddr/absolute-name./p2p/EXPECTED
```

Every numeric IP must satisfy the scope above. TCP ports are nonzero. Encodings
are at most 256 bytes, with two components for DNSADDR or three for other forms.
Exactly one terminal expected peer is required; missing/wrong/repeated/interior
peer components, inherited prefixes, circuits, duplicate IP/TCP components,
unsupported transports, extra components, and trailing malformed bytes all fail
closed. The expected suffix is a grammar constraint, not identity authorization
or a substitute for Noise authentication.

DNS text must already be lowercase canonical absolute ASCII at the borrowed
boundary. Validation reuses the actual `discovery::absolute_name` and Hickory
`Name`; DNSADDR additionally validates the `_dnsaddr`-prefixed query name and its
253-character limit. It neither resolves names nor materializes an owned
`Multiaddr`, address `Vec`, or formatted address string. The returned host retains
borrowed DNS text from the input encoding. Hickory name parsing/normalization and
upstream malformed-input diagnostics can allocate: this is **not** a universal
zero-allocation claim. Work and name storage are bounded by the 256-byte input.

## Constructor consumes the same classifier

The constructor preserves uppercase-to-lowercase name normalization and the
optional consistent seed peer suffix. It serializes normalized protocols using
upstream `Protocol::write_bytes` into a fixed 256-byte stack buffer, adding the
expected suffix there when the input omits it. A fixed slice writer fails on
capacity exhaustion. Thus the budget includes the suffix Swarm will append:
a 257-byte fully qualified address fails even when its suffixless input fits.

The completed scratch encoding goes through `classify_complete`. Only its
validated host/port are used to construct the normalized descriptor retained in
config; an omitted suffix stays omitted in that descriptor. No second owned
address is materialized solely for inspection. Upstream P2p serialization may
allocate its PeerId byte representation; the scratch guarantee does not claim
that upstream serialization is allocation-free. Error messages remain static,
field-specific, and do not reproduce input addresses, names, or identities.

## Verification boundary

The separate `discovery_address_` selector adds **16 pure tests**, with a CI gate
requiring exactly 16 passing tests. Existing foundation 30, wire 29, prepared DNS
24, and SDK 58 selectors/counts are not changed. The sole existing behavioral
assertion changed is discovery's private numeric-seed acceptance, now rejection;
no application, explicit-relay, or nameserver assertion is weakened.

Added cases exercise actual encoded Multiaddr bytes and `DiscoveryConfig::new`:

- Every reviewed registry row, including nested and globally reachable entries,
  with independent inclusive-endpoint vectors and midpoint samples.
- Adjacent permitted global controls; multicast/reserved limits, mapped IPv6,
  outside-`2000::/3` rejection, and both admitted port boundaries.
- All six complete shapes, borrowed DNS results, constructor normalization,
  optional suffix preservation, wrong/missing/repeated/interior peers, inherited
  circuit/prefixes, extra components, zero/missing ports, and invalid names.
- Every proper byte-prefix truncation of numeric and DNSADDR controls; malformed
  protocol/length/UTF-8 bytes and malformed trailing data.
- Exact fully qualified 256/257-byte boundaries for every DNS form, both with
  and without a suffix in constructor input.
- Pure pre-runtime numeric-seed rejection with static field errors; private and
  loopback nameservers still accepted while identical seed IPs are rejected.

CI run `40286191559` at `eb3c361` passed the complete workflow on Linux and
Windows. All 16 address contracts and the preserved 29 wire, 30 foundation,
24 prepared DNS, and 58 SDK contracts were independently checked in actual logs.
Host-resolved dependency/feature and exact lock receipts remained unchanged.

No Cargo/rustc commands, compilation, builds, or tests were run locally, and no
public DNS/reachability probes were performed. Source inspection and standalone
formatting/syntax checks are not execution evidence. Later role/native/DNS
integration must supply its own pre-connect and pre-materialization proofs.
