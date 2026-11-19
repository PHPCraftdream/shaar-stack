//! Network section of generated configuration files.
//!
//! `Public` files carry the bootstrap hosts and Yggdrasil peers of the
//! recorded public smoke contract (owner decision 2026-11-17); `Private`
//! files stay direct-only. Nothing here contacts a network.

/// Network shape of a generated configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkChoice {
    /// Direct-only file without a `network` object (the legacy first run).
    #[default]
    Private,
    /// Composed file with public Mainline bootstrap hosts and Yggdrasil peers.
    Public,
}

/// The `network` object written for [`NetworkChoice::Public`], with its comments.
pub fn public_network_text() -> &'static str {
    "## Public networks, written by init (use --private for a direct-only file).\n\
     ## The Server publishes a signed record in the Mainline DHT and the Client finds\n\
     ## it by the Server key alone; Yggdrasil carries the fallback when UDP is blocked.\n\
     ## Bootstrap hosts are resolved at startup. The Yggdrasil peers come from the\n\
     ## public list github.com/yggdrasil-network/public-peers; replace them freely.\n\
     network: {\n\
     \x20   mainline: {\n\
     \x20       bootstrap: [\n\
     \x20           dht.libtorrent.org:25401\n\
     \x20           router.bittorrent.com:6881\n\
     \x20       ]\n\
     \x20   }\n\
     \x20   signaling: {\n\
     \x20       bind: 0.0.0.0:0\n\
     \x20   }\n\
     \x20   ygg: {\n\
     \x20       peers: [\n\
     \x20           tcp://ygg-pa.incognet.io:8883\n\
     \x20           tcp://mo.us.ygg.triplebit.org:9000\n\
     \x20       ]\n\
     \x20   }\n\
     }\n"
}

/// Appends the network section for `choice` to a generated file text.
pub(super) fn append(text: &mut String, choice: NetworkChoice) {
    if choice == NetworkChoice::Public {
        text.push_str(public_network_text());
    }
}

#[cfg(test)]
mod tests;
