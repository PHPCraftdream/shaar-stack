//! Settings validation that runs before any core is created. Errors name only
//! the offending field; values are never echoed because URIs can carry secrets.

use crate::transport::{YggConfig, YggError};

/// Schemes the core supports with its optional transports compiled out.
const SCHEMES: [&str; 2] = ["tcp", "tls"];

/// The single lexical grammar check shared by the adapter's validate and external
/// configuration layers. A lexical pre-check only, not a URI parser and not a
/// connection attempt; it does not echo or retain the inspected value.
pub fn uri_supported(uri: &str) -> bool {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return false;
    };
    SCHEMES
        .iter()
        .any(|known| scheme.eq_ignore_ascii_case(known))
        && !rest.is_empty()
        && !rest.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Check every setting that can be judged without touching the network. This is a
/// lexical pre-check, not a full URI parse: the core can still reject a value at
/// start, which `start` reports as `Start { stage }`.
pub(crate) fn validate(config: &YggConfig) -> Result<(), YggError> {
    if !config.listen.iter().all(|uri| uri_supported(uri)) {
        return Err(YggError::InvalidConfig { field: "listen" });
    }
    if !config.peers.iter().all(|uri| uri_supported(uri)) {
        return Err(YggError::InvalidConfig { field: "peers" });
    }
    if config.group_password.as_deref() == Some("") {
        return Err(YggError::InvalidConfig {
            field: "group_password",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> YggConfig {
        YggConfig {
            seed: [1; 32],
            listen: vec!["tcp://127.0.0.1:9001".to_string()],
            peers: vec!["tls://example.org:443".to_string()],
            allowed_public_keys: Vec::new(),
            group_password: Some("group".to_string()),
        }
    }

    #[test]
    fn valid_settings_and_empty_lists_are_accepted() {
        assert_eq!(validate(&config()), Ok(()));
        let mut open = config();
        open.listen.clear();
        open.peers.clear();
        open.group_password = None;
        assert_eq!(validate(&open), Ok(()));
    }

    #[test]
    fn uri_supported_accepts_ipv6_tls_and_rejects_unknown_schemes() {
        assert!(uri_supported("tls://[2001:db8::1]:443"));
        assert!(!uri_supported("quic://host:1"));
    }

    #[test]
    fn invalid_listen_uris_name_the_listen_field() {
        for bad in [
            "",
            "tcp://",
            "tcp//host:1",
            "http://host:1",
            "tcp://host :1",
            "tcp://host\n:1",
            "://host",
        ] {
            let mut settings = config();
            settings.listen = vec!["tcp://127.0.0.1:1".to_string(), bad.to_string()];
            assert_eq!(
                validate(&settings),
                Err(YggError::InvalidConfig { field: "listen" }),
                "listen URI {bad:?}"
            );
        }
    }

    #[test]
    fn schemes_match_case_insensitively_like_url_parsing() {
        let mut settings = config();
        settings.listen = vec!["TCP://127.0.0.1:9".to_string(), "Tls://[::1]:9".to_string()];
        assert_eq!(validate(&settings), Ok(()));
    }

    #[test]
    fn invalid_peer_uris_name_the_peers_field() {
        let mut settings = config();
        settings.peers = vec!["quic://host:1".to_string()];
        assert_eq!(
            validate(&settings),
            Err(YggError::InvalidConfig { field: "peers" })
        );
    }

    #[test]
    fn empty_group_password_is_rejected_and_never_echoed() {
        let mut settings = config();
        settings.group_password = Some(String::new());
        let error = validate(&settings).expect_err("empty password is rejected");
        assert_eq!(
            error,
            YggError::InvalidConfig {
                field: "group_password"
            }
        );
    }

    #[test]
    fn errors_never_echo_the_rejected_value() {
        let mut settings = config();
        settings.peers = vec!["http://host:1?password=hunter2".to_string()];
        let error = validate(&settings).expect_err("unsupported scheme is rejected");
        let text = format!("{error} {error:?} {settings:?}");
        assert!(!text.contains("hunter2"), "secret leaked: {text}");
    }
}
