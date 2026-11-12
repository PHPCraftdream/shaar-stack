#![forbid(unsafe_code)]

use shaar::config::{
    ClientConfig, ClientEndpointOverrides, ClientOverrides, ConfigError, ServerConfig,
    ServerEndpointOverrides, ServerOverrides, ValidationKind,
};

const RFC8032_PUB_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[test]
fn endpoint_overrides_supply_addresses_absent_from_files() {
    let server = ServerConfig::from_text_with_endpoint_overrides(
        "target: 127.0.0.1:9000\n",
        &ServerOverrides::default(),
        &ServerEndpointOverrides {
            bind: Some("[::]:0".to_string()),
        },
    )
    .unwrap();
    assert_eq!(server.bind().to_string(), "[::]:0");

    let client = ClientConfig::from_text_with_endpoint_overrides(
        &format!("server: {RFC8032_PUB_HEX}\n"),
        &ClientOverrides::default(),
        &ClientEndpointOverrides {
            server_address: Some("127.0.0.1:443".to_string()),
        },
    )
    .unwrap();
    assert_eq!(
        client.server_address().unwrap().to_string(),
        "127.0.0.1:443"
    );
}

#[test]
fn invalid_server_bind_override_replaces_valid_file_value() {
    let err = ServerConfig::from_text_with_endpoint_overrides(
        "target: 127.0.0.1:9000\nbind: 127.0.0.1:80\n",
        &ServerOverrides::default(),
        &ServerEndpointOverrides {
            bind: Some("localhost:8080".to_string()),
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "bind",
            kind: ValidationKind::InvalidAddress
        }
    ));
}

#[test]
fn invalid_endpoint_address_shapes_are_attributed_to_each_field() {
    let invalid_addresses = ["localhost:80", "127.0.0.1", "127.0.0.1:65536", ""];

    for address in invalid_addresses {
        let err = ServerConfig::from_text_with_endpoint_overrides(
            "target: 127.0.0.1:9000\n",
            &ServerOverrides::default(),
            &ServerEndpointOverrides {
                bind: Some(address.to_string()),
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Validation {
                    field: "bind",
                    kind: ValidationKind::InvalidAddress
                }
            ),
            "bind {address:?}"
        );

        let err = ClientConfig::from_text_with_endpoint_overrides(
            &format!("server: {RFC8032_PUB_HEX}\n"),
            &ClientOverrides::default(),
            &ClientEndpointOverrides {
                server_address: Some(address.to_string()),
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Validation {
                    field: "server_address",
                    kind: ValidationKind::InvalidAddress
                }
            ),
            "server_address {address:?}"
        );
    }
}

#[test]
fn endpoint_overrides_do_not_repair_syntax_or_unknown_fields() {
    let server_override = ServerEndpointOverrides {
        bind: Some("127.0.0.1:80".to_string()),
    };
    let err = ServerConfig::from_text_with_endpoint_overrides(
        "target: 127.0.0.1:9000\n}\n",
        &ServerOverrides::default(),
        &server_override,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Parsing { kind: "syntax", .. }));

    let err = ServerConfig::from_text_with_endpoint_overrides(
        "target: 127.0.0.1:9000\nbind: 127.0.0.1:81\nextra: value\n",
        &ServerOverrides::default(),
        &server_override,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Parsing { kind: "schema", .. }));

    let client_override = ClientEndpointOverrides {
        server_address: Some("127.0.0.1:443".to_string()),
    };
    let err = ClientConfig::from_text_with_endpoint_overrides(
        &format!("server: {RFC8032_PUB_HEX}\n}}\n"),
        &ClientOverrides::default(),
        &client_override,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Parsing { kind: "syntax", .. }));

    let err = ClientConfig::from_text_with_endpoint_overrides(
        &format!("server: {RFC8032_PUB_HEX}\nserver_address: 127.0.0.1:80\nextra: value\n"),
        &ClientOverrides::default(),
        &client_override,
    )
    .unwrap_err();
    assert!(matches!(err, ConfigError::Parsing { kind: "schema", .. }));
}

const RELAY: &str = "12D3KooWRhxsqdyvN1Cy4HDzPjKtdscPa9XUyqoqJwHSsGY8LQTQ";

fn composed_server(extra: &str) -> String {
    format!(
        "target: 127.0.0.1:9000\n{extra}network: {{\n    mainline: {{\n        bootstrap: [\n            192.0.2.10:6881\n        ]\n    }}\n    signaling: {{\n        relay: {RELAY}\n        relay_address: 192.0.2.20:7000\n    }}\n    ygg: {{\n        peers: [\n            tcp://127.0.0.1:9001\n        ]\n    }}\n}}\n"
    )
}

fn bind_error(err: ConfigError) -> ValidationKind {
    match err {
        ConfigError::Validation {
            field: "bind",
            kind,
        } => kind,
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn composed_server_rejects_a_bind_that_would_be_ignored() {
    let err = ServerConfig::from_text(
        &composed_server("bind: 127.0.0.1:0\n"),
        &ServerOverrides::default(),
    )
    .unwrap_err();
    assert_eq!(bind_error(err), ValidationKind::NotApplicable);
    assert_eq!(
        ServerConfig::from_text(
            &composed_server("bind: 127.0.0.1:0\n"),
            &ServerOverrides::default()
        )
        .unwrap_err()
        .to_string(),
        "invalid configuration value for field `bind` (NotApplicable)"
    );

    let err = ServerConfig::from_text_with_endpoint_overrides(
        &composed_server(""),
        &ServerOverrides::default(),
        &ServerEndpointOverrides {
            bind: Some("127.0.0.1:0".to_string()),
        },
    )
    .unwrap_err();
    assert_eq!(bind_error(err), ValidationKind::NotApplicable);
}

#[test]
fn invalid_bind_is_still_an_address_error_in_the_composed_shape() {
    let err = ServerConfig::from_text(
        &composed_server("bind: nope\n"),
        &ServerOverrides::default(),
    )
    .unwrap_err();
    assert_eq!(bind_error(err), ValidationKind::InvalidAddress);
}

#[test]
fn bind_stays_valid_without_network_and_composed_without_bind_uses_the_default() {
    let direct = ServerConfig::from_text(
        "target: 127.0.0.1:9000\nbind: 127.0.0.1:0\n",
        &ServerOverrides::default(),
    )
    .unwrap();
    assert_eq!(direct.bind().to_string(), "127.0.0.1:0");
    let composed =
        ServerConfig::from_text(&composed_server(""), &ServerOverrides::default()).unwrap();
    assert_eq!(composed.bind().to_string(), "0.0.0.0:0");
}
