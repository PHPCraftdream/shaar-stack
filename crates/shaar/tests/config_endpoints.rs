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
