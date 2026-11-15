#![forbid(unsafe_code)]
use super::*;
use crate::config::{ClientConfig, ClientOverrides, ServerConfig, ServerOverrides};
use crate::identity::Identity;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::current_dir()
            .expect("current directory")
            .join("target/identity-provision-fixtures");
        std::fs::create_dir_all(&base).expect("fixture parent");
        for _ in 0..64 {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("fixture directory: {err}"),
            }
        }
        panic!("fixture namespace exhausted");
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn server_config_text_round_trips_with_target_missing() {
    let dir = FixtureDir::new();
    let paths = ProvisionPaths {
        dir: dir.0.clone(),
        config: dir.0.join("server.ktav"),
        key: dir.0.join("shaar.key"),
        allowlist: Some(dir.0.join("allowed.txt")),
    };
    let text = server_config_text(&paths);
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(
        matches!(
            err,
            crate::config::ConfigError::Validation {
                field: "target",
                kind: crate::config::ValidationKind::MissingRequired
            }
        ),
        "unexpected error: {err}"
    );
    let text = format!("target: 127.0.0.1:8080\n{text}");
    let cfg = ServerConfig::from_text(&text, &ServerOverrides::default()).expect("server config");
    assert_eq!(cfg.key_file(), paths.key.as_path());
    assert_eq!(cfg.allowlist_path(), paths.allowlist.as_deref().unwrap());
}

#[test]
fn client_config_text_round_trips_with_server_fields() {
    let dir = FixtureDir::new();
    let paths = ProvisionPaths {
        dir: dir.0.clone(),
        config: dir.0.join("client.ktav"),
        key: dir.0.join("shaar.key"),
        allowlist: None,
    };
    let server_key = hex(&Identity::from_seed([7; 32]).public_key_bytes());
    let text = client_config_text(&paths, Some(server_key.as_str()), Some("127.0.0.1:9"));
    let cfg = ClientConfig::from_text(&text, &ClientOverrides::default()).expect("client config");
    assert_eq!(
        cfg.server_key_bytes(),
        &Identity::from_seed([7; 32]).public_key_bytes()
    );
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert_eq!(cfg.server_address(), Some(addr));
    assert_eq!(cfg.key_file(), paths.key.as_path());

    let bare = client_config_text(&paths, None, None);
    let err = ClientConfig::from_text(&bare, &ClientOverrides::default()).unwrap_err();
    assert!(
        matches!(
            err,
            crate::config::ConfigError::Validation {
                field: "server",
                kind: crate::config::ValidationKind::MissingRequired
            }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn digit_only_server_key_stays_a_ktav_string() {
    #[derive(serde::Deserialize)]
    struct Probe {
        server: Option<String>,
        #[serde(default)]
        key_file: Option<String>,
    }
    let dir = FixtureDir::new();
    let paths = ProvisionPaths {
        dir: dir.0.clone(),
        config: dir.0.join("client.ktav"),
        key: dir.0.join("shaar.key"),
        allowlist: None,
    };
    let digits: String = "1".repeat(64);
    let text = client_config_text(&paths, Some(digits.as_str()), None);
    let probe: Probe = ktav::from_str(&text).expect("ktav parse");
    assert_eq!(probe.server.as_deref(), Some(digits.as_str()));
}

#[tokio::test]
async fn provision_is_idempotent_and_never_rewrites() {
    let dir = FixtureDir::new();
    let first = provision(Role::Server, &dir.0, None, None)
        .await
        .expect("first provision");
    let r = &first.report;
    assert_eq!(r.dir, FileState::Created);
    assert_eq!(r.config, FileState::Created);
    assert_eq!(r.key, FileState::Created);
    assert_eq!(r.allowlist, Some(FileState::Created));
    assert!(r.paths.config.exists());
    assert!(r.paths.key.exists());
    assert!(r.paths.allowlist.as_deref().unwrap().exists());
    let loaded = Identity::load(r.paths.key.clone())
        .await
        .expect("reload key");
    assert_eq!(loaded.public_key_bytes(), first.identity.public_key_bytes());

    let config_bytes = std::fs::read(&r.paths.config).unwrap();
    let second = provision(Role::Server, &dir.0, None, None)
        .await
        .expect("second provision");
    let r2 = &second.report;
    assert_eq!(r2.dir, FileState::Kept);
    assert_eq!(r2.config, FileState::Kept);
    assert_eq!(r2.key, FileState::Kept);
    assert_eq!(r2.allowlist, Some(FileState::Kept));
    assert_eq!(std::fs::read(&r2.paths.config).unwrap(), config_bytes);
    assert_eq!(
        second.identity.public_key_bytes(),
        first.identity.public_key_bytes()
    );
}

#[tokio::test]
async fn provision_never_overwrites_existing_config_and_allowlist() {
    let dir = FixtureDir::new();
    let role_dir = role_dir(&dir.0, Role::Server);
    std::fs::create_dir_all(&role_dir).unwrap();
    std::fs::write(role_dir.join("server.ktav"), b"sentinel\n").unwrap();
    std::fs::write(role_dir.join("allowed.txt"), b"# x\n").unwrap();
    let p = provision(Role::Server, &dir.0, None, None)
        .await
        .expect("provision");
    assert_eq!(p.report.config, FileState::Kept);
    assert_eq!(p.report.allowlist, Some(FileState::Kept));
    assert_eq!(
        std::fs::read(role_dir.join("server.ktav")).unwrap(),
        b"sentinel\n"
    );
    assert_eq!(
        std::fs::read(role_dir.join("allowed.txt")).unwrap(),
        b"# x\n"
    );
}

#[tokio::test]
async fn provision_keeps_a_pre_existing_key() {
    let dir = FixtureDir::new();
    let role_dir = role_dir(&dir.0, Role::Server);
    std::fs::create_dir_all(&role_dir).unwrap();
    let key_path = role_dir.join("shaar.key");
    let existing = Identity::create_new(&key_path).await.expect("seed key");
    let p = provision(Role::Server, &dir.0, None, None)
        .await
        .expect("provision");
    assert_eq!(p.report.key, FileState::Kept);
    assert_eq!(p.identity.public_key_bytes(), existing.public_key_bytes());
}

#[tokio::test]
async fn client_provision_has_no_allowlist_file() {
    let dir = FixtureDir::new();
    let p = provision(Role::Client, &dir.0, None, None)
        .await
        .expect("client provision");
    assert!(p.report.allowlist.is_none());
    assert!(p.report.paths.allowlist.is_none());
    assert!(p.report.paths.config.exists());
    assert!(p.report.paths.key.exists());
    assert!(!role_dir(&dir.0, Role::Client).join("allowed.txt").exists());
}

#[test]
fn resolve_data_dir_rules_are_platform_exact() {
    let os = |v: &str| Some(std::ffi::OsString::from(v));
    #[cfg(windows)]
    {
        assert_eq!(
            resolve_data_dir(|name| if name == "APPDATA" {
                os("C:/u/AppData")
            } else {
                None
            })
            .unwrap(),
            PathBuf::from("C:/u/AppData").join("shaar")
        );
        assert!(matches!(
            resolve_data_dir(|_| None),
            Err(ProvisionError::MissingEnv("APPDATA"))
        ));
        assert!(matches!(
            resolve_data_dir(|name| if name == "APPDATA" { os("") } else { None }),
            Err(ProvisionError::MissingEnv("APPDATA"))
        ));
    }
    #[cfg(not(windows))]
    {
        assert_eq!(
            resolve_data_dir(|name| {
                match name {
                    "XDG_DATA_HOME" => os("/tmp/data"),
                    "HOME" => os("/home/u"),
                    _ => None,
                }
            })
            .unwrap(),
            PathBuf::from("/tmp/data").join("shaar"),
            "absolute XDG_DATA_HOME wins"
        );
        assert_eq!(
            resolve_data_dir(|name| {
                match name {
                    "XDG_DATA_HOME" => os("relative/path"),
                    "HOME" => os("/home/u"),
                    _ => None,
                }
            })
            .unwrap(),
            PathBuf::from("/home/u").join(".local/share/shaar"),
            "relative XDG_DATA_HOME is ignored per the XDG spec"
        );
        assert_eq!(
            resolve_data_dir(|name| {
                match name {
                    "XDG_DATA_HOME" => os(""),
                    "HOME" => os("/home/u"),
                    _ => None,
                }
            })
            .unwrap(),
            PathBuf::from("/home/u").join(".local/share/shaar"),
            "empty XDG_DATA_HOME counts as unset"
        );
        assert!(matches!(
            resolve_data_dir(|_| None),
            Err(ProvisionError::MissingEnv("HOME"))
        ));
    }
}

#[test]
fn first_run_summary_lines_are_exact() {
    let dir = FixtureDir::new();
    let paths = ProvisionPaths {
        dir: dir.0.join("server"),
        config: dir.0.join("server").join("server.ktav"),
        key: dir.0.join("server").join("shaar.key"),
        allowlist: Some(dir.0.join("server").join("allowed.txt")),
    };
    let report = ProvisionReport {
        paths: paths.clone(),
        dir: FileState::Created,
        config: FileState::Created,
        key: FileState::Kept,
        allowlist: Some(FileState::Created),
    };
    let identity = Identity::from_seed([7; 32]);
    let expected = vec![
        format!(
            "first run data directory: {} (created)",
            paths.dir.to_string_lossy()
        ),
        format!("created: {}", paths.config.to_string_lossy()),
        format!("kept: {}", paths.key.to_string_lossy()),
        format!(
            "created: {}",
            paths.allowlist.as_deref().unwrap().to_string_lossy()
        ),
        format!("public_key={}", hex(&identity.public_key_bytes())),
    ];
    assert_eq!(
        first_run_summary_lines(Role::Server, &report, &identity),
        expected
    );
    let reused = ProvisionReport {
        dir: FileState::Kept,
        ..report
    };
    assert_eq!(
        first_run_summary_lines(Role::Server, &reused, &identity)[0],
        format!(
            "first run data directory: {} (reused)",
            paths.dir.to_string_lossy()
        )
    );
}

#[test]
fn path_as_config_value_rejects_bad_paths() {
    assert!(matches!(
        path_as_config_value(Path::new("a\nb")),
        Err(ProvisionError::PathControlChars)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bad = Path::new(std::ffi::OsStr::from_bytes(b"bad\xffpath"));
        assert!(matches!(
            path_as_config_value(bad),
            Err(ProvisionError::PathNotUtf8)
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let bad = std::ffi::OsString::from_wide(&[0xD800]);
        assert!(matches!(
            path_as_config_value(Path::new(&bad)),
            Err(ProvisionError::PathNotUtf8)
        ));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unix_role_dir_mode_is_0o700_and_never_fixed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = FixtureDir::new();
    let p = provision(Role::Server, &dir.0, None, None)
        .await
        .expect("provision");
    let mode = std::fs::metadata(&p.report.paths.dir)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    // A pre-existing loose directory is reused WITHOUT chmod.
    let dir2 = FixtureDir::new();
    let role = role_dir(&dir2.0, Role::Server);
    std::fs::create_dir_all(&role).unwrap();
    std::fs::set_permissions(&role, std::fs::Permissions::from_mode(0o755)).unwrap();
    provision(Role::Server, &dir2.0, None, None)
        .await
        .expect("provision kept");
    let mode = std::fs::metadata(&role).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o755,
        "existing directory permissions must not change"
    );
}

#[test]
fn allowlist_template_lines_are_all_comments_and_empty_list_is_valid() {
    for line in allowlist_template_text().lines() {
        assert!(!line.trim().is_empty(), "no blank lines in template");
        assert!(
            line.starts_with('#'),
            "template line must be a comment: {line}"
        );
    }
    assert!(crate::network::Allowlist::new(&[]).is_ok());
}
