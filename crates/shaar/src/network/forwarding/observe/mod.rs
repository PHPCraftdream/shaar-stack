//! The products' ONE stable structured stderr line when a route is decided and
//! one when a session ends. The grammar is documented in
//! `docs/guide/operations.md` and must stay stable; values carry counts and
//! typed tokens only — never keys, addresses or secrets.

use super::{ForwardError, ForwardStats, ServeReport};
use crate::path::PathKind;

mod dht;
mod trace;
pub use dht::install_dht_trace;
pub use trace::{PortMapping, client_direct, client_lookup, server_publication};

/// Which product emits an operator line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Product {
    Server,
    Client,
}

impl Product {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "shaar-server",
            Self::Client => "shaar-client",
        }
    }
}

/// The path a forwarding decision uses. A Yggdrasil payload lease always means
/// standby today; `YggSignal` is reserved for future signal-mode negotiation
/// routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutePath {
    Native,
    YggSignal,
    YggStandby,
}

impl RoutePath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::YggSignal => "ygg-signal",
            Self::YggStandby => "ygg-standby",
        }
    }

    pub(crate) fn from_kind(kind: PathKind) -> Self {
        match kind {
            PathKind::Native => Self::Native,
            // A Yggdrasil payload lease always means standby today.
            PathKind::Yggdrasil => Self::YggStandby,
        }
    }
}

/// How a Mainline resolve contributed to a route decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    Found,
    NotFound,
    Timeout,
    Cached,
}

impl ResolveOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::NotFound => "not-found",
            Self::Timeout => "timeout",
            Self::Cached => "cached",
        }
    }
}

/// Candidate counts at a route decision, split by source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolveObservation {
    pub outcome: ResolveOutcome,
    pub record: usize,
    pub hint: usize,
}

impl ResolveObservation {
    /// `n` is the address count taken from ONE Mainline resolve. A failed or
    /// unfinished lookup yields no answer; the stable value is timeout.
    pub fn from_answer(answer: Option<usize>) -> Self {
        match answer {
            Some(0) => Self {
                outcome: ResolveOutcome::NotFound,
                record: 0,
                hint: 0,
            },
            Some(n) => Self {
                outcome: ResolveOutcome::Found,
                record: n,
                hint: 0,
            },
            None => Self {
                outcome: ResolveOutcome::Timeout,
                record: 0,
                hint: 0,
            },
        }
    }

    /// No lookup happened for this decision; the counts are the already-carried
    /// candidate list split by source.
    pub fn cached(record: usize, hint: usize) -> Self {
        Self {
            outcome: ResolveOutcome::Cached,
            record,
            hint,
        }
    }
}

/// How a served or forwarded session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Ok { bytes_in: u64, bytes_out: u64 },
    Error { code: &'static str },
}

impl SessionOutcome {
    pub fn of_report(report: &ServeReport) -> Self {
        Self::Ok {
            bytes_in: report.bytes_in,
            bytes_out: report.bytes_out,
        }
    }

    pub fn of_stats(stats: &ForwardStats) -> Self {
        Self::Ok {
            bytes_in: stats.from_peer,
            bytes_out: stats.to_peer,
        }
    }

    /// A clean peer close is NOT an error; every other variant is.
    pub fn of_error(error: &ForwardError) -> Self {
        match error {
            ForwardError::PeerClosed => Self::Ok {
                bytes_in: 0,
                bytes_out: 0,
            },
            _ => Self::Error {
                code: Self::error_token(error),
            },
        }
    }

    pub fn of_session(result: &Result<ServeReport, ForwardError>) -> Self {
        match result {
            Ok(report) => Self::of_report(report),
            Err(error) => Self::of_error(error),
        }
    }

    pub fn of_worker(result: &Result<ForwardStats, ForwardError>) -> Self {
        match result {
            Ok(stats) => Self::of_stats(stats),
            Err(error) => Self::of_error(error),
        }
    }

    /// `PeerClosed` is never rendered as an error because `of_error` maps it to
    /// `Ok` first.
    pub fn error_token(error: &ForwardError) -> &'static str {
        match error {
            ForwardError::InvalidTarget => "invalid-target",
            ForwardError::Capacity => "capacity",
            ForwardError::AccessDenied => "access-denied",
            ForwardError::PathUnavailable => "path-unavailable",
            ForwardError::TargetUnavailable => "target-unavailable",
            ForwardError::Protocol => "protocol",
            ForwardError::Deadline => "deadline",
            ForwardError::StreamReset => "stream-reset",
            ForwardError::TaskFailure => "task-failure",
            ForwardError::Io(_) => "io",
            ForwardError::PeerClosed => "peer-closed",
        }
    }
}

/// The client's stable route line; space-separated `key=value`, fixed key
/// order, decimal digits only.
pub fn client_route(path: RoutePath, observation: ResolveObservation, elapsed_ms: u64) -> String {
    format!(
        "shaar-client: route path={} candidates=record:{},hint:{} resolve={} elapsed_ms={}",
        path.as_str(),
        observation.record,
        observation.hint,
        observation.outcome.as_str(),
        elapsed_ms,
    )
}

/// The server's stable route line.
pub fn server_route(path: RoutePath) -> String {
    format!("shaar-server: route path={}", path.as_str())
}

/// The stable session-end line. Bytes are always literal zeros on error lines:
/// unknown.
pub fn session_line(product: Product, path: RoutePath, outcome: SessionOutcome) -> String {
    let product = product.as_str();
    let path = path.as_str();
    match outcome {
        SessionOutcome::Ok {
            bytes_in,
            bytes_out,
        } => format!(
            "{product}: session path={path} result=ok bytes_in={bytes_in} bytes_out={bytes_out}"
        ),
        SessionOutcome::Error { code } => format!(
            "{product}: session path={path} result=error error={code} bytes_in=0 bytes_out=0"
        ),
    }
}

/// Emits one operator line on stderr.
pub fn emit(line: String) {
    eprintln!("{line}");
}

/// Saturating elapsed milliseconds since `started`.
pub fn elapsed_ms(started: std::time::Instant) -> u64 {
    duration_ms(started.elapsed())
}

/// Saturating milliseconds of a duration.
pub fn duration_ms(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        time::{Duration, Instant},
    };

    /// A rendered route line split into its field values.
    #[derive(Debug, PartialEq, Eq)]
    struct RouteFields {
        product: String,
        path: String,
        record: Option<usize>,
        hint: Option<usize>,
        resolve: Option<String>,
        elapsed_ms: Option<u64>,
    }

    /// A rendered session line split into its field values.
    #[derive(Debug, PartialEq, Eq)]
    struct SessionFields {
        product: String,
        path: String,
        result: String,
        error: Option<String>,
        bytes_in: Option<u64>,
        bytes_out: Option<u64>,
    }

    fn parse_route_line(line: &str) -> Option<RouteFields> {
        let (product, rest) = line.split_once(": ")?;
        let mut fields = RouteFields {
            product: product.to_owned(),
            path: String::new(),
            record: None,
            hint: None,
            resolve: None,
            elapsed_ms: None,
        };
        for token in rest.split(' ') {
            match token.split_once('=') {
                Some(("path", value)) => fields.path = value.to_owned(),
                Some(("candidates", value)) => {
                    let (record, hint) = value.split_once(',')?;
                    let (source, count) = record.split_once(':')?;
                    if source != "record" {
                        return None;
                    }
                    fields.record = Some(count.parse().ok()?);
                    let (source, count) = hint.split_once(':')?;
                    if source != "hint" {
                        return None;
                    }
                    fields.hint = Some(count.parse().ok()?);
                }
                Some(("resolve", value)) => fields.resolve = Some(value.to_owned()),
                Some(("elapsed_ms", value)) => fields.elapsed_ms = Some(value.parse().ok()?),
                None if token == "route" || token == "session" => {}
                _ => return None,
            }
        }
        if fields.path.is_empty()
            || fields.record.is_none()
            || fields.hint.is_none()
            || fields.resolve.is_none()
            || fields.elapsed_ms.is_none()
        {
            return None;
        }
        Some(fields)
    }

    fn parse_session_line(line: &str) -> Option<SessionFields> {
        let (product, rest) = line.split_once(": ")?;
        let mut fields = SessionFields {
            product: product.to_owned(),
            path: String::new(),
            result: String::new(),
            error: None,
            bytes_in: None,
            bytes_out: None,
        };
        for token in rest.split(' ') {
            match token.split_once('=') {
                Some(("path", value)) => fields.path = value.to_owned(),
                Some(("result", value)) => {
                    if value != "ok" && value != "error" {
                        return None;
                    }
                    fields.result = value.to_owned();
                }
                Some(("error", value)) => fields.error = Some(value.to_owned()),
                Some(("bytes_in", value)) => fields.bytes_in = Some(value.parse().ok()?),
                Some(("bytes_out", value)) => fields.bytes_out = Some(value.parse().ok()?),
                None if token == "route" || token == "session" => {}
                _ => return None,
            }
        }
        if fields.path.is_empty()
            || fields.result.is_empty()
            || fields.bytes_in.is_none()
            || fields.bytes_out.is_none()
        {
            return None;
        }
        Some(fields)
    }

    fn session_fields(product: Product, path: RoutePath, outcome: SessionOutcome) -> SessionFields {
        SessionFields {
            product: product.as_str().into(),
            path: path.as_str().into(),
            result: match outcome {
                SessionOutcome::Ok { .. } => "ok".into(),
                SessionOutcome::Error { .. } => "error".into(),
            },
            error: match outcome {
                SessionOutcome::Error { code } => Some(code.into()),
                SessionOutcome::Ok { .. } => None,
            },
            bytes_in: match outcome {
                SessionOutcome::Ok { bytes_in, .. } => Some(bytes_in),
                SessionOutcome::Error { .. } => Some(0),
            },
            bytes_out: match outcome {
                SessionOutcome::Ok { bytes_out, .. } => Some(bytes_out),
                SessionOutcome::Error { .. } => Some(0),
            },
        }
    }

    #[test]
    fn every_route_and_session_value_round_trips_through_the_parser() {
        for path in [
            RoutePath::Native,
            RoutePath::YggSignal,
            RoutePath::YggStandby,
        ] {
            assert_eq!(
                server_route(path),
                format!("shaar-server: route path={}", path.as_str())
            );
            for (outcome, record, hint) in [
                (ResolveOutcome::Found, 3, 0),
                (ResolveOutcome::NotFound, 0, 0),
                (ResolveOutcome::Timeout, 0, 0),
                (ResolveOutcome::Cached, 2, 5),
            ] {
                let observation = ResolveObservation {
                    outcome,
                    record,
                    hint,
                };
                let elapsed: u64 = 42;
                let line = client_route(path, observation, elapsed);
                assert_eq!(
                    line,
                    format!(
                        "shaar-client: route path={} candidates=record:{},hint:{} resolve={} elapsed_ms=42",
                        path.as_str(),
                        record,
                        hint,
                        outcome.as_str(),
                    )
                );
                assert_eq!(
                    parse_route_line(&line).as_ref(),
                    Some(&RouteFields {
                        product: "shaar-client".into(),
                        path: path.as_str().into(),
                        record: Some(record),
                        hint: Some(hint),
                        resolve: Some(outcome.as_str().into()),
                        elapsed_ms: Some(elapsed),
                    })
                );
            }
            for product in [Product::Server, Product::Client] {
                for outcome in [
                    SessionOutcome::Ok {
                        bytes_in: 19,
                        bytes_out: 7,
                    },
                    SessionOutcome::Ok {
                        bytes_in: 0,
                        bytes_out: 0,
                    },
                    SessionOutcome::Error { code: "deadline" },
                ] {
                    let line = session_line(product, path, outcome);
                    assert_eq!(
                        parse_session_line(&line).as_ref(),
                        Some(&session_fields(product, path, outcome))
                    );
                }
            }
        }
    }

    #[test]
    fn every_error_token_is_rendered_and_parsed() {
        let errors = [
            ForwardError::InvalidTarget,
            ForwardError::Capacity,
            ForwardError::AccessDenied,
            ForwardError::PathUnavailable,
            ForwardError::PeerClosed,
            ForwardError::TargetUnavailable,
            ForwardError::Protocol,
            ForwardError::Deadline,
            ForwardError::StreamReset,
            ForwardError::TaskFailure,
            ForwardError::Io(io::Error::other("no details parsed")),
        ];
        for error in errors {
            let outcome = SessionOutcome::Error {
                code: SessionOutcome::error_token(&error),
            };
            let line = session_line(Product::Server, RoutePath::Native, outcome);
            assert_eq!(
                parse_session_line(&line).as_ref(),
                Some(&session_fields(Product::Server, RoutePath::Native, outcome))
            );
        }
        assert_eq!(
            session_line(
                Product::Server,
                RoutePath::Native,
                SessionOutcome::Error { code: "deadline" }
            ),
            "shaar-server: session path=native result=error error=deadline bytes_in=0 bytes_out=0"
        );
    }

    #[test]
    fn resolve_observations_classify_answers_and_cached_counts() {
        assert_eq!(
            ResolveObservation::from_answer(Some(0)),
            ResolveObservation {
                outcome: ResolveOutcome::NotFound,
                record: 0,
                hint: 0,
            }
        );
        assert_eq!(
            ResolveObservation::from_answer(Some(2)),
            ResolveObservation {
                outcome: ResolveOutcome::Found,
                record: 2,
                hint: 0,
            }
        );
        assert_eq!(
            ResolveObservation::from_answer(None),
            ResolveObservation {
                outcome: ResolveOutcome::Timeout,
                record: 0,
                hint: 0,
            }
        );
        assert_eq!(
            ResolveObservation::cached(4, 9),
            ResolveObservation {
                outcome: ResolveOutcome::Cached,
                record: 4,
                hint: 9,
            }
        );
    }

    #[test]
    fn peer_close_maps_to_ok_and_other_errors_keep_their_tokens() {
        assert_eq!(
            SessionOutcome::of_error(&ForwardError::PeerClosed),
            SessionOutcome::Ok {
                bytes_in: 0,
                bytes_out: 0,
            }
        );
        assert_eq!(
            SessionOutcome::of_error(&ForwardError::PathUnavailable),
            SessionOutcome::Error {
                code: "path-unavailable",
            }
        );
        assert_eq!(
            SessionOutcome::of_error(&ForwardError::AccessDenied),
            SessionOutcome::Error {
                code: "access-denied",
            }
        );
        assert_eq!(
            SessionOutcome::of_error(&ForwardError::Io(io::Error::other("x"))),
            SessionOutcome::Error { code: "io" }
        );
        let report = super::super::ServeReport {
            completed: 1,
            failed: 0,
            cancelled: 0,
            bytes_in: 19,
            bytes_out: 7,
        };
        assert_eq!(
            SessionOutcome::of_report(&report),
            SessionOutcome::Ok {
                bytes_in: 19,
                bytes_out: 7,
            }
        );
        let stats = super::super::ForwardStats {
            to_peer: 19,
            from_peer: 7,
        };
        assert_eq!(
            SessionOutcome::of_stats(&stats),
            SessionOutcome::Ok {
                bytes_in: 7,
                bytes_out: 19,
            }
        );
        assert_eq!(
            SessionOutcome::of_session(&Ok(report)),
            SessionOutcome::Ok {
                bytes_in: 19,
                bytes_out: 7,
            }
        );
        assert_eq!(
            SessionOutcome::of_session(&Err(ForwardError::Protocol)),
            SessionOutcome::Error { code: "protocol" }
        );
        assert_eq!(
            SessionOutcome::of_worker(&Ok(stats)),
            SessionOutcome::Ok {
                bytes_in: 7,
                bytes_out: 19,
            }
        );
        assert_eq!(
            SessionOutcome::of_worker(&Err(ForwardError::Deadline)),
            SessionOutcome::Error { code: "deadline" }
        );
    }

    #[test]
    fn malformed_route_and_session_lines_do_not_parse() {
        assert!(parse_route_line(
            "shaar-client: route path=native candidates=record:1,hint:0 resolve=found elapsed_ms=1 extra"
        )
        .is_none());
        assert!(parse_route_line(
            "shaar-client: route path=native candidates=record:x,hint:0 resolve=found elapsed_ms=1"
        )
        .is_none());
        assert!(parse_route_line("shaar-client: route path=native resolve=found").is_none());
        assert!(
            parse_session_line(
                "shaar-server: session path=native result=ok bytes_in=1 bytes_out=2 extra"
            )
            .is_none()
        );
        assert!(
            parse_session_line(
                "shaar-server: session path=native result=unknown bytes_in=1 bytes_out=2"
            )
            .is_none()
        );
        assert!(
            parse_session_line("shaar-server: session path=native result=ok bytes_in=1").is_none()
        );
    }

    #[test]
    fn elapsed_ms_wraps_the_u128_elapsed_time_and_saturates() {
        let started = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            elapsed_ms(started),
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
        );
        assert_eq!(
            elapsed_ms(Instant::now() + Duration::from_secs(1)),
            0,
            "saturating conversion never wraps a not-yet-elapsed instant"
        );
    }
}
