//! The `diag` subcommands of `shaar-server`: measurements of this machine's network (leaves
//! NAT-3a to NAT-3c). They print ports and counts, and an address only on request.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use shaar::network::observe::{
    ANSWER_WAIT, CATCH_EVERY, Catch, DEFAULT_CATCH_SECONDS, DEFAULT_KNOCK_AFTER_SECONDS,
    DEFAULT_LISTEN_SECONDS, DEFAULT_PROBE_WAIT_SECONDS, DEFAULT_SWEEP_AFTER_SECONDS,
    DEFAULT_SWEEP_FROM, DEFAULT_SWEEP_RATE, DEFAULT_SWEEP_TO, KNOCK_EVERY, KNOCK_PORT, Knock,
    Listen, MAX_CATCH_SECONDS, MAX_LISTEN_SECONDS, MAX_PROBE_WAIT_SECONDS, MAX_SOCKETS,
    MAX_SWEEP_RATE, Sweep, nat_filter_catch, nat_filter_listen, nat_filter_probe, nat_ports,
};
use shaar::network::ports::{PORTS, mapping};

use super::{Invocation, ParseError, Place, mainline_of, place_of};

/// The sweep of `diag nat-filter listen`, as typed: the other device's address and, in seconds
/// and datagrams per second, when and how fast to send to each port from `from` to `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SweepArgs {
    pub(crate) ip: Ipv4Addr,
    pub(crate) after: u16,
    pub(crate) rate: u16,
    pub(crate) from: u16,
    pub(crate) to: u16,
}

impl SweepArgs {
    fn sweep(self) -> Sweep {
        Sweep {
            ip: self.ip,
            from: self.from,
            to: self.to,
            after: Duration::from_secs(u64::from(self.after)),
            rate: self.rate,
        }
    }
}

fn show_address_arg() -> Arg {
    Arg::new("show-address")
        .long("show-address")
        .action(ArgAction::SetTrue)
        .help("Print the external address too (it stays on this screen and in this log)")
}

fn seconds_arg(name: &'static str, max: u16, help: String) -> Arg {
    Arg::new(name)
        .long(name)
        .value_name("S")
        .value_parser(value_parser!(u16).range(1..=i64::from(max)))
        .help(help)
}

fn port_arg(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .value_name("PORT")
        .value_parser(value_parser!(u16).range(1..=i64::from(u16::MAX)))
        .help(help)
}

fn target_arg() -> Arg {
    Arg::new("target")
        .long("target")
        .value_name("IP:PORT")
        .required(true)
        .value_parser(value_parser!(SocketAddrV4))
        .help("The listener's external address and port")
}

fn listen_command() -> Command {
    Command::new("listen")
        .about("Listen on a fresh socket, print its external port and the probes that arrive")
        .arg(seconds_arg(
            "seconds",
            MAX_LISTEN_SECONDS,
            format!("How long to listen (default {DEFAULT_LISTEN_SECONDS})"),
        ))
        .arg(
            Arg::new("knock-ip")
                .long("knock-ip")
                .value_name("IP")
                .value_parser(value_parser!(Ipv4Addr))
                .help("Send knocks to this address (the other device) from the listening socket"),
        )
        .arg(
            Arg::new("knock-after")
                .long("knock-after")
                .value_name("S")
                .value_parser(value_parser!(u16).range(0..i64::from(MAX_LISTEN_SECONDS)))
                .help(format!(
                    "Seconds from the start of listening to the first knock (default {DEFAULT_KNOCK_AFTER_SECONDS})"
                )),
        )
        .arg(
            Arg::new("sweep-ip")
                .long("sweep-ip")
                .value_name("IP")
                .value_parser(value_parser!(Ipv4Addr))
                .help("Send one datagram to every port of this address (the other device) from the listening socket"),
        )
        .arg(
            Arg::new("sweep-after")
                .long("sweep-after")
                .value_name("S")
                .value_parser(value_parser!(u16).range(0..i64::from(MAX_LISTEN_SECONDS)))
                .help(format!(
                    "Seconds from the start of listening to the sweep (default {DEFAULT_SWEEP_AFTER_SECONDS})"
                )),
        )
        .arg(
            Arg::new("sweep-rate")
                .long("sweep-rate")
                .value_name("N")
                .value_parser(value_parser!(u16).range(1..=i64::from(MAX_SWEEP_RATE)))
                .help(format!(
                    "Sweep datagrams per second (default {DEFAULT_SWEEP_RATE}, at most {MAX_SWEEP_RATE})"
                )),
        )
        .arg(port_arg(
            "sweep-from",
            "First port of the sweep (default 1024)",
        ))
        .arg(port_arg("sweep-to", "Last port of the sweep (default 65535)"))
        .arg(show_address_arg())
}

fn probe_command() -> Command {
    Command::new("probe")
        .about("Send probes to a listening device, before and after a pause")
        .arg(target_arg())
        .arg(seconds_arg(
            "wait",
            MAX_PROBE_WAIT_SECONDS,
            format!("Seconds between the two probe phases (default {DEFAULT_PROBE_WAIT_SECONDS})"),
        ))
}

fn catch_command() -> Command {
    Command::new("catch")
        .about("Talk to a listening device from one socket and report the sweep datagram that reaches it")
        .arg(target_arg())
        .arg(seconds_arg(
            "seconds",
            MAX_CATCH_SECONDS,
            format!("How long to talk and listen (default {DEFAULT_CATCH_SECONDS})"),
        ))
}

fn port_map_command() -> Command {
    Command::new("port-map")
        .about("Ask the home router for a UDP port mapping (PCP, then NAT-PMP), report it and delete it")
        .arg(port_arg(
            "port",
            "The port to map to the same external port (default: the first port of the fixed set)",
        ))
        .arg(show_address_arg())
}

/// The `diag` command tree (the place arguments are added by the caller).
pub(super) fn command() -> Command {
    Command::new("diag")
        .about("Measure this machine's network (ports and counts; an address only on request)")
        .subcommand_required(true)
        .subcommand(
            Command::new("nat-ports")
                .about("Print the external UDP ports that fresh sockets get at the DHT bootstrap hosts")
                .arg(
                    Arg::new("sockets")
                        .long("sockets")
                        .value_name("N")
                        .value_parser(value_parser!(u8).range(1..=i64::from(MAX_SOCKETS)))
                        .default_value("6")
                        .help("Sockets to measure"),
                )
                .arg(
                    Arg::new("map")
                        .long("map")
                        .action(ArgAction::SetTrue)
                        .help(
                            "Put the sockets on ports of the fixed set and ask the home router to map each \
                             (PCP, NAT-PMP, UPnP) until the run ends, then delete the mappings",
                        ),
                )
                .arg(show_address_arg()),
        )
        .subcommand(port_map_command())
        .subcommand(
            Command::new("nat-filter")
                .about("Measure which datagrams the NAT in front of this machine lets in")
                .subcommand_required(true)
                .subcommand(listen_command())
                .subcommand(probe_command())
                .subcommand(catch_command()),
        )
}

/// The sweep named by the arguments of `listen`, checked against the listening window.
fn parse_sweep(args: &ArgMatches, seconds: u16) -> Result<Option<SweepArgs>, ParseError> {
    let number = |name: &str| args.get_one::<u16>(name).copied();
    let Some(ip) = args.get_one::<Ipv4Addr>("sweep-ip").copied() else {
        let orphan = ["sweep-after", "sweep-rate", "sweep-from", "sweep-to"]
            .into_iter()
            .any(|name| number(name).is_some());
        return if orphan {
            Err(ParseError::Value(
                "--sweep-after, --sweep-rate, --sweep-from and --sweep-to need --sweep-ip"
                    .to_owned(),
            ))
        } else {
            Ok(None)
        };
    };
    let sweep = SweepArgs {
        ip,
        after: number("sweep-after").unwrap_or(DEFAULT_SWEEP_AFTER_SECONDS),
        rate: number("sweep-rate").unwrap_or(DEFAULT_SWEEP_RATE),
        from: number("sweep-from").unwrap_or(DEFAULT_SWEEP_FROM),
        to: number("sweep-to").unwrap_or(DEFAULT_SWEEP_TO),
    };
    sweep
        .sweep()
        .check(Duration::from_secs(u64::from(seconds)))
        .map_err(|message| {
            ParseError::Value(format!(
                "{message} (see --seconds, --sweep-after, --sweep-rate, --sweep-from, --sweep-to)"
            ))
        })?;
    Ok(Some(sweep))
}

fn parse_listen(place: Place, args: &ArgMatches) -> Result<Invocation, ParseError> {
    let seconds = args
        .get_one::<u16>("seconds")
        .copied()
        .unwrap_or(DEFAULT_LISTEN_SECONDS);
    let named_after = args.get_one::<u16>("knock-after").copied();
    let after = named_after.unwrap_or(DEFAULT_KNOCK_AFTER_SECONDS);
    let knock = args.get_one::<Ipv4Addr>("knock-ip").map(|ip| (*ip, after));
    if knock.is_none() && named_after.is_some() {
        return Err(ParseError::Value(
            "--knock-after needs --knock-ip".to_owned(),
        ));
    }
    if knock.is_some_and(|(_, after)| after >= seconds) {
        return Err(ParseError::Value(
            "--knock-after must be shorter than --seconds".to_owned(),
        ));
    }
    Ok(Invocation::DiagNatFilterListen {
        place,
        seconds,
        knock,
        sweep: parse_sweep(args, seconds)?,
        show_address: args.get_flag("show-address"),
    })
}

/// Parses the arguments of `diag` (`sub` is the matches of `diag` itself).
pub(super) fn parse(sub: &ArgMatches) -> Result<Invocation, ParseError> {
    let (what, args) = sub.subcommand().expect("a subcommand is required");
    if what == "nat-ports" {
        return Ok(Invocation::DiagNatPorts {
            place: place_of(sub),
            sockets: *args.get_one::<u8>("sockets").expect("has a default"),
            show_address: args.get_flag("show-address"),
            map: args.get_flag("map"),
        });
    }
    if what == "port-map" {
        return Ok(Invocation::DiagPortMap {
            port: args.get_one::<u16>("port").copied().unwrap_or(PORTS[0]),
            show_address: args.get_flag("show-address"),
        });
    }
    let (role, args) = args.subcommand().expect("a subcommand is required");
    let target = || *args.get_one::<SocketAddrV4>("target").expect("required");
    match role {
        "listen" => parse_listen(place_of(sub), args),
        "probe" => Ok(Invocation::DiagNatFilterProbe {
            target: target(),
            wait: args
                .get_one::<u16>("wait")
                .copied()
                .unwrap_or(DEFAULT_PROBE_WAIT_SECONDS),
        }),
        _ => Ok(Invocation::DiagNatFilterCatch {
            target: target(),
            seconds: args
                .get_one::<u16>("seconds")
                .copied()
                .unwrap_or(DEFAULT_CATCH_SECONDS),
        }),
    }
}

/// `diag nat-ports`.
pub(super) async fn ports(
    place: &Place,
    sockets: u8,
    show_address: bool,
    map: bool,
) -> Result<Vec<String>, String> {
    nat_ports(&mainline_of(place).await?, sockets, show_address, map).await
}

/// `diag port-map`: one mapping at the home router of this machine by PCP or NAT-PMP, and one by
/// UPnP, each reported and deleted.
pub(super) async fn port_map(port: u16, show_address: bool) -> Vec<String> {
    let gateway = mapping::home_gateway().await;
    let mut lines = mapping::measure(gateway, port, show_address).await;
    lines.extend(mapping::measure_upnp(gateway, port, show_address, mapping::MEASURE_BUDGET).await);
    lines
}

/// Whether the invocation is a measurement that prints as it goes.
pub(super) fn is_streaming(invocation: &Invocation) -> bool {
    matches!(
        invocation,
        Invocation::DiagNatFilterListen { .. }
            | Invocation::DiagNatFilterProbe { .. }
            | Invocation::DiagNatFilterCatch { .. }
    )
}

/// Runs `diag nat-filter listen`, `probe` or `catch`; every line goes to `emit` as soon as it
/// exists, so a log shows the external port while the window is still open.
pub(super) async fn run_streaming(
    invocation: Invocation,
    emit: &mut (dyn FnMut(String) + Send),
) -> Result<(), String> {
    match invocation {
        Invocation::DiagNatFilterListen {
            place,
            seconds,
            knock,
            sweep,
            show_address,
        } => {
            let options = Listen {
                answer_wait: ANSWER_WAIT,
                window: Duration::from_secs(u64::from(seconds)),
                knock: knock.map(|(ip, after)| Knock {
                    target: SocketAddrV4::new(ip, KNOCK_PORT),
                    after: Duration::from_secs(u64::from(after)),
                    every: KNOCK_EVERY,
                }),
                sweep: sweep.map(SweepArgs::sweep),
                show_address,
            };
            nat_filter_listen(&mainline_of(&place).await?, &options, emit).await
        }
        Invocation::DiagNatFilterProbe { target, wait } => {
            nat_filter_probe(target, Duration::from_secs(u64::from(wait)), emit).await
        }
        Invocation::DiagNatFilterCatch { target, seconds } => {
            let options = Catch {
                target,
                window: Duration::from_secs(u64::from(seconds)),
                every: CATCH_EVERY,
            };
            nat_filter_catch(&options, emit).await
        }
        _ => Err("not a measurement that prints as it goes".to_owned()),
    }
}
