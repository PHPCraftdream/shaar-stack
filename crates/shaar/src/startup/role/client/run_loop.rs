//! Composed client loop and retained route leases.

#![forbid(unsafe_code)]

use super::*;

/// Pause after a failed local accept (for example descriptor exhaustion, which
/// fails again immediately): 10 ms doubling to 1 s, reset by a successful accept.
#[derive(Default)]
struct AcceptBackoff(u32);

impl AcceptBackoff {
    const BASE: std::time::Duration = std::time::Duration::from_millis(10);
    const CAP: std::time::Duration = std::time::Duration::from_secs(1);

    fn failed(&mut self) -> std::time::Duration {
        let delay = Self::BASE
            .saturating_mul(1_u32 << self.0.min(16))
            .min(Self::CAP);
        self.0 = self.0.saturating_add(1);
        delay
    }

    fn succeeded(&mut self) {
        self.0 = 0;
    }
}

/// The live role loop over retained parts (biased select, same arm order and emission points as
/// before). Once the outcome is set, `run` returns that error immediately; `Ok` closes nothing.
/// cancel-safe: YES — parts retain all owners; cancelling drops borrowed waiters only.
pub(super) async fn run_parts(
    parts: &mut ClientParts,
    listen: SocketAddr,
    listening: &tokio::sync::watch::Sender<Option<SocketAddr>>,
    shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
) -> Result<(), StartupError> {
    #[cfg(test)]
    emit_payload_acquired(parts.events.as_ref(), parts.payload.is_some());
    // Split borrow of the owned pump for the select arm.
    let mut pump = parts.payload.as_mut().map(|(_, pump)| pump);
    let mut accept_backoff = AcceptBackoff::default();
    loop {
        // Reap finished forward workers without blocking on the other arms.
        while let Some(result) = parts.workers.try_join_next() {
            match result {
                Ok(Ok(_)) | Ok(Err(ForwardError::PathUnavailable)) => {}
                Ok(Err(ForwardError::TaskFailure)) => {
                    parts.outcome = Some(StartupError::Close {
                        stage: "forward-serve",
                    });
                }
                Ok(Err(error)) => eprintln!("shaar: forward worker ended: {error}"),
                Err(_) => {
                    parts.outcome = Some(StartupError::Close {
                        stage: "forward-serve",
                    });
                }
            }
        }
        // Terminal: caller must call `shutdown` for the joined close.
        if let Some(error) = parts.outcome.clone() {
            return Err(error);
        }
        // Bind failure is terminal.
        if parts.listener.is_none() {
            let listener = match TcpListener::bind(listen).await {
                Ok(listener) => listener,
                Err(_) => {
                    let error = StartupError::Listener;
                    parts.outcome = Some(error.clone());
                    return Err(error);
                }
            };
            if let Ok(address) = listener.local_addr() {
                listening.send_replace(Some(address));
            }
            #[cfg(test)]
            if let Ok(address) = listener.local_addr() {
                emit(parts.events.as_ref(), RoleEvent::ListenerReady(address));
            }
            #[cfg(test)]
            emit(parts.events.as_ref(), RoleEvent::Admitted);
            parts.listener = Some(listener);
        }
        tokio::select! {
            biased;
            () = &mut *shutdown => break,
            advanced = parts.owner.as_mut().expect("live parts retain the path owner").follow(&mut parts.lease) => match advanced {
                Ok(kind) => {
                    // The lease owns its `Arc<Session>`: switching routes never
                    // aborts in-flight forward workers.
                    parts.lease = parts
                        .owner
                        .as_ref()
                        .expect("live parts retain the path owner")
                        .route()
                        .map(|route| (kind, route));
                    #[cfg(test)]
                    emit(parts.events.as_ref(), RoleEvent::RouteActive(kind));
                    #[cfg(test)]
                    if kind == PathKind::Native {
                        emit(
                            parts.events.as_ref(),
                            RoleEvent::NativeRouteActive(tokio::time::Instant::now()),
                        );
                    }
                }
                // The owner is closed; end the loop cleanly.
                Err(StandbyError::Closed) => break,
                // Truthful exhaustion of the attempt budget.
                Err(_) => {
                    let error = StartupError::Exhausted;
                    parts.outcome = Some(error.clone());
                    return Err(error);
                }
            },
            accepted = parts.listener.as_mut().expect("listener is bound").accept(),
                if parts.lease.is_some() && parts.workers.len() < MAX_FORWARDS => {
                match accepted {
                    Ok((stream, _)) => {
                        accept_backoff.succeeded();
                        if let Some((_kind, link)) = parts.lease.as_ref() {
                            let link = Arc::clone(link);
                            parts.workers.spawn(async move { link.forward(stream).await });
                            #[cfg(test)]
                            emit(parts.events.as_ref(), RoleEvent::ForwardStarted(*_kind));
                        }
                    }
                    // Local accept hiccups never kill the client; the retry is
                    // paced so a persistent failure cannot spin the loop.
                    Err(_) => {
                        eprintln!("shaar: local accept failed");
                        tokio::select! {
                            biased;
                            () = &mut *shutdown => break,
                            () = tokio::time::sleep(accept_backoff.failed()) => {}
                        }
                    }
                }
            }
            result = parts.workers.join_next(), if !parts.workers.is_empty() => {
                match result {
                    Some(Ok(Ok(_))) | Some(Ok(Err(ForwardError::PathUnavailable))) => {}
                    Some(Ok(Err(ForwardError::TaskFailure))) | Some(Err(_)) => {
                        let error = StartupError::Close {
                            stage: "forward-serve",
                        };
                        parts.outcome = Some(error.clone());
                        return Err(error);
                    }
                    Some(Ok(Err(error))) => eprintln!("shaar: forward worker ended: {error}"),
                    None => {}
                }
            }
            driven = async {
                pump.as_mut()
                    .expect("pump arm is guarded")
                    .run()
                    .await
            }, if pump.is_some() && !parts.pump_finished => {
                parts.pump_finished = true;
                if driven.is_err() {
                    eprintln!("shaar: ygg pump stopped");
                }
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod accept_backoff_tests {
    use super::AcceptBackoff;
    use std::time::Duration;

    #[test]
    fn failed_accepts_back_off_to_a_cap_and_success_resets() {
        let mut backoff = AcceptBackoff::default();
        let delays: Vec<Duration> = (0..12).map(|_| backoff.failed()).collect();
        assert_eq!(delays[0], Duration::from_millis(10));
        assert_eq!(delays[1], Duration::from_millis(20));
        assert!(delays.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(delays[11], Duration::from_secs(1));
        assert!(delays.iter().all(|delay| *delay <= Duration::from_secs(1)));
        backoff.succeeded();
        assert_eq!(backoff.failed(), Duration::from_millis(10));
    }

    #[test]
    fn a_very_long_failure_run_never_overflows_or_exceeds_the_cap() {
        let mut backoff = AcceptBackoff(u32::MAX);
        assert_eq!(backoff.failed(), Duration::from_secs(1));
        assert_eq!(backoff.failed(), Duration::from_secs(1));
    }
}
