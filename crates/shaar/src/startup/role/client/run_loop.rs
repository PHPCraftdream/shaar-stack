//! Composed client loop and retained route leases.

#![forbid(unsafe_code)]

use super::*;

/// The live role loop over retained parts (biased select, same arm order and emission points as
/// before). Once the outcome is set, `run` returns that error immediately; `Ok` closes nothing.
/// cancel-safe: YES — parts retain all owners; cancelling drops borrowed waiters only.
pub(super) async fn run_parts(
    parts: &mut ClientParts,
    listen: SocketAddr,
    shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
) -> Result<(), StartupError> {
    #[cfg(test)]
    emit_payload_acquired(parts.events.as_ref(), parts.payload.is_some());
    // Split borrow of the owned pump for the select arm.
    let mut pump = parts.payload.as_mut().map(|(_, pump)| pump);
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
            advanced = super::super::dialers::follow_releasing_stale_lease(
                parts.owner.as_mut().expect("live parts retain the path owner").as_mut(),
                &mut parts.lease,
            ) => match advanced {
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
                        if let Some((_kind, link)) = parts.lease.as_ref() {
                            let link = Arc::clone(link);
                            parts.workers.spawn(async move { link.forward(stream).await });
                            #[cfg(test)]
                            emit(parts.events.as_ref(), RoleEvent::ForwardStarted(*_kind));
                        }
                    }
                    // Local accept hiccups never kill the client; the next
                    // loop iteration retries the listener.
                    Err(_) => eprintln!("shaar: local accept failed"),
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
