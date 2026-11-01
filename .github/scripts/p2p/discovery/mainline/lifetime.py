# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact source transformation for retained-owner support in actor.rs."""


def edits() -> dict[str, list[tuple[str, str]]]:
    """Return narrowly anchored patches for retained actor ownership."""
    return {
        "src/actor.rs": [
            (
                '    hard_client_only: bool,\n}',
                '    hard_client_only: bool,\n'
                '    #[cfg(test)]\n'
                '    owned_cleanup_gate: Option<(tokio::sync::oneshot::Sender<()>, '
                'tokio::sync::oneshot::Receiver<()>)>,\n}',
            ),
            (
                '            hard_client_only,\n        })',
                '            hard_client_only,\n'
                '            #[cfg(test)]\n'
                '            owned_cleanup_gate: None,\n'
                '        })',
            ),
            (
                'pub(crate) async fn run(mut actor: Actor, mut receiver: mpsc::Receiver<ActorMessage>) {\n'
                '    // Maintenance interval',
                'pub(crate) async fn run(actor: Actor, receiver: mpsc::Receiver<ActorMessage>) {\n'
                '    run_inner(actor, receiver, None).await;\n'
                '}\n\n'
                'pub(crate) async fn run_owned(\n'
                '    actor: Actor,\n'
                '    receiver: mpsc::Receiver<ActorMessage>,\n'
                '    stop: oneshot::Receiver<()>,\n'
                ') {\n'
                '    run_inner(actor, receiver, Some(stop)).await;\n'
                '}\n\n'
                'async fn wait_stop(stop: &mut Option<oneshot::Receiver<()>>) {\n'
                '    match stop {\n'
                '        Some(receiver) => {\n'
                '            let _ = receiver.await;\n'
                '        }\n'
                '        None => std::future::pending::<()>().await,\n'
                '    }\n'
                '}\n\n'
                'async fn run_inner(\n'
                '    mut actor: Actor,\n'
                '    mut receiver: mpsc::Receiver<ActorMessage>,\n'
                '    mut stop: Option<oneshot::Receiver<()>>,\n'
                ') {\n'
                '    // Maintenance interval',
            ),
            (
                '        // Flush any queued outgoing packets\n'
                '        actor.socket.flush().await;\n\n'
                '        tokio::select! {\n'
                '            msg = receiver.recv() => {',
                '        tokio::select! {\n'
                '            biased;\n'
                '            _ = wait_stop(&mut stop) => break,\n'
                '            _ = actor.socket.flush() => {}\n'
                '        }\n\n'
                '        tokio::select! {\n'
                '            biased;\n'
                '            _ = wait_stop(&mut stop) => break,\n'
                '            keep_running = async {\n'
                '                tokio::select! {\n'
                '            msg = receiver.recv() => {',
            ),
            (
                '                    None => {\n'
                '                        // All senders dropped, shutdown.\n'
                '                        debug!("dht::Dht\'s actor task was shutdown after Drop.");\n'
                '                        break;\n'
                '                    }',
                '                    None => {\n'
                '                        // All senders dropped, shutdown.\n'
                '                        debug!("dht::Dht\'s actor task was shutdown after Drop.");\n'
                '                        return false;\n'
                '                    }',
            ),
            (
                '        }\n\n'
                '        actor.tick();',
                '                }\n'
                '                true\n'
                '            } => {\n'
                '                if !keep_running {\n'
                '                    break;\n'
                '                }\n'
                '            }\n'
                '        }\n\n'
                '        actor.tick();',
            ),
            (
                '        actor.tick();\n'
                '    }\n'
                '}\n\n'
                'fn send(',
                '        actor.tick();\n'
                '    }\n'
                '    #[cfg(test)]\n'
                '    if let Some((entered, release)) = actor.owned_cleanup_gate.take() {\n'
                '        let _ = entered.send(());\n'
                '        let _ = release.await;\n'
                '    }\n'
                '}\n\n'
                'fn send(',
            ),
            (
                'pub use info::Info;',
                'pub use info::Info;\n\n'
                '#[cfg(test)]\n'
                '#[path = "actor/owned_tests.rs"]\n'
                'mod owned_tests;',
            ),
        ],
        "src/actor/socket.rs": [
            (
                '    pub async fn recv_from(&mut self) -> Option<(Message, SocketAddrV4)> {\n'
                '        let mut buf = [0u8; MTU];',
                '    pub async fn recv_from(&mut self) -> Option<(Message, SocketAddrV4)> {\n'
                '        #[cfg(test)]\n'
                '        if let Some((entered, release)) = self.owned_recv_gate.take() {\n'
                '            let _ = entered.send(());\n'
                '            let _ = release.await;\n'
                '        }\n'
                '        let mut buf = [0u8; MTU];',
            ),
            (
                '    datagram_hook: Option<DatagramHook>,\n\n'
                '    #[cfg(test)]',
                '    datagram_hook: Option<DatagramHook>,\n'
                '    #[cfg(test)]\n'
                '    pub(crate) owned_flush_gate: Option<(tokio::sync::oneshot::Sender<()>, '
                'tokio::sync::oneshot::Receiver<()>)>,\n'
                '    #[cfg(test)]\n'
                '    pub(crate) owned_recv_gate: Option<(tokio::sync::oneshot::Sender<()>, '
                'tokio::sync::oneshot::Receiver<()>)>,\n\n'
                '    #[cfg(test)]',
            ),
            (
                '            datagram_hook: None,\n\n'
                '            #[cfg(test)]',
                '            datagram_hook: None,\n'
                '            #[cfg(test)]\n'
                '            owned_flush_gate: None,\n'
                '            #[cfg(test)]\n'
                '            owned_recv_gate: None,\n\n'
                '            #[cfg(test)]',
            ),
            (
                '    pub async fn flush(&mut self) {\n'
                '        while let Some((bytes, addr)) = self.outbox.pop_front() {',
                '    pub async fn flush(&mut self) {\n'
                '        #[cfg(test)]\n'
                '        if let Some((entered, release)) = self.owned_flush_gate.take() {\n'
                '            let _ = entered.send(());\n'
                '            let _ = release.await;\n'
                '        }\n'
                '        while let Some((bytes, addr)) = self.outbox.pop_front() {',
            ),
        ],
        "src/lib.rs": [
            (
                'mod dht;',
                'mod dht;\nmod owned;\npub use owned::OwnedDht;',
            ),
        ],
        "src/dht.rs": [
            (
                'const ACTOR_INBOX_CAPACITY:',
                'pub(crate) const ACTOR_INBOX_CAPACITY:',
            ),
        ],
    }
