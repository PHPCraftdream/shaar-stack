# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Reversible bounded-resource integration for the private KRPC socket owner."""
from __future__ import annotations


def edits() -> dict[str, list[tuple[str, str]]]:
    return {
        "src/lib.rs": [
            ("mod dht;\n", "mod dht;\nmod resource;\n"),
        ],
        "src/actor/socket.rs": [
            (
                "    /// Receive one datagram. Waits for readability, then calls",
                '''    async fn send_to_owned(&self, buffer: &[u8], target: SocketAddr, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let transmit = noq_udp::Transmit {
            destination: target,
            ecn: None,
            contents: buffer,
            segment_size: None,
            src_ip: None,
        };
        loop {
            match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, self.socket.writable()).await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "owned operation deadline elapsed"))??,
                None => self.socket.writable().await?,
            }
            if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "owned operation deadline elapsed"));
            }
            match self.socket.try_io(Interest::WRITABLE, || {
                self.state.send((&self.socket).into(), &transmit)
            }) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }

    /// Receive one datagram. Waits for readability, then calls''',
            ),
            (
                "use super::config::Config;\n",
                "use super::config::Config;\n#[path = \"socket/resources.rs\"]\nmod resources;\n#[path = \"socket/owned.rs\"]\nmod owned_socket;\n",
            ),
            (
                "    outbox: VecDeque<(Vec<u8>, SocketAddr)>,\n",
                "    outbox: VecDeque<(Vec<u8>, SocketAddr)>,\n    owned: Option<owned_socket::OwnedSocket>,\n",
            ),
            (
                "            outbox: VecDeque::new(),\n",
                "            outbox: VecDeque::new(),\n            owned: None,\n",
            ),
            (
                "        self.inflight_requests.cleanup();\n",
                "        if let Some(owned) = self.owned.as_mut() {\n            for tid in owned.resources.expired(self.inflight_requests.request_timeout()) {\n                self.inflight_requests.remove(tid);\n                owned.resources.rollback_rpc(tid);\n            }\n        } else {\n            self.inflight_requests.cleanup();\n        }\n",
            ),
            (
                "    pub fn inflight(&self, transaction_id: &u32) -> bool {\n        self.inflight_requests.get(*transaction_id).is_some()\n    }",
                "    pub fn inflight(&self, transaction_id: &u32) -> bool {\n        if self.owned.is_some() {\n            self.owned_inflight(*transaction_id)\n        } else {\n            self.inflight_requests.get(*transaction_id).is_some()\n        }\n    }",
            ),
            (
                "        match self.inflight_requests.remove(message.transaction_id) {\n            Some(request) => {\n                if compare_socket_addr(&request.to, from) {\n                    return true;\n                } else {",
                "        if self.owned.is_some() {\n            self.maintain_owned_requests();\n            return self.accept_owned_response(message.transaction_id, *from);\n        }\n        match self.inflight_requests.remove(message.transaction_id) {\n            Some(request) => {\n                if compare_socket_addr(&request.to, from) {\n                    return true;\n                } else {",
            ),
            (
                "    pub fn response(\n        &mut self,\n        address: SocketAddrV4,\n        transaction_id: u32,\n        response: ResponseSpecific,\n    ) {\n        let message =",
                "    pub fn response(\n        &mut self,\n        address: SocketAddrV4,\n        transaction_id: u32,\n        response: ResponseSpecific,\n    ) {\n        if self.owned.is_some() {\n            if let Err(error) = self.response_owned(address, transaction_id, response) {\n                if let Some(owned) = self.owned.as_mut() { owned.failure = Some(error); }\n            }\n            return;\n        }\n        let message =",
            ),
            (
                "    pub fn error(&mut self, address: SocketAddrV4, transaction_id: u32, error: ErrorSpecific) {\n        let message =",
                "    pub fn error(&mut self, address: SocketAddrV4, transaction_id: u32, error: ErrorSpecific) {\n        if self.owned.is_some() {\n            if let Err(error) = self.error_owned(address, transaction_id, error) {\n                if let Some(owned) = self.owned.as_mut() { owned.failure = Some(error); }\n            }\n            return;\n        }\n        let message =",
            ),
            (
                "        while let Some((bytes, addr)) = self.outbox.pop_front() {\n            if let Err(e) = self.io.send_to(&bytes, addr).await {",
                "        if self.owned.is_some() {\n            self.flush_owned().await;\n            return;\n        }\n        while let Some((bytes, addr)) = self.outbox.pop_front() {\n            if let Err(e) = self.io.send_to(&bytes, addr).await {",
            ),
            (
                "    pub(crate) fn send_datagram(&mut self, bytes: Vec<u8>, address: SocketAddrV4) {\n        self.outbox.push_back((bytes, address.into()));\n    }",
                "    pub(crate) fn send_datagram(&mut self, bytes: Vec<u8>, address: SocketAddrV4) {\n        if self.owned.is_some() {\n            if let Err(error) = self.send_datagram_owned(bytes, address) {\n                if let Some(owned) = self.owned.as_mut() { owned.failure = Some(error); }\n            }\n        } else {\n            self.outbox.push_back((bytes, address.into()));\n        }\n    }",
            ),
            (
                "                                    \"Received response message\"\n                                );\n\n                                self.is_expected_response(&message, &from)",
                "                                    \"Received response message\"\n                                );\n\n                                self.is_expected_owned_publication_response(&message, &from)",
            ),
            (
                "                                    \"Received error message\"\n                                );\n\n                                self.is_expected_response(&message, &from)",
                "                                    \"Received error message\"\n                                );\n\n                                self.is_expected_owned_publication_response(&message, &from)",
            ),
        ],
    }
