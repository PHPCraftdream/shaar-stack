# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0


"""Bounded n0source ingress decoding; depth 3 covers the root dictionary,
its request/response arguments, and a peer/value list within those arguments.
"""


def edits() -> dict[str, list[tuple[str, str]]]:
    return {
        "src/common/messages.rs": [
            (
                "Message::from_serde_message(internal::DHTMessage::from_bytes(bytes)?)",
                "Message::from_serde_message(serde_bencode::de::from_bytes_bounded(bytes, 2048, 3)?)",
            ),
            (
                "                        internal::DHTResponseSpecific::GetMutable { arguments } => {\n                            ResponseSpecific::GetMutable",
                "                        internal::DHTResponseSpecific::GetMutable { arguments } => {\n                            if arguments.v.len() > 1000 {\n                                return Err(DecodeMessageError::ValueTooLarge);\n                            }\n                            ResponseSpecific::GetMutable",
            ),
            (
                "    #[error(\"Expected message to be longer than 15 characters\")]\n",
                "    #[error(\"Mutable value exceeds 1000 bytes\")]\n    /// Mutable value exceeds 1000 bytes\n    ValueTooLarge,\n\n    #[error(\"Expected message to be longer than 15 characters\")]\n",
            ),
            (
                "                                            PutMutableRequestArguments {\n                                                target: Id::from_bytes(arguments.target)?,\n                                                v: arguments.v,",
                "                                            PutMutableRequestArguments {\n                                                target: Id::from_bytes(arguments.target)?,\n                                                v: {\n                                                    if arguments.v.len() > 1000 {\n                                                        return Err(DecodeMessageError::ValueTooLarge);\n                                                    }\n                                                    arguments.v\n                                                },",
            ),
        ],
        "src/common/mutable.rs": [
            (
                "    ) -> Result<Self, MutableError> {\n        let key = VerifyingKey::try_from(key)",
                "    ) -> Result<Self, MutableError> {\n        if v.len() > 1000 {\n            return Err(MutableError::ValueTooLarge);\n        }\n        let key = VerifyingKey::try_from(key)",
            ),
            (
                "    #[error(\"Invalid mutable item signature\")]\n    /// Invalid mutable item signature\n    InvalidMutableSignature,",
                "    #[error(\"Mutable item value exceeds 1000 bytes\")]\n    /// Mutable item value exceeds 1000 bytes\n    ValueTooLarge,\n\n    #[error(\"Invalid mutable item signature\")]\n    /// Invalid mutable item signature\n    InvalidMutableSignature,",
            ),
        ],
        "src/actor/socket.rs": [
            (
                "struct UdpIo {\n    socket: UdpSocket,\n    state: noq_udp::UdpSocketState,\n}",
                "struct UdpIo {\n    socket: UdpSocket,\n    state: noq_udp::UdpSocketState,\n    #[cfg(test)]\n    ingress_override_len: std::sync::atomic::AtomicUsize,\n    #[cfg(test)]\n    ingress_override_stride: std::sync::atomic::AtomicUsize,\n}",
            ),
            (
                "        Ok(Self { socket, state })",
                "        Ok(Self {\n            socket,\n            state,\n            #[cfg(test)]\n            ingress_override_len: std::sync::atomic::AtomicUsize::new(0),\n            #[cfg(test)]\n            ingress_override_stride: std::sync::atomic::AtomicUsize::new(0),\n        })",
            ),
            (
                "        let mut buf = [0u8; MTU];\n\n        self.inflight_requests.cleanup();",
                "        let mut buf = [0u8; MTU + 1];\n\n        self.inflight_requests.cleanup();",
            ),
            (
                "            Ok((amt, SocketAddr::V4(from))) => {\n                let bytes = &buf[..amt];",
                "            Ok((amt, SocketAddr::V4(from))) => {\n                if amt > MTU || amt > buf.len() {\n                    return None;\n                }\n                let bytes = &buf[..amt];",
            ),
            (
                "            let mut iov = [IoSliceMut::new(buf)];\n            let mut meta = [noq_udp::RecvMeta::default()];\n            let n = self\n                .state\n                .recv((&self.socket).into(), &mut iov, &mut meta)?;\n            if n > 0 {\n                Ok((meta[0].len, meta[0].addr))",
                "            let capacity = buf.len();\n            let mut iov = [IoSliceMut::new(buf)];\n            let mut meta = [noq_udp::RecvMeta::default()];\n            let n = self\n                .state\n                .recv((&self.socket).into(), &mut iov, &mut meta)?;\n            if n > 0 {\n                #[cfg(test)]\n                {\n                    use std::sync::atomic::Ordering;\n                    let override_len = self.ingress_override_len.swap(0, Ordering::Relaxed);\n                    if override_len != 0 {\n                        meta[0].len = override_len;\n                        meta[0].stride = self.ingress_override_stride.swap(0, Ordering::Relaxed);\n                    }\n                }\n                if n != 1 || meta[0].stride == 0 || meta[0].len != meta[0].stride || meta[0].len > capacity {\n                    return Err(io::Error::new(ErrorKind::InvalidData, \"invalid UDP receive metadata\"));\n                }\n                Ok((meta[0].len, meta[0].addr))",
            ),
        ],
    }
