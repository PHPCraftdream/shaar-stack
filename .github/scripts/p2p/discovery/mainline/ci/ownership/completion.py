# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Wire typed mutable-query completion to the bounded actor owner."""
from __future__ import annotations


def edits() -> dict[str, list[tuple[str, str]]]:
    return {
        "src/actor.rs": [
            (
                "                        ActorMessage::ToBootstrap(sender) => {",
                "                        ActorMessage::OwnedAdmission(target, sender, deadline, request_lease) => {\n                            actor.owned_admission_until(target, sender, deadline, request_lease);\n                        }\n                        ActorMessage::OwnedMutable(target, sender, deadline) => {\n                            if let Err(error) = actor.owned_mutable_until(target, sender, deadline) {\n                                match error {\n                                    crate::resource::ResourceError::OperationLimit | crate::resource::ResourceError::ResultLimit => {}\n                                    _ => actor.owned_fail(error),\n                                }\n                            }\n                        }\n                        ActorMessage::ToBootstrap(sender) => {",
            ),
            (
                "    ToBootstrap(oneshot::Sender<Vec<String>>),",
                "    OwnedAdmission(Id, oneshot::Sender<crate::resource::RequestReply>, tokio::time::Instant, std::sync::Arc<crate::resource::RequestLease>),\n    OwnedMutable(Id, oneshot::Sender<Result<crate::resource::OwnedQueryCompletion, crate::resource::ResourceError>>, tokio::time::Instant),\n    ToBootstrap(oneshot::Sender<Vec<String>>),",
            ),
            (
                "        actor.process_message(message, from);",
                "        let transaction_id = message.transaction_id;\n        let has_response = matches!(&message.message_type, MessageType::Response(_) | MessageType::Error(_));\n        actor.process_message(message, from);\n        if has_response { actor.owned_note_response(transaction_id); }",
            ),
        ],
        "src/lib.rs": [
            (
                "mod resource;",
                "mod resource;\npub use resource::{OwnedQueryCompletion, ResourceError};",
            ),
        ],
    }
