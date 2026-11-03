# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Wire typed mutable-query completion and bounded PUT admission to the actor."""
from __future__ import annotations


def edits() -> dict[str, list[tuple[str, str]]]:
    """Return actor wiring edits while preserving GET completion and response receipts."""
    return {
        "src/actor.rs": [
            (
                "                        ActorMessage::ToBootstrap(sender) => {",
                "                        ActorMessage::OwnedAdmission(target, sender, deadline, request_lease) => {\n                            actor.owned_admission_until(target, sender, deadline, request_lease);\n                        }\n                        ActorMessage::OwnedMutable(target, sender, deadline) => {\n                            if let Err(error) = actor.owned_mutable_until(target, sender, deadline) {\n                                match error {\n                                    crate::resource::ResourceError::OperationLimit | crate::resource::ResourceError::ResultLimit => {}\n                                    _ => actor.owned_fail(error),\n                                }\n                            }\n                        }\n                        ActorMessage::OwnedPut(target, item, reply, cleanup, cancel, deadline, request_lease) => {\n                            actor.owned_put_admission_until(target, item, reply, cleanup, cancel, deadline, request_lease);\n                        }\n                        ActorMessage::ToBootstrap(sender) => {",
            ),
            (
                "    ToBootstrap(oneshot::Sender<Vec<String>>),",
                "    OwnedAdmission(Id, oneshot::Sender<crate::resource::RequestReply>, tokio::time::Instant, std::sync::Arc<crate::resource::RequestLease>),\n    OwnedMutable(Id, oneshot::Sender<Result<crate::resource::OwnedQueryCompletion, crate::resource::ResourceError>>, tokio::time::Instant),\n    OwnedPut(Id, crate::MutableItem, oneshot::Sender<Result<crate::resource::ChargedPutReceiver, crate::resource::ResourceError>>, oneshot::Sender<()>, oneshot::Receiver<()>, tokio::time::Instant, std::sync::Arc<crate::resource::RequestLease>),\n    ToBootstrap(oneshot::Sender<Vec<String>>),",
            ),
            (
                "        actor.process_message(message, from);",
                "        actor.process_owned_publication_message(message, from);",
            ),
        ],
        "src/lib.rs": [
            (
                "mod resource;",
                "mod resource;\npub use resource::{OwnedQueryCompletion, OwnedPutCompletion, OwnedPutError, OwnedPutOperation, OwnedPutAdmission, OwnedPutAdmissionError, OwnedPutCleanup, Observer, CleanupHold, ResourceError};",
            ),
        ],
    }
