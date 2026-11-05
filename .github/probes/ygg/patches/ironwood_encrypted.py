# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact lifecycle hunk for crates/ironwood/src/encrypted/mod.rs (leaf 53.2b)."""

ORIGINAL_SHA256 = "d9ec589e31f4322ef17635165a55c1566031fa1d8d022efa4242e82106da0286"
PATCHED_SHA256 = "3cbb511154ba1c1990e5b9d5005f5111bd5afea860f8fdbb2490fcae7c16cbc3"

HUNKS = (
    # Hunk 1: a delivery blocked on a full receive queue must not outlive `close`.
    {
        "old": (
            b"                    if recv_tx.send(msg).await.is_err() {\n",
            b"                        return; // channel closed\n",
            b"                    }\n",
        ),
        "new": (
            b"                    // Cancellation must interrupt a delivery blocked on a full queue.\n",
            b"                    tokio::select! {\n",
            b"                        _ = cancel.cancelled() => return,\n",
            b"                        result = recv_tx.send(msg) => {\n",
            b"                            if result.is_err() {\n",
            b"                                return; // channel closed\n",
            b"                            }\n",
            b"                        }\n",
            b"                    }\n",
        ),
    },
)
