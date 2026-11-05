# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact lifecycle hunks for crates/yggdrasil/src/proto.rs (leaf 53.2)."""

ORIGINAL_SHA256 = "3f8632200e77ad7079683237737e3c959af54c196c70816bc18dbf09f8dd94dd"
PATCHED_SHA256 = "0253da251e3efbd32c83d2fc74e75c30424c2c5a0198a890c4461f2f02f159d5"

HUNKS = (
    # Hunk 1: old = lines 12..12
    {
        "old": (
            b"use tokio::sync::{mpsc, oneshot, Mutex};\n",
        ),
        "new": (
            b"use tokio::sync::{mpsc, oneshot, Mutex};\n",
            b"use tokio_util::sync::CancellationToken;\n",
        ),
    },
    # Hunk 2: old = lines 83..104
    {
        "old": (
            b"impl ProtoHandler {\n",
            b"    /// Create a new protocol handler.\n",
            b"    pub fn new(proto_tx: mpsc::Sender<(Addr, Vec<u8>)>) -> Arc<Self> {\n",
            b"        let handler = Arc::new(Self {\n",
            b"            self_callbacks: Arc::new(Mutex::new(HashMap::new())),\n",
            b"            peers_callbacks: Arc::new(Mutex::new(HashMap::new())),\n",
            b"            tree_callbacks: Arc::new(Mutex::new(HashMap::new())),\n",
            b"            nodeinfo_callbacks: Arc::new(Mutex::new(HashMap::new())),\n",
            b"            proto_tx,\n",
            b"        });\n",
            b"\n",
            b"        // Spawn cleanup task\n",
            b"        let handler_clone = handler.clone();\n",
            b"        tokio::spawn(async move {\n",
            b"            loop {\n",
            b"                tokio::time::sleep(CLEANUP_INTERVAL).await;\n",
            b"                handler_clone.cleanup_expired().await;\n",
            b"            }\n",
            b"        });\n",
            b"\n",
            b"        handler\n",
            b"    }\n",
        ),
        "new": (
            b"impl ProtoHandler {\n",
            b"    /// Create a new protocol handler.\n",
            b"    pub fn new(proto_tx: mpsc::Sender<(Addr, Vec<u8>)>) -> Arc<Self> {\n",
            b"        let (handler, _) = Self::with_shutdown(proto_tx, CancellationToken::new());\n",
            b"        handler\n",
            b"    }\n",
            b"\n",
            b"    /// Create a new protocol handler; its cleanup task exits when `shutdown`\n",
            b"    /// fires, and the join handle is returned for the owner to await.\n",
            b"    pub fn with_shutdown(\n",
            b"        proto_tx: mpsc::Sender<(Addr, Vec<u8>)>,\n",
            b"        shutdown: CancellationToken,\n",
            b"    ) -> (Arc<Self>, tokio::task::JoinHandle<()>) {\n",
            b"        let handler = Arc::new(Self {\n",
            b"            self_callbacks: Arc::new(Mutex::new(HashMap::new())),\n",
            b"            peers_callbacks: Arc::new(Mutex::new(HashMap::new())),\n",
            b"            tree_callbacks: Arc::new(Mutex::new(HashMap::new())),\n",
            b"            nodeinfo_callbacks: Arc::new(Mutex::new(HashMap::new())),\n",
            b"            proto_tx,\n",
            b"        });\n",
            b"\n",
            b"        // Spawn cleanup task; exits on shutdown or keeps expiring callbacks\n",
            b"        let handler_clone = handler.clone();\n",
            b"        let handle = tokio::spawn(async move {\n",
            b"            loop {\n",
            b"                tokio::select! {\n",
            b"                    _ = shutdown.cancelled() => break,\n",
            b"                    _ = tokio::time::sleep(CLEANUP_INTERVAL) => {}\n",
            b"                }\n",
            b"                handler_clone.cleanup_expired().await;\n",
            b"            }\n",
            b"        });\n",
            b"\n",
            b"        (handler, handle)\n",
            b"    }\n",
        ),
    },
)
