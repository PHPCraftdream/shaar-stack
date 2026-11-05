# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact lifecycle hunks for crates/yggdrasil/src/core.rs (leaf 53.2)."""

ORIGINAL_SHA256 = "9995d4e31105ab6d518c1f25e8869774e81d98beee4a51518f83b2b0d7dab7b5"
PATCHED_SHA256 = "128dd275a3ab23c2d6db0e6dc2e7b4fe6b150305058b450a8d9559e79feb635a"

HUNKS = (
    # Hunk 1: old = lines 7..7
    {
        "old": (
            b"use tokio::sync::{mpsc, watch, Mutex, RwLock};\n",
        ),
        "new": (
            b"use tokio::sync::{mpsc, watch, Mutex, RwLock};\n",
            b"use tokio::task::JoinHandle;\n",
            b"use tokio_util::sync::CancellationToken;\n",
        ),
    },
    # Hunk 2: old = lines 42..45
    {
        "old": (
            b"    proto_tx: mpsc::Sender<(Addr, Vec<u8>)>,\n",
            b"    /// Queue of inbound protocol messages, drained by a dedicated task so that\n",
            b"    /// handling them never blocks the traffic read path.\n",
            b"    proto_in_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,\n",
        ),
        "new": (
            b"    proto_tx: mpsc::Sender<(Addr, Vec<u8>)>,\n",
            b"    /// Queue of inbound protocol messages, drained by a dedicated task so that\n",
            b"    /// handling them never blocks the traffic read path.\n",
            b"    proto_in_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,\n",
            b"    /// Cancels every task spawned on the library path when `close` runs.\n",
            b"    shutdown: CancellationToken,\n",
            b"    /// Join handles of tasks spawned by `new`, drained and joined by `close`.\n",
            b"    task_handles: std::sync::Mutex<Vec<JoinHandle<()>>>,\n",
            b"    /// Serializes `close` so a concurrent caller returns only after shutdown finished.\n",
            b"    close_lock: Mutex<()>,\n",
            b"    /// Set once `close` completed; later calls return immediately.\n",
            b"    close_started: std::sync::atomic::AtomicBool,\n",
        ),
    },
    # Hunk 3: old = lines 113..115
    {
        "old": (
            b"        // Create protocol message channel\n",
            b"        let (proto_tx, mut proto_rx) = mpsc::channel::<(Addr, Vec<u8>)>(64);\n",
            b"        let proto_handler = ProtoHandler::new(proto_tx.clone());\n",
        ),
        "new": (
            b"        // Cancellation root for every task spawned by this constructor.\n",
            b"        let shutdown = CancellationToken::new();\n",
            b"\n",
            b"        // Create protocol message channel\n",
            b"        let (proto_tx, mut proto_rx) = mpsc::channel::<(Addr, Vec<u8>)>(64);\n",
            b"        let (proto_handler, proto_cleanup) =\n",
            b"            ProtoHandler::with_shutdown(proto_tx.clone(), shutdown.child_token());\n",
            b"        let mut task_handles = Vec::new();\n",
            b"        task_handles.push(proto_cleanup);\n",
        ),
    },
    # Hunk 4: old = lines 117..127
    {
        "old": (
            b"        // Spawn proto sender task\n",
            b"        let inner_clone = inner.clone();\n",
            b"        tokio::spawn(async move {\n",
            b"            while let Some((addr, msg)) = proto_rx.recv().await {\n",
            b"                // Prepend TYPE_SESSION_PROTO byte\n",
            b"                let mut full_msg = Vec::with_capacity(1 + msg.len());\n",
            b"                full_msg.push(TYPE_SESSION_PROTO);\n",
            b"                full_msg.extend_from_slice(&msg);\n",
            b"                let _ = inner_clone.write_to(&full_msg, &addr).await;\n",
            b"            }\n",
            b"        });\n",
        ),
        "new": (
            b"        // Spawn proto sender task; exits on shutdown or when the channel closes\n",
            b"        let inner_clone = inner.clone();\n",
            b"        let sender_token = shutdown.child_token();\n",
            b"        task_handles.push(tokio::spawn(async move {\n",
            b"            loop {\n",
            b"                let item = tokio::select! {\n",
            b"                    _ = sender_token.cancelled() => None,\n",
            b"                    item = proto_rx.recv() => item,\n",
            b"                };\n",
            b"                let Some((addr, msg)) = item else {\n",
            b"                    break;\n",
            b"                };\n",
            b"                // Prepend TYPE_SESSION_PROTO byte\n",
            b"                let mut full_msg = Vec::with_capacity(1 + msg.len());\n",
            b"                full_msg.push(TYPE_SESSION_PROTO);\n",
            b"                full_msg.extend_from_slice(&msg);\n",
            b"                let _ = inner_clone.write_to(&full_msg, &addr).await;\n",
            b"            }\n",
            b"        }));\n",
        ),
    },
    # Hunk 5: old = lines 147..149
    {
        "old": (
            b"            proto_tx,\n",
            b"            proto_in_tx,\n",
            b"            multicast: Mutex::new(None),\n",
        ),
        "new": (
            b"            proto_tx,\n",
            b"            proto_in_tx,\n",
            b"            shutdown,\n",
            b"            task_handles: std::sync::Mutex::new(task_handles),\n",
            b"            close_lock: Mutex::new(()),\n",
            b"            close_started: std::sync::atomic::AtomicBool::new(false),\n",
            b"            multicast: Mutex::new(None),\n",
        ),
    },
    # Hunk 6: old = lines 155..161
    {
        "old": (
            b"        // Spawn inbound proto handler task\n",
            b"        let core_clone = core.clone();\n",
            b"        tokio::spawn(async move {\n",
            b"            while let Some((from_key, payload)) = proto_in_rx.recv().await {\n",
            b"                core_clone.handle_inbound_proto(from_key, &payload).await;\n",
            b"            }\n",
            b"        });\n",
        ),
        "new": (
            b"        // Spawn inbound proto handler task; exits on shutdown or channel close\n",
            b"        let core_clone = core.clone();\n",
            b"        let inbound_token = core.shutdown.child_token();\n",
            b"        let inbound = tokio::spawn(async move {\n",
            b"            loop {\n",
            b"                let item = tokio::select! {\n",
            b"                    _ = inbound_token.cancelled() => None,\n",
            b"                    item = proto_in_rx.recv() => item,\n",
            b"                };\n",
            b"                let Some((from_key, payload)) = item else {\n",
            b"                    break;\n",
            b"                };\n",
            b"                core_clone.handle_inbound_proto(from_key, &payload).await;\n",
            b"            }\n",
            b"        });\n",
            b"        core.task_handles.lock().unwrap().push(inbound);\n",
        ),
    },
    # Hunk 7: old = lines 163..167
    {
        "old": (
            b"        // Spawn TLS certificate renewal task\n",
            b"        let core_clone = core.clone();\n",
            b"        tokio::spawn(async move {\n",
            b"            core_clone.tls_renewal_task().await;\n",
            b"        });\n",
        ),
        "new": (
            b"        // Spawn TLS certificate renewal task\n",
            b"        let core_clone = core.clone();\n",
            b"        let renewal_token = core.shutdown.child_token();\n",
            b"        let renewal = tokio::spawn(async move {\n",
            b"            core_clone.tls_renewal_task(renewal_token).await;\n",
            b"        });\n",
            b"        core.task_handles.lock().unwrap().push(renewal);\n",
        ),
    },
    # Hunk 8: old = lines 339..346
    {
        "old": (
            b"    /// Close the core and all links.\n",
            b"    pub async fn close(&self) -> Result<(), ironwood::Error> {\n",
            b"        {\n",
            b"            let mut links = self.links.lock().await;\n",
            b"            links.close().await;\n",
            b"        }\n",
            b"        self.inner.close().await\n",
            b"    }\n",
        ),
        "new": (
            b"    /// Close the core and all links.\n",
            b"    ///\n",
            b"    /// Cancels and joins every task spawned on the library path, releases the\n",
            b"    /// links and then closes the inner ironwood connection. Idempotent and\n",
            b"    /// serialized: concurrent or later calls return `Ok(())` only once the\n",
            b"    /// first shutdown has completed.\n",
            b"    pub async fn close(&self) -> Result<(), ironwood::Error> {\n",
            b"        let _close_guard = self.close_lock.lock().await;\n",
            b"        if self.close_started.load(std::sync::atomic::Ordering::SeqCst) {\n",
            b"            return Ok(());\n",
            b"        }\n",
            b"        {\n",
            b"            // Release the optional path-notify target so no RWC cycle survives.\n",
            b"            *self.path_notify_slot.lock().unwrap() = None;\n",
            b"            let mut links = self.links.lock().await;\n",
            b"            links.close().await;\n",
            b"        }\n",
            b"        self.shutdown.cancel();\n",
            b"        // Drain first so no std lock is held across the awaits below.\n",
            b"        let handles: Vec<JoinHandle<()>> = self.task_handles.lock().unwrap().drain(..).collect();\n",
            b"        for handle in handles {\n",
            b"            let _ = handle.await;\n",
            b"        }\n",
            b"        let result = self.inner.close().await;\n",
            b"        self.close_started.store(true, std::sync::atomic::Ordering::SeqCst);\n",
            b"        result\n",
            b"    }\n",
        ),
    },
    # Hunk 9: old = lines 576..581
    {
        "old": (
            b"    /// Background task to renew TLS certificate before expiry.\n",
            b"    /// Checks every 12 hours and renews if certificate expires within 10 days.\n",
            b"    async fn tls_renewal_task(self: Arc<Self>) {\n",
            b"        loop {\n",
            b"            // Check every 12 hours\n",
            b"            tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)).await;\n",
        ),
        "new": (
            b"    /// Background task to renew TLS certificate before expiry.\n",
            b"    /// Checks every 12 hours and renews if certificate expires within 10 days.\n",
            b"    async fn tls_renewal_task(self: Arc<Self>, shutdown: CancellationToken) {\n",
            b"        loop {\n",
            b"            // Check every 12 hours, or exit promptly when the core is closed\n",
            b"            tokio::select! {\n",
            b"                _ = shutdown.cancelled() => return,\n",
            b"                _ = tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)) => {}\n",
            b"            }\n",
        ),
    },
)
