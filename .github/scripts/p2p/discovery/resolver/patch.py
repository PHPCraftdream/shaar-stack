"""Reversible same-version resolver locking corrections."""


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError("reviewed resolver source anchor changed")
    return text.replace(old, new)


CONNECTION_OLD = '''        // Check for an existing usable connection (short lock)
        {
            let mut connections = self.connections.lock().await;
            connections
                .retain(|conn| matches!(conn.meta.status(), Status::Init | Status::Established));
            if let Some(conn) = policy.select_connection(
                self.config.ip,
                &*cx.transport_state().await,'''
CONNECTION_NEW = '''        // Select against both live states; never retain a guard while pending.
        {
            let mut connections_lock = pin!(self.connections.lock());
            let mut transport_lock = pin!(cx.transport_state());
            let (connections, transport_state) = poll_fn(|task| {
                let mut connections = ready!(connections_lock.as_mut().poll(task));
                connections
                    .retain(|conn| matches!(conn.meta.status(), Status::Init | Status::Established));
                match transport_lock.as_mut().poll(task) {
                    Poll::Ready(state) => Poll::Ready((connections, state)),
                    Poll::Pending => {
                        drop(connections);
                        connections_lock.set(self.connections.lock());
                        Poll::Pending
                    }
                }
            })
            .await;
            if let Some(conn) = policy.select_connection(
                self.config.ip,
                &transport_state,'''
CLEANUP_OLD = '''        self.active_requests.lock().remove(&self.key);'''
CLEANUP_NEW = '''        let removed = {
            let mut active = self.active_requests.lock();
            active.remove(&self.key)
        };
        drop(removed);'''
EDITS = {
    "src/name_server.rs": [
        ("    fmt::Debug,\n", "    fmt::Debug,\n    future::{Future, poll_fn},\n    pin::pin,\n    task::{Poll, ready},\n"),
        (CONNECTION_OLD, CONNECTION_NEW),
    ],
    "src/name_server_pool.rs": [(CLEANUP_OLD, CLEANUP_NEW)],
}


def transform(files):
    changed = {}
    for name, edits in EDITS.items():
        text = files[name].decode()
        for old, new in edits:
            text = replace(text, old, new)
        changed[name] = text.encode()
    return changed


def reverse(files):
    restored = dict(files)
    for name, edits in EDITS.items():
        text = files[name].decode()
        for old, new in reversed(edits):
            text = replace(text, new, old)
        restored[name] = text.encode()
    return restored
