use std::sync::atomic::AtomicBool;

use centipede_router::worker::WorkerHandle;
use sockets::Sockets;

mod sockets;

/// This is the entrypoint of a worker.
pub struct Worker<'r> {
    /// The underlying handle to the router.
    router_handle: WorkerHandle<'r>,

    /// Sockets in use by the worker.
    sockets: Sockets,

    /// A [`mio::Poll`] instance to use for polling sockets.
    poll: mio::Poll,

    /// A buffer of events to handle.
    events: mio::Events,
}

impl<'r> Worker<'r> {
    /// Create a new worker.
    pub fn new(router_handle: WorkerHandle<'r>) -> Self {
        Self {
            router_handle,
            sockets: Sockets::new(),
            poll: mio::Poll::new().unwrap(),
            events: mio::Events::with_capacity(1024),
        }
    }

    /// Wait for at least one event and handle it.
    pub fn wait_and_handle(&mut self) {
        todo!()
    }

    /// Handle events repeatedly until a shutdown is requested.
    pub fn handle_until(&mut self, shutdown: &AtomicBool) {
        todo!()
    }
}
