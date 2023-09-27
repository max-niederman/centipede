use std::{
    io,
    sync::{Arc, Mutex},
    thread,
};

use async_executor::Executor;

use crate::tunnel;

pub mod message;

/// A collection of background tasks which manage connections.
pub struct Daemon<'ts> {
    /// The executor on which background tasks are spawned.
    executor: Arc<Executor<'static>>,

    /// A signal to shut down the daemon.
    shutdown: async_channel::Sender<()>,

    /// The tunnel state transitioner.
    tunnel_state_trans: Mutex<tunnel::StateTransitioner<'ts>>,
}

impl<'ts> Daemon<'ts> {
    pub fn spawn(tunnel_state_trans: tunnel::StateTransitioner<'ts>) -> io::Result<Self> {
        let executor = Arc::new(Executor::new());
        let (shutdown_tx, shutdown_rx) = async_channel::unbounded::<()>();

        thread::Builder::new()
            .name("centipede-control".to_string())
            .spawn({
                let executor = executor.clone();
                move || async_io::block_on(executor.run(shutdown_rx.recv()))
            })?;

        Ok(Self {
            executor,
            shutdown: shutdown_tx,
            tunnel_state_trans: Mutex::new(tunnel_state_trans),
        })
    }
}

impl Drop for Daemon<'_> {
    fn drop(&mut self) {
        self.shutdown.try_send(()).unwrap();
    }
}
