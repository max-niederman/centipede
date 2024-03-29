#![feature(maybe_uninit_uninit_array)]
#![feature(maybe_uninit_slice)]

use std::{
    io,
    mem::{self, MaybeUninit},
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
    time::Duration,
};

use centipede_proto::{MessageDiscriminant, PacketMessage};
use centipede_router::worker::{ConfigChanged, WorkerHandle};
use mio::unix::SourceFd;
use sockets::Sockets;
use thiserror::Error;

mod sockets;

/// This is the entrypoint of a worker.
pub struct Worker<'r> {
    /// The underlying handle to the router.
    router_handle: WorkerHandle<'r>,

    /// The TUN queue.
    tun_queue: hypertube::Queue<'r, false>,

    /// Sockets in use by the worker.
    sockets: Sockets,

    /// A [`mio::Poll`] instance to use for polling sockets.
    poll: mio::Poll,
}

impl<'r> Worker<'r> {
    /// Create a new worker.
    pub fn new(router_handle: WorkerHandle<'r>, tun_queue: hypertube::Queue<'r, false>) -> Self {
        Self {
            router_handle,
            tun_queue,
            sockets: Sockets::new(),
            poll: mio::Poll::new().unwrap(),
        }
    }

    /// Wait for at least one event and handle it.
    ///
    /// Mutably borrows an event buffer for scratch space, to avoid reallocating it.
    pub fn wait_and_handle(&mut self, events: &mut mio::Events) -> Result<(), Error> {
        if let Poll::Ready(change) = self.router_handle.poll_config_changed() {
            self.handle_config_change(change)?;
        }

        events.clear();
        self.poll
            .poll(events, Some(Duration::from_secs(1)))
            .map_err(Error::Poll)?;

        for event in &*events {
            match event.token() {
                // FIXME: ensure one event source cannot starve the others
                TUN_TOKEN => self.handle_tun_readable()?,
                mio::Token(idx) => self.handle_socket_readable(idx)?,
            }
        }

        Ok(())
    }

    /// Handle events repeatedly until a shutdown is requested.
    pub fn handle_until(&mut self, shutdown: &AtomicBool) -> Result<(), Error> {
        let mut events_scratch = mio::Events::with_capacity(1024);

        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            self.wait_and_handle(&mut events_scratch)?;
        }

        Ok(())
    }

    /// Handle a configuration change.
    fn handle_config_change(&mut self, change: ConfigChanged) -> Result<(), Error> {
        self.sockets
            .update(change.recv_addrs().chain(change.send_addrs()))?;

        for (i, _) in change.recv_addrs().enumerate() {
            self.poll
                .registry()
                .register(
                    &mut SourceFd(&self.sockets.resolve_index(i).unwrap().as_raw_fd()),
                    mio::Token(i),
                    mio::Interest::READABLE,
                )
                .unwrap();
        }

        Ok(())
    }

    /// Handle a readable event on the TUN device.
    fn handle_tun_readable(&mut self) -> Result<(), Error> {
        // TODO: optimize this
        let mut read_buf = [0; PACKET_BUFFER_SIZE];
        let mut write_buf = Vec::new();

        while let Poll::Ready(n) = self.tun_queue.read(&mut read_buf).map_err(Error::ReadTun)? {
            let buf = &mut read_buf[..n];

            let mut obligations = self.router_handle.handle_outgoing(buf);

            while let Some(obligation) = obligations.resume(mem::take(&mut write_buf)) {
                let socket = self
                    .sockets
                    .resolve_or_bind_local_addr(obligation.link().local)?;

                socket
                    .send_to(
                        obligation.message().as_buffer(),
                        &obligation.link().remote.into(),
                    )
                    .map_err(Error::WriteSocket)?;

                write_buf = obligation.fulfill();
            }
        }

        Ok(())
    }

    /// Handle a readable event on a socket.
    fn handle_socket_readable(&mut self, idx: usize) -> Result<(), Error> {
        let socket = self
            .sockets
            .resolve_index(idx)
            .expect("invalid socket index");

        let mut buf: [MaybeUninit<u8>; PACKET_BUFFER_SIZE] = MaybeUninit::uninit_array();

        loop {
            match socket.recv(&mut buf) {
                Ok(n) => {
                    // SAFETY: we just read `n` bytes into the buffer.
                    let msg = unsafe { MaybeUninit::slice_assume_init_mut(&mut buf[..n]) };

                    match centipede_proto::discriminate(&*msg) {
                        Ok(MessageDiscriminant::Control) => todo!(),
                        Ok(MessageDiscriminant::Packet) => {
                            let packet = match PacketMessage::from_buffer(msg) {
                                Ok(packet) => packet,
                                Err(e) => {
                                    log::warn!("failed to parse packet message: {}", e);
                                    continue;
                                }
                            };

                            if let Some(obligation) = self.router_handle.handle_incoming(packet) {
                                // TODO: ensure writes complete
                                self.tun_queue
                                    .write(obligation.packet())
                                    .map_err(Error::WriteTun)?;
                            }
                        }
                        Err(e) => {
                            log::warn!("failed to parse message: {}", e);
                            continue;
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(Error::ReadSocket(e))?,
            }
        }

        todo!()
    }
}

const TUN_TOKEN: mio::Token = mio::Token(usize::MAX);

const PACKET_BUFFER_SIZE: usize = 65536;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to poll for events")]
    Poll(#[from] io::Error),

    #[error(transparent)]
    Sockets(#[from] sockets::SocketsError),

    #[error("failed to read from TUN device")]
    ReadTun(#[source] io::Error),

    #[error("failed to write to UDP socket")]
    WriteSocket(#[source] io::Error),

    #[error("failed to read from UDP socket")]
    ReadSocket(#[source] io::Error),

    #[error("failed to write to TUN device")]
    WriteTun(#[source] io::Error),
}
