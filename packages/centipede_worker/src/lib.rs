#![feature(maybe_uninit_uninit_array)]
#![feature(maybe_uninit_slice)]

use std::{
    io,
    mem::{self, MaybeUninit},
    net::SocketAddr,
    ops::Deref,
    os::fd::AsRawFd,
    task::Poll,
    time::Duration,
};

use centipede_proto::{marker::auth, ControlMessage, MessageDiscriminant, PacketMessage};
use centipede_router::worker::{ConfigChanged, WorkerHandle};
use miette::Diagnostic;
use mio::unix::SourceFd;
use sockets::Sockets;
use thiserror::Error;

mod sockets;

/// This is the entrypoint of a worker.
pub struct Worker<'r> {
    /// The underlying handle to the router.
    router_handle: WorkerHandle<'r>,

    /// A callback for received control messages.
    control_message_sink: Box<ControlMessageSink<'r>>,

    /// The TUN queue.
    tun_queue: hypertube::Queue<'r, false>,

    /// Sockets in use by the worker.
    sockets: Sockets,

    /// A [`mio::Poll`] instance to use for polling sockets.
    poll: mio::Poll,
}

pub type ControlMessageSink<'r> =
    dyn FnMut(SocketAddr, ControlMessage<Vec<u8>, auth::Unknown>) + Send + 'r;

impl<'r> Worker<'r> {
    /// Create a new worker.
    pub fn new(
        router_handle: WorkerHandle<'r>,
        control_message_sink: Box<ControlMessageSink<'r>>,
        tun_queue: hypertube::Queue<'r, false>,
    ) -> Result<Self, Error> {
        let poll = mio::Poll::new()?;

        poll.registry().register(
            &mut SourceFd(&tun_queue.as_raw_fd()),
            TUN_TOKEN,
            mio::Interest::READABLE,
        )?;

        Ok(Self {
            router_handle,
            control_message_sink,
            tun_queue,
            sockets: Sockets::new(),
            poll,
        })
    }

    /// Send a control message using the worker's set of sockets.
    pub fn send_control_message<B: Deref<Target = [u8]>>(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        message: ControlMessage<B, auth::Valid>,
    ) -> Result<(), Error> {
        self.sockets
            .resolve_or_bind_local_addr(local_addr)?
            .send_to(message.as_buffer(), &remote_addr.into())?;

        Ok(())
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

    /// Handle a configuration change.
    fn handle_config_change(&mut self, change: ConfigChanged) -> Result<(), Error> {
        let update = self
            .sockets
            .update(change.recv_addrs().chain(change.send_addrs()))?;

        for i in update.opened_indices {
            self.poll
                .registry()
                .register(
                    &mut SourceFd(&self.sockets.resolve_index(i).unwrap().as_raw_fd()),
                    mio::Token(i),
                    mio::Interest::READABLE,
                )
                .unwrap();
        }

        // FIXME: deregister closed sockets

        Ok(())
    }

    /// Handle a readable event on the TUN device.
    fn handle_tun_readable(&mut self) -> Result<(), Error> {
        log::trace!("tun readable");

        // TODO: optimize this
        let mut read_buf = [0; PACKET_BUFFER_SIZE];
        let mut write_buf = Vec::new();

        while let Poll::Ready(n) = self.tun_queue.read(&mut read_buf).map_err(Error::ReadTun)? {
            log::trace!("tun read {} byte packet", n);

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
        log::trace!("socket {} readable", idx);

        let socket = self
            .sockets
            .resolve_index(idx)
            .expect("invalid socket index");

        let mut buf: [MaybeUninit<u8>; PACKET_BUFFER_SIZE] = MaybeUninit::uninit_array();

        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    log::trace!("socket {} read {} byte packet", idx, n);

                    // SAFETY: we just read `n` bytes into the buffer.
                    let msg = unsafe { MaybeUninit::slice_assume_init_mut(&mut buf[..n]) };

                    match centipede_proto::discriminate(&*msg) {
                        Ok(MessageDiscriminant::Control) => {
                            let control = match ControlMessage::deserialize(&*msg) {
                                Ok(control) => control,
                                Err(e) => {
                                    log::warn!("failed to parse packet message: {}", e);
                                    continue;
                                }
                            };

                            (self.control_message_sink)(
                                from.as_socket()
                                    .expect("socket should have an IP family address"),
                                control.to_vec_backed(),
                            )
                        }
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
                                let _ = self
                                    .tun_queue
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
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(Error::ReadSocket(e))?,
            }
        }
    }
}

const TUN_TOKEN: mio::Token = mio::Token(usize::MAX);

const PACKET_BUFFER_SIZE: usize = 65536;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("failed to poll for events")]
    #[diagnostic(code(centipede::worker::poll_failed))]
    Poll(#[from] io::Error),

    #[error(transparent)]
    Sockets(#[from] sockets::SocketsError),

    #[error("failed to read from TUN device")]
    #[diagnostic(code(centipede::worker::read_tun_failed))]
    ReadTun(#[source] io::Error),

    #[error("failed to write to UDP socket")]
    #[diagnostic(code(centipede::worker::write_socket_failed))]
    WriteSocket(#[source] io::Error),

    #[error("failed to read from UDP socket")]
    #[diagnostic(code(centipede::worker::read_socket_failed))]
    ReadSocket(#[source] io::Error),

    #[error("failed to write to TUN device")]
    #[diagnostic(code(centipede::worker::write_tun_failed))]
    WriteTun(#[source] io::Error),
}
