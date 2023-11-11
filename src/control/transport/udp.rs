use std::{
    io,
    net::SocketAddr,
    ops::DerefMut,
    os::fd::{FromRawFd, IntoRawFd},
};

use mio::{net::UdpSocket, Interest};
use stakker::{actor_new, fail, fwd_to, idle, Actor, ActorOwn, Cx, Fwd};
use stakker_mio::{MioPoll, MioSource, Ready, UdpQueue, UdpServerQueue};

// I/O Priorities:
// 0: Listener sockets
// 1: Connected sockets
//
// This prevents a DoS attack on the listener from blocking connected
// sockets from receiving messages.

/// An actor responsible for accepting inbound connections.
pub struct Acceptor {
    /// Queue for asynchronous UDP I/O.
    queue: UdpServerQueue,

    /// Receiver for inbound sockets.
    receiver: Fwd<AcceptedSocket>,

    /// The local address we're listening on.
    local_addr: SocketAddr,

    /// Scratch space for reading messages.
    recv_buf: Vec<u8>,
}

impl Acceptor {
    pub fn new(
        cx: &mut Cx<'_, Self>,
        local_addr: SocketAddr,
        receiver: Fwd<AcceptedSocket>,
    ) -> Option<Self> {
        let socket = match bind_listener(local_addr) {
            Ok(socket) => socket,
            Err(e) => {
                fail!(cx, "failed to bind listener socket: {}", e);
                return None;
            }
        };

        let mio_poll = cx.anymap_get::<MioPoll>();
        let socket = match mio_poll.add(
            socket,
            Interest::READABLE | Interest::WRITABLE,
            0,
            fwd_to!([cx], ready() as (Ready)),
        ) {
            Ok(socket) => socket,
            Err(e) => {
                fail!(cx, "failed to register socket: {}", e);
                return None;
            }
        };

        let mut queue = UdpServerQueue::new();
        queue.init(socket);

        Some(Self {
            queue,
            receiver,
            local_addr,
            recv_buf: vec![0; 65536],
        })
    }

    fn ready(&mut self, cx: &mut Cx<'_, Self>, ready: Ready) {
        if ready.is_readable() {
            // NOTE: theoretically, multiple messages from the same sender could be received in a single read.
            //       we don't handle this because it doesn't happen with our application protocol
            loop {
                match self.queue.read_to_vec(&mut self.recv_buf) {
                    Ok(Some((remote_addr, first_message))) => {
                        // NOTE: we use `idle!` here to avoid blocking existing connections in case of a DoS attack.
                        idle!([cx], accept(remote_addr, first_message))
                    }
                    Ok(None) => break,
                    Err(e) => {
                        fail!(cx, "UDP read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    fn accept(&mut self, cx: &mut Cx<'_, Self>, remote_addr: SocketAddr, first_message: Vec<u8>) {
        let mio_poll = cx.anymap_get::<MioPoll>();

        let socket = match connect_over(self.local_addr, remote_addr) {
            Ok(socket) => socket,
            Err(e) => {
                log::warn!("failed to accept a connection from {}: {}", remote_addr, e);
                return;
            }
        };

        let socket = match mio_poll.add(
            socket,
            Interest::READABLE | Interest::WRITABLE,
            1,
            fwd_to!([cx], ready() as (Ready)),
        ) {
            Ok(socket) => socket,
            Err(e) => {
                fail!(cx, "failed to register socket: {}", e);
                return;
            }
        };

        self.receiver.fwd(AcceptedSocket {
            socket,
            first_message,
        });
    }
}

/// An accepted socket, waiting to be initialized with a receiver.
pub struct AcceptedSocket {
    /// The underlying UDP socket.
    socket: MioSource<UdpSocket>,

    /// The first message, which was received before the receiver was initialized.
    first_message: Vec<u8>,
}

impl AcceptedSocket {
    /// Peek at the first message.
    pub fn peek(&self) -> &[u8] {
        &self.first_message
    }
}

/// An actor wrapping a connected UDP socket.
pub struct Socket {
    /// Queue for asynchronous UDP I/O.
    queue: UdpQueue,

    /// Receiver for inbound messages.
    receiver: Fwd<Vec<u8>>,

    /// Scratch space for reading messages.
    recv_buf: Vec<u8>,
}

impl Socket {
    pub fn from_accepted(
        cx: &mut Cx<'_, Self>,
        accepted: AcceptedSocket,
        receiver: Fwd<Vec<u8>>,
    ) -> Option<Self> {
        let mut queue = UdpQueue::new();
        queue.init(accepted.socket);

        Some(Self {
            queue,
            receiver,
            recv_buf: accepted.first_message,
        })
    }

    pub fn connect(
        cx: &mut Cx<'_, Self>,
        remote_addr: SocketAddr,
        receiver: Fwd<Vec<u8>>,
    ) -> Option<Self> {
        let socket = match connect(remote_addr) {
            Ok(socket) => socket,
            Err(e) => {
                fail!(cx, "failed to connect to {}: {}", remote_addr, e);
                return None;
            }
        };

        let mio_poll = cx.anymap_get::<MioPoll>();
        let socket = match mio_poll.add(
            socket,
            Interest::READABLE | Interest::WRITABLE,
            1,
            fwd_to!([cx], ready() as (Ready)),
        ) {
            Ok(socket) => socket,
            Err(e) => {
                fail!(cx, "failed to register socket: {}", e);
                return None;
            }
        };

        let mut queue = UdpQueue::new();
        queue.init(socket);

        Some(Self {
            queue,
            receiver,
            recv_buf: vec![0; 65536],
        })
    }

    pub fn send(&mut self, _cx: &mut Cx<'_, Self>, data: Vec<u8>) {
        self.queue.push(data)
    }

    fn ready(&mut self, cx: &mut Cx<'_, Self>, ready: Ready) {
        if ready.is_writable() {
            self.queue.flush();
        }

        if ready.is_readable() {
            loop {
                match self.queue.read_to_vec(&mut self.recv_buf) {
                    Ok(Some(data)) => {
                        self.receiver.fwd(data);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        fail!(cx, "UDP read error: {}", e);
                        break;
                    }
                }
            }
        }
    }
}

/// Bind a listener UDP socket.
fn bind_listener(local_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_nonblocking(true)?;

    // Allow connected sockets to be bound over this one.
    socket.set_reuse_address(true)?;

    socket.bind(&local_addr.into())?;

    Ok(unsafe { UdpSocket::from_raw_fd(socket.into_raw_fd()) })
}

/// Connect over top of a listener UDP socket.
fn connect_over(local_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_nonblocking(true)?;

    // Allow connected sockets to be bound over this one.
    socket.set_reuse_address(true)?;

    socket.bind(&local_addr.into())?;
    socket.connect(&remote_addr.into())?;

    // FIXME: it's possible for the listener to receive packets from other peers
    //        in-between binding and connecting. this will cause both peers'
    //        connection attempts to fail permanently or at least until a retry timeout.

    Ok(unsafe { UdpSocket::from_raw_fd(socket.into_raw_fd()) })
}

/// Connect to a remote UDP socket.
fn connect(remote_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_nonblocking(true)?;

    // Connect without binding to avoid receiving packets from other peers.
    socket.connect(&remote_addr.into())?;

    Ok(unsafe { UdpSocket::from_raw_fd(socket.into_raw_fd()) })
}
