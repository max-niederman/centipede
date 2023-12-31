use std::{
    collections::hash_map::{self, HashMap},
    io,
    mem::MaybeUninit,
    net::SocketAddr,
    os::fd::AsRawFd,
    rc::Rc,
    sync::atomic::Ordering,
    task::Poll,
};

use mio::unix::SourceFd;
use socket2::{SockAddr, Socket};
use thiserror::Error;

use super::{message::Message, packet_memory::PacketRecollection, SharedState};

// TODO: make this configurable or use path MTU discovery
const BUFFER_SIZE: usize = 64 * 1024;

/// The entrypoint of each tunnel worker.
pub fn entrypoint(
    shared_state: &SharedState,
    tun_queue: &hypertube::queue::Queue<false>,
) -> Result<!, Error> {
    // TODO: Ensure the passed TUN queue is correctly configured, once we use a seperate tun lib.

    // Create a mio poller and event queue.
    let mut poll = mio::Poll::new().map_err(Error::EventLoopCreation)?;
    let mut events = mio::Events::with_capacity(1024);

    let mut send_sockets: HashMap<SocketAddr, Rc<Socket>> = HashMap::new();

    // TODO: dynamic swapping
    // Bind each of the receive sockets.
    let recv_sockets: Vec<_> = shared_state
        .recv_addrs
        .iter()
        .map(|addr| {
            let socket = Rc::new(bind_recv_socket(*addr)?);

            send_sockets.insert(*addr, socket.clone());

            Ok::<_, Error>(socket)
        })
        .try_collect()?;

    // Register the TUN queue with the poller.
    poll.registry()
        .register(
            &mut SourceFd(&tun_queue.as_raw_fd()),
            TUN_TOKEN,
            mio::Interest::READABLE,
        )
        .map_err(Error::EventLoopCreation)?;

    // Register the receive sockets with the poller.
    for (i, socket) in recv_sockets.iter().enumerate() {
        poll.registry()
            .register(
                &mut SourceFd(&socket.as_raw_fd()),
                mio::Token(i),
                mio::Interest::READABLE,
            )
            .map_err(Error::EventLoopCreation)?;
    }

    loop {
        // Poll for events.
        match poll.poll(&mut events, None) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::EventPolling(e)),
        }

        // Iterate over each event.
        for event in events.iter() {
            match event.token() {
                // The TUN queue has a packet to read.
                TUN_TOKEN => loop {
                    let mut packet_buf = [0; BUFFER_SIZE];
                    let len = match tun_queue.read(&mut packet_buf).map_err(Error::ReadTun)? {
                        Poll::Ready(len) => len,
                        Poll::Pending => break,
                    };
                    let packet = &packet_buf[..len];

                    let tunnels_guard = shared_state.send_tunnels.guard();

                    // TODO: routing
                    // Iterate over each send tunnel.
                    for tunnel in shared_state.send_tunnels.values(&tunnels_guard) {
                        // Get the unique sequence number for this packet.
                        let sequence_number =
                            tunnel.next_sequence_number.fetch_add(1, Ordering::Relaxed);

                        for remote_addr in tunnel.remote_addrs.iter() {
                            let message = Message {
                                sender: shared_state.local_id,
                                sequence_number,
                                packet,
                            };

                            log::trace!("sending message to {}: {:#?}", remote_addr, message);

                            // Encode the message.
                            let mut encoded_buf = [0; BUFFER_SIZE];
                            let encoded: &_ =
                                message.encode(&tunnel.cipher, &mut encoded_buf).unwrap();

                            // Iterate over each local address.
                            for &local_addr in tunnel.local_addrs.iter() {
                                // Get the local socket.
                                let socket = get_or_bind_send_socket(&mut send_sockets, local_addr)
                                    .map_err(Error::BindSocket)?;

                                // Send the encoded message.
                                socket
                                    .send_to(encoded, &SockAddr::from(*remote_addr))
                                    .map_err(Error::WriteSocket)?;
                            }
                        }
                    }
                },
                // A receive socket has a datagram to receive.
                mio::Token(recv_socket_index) => loop {
                    let socket = &recv_sockets[recv_socket_index];

                    // Receive a datagram.
                    let mut buf = MaybeUninit::uninit_array::<{ BUFFER_SIZE }>();
                    let (len, _) = match socket.recv_from(&mut buf) {
                        Ok(len) => len,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(Error::ReadSocket(e)),
                    };
                    let datagram = unsafe { MaybeUninit::slice_assume_init_mut(&mut buf[..len]) };

                    // Parse the message header.
                    let message = match Message::parse(datagram) {
                        Ok(message) => message,
                        Err(e) => {
                            log::warn!("failed to parse message: {}", e);
                            continue;
                        }
                    };

                    // Find the tunnel for this endpoint.
                    let tunnel_guard = shared_state.recv_tunnels.guard();

                    let tunnel = match shared_state
                        .recv_tunnels
                        .get(&message.sender, &tunnel_guard)
                    {
                        Some(cipher) => cipher,
                        None => {
                            log::warn!("received message for unknown endpoint");
                            continue;
                        }
                    };

                    let message = match Message::decode(&tunnel.cipher, datagram) {
                        Ok(message) => message,
                        Err(e) => {
                            log::warn!("failed to decode message: {}", e);
                            continue;
                        }
                    };

                    log::trace!("received message: {:?}", message);

                    // Write the packet to the TUN device if it is new.
                    match tunnel.memory.observe(message.sequence_number) {
                        PacketRecollection::New => {
                            match tun_queue.write(message.packet).map_err(Error::WriteTun)? {
                                Poll::Ready(_) => {}
                                Poll::Pending => {
                                    log::warn!("writing packet to TUN device would block");
                                    continue;
                                }
                            };
                        }
                        PacketRecollection::Seen => {}
                        PacketRecollection::Confusing => {
                            log::warn!("received confusing packet");
                            continue;
                        }
                    }

                    drop(tunnel_guard);
                },
            }
        }
    }
}

const TUN_TOKEN: mio::Token = mio::Token(usize::MAX);

/// Bind a UDP socket for receiving packets.
fn bind_recv_socket(addr: SocketAddr) -> Result<Socket, Error> {
    // Create a new UDP socket.
    let socket = Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
        .map_err(Error::BindSocket)?;

    // Each worker will bind to the same addresses.
    socket.set_reuse_address(true).map_err(Error::BindSocket)?;
    socket.set_reuse_port(true).map_err(Error::BindSocket)?;

    // Bind the socket to the address.
    socket.bind(&addr.into()).map_err(Error::BindSocket)?;

    // Set the socket to non-blocking mode.
    socket.set_nonblocking(true).map_err(Error::BindSocket)?;

    Ok(socket)
}

/// Get a UDP socket for sending packets from the map,
/// or bind a new one if it hasn't been created yet.
fn get_or_bind_send_socket(
    sockets: &mut HashMap<SocketAddr, Rc<Socket>>,
    addr: SocketAddr,
) -> io::Result<&Socket> {
    if let hash_map::Entry::Vacant(entry) = sockets.entry(addr) {
        // Create a new UDP socket.
        let socket = Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;

        // Each worker will bind to the same addresses.
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;

        // Bind the socket to the address.
        socket.bind(&addr.into())?;

        // Set the socket to non-blocking mode.
        socket.set_nonblocking(true)?;

        // Add the socket to the map.
        entry.insert(Rc::new(socket));
    }

    Ok(sockets.get(&addr).unwrap())
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("error setting up the event loop")]
    EventLoopCreation(#[source] io::Error),

    #[error("error polling for events")]
    EventPolling(#[source] io::Error),

    #[error("error binding socket")]
    BindSocket(#[source] io::Error),

    #[error("error reading from TUN device")]
    ReadTun(#[source] io::Error),

    #[error("error writing to TUN device")]
    WriteTun(#[source] io::Error),

    #[error("error reading datagram from socket")]
    ReadSocket(#[source] io::Error),

    #[error("error writing datagram to socket")]
    WriteSocket(#[source] io::Error),
}
