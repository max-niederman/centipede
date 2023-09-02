use std::{
    collections::HashMap,
    io::{self, Read, Write},
    mem::MaybeUninit,
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::atomic::Ordering,
};

use mio::{unix::SourceFd, Poll};
use socket2::{SockAddr, Socket};

use super::{message::Message, packet_memory::PacketRecollection, State};

// TODO: make this configurable or use path MTU discovery
const BUFFER_SIZE: usize = 64 * 1024;

/// The entrypoint for each tunnel worker.
pub fn entrypoint(state: &State, mut tun_queue: tun::platform::Queue) -> io::Result<!> {
    // Ensure the passed TUN queue is correctly configured.
    tun_queue.set_nonblock()?;
    assert!(!tun_queue.has_packet_information());

    // Create a mio poller and event queue.
    let mut poll = Poll::new()?;
    let mut events = mio::Events::with_capacity(1024);

    // TODO: dynamic swapping
    // Bind each of the receive sockets.
    let recv_sockets: Vec<_> = state
        .recv_addrs
        .iter()
        .copied()
        .map(bind_recv_socket)
        .try_collect()?;

    let mut send_sockets: HashMap<SocketAddr, Socket> = HashMap::new();

    // Register the TUN device with the poller.
    poll.registry().register(
        &mut SourceFd(&tun_queue.as_raw_fd()),
        TUN_TOKEN,
        mio::Interest::READABLE,
    )?;

    // Register the receive sockets with the poller.
    for (i, socket) in recv_sockets.iter().enumerate() {
        poll.registry().register(
            &mut SourceFd(&socket.as_raw_fd()),
            mio::Token(i),
            mio::Interest::READABLE,
        )?;
    }

    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                TUN_TOKEN => {
                    let mut packet_buf = [0; BUFFER_SIZE];
                    let len = tun_queue.read(&mut packet_buf)?;
                    let packet = &packet_buf[..len];

                    let tunnels_guard = state.send_tunnels.guard();

                    // TODO: routing
                    // Iterate over each send tunnel.
                    for tunnel in state.send_tunnels.values(&tunnels_guard) {
                        let remote_addrs_guard = tunnel.remote_addrs.guard();

                        // Get the unique sequence number for this packet.
                        let sequence_number =
                            tunnel.next_sequence_number.fetch_add(1, Ordering::Relaxed);

                        for (&endpoint, cipher) in tunnel.ciphers.iter() {
                            let message = Message {
                                endpoint,
                                sequence_number,
                                packet,
                            };

                            // Encode the message.
                            let mut encoded_buf = [0; BUFFER_SIZE];
                            let encoded: &_ = message.encode(cipher, &mut encoded_buf).unwrap();

                            // Get the remote addresses for this endpoint.
                            let remote_addr = SockAddr::from(
                                *tunnel
                                    .remote_addrs
                                    .get(&endpoint, &remote_addrs_guard)
                                    .expect("endpoint and remote addresses are in sync"),
                            );

                            // Iterate over each local address.
                            for &local_addr in tunnel.local_addrs.iter() {
                                // Get the local socket.
                                let socket =
                                    get_or_bind_send_socket(&mut send_sockets, local_addr)?;

                                // Send the message.
                                socket.send_to(encoded, &remote_addr)?;
                            }
                        }
                    }
                }
                mio::Token(recv_socket_index) => {
                    let socket = &recv_sockets[recv_socket_index];

                    // Receive a datagram.
                    let mut buf = MaybeUninit::uninit_array::<{ BUFFER_SIZE }>();
                    let (len, _) = socket.recv_from(&mut buf)?; // TODO: does this need to be non-blocking?
                    let datagram = unsafe { MaybeUninit::slice_assume_init_mut(&mut buf[..len]) };

                    // Parse the message header.
                    let message = match Message::parse(datagram) {
                        Ok(message) => message,
                        Err(e) => {
                            log::warn!("failed to parse message: {}", e);
                            continue;
                        }
                    };

                    // Find the cipher for this endpoint.
                    let cipher_guard = state.recv_ciphers.guard();

                    let cipher = match state.recv_ciphers.get(&message.endpoint, &cipher_guard) {
                        Some(cipher) => cipher,
                        None => {
                            log::warn!("received message for unknown endpoint");
                            continue;
                        }
                    };

                    let message = match Message::decode(cipher, datagram) {
                        Ok(message) => message,
                        Err(e) => {
                            log::warn!("failed to decode message: {}", e);
                            continue;
                        }
                    };

                    drop(cipher_guard);

                    // Write the packet to the TUN device if it is new.
                    let recv_memory_guard = state.recv_memory.guard();

                    let memory = state
                        .recv_memory
                        .get(&message.endpoint, &recv_memory_guard)
                        .expect("cipher and memory are in sync");

                    match memory.observe(message.sequence_number) {
                        Some(PacketRecollection::Seen) | None => {}
                        Some(PacketRecollection::New) => {
                            tun_queue.write(&message.packet)?;
                        }
                    }

                    drop(recv_memory_guard);
                }
            }
        }
    }
}

const TUN_TOKEN: mio::Token = mio::Token(usize::MAX);

/// Bind a UDP socket for receiving packets.
fn bind_recv_socket(addr: SocketAddr) -> io::Result<Socket> {
    // Create a new UDP socket.
    let socket = Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;

    // Each worker will bind to the same addresses.
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    // Bind the socket to the address.
    socket.bind(&addr.into())?;

    // Set the socket to non-blocking mode.
    socket.set_nonblocking(true)?;

    Ok(socket)
}

/// Get a UDP socket for sending packets from the map,
/// or bind a new one if it hasn't been created yet.
fn get_or_bind_send_socket(
    sockets: &mut HashMap<SocketAddr, Socket>,
    addr: SocketAddr,
) -> io::Result<&Socket> {
    if !sockets.contains_key(&addr) {
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
        sockets.insert(addr, socket);
    }

    Ok(sockets.get(&addr).unwrap())
}
