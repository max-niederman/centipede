use std::{
    collections::HashMap,
    io::{self, Write},
    mem::MaybeUninit,
    net::SocketAddr,
};

use mio::{unix::SourceFd, Poll};
use socket2::{SockAddr, Socket};

use super::{
    message::{self, Message},
    packet_memory::PacketRecollection,
    State,
};

pub fn entrypoint(state: &State, mut tun_queue: tun::platform::Queue) -> io::Result<!> {
    let mut poll = Poll::new()?;
    let mut events = mio::Events::with_capacity(1024);

    let mut recv_sockets: Vec<_> = state
        .recv_addrs
        .iter()
        .copied()
        .map(bind_recv_socket)
        .try_collect()?;

    let mut send_sockets: HashMap<SocketAddr, Socket> = HashMap::new();

    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                TUN_TOKEN => {
                    todo!()
                }
                mio::Token(recv_socket_index) => {
                    let socket = &recv_sockets[recv_socket_index];

                    // Receive a datagram.
                    let mut buf = MaybeUninit::uninit_array::<{ message::MTU }>();
                    let (len, addr) = socket.recv_from(&mut buf)?; // TODO: does this need to be non-blocking?
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

                    // Update the opposite endpoint's remote address.

                    // The message specifies an opposite endpoint.
                    if let Some(opposite_endpoint) = message.opposite_endpoint {
                        // The receive tunnel has an opposite tunnel.
                        if let Some(&opposite_tunnel_id) = state
                            .recv_endpoint_to_opposite_tunnel
                            .pin()
                            .get(&message.endpoint)
                        {
                            // The opposite tunnel still exists.
                            if let Some(opposite_tunnel) =
                                state.send_tunnels.pin().get(&opposite_tunnel_id)
                            {
                                let remote_addrs = opposite_tunnel.remote_addrs.pin();

                                // The opposite tunnel has the specified endpoint.
                                if let Some(&old_remote_addr) = remote_addrs.get(&opposite_endpoint)
                                {
                                    let sender_addr = addr.as_socket().unwrap();

                                    if old_remote_addr != sender_addr {
                                        remote_addrs.insert(opposite_endpoint, sender_addr);
                                    }
                                } else {
                                    log::warn!("received message specifying nonexistent endpoint as opposite");
                                }
                            }
                        }
                    }
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

        // Add the socket to the map.
        sockets.insert(addr, socket);
    }

    Ok(sockets.get(&addr).unwrap())
}

// impl State {

//     /// Worker loop for receiving packets.
//     pub fn worker(&self, mut tun_queue: tun::platform::Queue) -> io::Result<!> {
//         // Create a mio poller.
//         let mut poll = Poll::new()?;
//         let mut events = mio::Events::with_capacity(1024);

//         // Bind to each listen address.
//         let sockets: Vec<_> = self.listen_addrs.iter().map(bind_socket).try_collect()?;

//         // Register all sockets with the poller.
//         for (i, socket) in sockets.iter().enumerate() {
//             poll.registry().register(
//                 &mut SourceFd(&socket.as_raw_fd()),
//                 mio::Token(i),
//                 mio::Interest::READABLE,
//             )?;
//         }

//         loop {
//             poll.poll(&mut events, None)?;

//             for event in events.iter() {
//                 let socket = &sockets[event.token().0];

//
//             }
//         }
//     }
// }
