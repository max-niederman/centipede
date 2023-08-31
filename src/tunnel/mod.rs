use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use chacha20poly1305::ChaCha20Poly1305;
use socket2::{SockAddr, Socket};

use crate::{EndpointId, TunnelId};
use packet_memory::PacketMemory;

mod packet_memory;

pub struct State {
    /// Local addresses on which to receive messages.
    recv_addrs: Vec<Socket>,

    /// Ciphers with which to decrypt messages, by receiving endpoint.
    recv_ciphers: flurry::HashMap<EndpointId, ChaCha20Poly1305>,

    /// Memory of received packets for each endpoint.
    /// Endpoints on the same tunnel share ownership of one memory.
    recv_memory: flurry::HashMap<EndpointId, Arc<PacketMemory>>,

    /// Map of receiving endpoints to opposite send tunnels.
    /// This is used to update the send tunnels' remote addresses.
    recv_endpoint_to_opposite_tunnel: flurry::HashMap<EndpointId, TunnelId>,

    /// Set of sending tunnels.
    send_tunnels: flurry::HashMap<TunnelId, SendTunnel>,
}

struct SendTunnel {
    /// Local addresses over which to send messages.
    local_addrs: Vec<SockAddr>, // TODO: use an atomic Box for lock-free swapping

    /// Ciphers with which to encrypt messages, by sending endpoint.
    ciphers: HashMap<EndpointId, ChaCha20Poly1305>,

    /// Addresses of the remote endpoints.
    remote_addrs: flurry::HashMap<EndpointId, SockAddr>,
}

/// A handle to the state of the tunnel used to mutate it.
///
/// While it is _safe_ for multiple [`StateTransitioner`]s to exist at the same time,
/// doing so is almost certainly incorrect, as the internal state of each transitioner
/// assumes it is exclusive.
pub struct StateTransitioner<'s> {
    state: &'s State,

    recv_tunnels: HashMap<TunnelId, Vec<EndpointId>>,
}

impl<'s> StateTransitioner<'s> {
    /// Create a receive tunnel.
    ///
    /// # Panics
    /// This tunnel ID must not already exist.
    fn create_receive_tunnel(
        &mut self,
        id: TunnelId,
        endpoints: Vec<(EndpointId, ChaCha20Poly1305)>,
    ) {
        assert!(
            self.recv_tunnels.get(&id).is_none(),
            "tunnel already exists"
        );

        // Create the packet memory and populate the recv_memory index.
        let memory = Arc::new(PacketMemory::default());
        {
            let recv_memory = self.state.recv_memory.pin();
            for (endpoint, _) in endpoints.iter() {
                recv_memory.insert(*endpoint, memory.clone());
            }
        }

        // Populate the recv_ciphers index.
        {
            let recv_ciphers = self.state.recv_ciphers.pin();
            for (endpoint, cipher) in endpoints.iter() {
                recv_ciphers.insert(*endpoint, cipher.clone());
            }
        }

        // Record the endpoints for this tunnel to allow for later deletion.
        self.recv_tunnels
            .insert(id, endpoints.into_iter().map(|(e, _)| e).collect());
    }

    /// Delete a receive tunnel.
    fn delete_receive_tunnel(&mut self, id: TunnelId) -> Vec<EndpointId> {
        // Remove the endpoints from the transitioner's state.
        let endpoints = self
            .recv_tunnels
            .remove(&id)
            .expect("tunnel does not exist");

        // Remove the endpoints from the recv_ciphers index.
        {
            let recv_ciphers = self.state.recv_ciphers.pin();
            for endpoint in endpoints.iter() {
                recv_ciphers.remove(endpoint);
            }
        }

        // Remove the endpoints from the recv_memory index.
        {
            let recv_memory = self.state.recv_memory.pin();
            for endpoint in endpoints.iter() {
                recv_memory.remove(endpoint);
            }
        }

        // Remove the endpoints from the recv_endpoint_to_opposite_tunnel index.
        {
            let recv_endpoint_to_opposite_tunnel =
                self.state.recv_endpoint_to_opposite_tunnel.pin();
            for endpoint in endpoints.iter() {
                recv_endpoint_to_opposite_tunnel.remove(endpoint);
            }
        }

        endpoints
    }

    /// Create a send tunnel.
    ///
    /// # Panics
    /// This tunnel ID must not already exist.
    fn create_send_tunnel(
        &mut self,
        id: TunnelId,
        local_addrs: Vec<SocketAddr>,
        endpoints: Vec<(EndpointId, SocketAddr, ChaCha20Poly1305)>,
    ) {
        let mut ciphers = HashMap::with_capacity(endpoints.len());
        let mut remote_addrs = Vec::with_capacity(endpoints.len());
        for (endpoint, remote_addr, cipher) in endpoints.into_iter() {
            ciphers.insert(endpoint, cipher);
            remote_addrs.push((endpoint, SockAddr::from(remote_addr)));
        }

        let tunnel = SendTunnel {
            local_addrs: local_addrs.into_iter().map(SockAddr::from).collect(),
            ciphers,
            remote_addrs: remote_addrs.into_iter().collect(),
        };

        let send_tunnels = self.state.send_tunnels.pin();

        assert!(send_tunnels.get(&id).is_none(), "tunnel already exists");
        send_tunnels.insert(id, tunnel);
    }

    /// Delete a send tunnel.
    ///
    /// # Panics
    /// This tunnel ID must exist.
    fn delete_send_tunnel(&mut self, id: TunnelId) {
        let send_tunnels = self.state.send_tunnels.pin();
        assert!(send_tunnels.get(&id).is_some(), "tunnel does not exist");
        send_tunnels.remove(&id);
    }

    /// Sets or unsets the opposing send tunnel of a receive tunnel.
    ///
    /// # Panics
    /// The receive tunnel must exist.
    /// If the send tunnel does not exist, workers will panic when they try to update the remote address.
    fn set_opposition(&self, receive: TunnelId, send: Option<TunnelId>) {
        let recv_endpoints = self
            .recv_tunnels
            .get(&receive)
            .expect("receive tunnel does not exist");

        let recv_to_opposite = self.state.recv_endpoint_to_opposite_tunnel.pin();
        for endpoint in recv_endpoints.iter() {
            match send {
                Some(send) => recv_to_opposite.insert(*endpoint, send),
                None => recv_to_opposite.remove(endpoint),
            };
        }
    }
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

//                 let mut buf = MaybeUninit::uninit_array::<{ message::MTU }>();
//                 let (len, addr) = socket.recv_from(&mut buf)?; // TODO: does this need to be non-blocking?
//                 let datagram = unsafe { MaybeUninit::slice_assume_init_mut(&mut buf[..len]) };

//                 let message = match Message::parse(datagram) {
//                     Ok(message) => message,
//                     Err(e) => {
//                         log::warn!("failed to parse message: {}", e);
//                         continue;
//                     }
//                 };

//                 let cipher_guard = self.ciphers.guard();

//                 let cipher = match self.ciphers.get(&message.link, &cipher_guard) {
//                     Some(cipher) => cipher,
//                     None => {
//                         log::warn!("received message for unknown endpoint");
//                         continue;
//                     }
//                 };

//                 let message = match Message::decode(cipher, datagram) {
//                     Ok(message) => message,
//                     Err(e) => {
//                         log::warn!("failed to decode message: {}", e);
//                         continue;
//                     }
//                 };

//                 drop(cipher_guard);

//                 match self.deduplicator.observe(message.seq) {
//                     Some(PacketRecollection::Seen) | None => {}
//                     Some(PacketRecollection::New) => {
//                         tun_queue.write(&message.packet)?;
//                     }
//                 }
//             }
//         }
//     }
// }

// fn bind_socket(addr: &SocketAddr) -> io::Result<Socket> {
//     let socket = Socket::new(Domain::IPV4, socket2::Type::DGRAM, None)?;

//     // Each worker will bind to the same addresses.
//     socket.set_reuse_address(true)?;
//     socket.set_reuse_port(true)?;

//     socket.bind(&(*addr).into())?;

//     Ok(socket)
// }
