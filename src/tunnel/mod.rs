use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use chacha20poly1305::ChaCha20Poly1305;
use socket2::{SockAddr, Socket};

use crate::{EndpointId, TunnelId};
use packet_memory::PacketMemory;

pub mod message;
mod packet_memory;
pub mod worker;

pub struct State {
    /// Local addresses on which to receive messages.
    recv_addrs: Vec<SocketAddr>, // TODO: dynamic swapping

    /// Ciphers with which to decrypt messages, by receiving endpoint.
    recv_ciphers: flurry::HashMap<EndpointId, ChaCha20Poly1305>,

    /// Memory of received packets for each endpoint.
    /// Endpoints on the same tunnel share ownership of one memory.
    recv_memory: flurry::HashMap<EndpointId, Arc<PacketMemory>>,

    /// Set of sending tunnels.
    send_tunnels: flurry::HashMap<TunnelId, SendTunnel>,
}

struct SendTunnel {
    /// Local addresses over which to send messages,
    /// along with an optional endpoint to send as the opposite endpoint.
    local_addrs: Vec<SocketAddr>, // TODO: dynamic swapping

    /// Ciphers with which to encrypt messages, by sending endpoint.
    ciphers: HashMap<EndpointId, ChaCha20Poly1305>,

    /// Addresses of the remote endpoints.
    remote_addrs: flurry::HashMap<EndpointId, SocketAddr>,

    /// The next sequence number.
    next_sequence_number: AtomicU64,
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
            remote_addrs.push((endpoint, remote_addr));
        }

        let tunnel = SendTunnel {
            local_addrs,
            ciphers,
            remote_addrs: remote_addrs.into_iter().collect(),
            next_sequence_number: AtomicU64::new(0),
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
}
