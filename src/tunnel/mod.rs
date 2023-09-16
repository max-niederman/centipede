use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use chacha20poly1305::ChaCha20Poly1305;

use crate::{EndpointId, TunnelId};
use packet_memory::PacketMemory;

pub mod message;
mod packet_memory;
pub mod worker;

pub struct State {
    /// Local addresses on which to receive messages.
    recv_addrs: Vec<SocketAddr>, // TODO: dynamic swapping

    /// Set of receiving tunnels, by endpoint ID.
    recv_tunnels: flurry::HashMap<EndpointId, Arc<RecvTunnel>>,

    /// Set of sending tunnels.
    send_tunnels: flurry::HashMap<TunnelId, SendTunnel>,
}

struct RecvTunnel {
    /// Cipher with which to decrypt messages.
    cipher: ChaCha20Poly1305,
    /// Memory of received packets.
    memory: PacketMemory,
}

struct SendTunnel {
    /// Local addresses over which to send messages,
    /// along with an optional endpoint to send as the opposite endpoint.
    local_addrs: Vec<SocketAddr>, // TODO: dynamic swapping

    /// Cipher with which to encrypt messages, by sending endpoint.
    cipher: ChaCha20Poly1305,

    /// Addresses of the remote endpoints.
    remote_addrs: flurry::HashMap<EndpointId, SocketAddr>,

    /// The next sequence number.
    next_sequence_number: AtomicU64,
}

impl State {
    /// Create a new state.
    pub fn new(recv_addrs: Vec<SocketAddr>) -> Self {
        Self {
            recv_addrs,
            recv_tunnels: flurry::HashMap::new(),
            send_tunnels: flurry::HashMap::new(),
        }
    }

    /// Create a new state transitioner.
    ///
    /// It is usually a logic error for multiple transitioners to exist simultaneously.
    pub fn transitioner(&self) -> StateTransitioner<'_> {
        StateTransitioner {
            state: self,
            recv_tunnel_endpoints: HashMap::new(),
        }
    }
}

/// A handle to the state of the tunnel used to mutate it.
///
/// While it is _safe_ for multiple [`StateTransitioner`]s to exist at the same time,
/// doing so is almost certainly incorrect, as the internal state of each transitioner
/// assumes it is exclusive.
pub struct StateTransitioner<'s> {
    state: &'s State,

    recv_tunnel_endpoints: HashMap<TunnelId, Vec<EndpointId>>,
}

impl<'s> StateTransitioner<'s> {
    /// Create a receive tunnel.
    ///
    /// # Panics
    /// This tunnel ID must not already exist.
    pub fn create_receive_tunnel(
        &mut self,
        id: TunnelId,
        cipher: ChaCha20Poly1305,
        endpoints: Vec<EndpointId>,
    ) {
        assert!(
            self.recv_tunnel_endpoints.get(&id).is_none(),
            "tunnel already exists"
        );

        // Create the `RecvTunnel` struct and add it to the recv_tunnels index.
        let tunnel = Arc::new(RecvTunnel {
            cipher,
            memory: PacketMemory::default(),
        });
        {
            let recv_tunnels = self.state.recv_tunnels.pin();
            for endpoint in endpoints.iter().copied() {
                recv_tunnels.insert(endpoint, tunnel.clone());
            }
        }

        // Record the endpoints for this tunnel to allow for later deletion.
        self.recv_tunnel_endpoints.insert(id, endpoints);
    }

    /// Delete a receive tunnel.
    pub fn delete_receive_tunnel(&mut self, id: TunnelId) -> Vec<EndpointId> {
        // Remove the endpoints from the transitioner's state.
        let endpoints = self
            .recv_tunnel_endpoints
            .remove(&id)
            .expect("tunnel does not exist");

        // Remove the endpoints from the recv_tunnel index.
        {
            let recv_tunnels = self.state.recv_tunnels.pin();
            for endpoint in endpoints.iter() {
                recv_tunnels.remove(endpoint);
            }
        }

        endpoints
    }

    /// Create a send tunnel.
    ///
    /// # Panics
    /// This tunnel ID must not already exist.
    pub fn create_send_tunnel(
        &mut self,
        id: TunnelId,
        cipher: ChaCha20Poly1305,
        local_addrs: Vec<SocketAddr>,
        endpoints: Vec<(EndpointId, SocketAddr)>,
    ) {
        let remote_addrs = endpoints.into_iter().collect();

        let tunnel = SendTunnel {
            local_addrs,
            cipher,
            remote_addrs,
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
    pub fn delete_send_tunnel(&mut self, id: TunnelId) {
        let send_tunnels = self.state.send_tunnels.pin();
        assert!(send_tunnels.get(&id).is_some(), "tunnel does not exist");
        send_tunnels.remove(&id);
    }
}
