use std::{
    collections::HashMap,
    net::SocketAddr,
    num::NonZeroU32,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

use chacha20poly1305::ChaCha20Poly1305;
use serde::{Deserialize, Serialize};

use packet_memory::PacketMemory;

pub mod message;
mod packet_memory;
pub mod worker;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct EndpointId(pub NonZeroU32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// The ID of the endpoint.
    pub id: EndpointId,

    /// The address of the endpoint.
    pub address: SocketAddr,
}

/// The shared state of all tunnels.
pub struct SharedState {
    /// Local addresses on which to receive messages.
    recv_addrs: Vec<SocketAddr>, // TODO: dynamic swapping

    /// Set of receiving tunnels, by endpoint ID.
    recv_tunnels: flurry::HashMap<EndpointId, Arc<RecvTunnel>>,

    /// Set of sending tunnels.
    send_tunnels: flurry::HashMap<SendTunnelId, SendTunnel>,

    /// The next receive tunnel ID.
    next_recv_tunnel_id: AtomicUsize,

    /// The next send tunnel ID.
    next_send_tunnel_id: AtomicUsize,

    /// Lock to prevent multiple transitioners from existing simultaneously.
    transitioner_exists: AtomicBool,
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

impl SharedState {
    /// Create a new state.
    pub fn new(recv_addrs: Vec<SocketAddr>) -> Self {
        Self {
            recv_addrs,
            recv_tunnels: flurry::HashMap::new(),
            send_tunnels: flurry::HashMap::new(),
            next_recv_tunnel_id: AtomicUsize::new(0),
            next_send_tunnel_id: AtomicUsize::new(0),
            transitioner_exists: AtomicBool::new(false),
        }
    }

    /// Create a new state transitioner.
    ///
    /// It is usually a logic error for multiple transitioners to exist simultaneously.
    pub fn transitioner(&self) -> Result<StateTransitioner<'_>, ()> {
        self.transitioner_exists
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ())?;

        Ok(StateTransitioner {
            state: self,
            recv_tunnel_endpoints: HashMap::new(),
        })
    }
}

/// The ID of a receiving tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecvTunnelId(usize);

/// The ID of a sending tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SendTunnelId(usize);

/// A handle to the state of the tunnel used to mutate it.
pub struct StateTransitioner<'s> {
    state: &'s SharedState,

    recv_tunnel_endpoints: HashMap<RecvTunnelId, Vec<EndpointId>>,
}

impl<'a> Drop for StateTransitioner<'a> {
    fn drop(&mut self) {
        self.state
            .transitioner_exists
            .store(false, Ordering::Release);
    }
}

impl<'s> StateTransitioner<'s> {
    /// Create a receive tunnel.
    ///
    /// # Panics
    /// This tunnel ID must not already exist.
    pub fn create_receive_tunnel(
        &mut self,
        cipher: ChaCha20Poly1305,
        endpoints: Vec<EndpointId>,
    ) -> RecvTunnelId {
        let id = RecvTunnelId(
            self.state
                .next_recv_tunnel_id
                .fetch_add(1, Ordering::Relaxed),
        );

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

        id
    }

    /// Delete a receive tunnel.
    pub fn delete_receive_tunnel(&mut self, id: RecvTunnelId) -> Vec<EndpointId> {
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
        cipher: ChaCha20Poly1305,
        local_addrs: Vec<SocketAddr>,
        endpoints: Vec<Endpoint>,
    ) -> SendTunnelId {
        let id = SendTunnelId(
            self.state
                .next_send_tunnel_id
                .fetch_add(1, Ordering::Relaxed),
        );

        let remote_addrs = endpoints
            .into_iter()
            .map(|ep| (ep.id, ep.address))
            .collect();

        let tunnel = SendTunnel {
            local_addrs,
            cipher,
            remote_addrs,
            next_sequence_number: AtomicU64::new(0),
        };

        let send_tunnels = self.state.send_tunnels.pin();

        assert!(send_tunnels.get(&id).is_none(), "tunnel already exists");
        send_tunnels.insert(id, tunnel);

        id
    }

    /// Delete a send tunnel.
    ///
    /// # Panics
    /// This tunnel ID must exist.
    pub fn delete_send_tunnel(&mut self, id: SendTunnelId) {
        let send_tunnels = self.state.send_tunnels.pin();
        assert!(send_tunnels.get(&id).is_some(), "tunnel does not exist");
        send_tunnels.remove(&id);
    }
}
