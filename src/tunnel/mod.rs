use std::{
    collections::HashMap,
    net::SocketAddr,
    rc::Rc,
    sync::{atomic::AtomicU64, Arc},
};

use chacha20poly1305::ChaCha20Poly1305;
use serde::{Deserialize, Serialize};

use packet_memory::PacketMemory;

use self::number_allocator::NumberAllocator;

pub mod message;
mod number_allocator;
mod packet_memory;
pub mod worker;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct EndpointId(pub u32);

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
    /// Create a new state, along with its unique transitioner.
    pub fn new(recv_addrs: Vec<SocketAddr>) -> (Arc<Self>, StateTransitioner) {
        let this = Arc::new(Self {
            recv_addrs,
            recv_tunnels: flurry::HashMap::new(),
            send_tunnels: flurry::HashMap::new(),
        });

        let transitioner = StateTransitioner {
            state: this.clone(),
            recv_tunnel_id_alloc: NumberAllocator::new(),
            send_tunnel_id_alloc: NumberAllocator::new(),
            endpoint_id_alloc: NumberAllocator::new(),
            recv_tunnel_endpoints: HashMap::new(),
        };

        (this, transitioner)
    }
}

/// The ID of a receiving tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecvTunnelId(usize);

/// The ID of a sending tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SendTunnelId(usize);

/// A handle to the state of the tunnel used to mutate it.
pub struct StateTransitioner {
    state: Arc<SharedState>,

    /// The receive tunnel ID allocator.
    recv_tunnel_id_alloc: NumberAllocator<usize>,

    /// The send tunnel ID allocator.
    send_tunnel_id_alloc: NumberAllocator<usize>,

    /// The endpoint ID allocator.
    endpoint_id_alloc: NumberAllocator<u32>,

    /// The endpoints of each receive tunnel.
    recv_tunnel_endpoints: HashMap<RecvTunnelId, Rc<[EndpointId]>>,
}

impl StateTransitioner {
    /// Create a receive tunnel.
    ///
    /// # Panics
    /// This tunnel ID must not already exist.
    pub fn create_receive_tunnel(
        &mut self,
        cipher: ChaCha20Poly1305,
        endpoint_count: usize,
    ) -> (RecvTunnelId, Rc<[EndpointId]>) {
        let id = RecvTunnelId(self.recv_tunnel_id_alloc.allocate());

        assert!(
            self.recv_tunnel_endpoints.get(&id).is_none(),
            "tunnel already exists"
        );

        // Create the `RecvTunnel` struct and add it to the recv_tunnels index.
        let tunnel = Arc::new(RecvTunnel {
            cipher,
            memory: PacketMemory::default(),
        });

        let mut endpoints = Vec::with_capacity(endpoint_count);

        {
            let recv_tunnels = self.state.recv_tunnels.pin();

            for _ in 0..endpoint_count {
                let endpoint_id = EndpointId(self.endpoint_id_alloc.allocate());
                endpoints.push(endpoint_id);
                recv_tunnels.insert(endpoint_id, tunnel.clone());
            }
        }

        let endpoints: Rc<[EndpointId]> = endpoints.into();

        // Record the endpoints for this tunnel to allow for later deletion.
        self.recv_tunnel_endpoints.insert(id, endpoints.clone());

        (id, endpoints)
    }

    /// Delete a receive tunnel.
    pub fn delete_receive_tunnel(&mut self, id: RecvTunnelId) {
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
        let id = SendTunnelId(self.send_tunnel_id_alloc.allocate());

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
