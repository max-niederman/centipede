//! The data plane of the Centipede VPN.

#![feature(
    iterator_try_collect,
    maybe_uninit_slice,
    maybe_uninit_uninit_array,
    never_type
)]

use std::{
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use chacha20poly1305::ChaCha20Poly1305;

use packet_memory::PacketMemory;

pub mod message;
mod packet_memory;
pub mod worker;

pub type PeerId = [u8; 8];

/// The shared state of all tunnels.
pub struct SharedState {
    /// Our local peer identifier.
    local_id: PeerId,

    /// Local addresses on which to receive messages.
    recv_addrs: Vec<SocketAddr>, // TODO: dynamic swapping

    /// Set of receiving tunnels, by sender identifier.
    recv_tunnels: flurry::HashMap<PeerId, RecvTunnel>,

    /// Set of sending tunnels, by receiver identifier.
    send_tunnels: flurry::HashMap<PeerId, SendTunnel>,
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
    remote_addrs: Vec<SocketAddr>, // TODO: dynamic swapping

    /// The next sequence number.
    next_sequence_number: AtomicU64,
}

impl SharedState {
    /// Create a new state, along with its unique transitioner.
    pub fn new(local_id: PeerId, recv_addrs: Vec<SocketAddr>) -> (Arc<Self>, StateTransitioner) {
        let this = Arc::new(Self {
            local_id,
            recv_addrs,
            recv_tunnels: flurry::HashMap::new(),
            send_tunnels: flurry::HashMap::new(),
        });

        let transitioner = StateTransitioner {
            state: this.clone(),
        };

        (this, transitioner)
    }
}

/// A handle to the state of the tunnel used to mutate it.
pub struct StateTransitioner {
    state: Arc<SharedState>,
}

impl StateTransitioner {
    /// Insert or update a receive tunnel.
    pub fn upsert_receive_tunnel(&mut self, sender_id: PeerId, cipher: ChaCha20Poly1305) {
        let recv_tunnels = self.state.recv_tunnels.pin();

        let tunnel = RecvTunnel {
            cipher,
            memory: PacketMemory::default(),
        };

        recv_tunnels.insert(sender_id, tunnel);
    }

    /// Delete a receive tunnel.
    pub fn delete_receive_tunnel(&mut self, sender_id: PeerId) {
        self.state.recv_tunnels.pin().remove(&sender_id);
    }

    /// Insert or update a send tunnel.
    pub fn upsert_send_tunnel(
        &mut self,
        receiver_id: PeerId,
        cipher: ChaCha20Poly1305,
        local_addrs: Vec<SocketAddr>,
        remote_addrs: Vec<SocketAddr>,
    ) {
        let send_tunnels = self.state.send_tunnels.pin();

        let tunnel = SendTunnel {
            local_addrs,
            cipher,
            remote_addrs,
            next_sequence_number: AtomicU64::new(0),
        };

        send_tunnels.insert(receiver_id, tunnel);
    }

    /// Delete a send tunnel.
    pub fn delete_send_tunnel(&mut self, receiver_id: PeerId) {
        self.state.send_tunnels.pin().remove(&receiver_id);
    }
}
