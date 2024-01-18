pub mod worker;

pub mod controller;
mod packet_memory;

use std::{
    collections::HashMap,
    iter,
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use arc_swap::ArcSwap;
use chacha20poly1305::ChaCha20Poly1305;
use controller::Controller;
use packet_memory::PacketMemory;
use worker::Worker;

/// The shared state of a Centipede tunnel router.
pub struct Router {
    /// The configured state of the router.
    state: ArcSwap<ConfiguredRouter>,
}

/// The shared state of a configured Centipede tunnel router.
#[derive(Clone)]
struct ConfiguredRouter {
    /// The generation of this configuration.
    generation: u64,

    /// Our local peer identifier.
    local_id: PeerId,

    /// Addresses on which to listen for incoming packets.
    recv_addrs: Vec<SocketAddr>,

    /// Set of receiving tunnels, by sender identifier.
    recv_tunnels: HashMap<PeerId, RecvTunnel>,

    /// Set of sending tunnels, by receiver identifier.
    send_tunnels: HashMap<PeerId, SendTunnel>,
}

/// The state of a receiving tunnel.
#[derive(Clone)]
struct RecvTunnel {
    /// Cipher with which to decrypt messages.
    cipher: ChaCha20Poly1305,

    /// Memory of received packets.
    memory: Arc<PacketMemory>,
}

/// The state of a sending tunnel.
#[derive(Clone)]
struct SendTunnel {
    /// Address pairs on which to send messages.
    links: Vec<Link>,

    /// Cipher with which to encrypt messages, by sending endpoint.
    cipher: ChaCha20Poly1305,

    /// The next sequence number.
    next_sequence_number: Arc<AtomicU64>,
}

/// The two endpoint addresses of a tunnel link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Link {
    /// The local address.
    pub local: SocketAddr,

    /// The remote address.
    pub remote: SocketAddr,
}

pub type PeerId = [u8; 8];

impl Router {
    /// Create a new router.
    pub fn new(peer_id: PeerId, recv_addrs: Vec<SocketAddr>) -> Self {
        Self {
            state: ArcSwap::from_pointee(ConfiguredRouter {
                generation: 0,
                local_id: peer_id,
                recv_addrs,
                recv_tunnels: HashMap::new(),
                send_tunnels: HashMap::new(),
            }),
        }
    }

    /// Get one controller and N worker handles to the router.
    pub fn handles(&mut self, n: usize) -> (Controller<'_>, Vec<Worker<'_>>) {
        let this = &*self;

        let controller = Controller::new(this);
        let workers = iter::repeat_with(|| Worker::new(this)).take(n).collect();

        (controller, workers)
    }
}
