pub mod worker;

pub mod config;
mod packet_memory;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

use arc_swap::ArcSwap;
use chacha20poly1305::ChaCha20Poly1305;
use packet_memory::PacketMemory;

pub use config::ConfiguratorHandle;
pub use worker::WorkerHandle;

/// The shared state of a Centipede tunnel router.
pub struct Router {
    /// The configured state of the router.
    state: ArcSwap<ConfiguredRouter>,

    /// Lock to prevent multiple configurators from existing at once.
    configurator_lock: AtomicBool,
}

/// The shared state of a configured Centipede tunnel router.
#[derive(Clone, Default)]
struct ConfiguredRouter {
    /// The generation of this configuration.
    generation: usize,

    /// Our local peer identifier.
    local_id: PeerId,

    /// Addresses on which to listen for incoming packets.
    ///
    /// This list should not contain duplicates.
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
    pub fn new(config: &config::Router) -> Self {
        Self {
            state: ArcSwap::from_pointee(config::apply(config, &ConfiguredRouter::default())),
            configurator_lock: AtomicBool::new(false),
        }
    }

    /// Get a configurator handle to the router.
    ///
    /// # Panics
    /// Panics if another configurator handle already exists.
    pub fn configurator(&self) -> ConfiguratorHandle<'_> {
        if self.configurator_lock.swap(true, Ordering::Acquire) {
            panic!("another configurator already exists");
        }

        ConfiguratorHandle::new(self)
    }

    /// Get a worker handle to the router.
    pub fn worker(&self) -> WorkerHandle<'_> {
        WorkerHandle::new(self)
    }
}
