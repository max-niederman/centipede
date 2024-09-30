use std::{ffi::CString, net::SocketAddr, time::Duration};

use serde::{Deserialize, Serialize};

/// Instance of the Centipede API.
pub trait CentipedeApi {
    type Error;

    /// Update or create a new interface.
    fn upsert_interface(&self, id: String, interface: Interface) -> Result<(), Self::Error>;

    /// Destroy an interface.
    fn destroy_interface(&self, id: String) -> Result<(), Self::Error>;

    /// Update or create a new peer.
    fn upsert_peer(&self, interface: String, id: String, peer: Peer) -> Result<(), Self::Error>;

    /// Destroy a peer.
    fn destroy_peer(&self, interface: String, id: String) -> Result<(), Self::Error>;

    /// Update or create a new routing policy.
    fn upsert_routing_policy(
        &self,
        id: String,
        routing_policy: ClearnetRoutingPolicy,
    ) -> Result<(), Self::Error>;

    /// Destroy a routing policy.
    fn destroy_routing_policy(&self, id: String) -> Result<(), Self::Error>;
}

/// Configuration for a Centipede virtual interface.
#[derive(Serialize, Deserialize)]
pub struct Interface {
    /// Private key of the interface.
    pub private_key: ed25519_dalek::SecretKey,

    /// Name of the OS network interface.
    pub os_name: CString,

    /// Number of workers to spawn.
    #[serde(default = "num_cpus::get")]
    pub workers: usize,

    /// Address of the host on the Centipede network.
    pub address: Vec<cidr::IpInet>,
}

/// A peer in the Centipede network.
#[derive(Serialize, Deserialize)]
pub struct Peer {
    /// Public key of the peer.
    pub public_key: ed25519_dalek::VerifyingKey,

    /// Name of the routing policy with which to send messages to the peer.
    pub clearnet_routing_policy: String,

    /// Maximum time to wait for heartbeats from the peer before disconnecting.
    #[serde(default = "default_max_heartbeat_interval")]
    pub max_heartbeat_interval: Duration,
}

/// A routing policy, specifying how to send and receive messages from a peer on the clearnet.
#[derive(Serialize, Deserialize)]
pub struct ClearnetRoutingPolicy {
    /// Addresses on which to listen for incoming packets.
    pub recv_addrs: Vec<SocketAddr>,
}

fn default_max_heartbeat_interval() -> Duration {
    Duration::from_secs(60)
}
