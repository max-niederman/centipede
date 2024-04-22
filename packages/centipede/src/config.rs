use std::{ffi::CString, net::SocketAddr, time::Duration};

use cidr::IpInet;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

/// Centipede configuration.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Centipede {
    /// Address of the host on the Centipede network.
    pub address: IpInet,

    /// Private key of the daemon.
    #[serde_as(as = "Base64")]
    pub private_key: ed25519_dalek::SecretKey,

    /// Name of the Centipede network interface.
    pub interface_name: CString,

    /// Addresses on which the daemon should listen for incoming packets.
    pub recv_addrs: Vec<SocketAddr>,

    /// List of peers.
    pub peers: Vec<Peer>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Peer {
    /// Public key of the peer.
    #[serde_as(as = "Base64")]
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],

    // TODO: rename to make it clear that these are only for sending messages.
    /// Local addresses from which to send messages to the peer.
    pub local_addrs: Vec<SocketAddr>,

    /// Known remote addresses of the peer.
    pub remote_addrs: Vec<SocketAddr>,

    /// Maximum time to wait for heartbeats from the peer before disconnecting.
    #[serde(default = "default_max_heartbeat_interval")]
    pub max_heartbeat_interval: Duration,
}

fn default_max_heartbeat_interval() -> Duration {
    Duration::from_secs(60)
}
