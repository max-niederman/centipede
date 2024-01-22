use std::{ffi::CString, net::SocketAddr};

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

    /// Number of workers to spawn.
    #[serde(default = "num_cpus::get")]
    pub workers: usize,

    /// List of peers.
    pub peers: Vec<Peer>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Peer {
    /// Public key of the peer.
    #[serde_as(as = "Base64")]
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],

    /// Links over which to send packets to the peer.
    pub links: Vec<Link>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Link {
    /// The local address.
    pub local: SocketAddr,

    /// The remote address.
    pub remote: SocketAddr,
}
