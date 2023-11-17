use std::{ffi::CString, net::SocketAddr};

use cidr::IpInet;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address of the host inside the VPN.
    pub address: IpInet,

    /// Name of the TUN interface.
    pub if_name: CString,

    /// Private key of the daemon.
    #[serde_as(as = "Base64")]
    pub private_key: ed25519_dalek::SecretKey,

    /// Local Internet address to bind the control socket to.
    pub local_control_address: SocketAddr,

    /// Number of tunnel workers to spawn.
    #[serde(default = "num_cpus::get")]
    pub workers: usize,

    /// List of peers.
    pub peers: Vec<PeerConfig>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Public key of the peer.
    #[serde_as(as = "Base64")]
    pub public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],

    /// Remote Internet address of the peer's control socket.
    /// If `None`, we can only accept connections from the peer.
    #[serde(default)]
    pub remote_control_address: Option<SocketAddr>,

    /// Local Internet addresses to bind tunnel sockets to.
    pub local_tunnel_addresses: Vec<SocketAddr>,
}

impl PeerConfig {
    pub fn public_key(&self) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::VerifyingKey::from_bytes(&self.public_key).expect("invalid peer public key")
    }
}

impl Config {
    pub fn private_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.private_key)
    }

    pub fn as_spec(&self) -> centipede_control::Spec {
        centipede_control::Spec {
            private_key: self.private_key(),
            local_control_address: self.local_control_address,
            peers: self
                .peers
                .iter()
                .map(|peer_config| {
                    (
                        peer_config.public_key(),
                        centipede_control::ConnectionSpec {
                            local_tunnel_addresses: peer_config.local_tunnel_addresses.clone(),
                            remote_control_address: peer_config.remote_control_address,
                        },
                    )
                })
                .collect(),
        }
    }
}
