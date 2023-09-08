use std::{ffi::CString, net::SocketAddr};

use cidr::IpInet;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::EndpointId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address of the host inside the VPN.
    pub address: IpInet,

    /// Name of the TUN interface.
    pub if_name: CString,

    /// Number of tunnel workers to spawn.
    #[serde(default = "num_cpus::get")]
    pub workers: usize,

    /// Local addresses on which to receive messages.
    pub recv_addresses: Vec<SocketAddr>,

    /// Receiving tunnels.
    pub recv_tunnels: Vec<RecvTunnel>,
    
    /// Sending tunnels.
    pub send_tunnels: Vec<SendTunnel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecvTunnel {
    /// Endpoints to receive on.
    pub endpoints: Vec<RecvEndpoint>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecvEndpoint {
    /// Endpoint ID.
    pub id: EndpointId,

    /// Encryption key.
    #[serde_as(as = "Base64")]
    pub key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTunnel {
    /// Local addresses to bind to.
    pub local_addresses: Vec<SocketAddr>,

    /// Remote endpoints to connect to.
    pub endpoints: Vec<SendEndpoint>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendEndpoint {
    /// Endpoint ID.
    pub id: EndpointId,

    /// Address of the endpoint.
    pub address: SocketAddr,

    /// Encryption key.
    #[serde_as(as = "Base64")]
    pub key: [u8; 32],
}
