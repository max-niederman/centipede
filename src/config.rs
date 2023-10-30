use std::{ffi::CString, net::SocketAddr};

use cidr::IpInet;
use serde::{Deserialize, Serialize};

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
}
