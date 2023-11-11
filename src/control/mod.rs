use std::net::SocketAddr;

use cidr::IpInet;
use ed25519_dalek::VerifyingKey;

pub mod message;

mod connection;
mod transport;

pub enum Command {
    Connection {
        /// The public key of the peer.
        key: VerifyingKey,

        /// The desired state of the connection, if any.
        desired_state: Option<ConnectionSpec>,
    },
}

pub struct ConnectionSpec {
    /// Local Internet addresses to bind tunnel sockets to.
    local_inet_addresses: Vec<SocketAddr>,

    /// Remote Internet address of the peer's control socket.
    remote_inet_address: SocketAddr,

    /// The VPN address and network of the local machine.
    local_vpn_inet: IpInet,

    /// The VPN address of the peer's control socket.
    remote_vpn_inet: SocketAddr,
}
