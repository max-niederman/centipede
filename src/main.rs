use std::{
    ffi::CString,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::{AsRawFd, IntoRawFd},
    sync::Mutex,
    thread,
};

use cidr::IpInet;

#[derive(Debug, clap::Parser)]
struct Opt {
    /// Address of the host inside the VPN.
    #[clap(long, short)]
    address: IpInet,

    /// Local address to bind to.
    #[clap(long, short)]
    local: SocketAddr,

    /// Address of the remote peer.
    #[clap(long, short)]
    remote: SocketAddr,

    /// Name of the TUN device.
    #[clap(long, short, default_value = "cp0")]
    if_name: String,
}

fn main() {
    let opt = <Opt as clap::Parser>::parse();
    dbg!(&opt);
}
