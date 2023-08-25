use std::{
    ffi::CString,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::{AsRawFd, IntoRawFd},
    sync::Mutex,
    thread,
};

use centipede::tun;
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

    let socket = UdpSocket::bind(opt.local).unwrap();

    let c_if_name = CString::new(opt.if_name.as_bytes()).unwrap();

    let dev = tun::Device::new(Some(c_if_name)).unwrap();
    dev.set_address(opt.address.address())
        .expect("failed to set address");
    dev.set_netmask(opt.address.network())
        .expect("failed to set netmask");
    dev.bring_up().expect("failed to bring interface up");

    thread::scope(|s| {
        s.spawn(|| {
            let mut dev = dev.handle();
            let mut buf = [0u8; 1504];
            loop {
                let n = dev.read(&mut buf).unwrap();

                socket.send_to(&buf[..n], opt.remote).unwrap();
                println!("sent packet of {n} bytes");
            }
        });

        s.spawn(|| {
            let mut dev = dev.handle();
            let mut buf = [0u8; 1504];
            loop {
                let (n, _) = socket.recv_from(&mut buf).unwrap();
                println!("received packet of {n} bytes");

                dev.write_all(&buf[..n]).unwrap();
                dev.flush().unwrap();
            }
        });
    });
}
