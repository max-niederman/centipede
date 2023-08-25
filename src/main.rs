use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::{IntoRawFd, AsRawFd},
    sync::Mutex,
    thread,
};

use tun::Device;

#[derive(Debug, clap::Parser)]
struct Opt {
    /// Address of the host inside the VPN.
    #[clap(long, short)]
    address: IpAddr,

    /// Local address to bind to.
    #[clap(long, short)]
    local: SocketAddr,

    /// Address of the remote peer.
    #[clap(long, short)]
    remote: SocketAddr,
}

fn main() {
    let opt = <Opt as clap::Parser>::parse();
    dbg!(&opt);

    let socket = UdpSocket::bind(opt.local).unwrap();

    thread::scope(|s| {
        s.spawn(|| {
            let mut buf = [0u8; 1504];
            loop {
                let n = unsafe { libc::read(queue, &mut buf as *const u8 as _, buf.len()) }
                    .try_into()
                    .unwrap();

                socket.send_to(&buf[..n], opt.remote).unwrap();
                println!("sent packet of {n} bytes");
            }
        });

        s.spawn(|| {
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
