use std::{
    cell::{Cell, RefCell, UnsafeCell},
    collections::HashMap,
    io::{self, Read, Write},
    net::{SocketAddr, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    thread,
};

use crate::{
    dispatcher::{Dispatcher, IncomingAction},
    message::{self, Message, HEADER_SIZE, MTU},
    LinkId,
};
use async_io::Async;
use chacha20poly1305::ChaCha20Poly1305;
use futures_lite::{
    future,
    io::{AsyncReadExt, AsyncWriteExt},
};
use socket2::{Domain, Socket, Type};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkSpec {
    pub id: LinkId,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

// TODO: would it be better to deduplicate sockets bound to the same local address?
//       this would mean exactly one socket per local address per worker
//       probably I need to benchmark both

pub struct Worker<D> {
    cipher: ChaCha20Poly1305,
    dispatcher: D,

    tun_queue: Async<TunQueue>,
    links: HashMap<LinkId, (RefCell<LinkSpec>, Async<UdpSocket>)>,
}

impl<D: Dispatcher> Worker<D> {
    pub fn new(
        cipher: ChaCha20Poly1305,
        dispatcher: D,
        tun_queue: tun::platform::Queue,
        links: Vec<LinkSpec>,
    ) -> Self {
        let tun_queue = Async::new(TunQueue::new(tun_queue)).unwrap();

        let links = links
            .into_iter()
            .map(|spec| (spec.id, (RefCell::new(spec), connect(spec).unwrap())))
            .collect();

        Self {
            cipher,
            dispatcher,
            tun_queue,
            links,
        }
    }

    pub fn spawn(self) {
        thread::spawn(move || {
            let executor = async_executor::LocalExecutor::new();

            for (_, (_, socket)) in &self.links {
                executor.spawn(self.handle_incoming_on(socket));
            }

            let outgoing_handler = executor.spawn(self.handle_outgoing());

            future::block_on(outgoing_handler);
        });
    }

    async fn handle_incoming_on(&self, socket: Async<UdpSocket>) -> io::Result<()> {
        let mut buf = [0u8; MTU];
        loop {
            let (len, remote) = socket.recv_from(&mut buf).await?;

            let message = match Message::decode(&self.cipher, &mut buf[..len]) {
                Ok(message) => message,
                Err(err) => {
                    eprintln!("Failed to decode message from {}: {}", remote, err);
                    continue;
                }
            };

            match self.dispatcher.dispatch_incoming(message.dispatcher_nonce) {
                IncomingAction::WriteToTun => {
                    (&self.tun_queue).write(message.packet).await?;
                }
                IncomingAction::Drop => {}
            }

            let (link_spec, link_socket) = self.links.get(&message.link).unwrap();

            if link_spec.borrow().remote != remote {
                link_spec.borrow_mut().remote = remote;
                link_socket.get_ref().connect(&remote)?;
            }
        }
    }

    async fn handle_outgoing(&self) -> io::Result<()> {
        let mut buf = [0u8; MTU - HEADER_SIZE];
        loop {
            let len = (&self.tun_queue).read(&mut buf).await?;

            let mut actions = self.dispatcher.dispatch_outgoing(&buf[..len]);

            for action in actions {
                let mut buf = [0u8; MTU];

                let message = Message {
                    link: action.link,
                    dispatcher_nonce: action.nonce,
                    packet: &buf[..len],
                };
                let encoded = message.encode(&self.cipher, &mut buf).unwrap();

                let (_, link_socket) = self.links.get(&action.link).unwrap();

                link_socket.send(&encoded).await?;
            }
        }
    }
}

fn connect(spec: LinkSpec) -> io::Result<Async<UdpSocket>> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;

    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    socket.bind(&spec.local.into())?;
    socket.connect(&spec.remote.into())?;

    let socket = unsafe { UdpSocket::from_raw_fd(socket.into_raw_fd()) };
    Ok(Async::new(socket)?)
}

// this is necessary because `tun` doesn't implement `Read` for `&Queue`,
// even though it should be perfectly safe to do so
struct TunQueue(UnsafeCell<tun::platform::Queue>);

impl TunQueue {
    fn new(queue: tun::platform::Queue) -> Self {
        Self(UnsafeCell::new(queue))
    }
}

impl AsRawFd for TunQueue {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        unsafe { (*self.0.get()).as_raw_fd() }
    }
}

impl<'q> Read for &'q TunQueue {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe { (*self.0.get()).read(buf) }
    }
}

impl<'q> Write for &'q TunQueue {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe { (*self.0.get()).write(buf) }
    }

    fn flush(&mut self) -> io::Result<()> {
        unsafe { (*self.0.get()).flush() }
    }
}
