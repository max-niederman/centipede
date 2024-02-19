#![feature(btree_extract_if)]

use std::{
    collections::HashMap,
    io,
    net::{SocketAddr, UdpSocket},
    sync::{atomic::AtomicBool, mpsc, Arc},
    thread,
    time::SystemTime,
};

use pure::Controller;
use rand::{rngs::ThreadRng, thread_rng};

pub mod pure;

/// The primary API for the Centipede control plane. Represents a control daemon.
pub struct Daemon {
    thread: Arc<thread::JoinHandle<io::Result<()>>>,
    send: mpsc::Sender<Command>,
}

type Command = Box<dyn FnOnce(&mut Controller<ThreadRng>) + Send>;

impl Daemon {
    /// Spawn a new control daemon.
    pub fn spawn(
        private_key: ed25519_dalek::SigningKey,
        on_router_config: impl FnMut(centipede_router::Config) + Send + 'static,
    ) -> Self {
        let (send, recv) = mpsc::channel();

        let thread =
            std::thread::spawn(move || Self::entrypoint(recv, on_router_config, private_key));

        Self {
            send,
            thread: Arc::new(thread),
        }
    }

    fn entrypoint(
        recv: mpsc::Receiver<Command>,
        mut on_router_config: impl FnMut(centipede_router::Config),
        private_key: ed25519_dalek::SigningKey,
    ) -> io::Result<()> {
        let mut controller = Controller::new(SystemTime::now(), private_key, thread_rng());
        let mut sockets = Sockets::new();

        loop {
            match recv.try_recv() {
                Ok(command) => {
                    (command)(&mut controller);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    let events = controller.poll(SystemTime::now());

                    todo!("check for incoming messages");

                    if let Some(config) = events.router_config {
                        on_router_config(config);
                    }

                    for outgoing in events.outgoing_messages {
                        sockets.send(outgoing.from, outgoing.to, outgoing.message.as_buffer())?;
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    break Ok(());
                }
            }
        }
    }
}

struct Sockets {
    by_addr: HashMap<SocketAddr, UdpSocket>,
}

impl Sockets {
    pub fn new() -> Self {
        Self {
            by_addr: HashMap::new(),
        }
    }

    pub fn send(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8]) -> io::Result<()> {
        let socket = match self.by_addr.get(&from) {
            Some(socket) => socket,
            None => {
                let socket = UdpSocket::bind(from)?;
                self.by_addr.insert(from, socket);
                self.by_addr.get(&from).unwrap()
            }
        };

        socket.send_to(data, to)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn spawns() {
        let daemon = Daemon::spawn(
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()),
            |_| {},
        );

        std::thread::sleep(Duration::from_millis(10));

        Arc::into_inner(daemon.thread)
            .unwrap()
            .join()
            .unwrap()
            .unwrap();
    }
}
