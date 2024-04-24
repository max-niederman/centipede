use std::{collections::HashMap, io, mem, net::SocketAddr};

use miette::Diagnostic;
use socket2::Socket;
use thiserror::Error;

/// A container for all the sockets used by a worker thread.
/// Handles binding and setting up sockets, and persisting
/// them across reconfigurations.
#[derive(Debug)]
pub struct Sockets {
    /// The arena of sockets.
    arena: Vec<Socket>,

    /// Map from local addresses to their corresponding socket.
    by_local_addr: HashMap<SocketAddr, usize>,
}

impl Sockets {
    /// Create a new [`Sockets`].
    pub fn new() -> Self {
        Self {
            arena: Vec::new(),
            by_local_addr: HashMap::new(),
        }
    }

    /// Update with a new set of socket specifications, opening sockets
    /// where necessary and closing sockets where possible.
    pub fn update(
        &mut self,
        addrs: impl Iterator<Item = SocketAddr>,
    ) -> Result<UpdateResults, SocketsError> {
        enum SocketSource {
            Kept,
            Opened,
            Duplicated,
        }

        let mut results = UpdateResults {
            closed_count: 0,
            kept_indices: Vec::new(),
            opened_indices: Vec::new(),
        };

        let old_arena: Vec<_> =
            mem::replace(&mut self.arena, Vec::with_capacity(addrs.size_hint().0));
        let old_by_local_addr = mem::replace(
            &mut self.by_local_addr,
            HashMap::with_capacity(addrs.size_hint().0),
        );

        for addr in addrs {
            let (socket, source) = match old_by_local_addr.get(&addr) {
                Some(&index) => (
                    old_arena[index]
                        .try_clone()
                        .map_err(SocketsError::DuplicateSocketFd)?,
                    SocketSource::Kept,
                ),
                None => match self.by_local_addr.get(&addr) {
                    Some(&index) => (
                        self.arena[index]
                            .try_clone()
                            .map_err(SocketsError::DuplicateSocketFd)?,
                        SocketSource::Duplicated,
                    ),
                    None => (
                        bind_socket(addr).map_err(SocketsError::BindSocket)?,
                        SocketSource::Opened,
                    ),
                },
            };

            let index = self.arena.len();
            self.arena.push(socket);

            match source {
                SocketSource::Kept => results.kept_indices.push(index),
                SocketSource::Opened => results.opened_indices.push(index),
                SocketSource::Duplicated => (),
            }

            self.by_local_addr.insert(addr, index);
        }

        results.closed_count =
            old_by_local_addr.len() - (self.by_local_addr.len() - results.opened_indices.len());

        Ok(results)
    }

    /// Resolve or bind a socket to a local address.
    pub fn resolve_or_bind_local_addr(
        &mut self,
        addr: SocketAddr,
    ) -> Result<&mut Socket, SocketsError> {
        let index = match self.by_local_addr.get(&addr) {
            Some(&index) => index,
            None => {
                let index = self.arena.len();
                self.arena
                    .push(bind_socket(addr).map_err(SocketsError::BindSocket)?);
                index
            }
        };
        Ok(&mut self.arena[index])
    }

    /// Resolve an index to a socket.
    pub fn resolve_index(&mut self, index: usize) -> Option<&mut Socket> {
        self.arena.get_mut(index)
    }
}

/// Bind and configure a socket.
fn bind_socket(local_addr: SocketAddr) -> io::Result<Socket> {
    log::debug!("binding to {}", local_addr);

    // Create a new UDP socket.
    let socket = Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;

    // Each worker will bind to the same addresses.
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    // Bind the socket to the address.
    socket.bind(&local_addr.into())?;

    // Set the socket to non-blocking mode.
    socket.set_nonblocking(true)?;

    Ok(socket)
}

/// Lists of sockets closed, kept, and opened during an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResults {
    pub closed_count: usize,
    pub kept_indices: Vec<usize>,
    pub opened_indices: Vec<usize>,
}

/// Statistics of the number of sockets closed, kept, and opened during an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateStats {
    pub closed: usize,
    pub kept: usize,
    pub opened: usize,
}

impl UpdateResults {
    #[cfg(test)]
    pub fn stats(&self) -> UpdateStats {
        UpdateStats {
            closed: self.closed_count,
            kept: self.kept_indices.len(),
            opened: self.opened_indices.len(),
        }
    }
}

#[derive(Debug, Error, Diagnostic)]
#[error("failed to update sockets")]
pub enum SocketsError {
    #[error("failed to bind socket")]
    #[diagnostic(code(centipede::worker::bind_socket_failed))]
    BindSocket(#[source] std::io::Error),

    #[error("failed to duplicate socket file descriptor")]
    #[diagnostic(code(centipede::worker::duplicate_socket_failed))]
    DuplicateSocketFd(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;

    #[test]
    fn construct() {
        Sockets::new();
    }

    #[test]
    fn update_once_to_empty() {
        let mut sockets = Sockets::new();

        assert_eq!(
            sockets.update(iter::empty()).unwrap().stats(),
            UpdateStats {
                closed: 0,
                kept: 0,
                opened: 0
            }
        );
    }

    #[test]
    fn update_once() {
        const PORT: u16 = 42001;

        let mut sockets = Sockets::new();

        assert_eq!(
            sockets
                .update([SocketAddr::from(([127, 0, 0, 1], PORT))].into_iter())
                .expect("update sockets errored")
                .stats(),
            UpdateStats {
                closed: 0,
                kept: 0,
                opened: 1
            }
        );
    }

    #[test]
    fn keep_open() {
        const PORT: u16 = 42002;

        let mut sockets = Sockets::new();

        assert_eq!(
            sockets
                .update([SocketAddr::from(([127, 0, 0, 1], PORT))].into_iter())
                .expect("update sockets errored")
                .stats(),
            UpdateStats {
                closed: 0,
                kept: 0,
                opened: 1
            }
        );

        assert_eq!(
            sockets
                .update([SocketAddr::from(([127, 0, 0, 1], PORT))].into_iter())
                .expect("update sockets errored")
                .stats(),
            UpdateStats {
                closed: 0,
                kept: 1,
                opened: 0
            }
        );
    }

    #[test]
    fn close_old() {
        const PORT: u16 = 42003;

        let mut sockets = Sockets::new();

        assert_eq!(
            sockets
                .update([SocketAddr::from(([127, 0, 0, 1], PORT))].into_iter())
                .expect("update sockets errored")
                .stats(),
            UpdateStats {
                closed: 0,
                kept: 0,
                opened: 1
            }
        );

        assert_eq!(
            sockets
                .update([SocketAddr::from(([127, 0, 0, 1], PORT + 100))].into_iter())
                .expect("update sockets errored")
                .stats(),
            UpdateStats {
                closed: 1,
                kept: 0,
                opened: 1
            }
        );
    }

    #[test]
    fn resolve() {
        const PORT: u16 = 42004;

        let mut sockets = Sockets::new();

        assert_eq!(
            sockets
                .update([SocketAddr::from(([127, 0, 0, 1], PORT))].into_iter(),)
                .expect("update sockets errored")
                .stats(),
            UpdateStats {
                closed: 0,
                kept: 0,
                opened: 1
            }
        );

        let socket = sockets
            .resolve_or_bind_local_addr(SocketAddr::from(([127, 0, 0, 1], PORT)))
            .unwrap();
        assert_eq!(
            socket.local_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], PORT)).into()
        );

        let socket = sockets.resolve_index(0).unwrap();
        assert_eq!(
            socket.local_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], PORT)).into()
        );
    }
}
