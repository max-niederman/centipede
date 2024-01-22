use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use chacha20poly1305::ChaCha20Poly1305;

use crate::{Link, PeerId};

/// Configuration of a router.
#[derive(Clone)]
pub struct Router {
    /// The router's local peer identifier.
    pub local_id: PeerId,

    /// Addresses on which workers should listen for incoming packets.
    pub recv_addrs: HashSet<SocketAddr>,

    /// Set of receiving tunnels, by sender identifier.
    pub recv_tunnels: HashMap<PeerId, RecvTunnel>,

    /// Set of sending tunnels, by receiver identifier.
    pub send_tunnels: HashMap<PeerId, SendTunnel>,
}

/// Configuration of a receiving tunnel.
#[derive(Clone)]
pub struct RecvTunnel {
    /// Cipher with which to decrypt messages.
    pub cipher: ChaCha20Poly1305,
}

/// Configuration of a sending tunndfel.
#[derive(Clone)]
pub struct SendTunnel {
    /// Cipher with which to encrypt messages.
    pub cipher: ChaCha20Poly1305,

    /// Address pairs on which to send messages.
    pub links: HashSet<Link>,
}

// TODO: optimize to avoid incrementing the generation where possible
/// Apply a configuration to the state of a router.
pub(crate) fn apply(config: &Router, state: &crate::ConfiguredRouter) -> crate::ConfiguredRouter {
    crate::ConfiguredRouter {
        generation: state.generation.wrapping_add(1),
        local_id: config.local_id,
        recv_addrs: config.recv_addrs.iter().copied().collect(),
        recv_tunnels: config
            .recv_tunnels
            .iter()
            .map(|(id, tun)| {
                (
                    *id,
                    crate::RecvTunnel {
                        cipher: tun.cipher.clone(),
                        memory: state
                            .recv_tunnels
                            .get(id)
                            .map(|tun| tun.memory.clone())
                            .unwrap_or_default(),
                    },
                )
            })
            .collect(),
        send_tunnels: config
            .send_tunnels
            .iter()
            .map(|(id, tun)| {
                (
                    *id,
                    crate::SendTunnel {
                        links: tun.links.iter().copied().collect(),
                        cipher: tun.cipher.clone(),
                        next_sequence_number: state
                            .send_tunnels
                            .get(id)
                            .map(|tun| tun.next_sequence_number.clone())
                            .unwrap_or(Arc::new(AtomicU64::new(0))),
                    },
                )
            })
            .collect(),
    }
}

/// A handle to the router for configuration.
pub struct ConfiguratorHandle<'r> {
    router: &'r crate::Router,
}

impl<'r> ConfiguratorHandle<'r> {
    /// Create a new configurator handle.
    pub(crate) fn new(router: &'r crate::Router) -> Self {
        Self { router }
    }

    /// Drive the router to a new configuration.
    pub fn configure(&self, config: &Router) {
        let state = self.router.state.load();
        let new_state = apply(config, &state);
        self.router.state.store(Arc::new(new_state));
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::KeyInit;

    use super::*;

    #[test]
    fn apply_config_to_default_state() {
        let mut state = crate::ConfiguredRouter::default();

        state = apply(
            &super::Router {
                local_id: [1; 8],
                recv_addrs: [SocketAddr::from(([127, 0, 0, 1], 0))]
                    .into_iter()
                    .collect(),
                recv_tunnels: HashMap::new(),
                send_tunnels: HashMap::new(),
            },
            &state,
        );
        assert_eq!(state.generation, 1);
        assert_eq!(state.local_id, [1; 8]);
        assert_eq!(
            state.recv_addrs.iter().copied().collect::<HashSet<_>>(),
            [SocketAddr::from(([127, 0, 0, 1], 0))]
                .into_iter()
                .collect()
        );
        assert!(state.recv_tunnels.is_empty());
        assert!(state.send_tunnels.is_empty());
    }

    #[test]
    fn updating_send_tunnel_preserves_sequence() {
        let mut state = crate::ConfiguredRouter::default();

        state = apply(
            &super::Router {
                local_id: [1; 8],
                recv_addrs: [SocketAddr::from(([127, 0, 0, 1], 0))]
                    .into_iter()
                    .collect(),
                recv_tunnels: HashMap::new(),
                send_tunnels: {
                    let mut map = HashMap::new();
                    map.insert(
                        [2; 8],
                        super::SendTunnel {
                            cipher: ChaCha20Poly1305::new((&[0; 32]).into()),
                            links: [Link {
                                local: SocketAddr::from(([127, 0, 0, 1], 0)),
                                remote: SocketAddr::from(([127, 0, 0, 1], 0)),
                            }]
                            .into_iter()
                            .collect(),
                        },
                    );
                    map
                },
            },
            &state,
        );
        assert_eq!(state.generation, 1);
        assert_eq!(state.local_id, [1; 8]);
        assert_eq!(
            state.recv_addrs.iter().copied().collect::<HashSet<_>>(),
            [SocketAddr::from(([127, 0, 0, 1], 0))]
                .into_iter()
                .collect()
        );
        assert!(state.recv_tunnels.is_empty());
        assert_eq!(state.send_tunnels.len(), 1);
        assert_eq!(
            state.send_tunnels[&[2; 8]].links,
            vec![Link {
                local: SocketAddr::from(([127, 0, 0, 1], 0)),
                remote: SocketAddr::from(([127, 0, 0, 1], 0)),
            }]
        );
        let sequence = state.send_tunnels[&[2; 8]].next_sequence_number.as_ref() as *const _;

        state = apply(
            &super::Router {
                local_id: [1; 8],
                recv_addrs: [SocketAddr::from(([127, 0, 0, 1], 0))]
                    .into_iter()
                    .collect(),
                recv_tunnels: HashMap::new(),
                send_tunnels: {
                    let mut map = HashMap::new();
                    map.insert(
                        [2; 8],
                        super::SendTunnel {
                            cipher: ChaCha20Poly1305::new((&[0; 32]).into()),
                            links: [Link {
                                local: SocketAddr::from(([127, 0, 0, 1], 0)),
                                remote: SocketAddr::from(([127, 0, 0, 1], 0)),
                            }]
                            .into_iter()
                            .collect(),
                        },
                    );
                    map
                },
            },
            &state,
        );

        assert_eq!(
            state.send_tunnels[&[2; 8]].next_sequence_number.as_ref() as *const _,
            sequence,
            "sequence number generator was not preserved"
        );
    }

    #[test]
    fn updating_recv_tunnel_preserves_memory() {
        let mut state = crate::ConfiguredRouter::default();

        state = apply(
            &super::Router {
                local_id: [1; 8],
                recv_addrs: [SocketAddr::from(([127, 0, 0, 1], 0))]
                    .into_iter()
                    .collect(),
                recv_tunnels: {
                    let mut map = HashMap::new();
                    map.insert(
                        [2; 8],
                        super::RecvTunnel {
                            cipher: ChaCha20Poly1305::new((&[0; 32]).into()),
                        },
                    );
                    map
                },
                send_tunnels: HashMap::new(),
            },
            &state,
        );
        assert_eq!(state.generation, 1);
        assert_eq!(state.local_id, [1; 8]);
        assert_eq!(
            state.recv_addrs.iter().copied().collect::<HashSet<_>>(),
            [SocketAddr::from(([127, 0, 0, 1], 0))]
                .into_iter()
                .collect()
        );
        assert_eq!(state.recv_tunnels.len(), 1);
        let memory = state.recv_tunnels[&[2; 8]].memory.as_ref() as *const _;
        assert!(state.send_tunnels.is_empty());

        state = apply(
            &super::Router {
                local_id: [1; 8],
                recv_addrs: [SocketAddr::from(([127, 0, 0, 1], 0))]
                    .into_iter()
                    .collect(),
                recv_tunnels: {
                    let mut map = HashMap::new();
                    map.insert(
                        [2; 8],
                        super::RecvTunnel {
                            cipher: ChaCha20Poly1305::new((&[1; 32]).into()),
                        },
                    );
                    map
                },
                send_tunnels: HashMap::new(),
            },
            &state,
        );

        assert_eq!(state.generation, 2);
        assert_eq!(
            state.recv_tunnels[&[2; 8]].memory.as_ref() as *const _,
            memory,
            "packet memory was not preserved"
        );
    }
}
