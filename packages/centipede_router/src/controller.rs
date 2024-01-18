use std::{
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use chacha20poly1305::ChaCha20Poly1305;

use crate::{
    packet_memory::PacketMemory, ConfiguredRouter, Link, PeerId, RecvTunnel, Router, SendTunnel,
};

pub struct Controller<'r> {
    router: &'r Router,
}

impl<'r> Controller<'r> {
    /// Create a new controller, given a router.
    ///
    /// It is a logic error to create a controller for a router when there is already a controller for that router.
    pub(crate) fn new(router: &'r Router) -> Self {
        Self { router }
    }

    /// Complete a transaction on the router.
    ///
    /// This function is the only way to mutate the router's state,
    /// and there can only be one controller for a router at a time.
    /// This guarantees that the state cannot be mutated concurrently.
    pub fn transaction<R>(&mut self, f: impl FnOnce(&mut Transaction) -> R) -> R {
        let mut transaction = Transaction {
            config: (*self.router.state.load_full()).clone(),
        };
        let ret = f(&mut transaction);

        transaction.config.generation = transaction.config.generation.wrapping_add(1);
        self.router.state.store(Arc::new(transaction.config));

        ret
    }
}

pub struct Transaction {
    config: ConfiguredRouter,
}

impl Transaction {
    /// Update the addresses on which to listen.
    pub fn set_recv_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.config.recv_addrs = addrs;
    }

    /// Insert or update a receive tunnel.
    pub fn upsert_receive_tunnel(&mut self, sender_id: PeerId, cipher: ChaCha20Poly1305) {
        if let Some(tunnel) = self.config.recv_tunnels.get_mut(&sender_id) {
            tunnel.cipher = cipher;
        } else {
            self.config.recv_tunnels.insert(
                sender_id,
                RecvTunnel {
                    cipher,
                    memory: Arc::new(PacketMemory::default()),
                },
            );
        }
    }

    /// Delete a receive tunnel.
    pub fn delete_receive_tunnel(&mut self, sender_id: PeerId) {
        self.config.recv_tunnels.remove(&sender_id);
    }

    /// Insert or update a send tunnel.
    pub fn upsert_send_tunnel(
        &mut self,
        receiver_id: PeerId,
        cipher: ChaCha20Poly1305,
        links: Vec<Link>,
    ) {
        if let Some(tunnel) = self.config.send_tunnels.get_mut(&receiver_id) {
            tunnel.cipher = cipher;
            tunnel.links = links;
        } else {
            self.config.send_tunnels.insert(
                receiver_id,
                SendTunnel {
                    links,
                    cipher,
                    next_sequence_number: Arc::new(AtomicU64::new(0)),
                },
            );
        }
    }

    /// Delete a send tunnel.
    pub fn delete_send_tunnel(&mut self, receiver_id: PeerId) {
        self.config.send_tunnels.remove(&receiver_id);
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::atomic::Ordering};

    use chacha20poly1305::KeyInit;

    use crate::{packet_memory::PacketRecollection, Router};

    use super::*;

    #[test]
    fn construct() {
        Router::new([0; 8], vec![]);
    }

    fn state(controller: &Controller) -> Arc<ConfiguredRouter> {
        controller.router.state.load_full()
    }

    #[test]
    fn set_recv_addrs() {
        let mut router = Router::new([0; 8], vec![]);
        let (mut controller, _) = router.handles(0);

        assert_eq!(state(&controller).recv_addrs, vec![]);
        let prev_generation = state(&controller).generation;

        controller.transaction(|trans| {
            trans.set_recv_addrs(vec![SocketAddr::from(([0, 0, 0, 0], 0))]);
        });

        assert_eq!(
            state(&controller).recv_addrs,
            vec![SocketAddr::from(([0, 0, 0, 0], 0))]
        );
        assert_ne!(state(&controller).generation, prev_generation);
    }

    #[test]
    fn crud_receive_tunnel() {
        let mut router = Router::new([0; 8], vec![]);
        let (mut controller, _) = router.handles(0);

        controller.transaction(|trans| {
            trans.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()));
            trans.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()));
        });
        assert!(state(&controller).recv_tunnels.contains_key(&[1; 8]));

        controller.transaction(|trans| trans.delete_receive_tunnel([1; 8]));
        assert!(!state(&controller).recv_tunnels.contains_key(&[1; 8]));
    }

    #[test]
    fn crud_send_tunnel() {
        let mut router = Router::new([0; 8], vec![]);
        let (mut controller, _) = router.handles(0);

        let link = Link {
            local: SocketAddr::from(([0, 0, 0, 0], 0)),
            remote: SocketAddr::from(([0, 0, 0, 1], 1)),
        };

        controller.transaction(|trans| {
            trans.upsert_send_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()), vec![link])
        });
        assert_eq!(state(&controller).send_tunnels[&[1; 8]].links, vec![link]);

        controller.transaction(|trans| {
            trans.upsert_send_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()), vec![link]);
        });
        assert_eq!(state(&controller).send_tunnels[&[1; 8]].links, vec![link]);

        controller.transaction(|trans| {
            trans.delete_send_tunnel([1; 8]);
        });
        assert!(state(&controller).send_tunnels.is_empty());
    }

    #[test]
    fn receive_updates_preserve_state() {
        let mut router = Router::new([0; 8], vec![]);
        let (mut controller, _) = router.handles(0);

        controller.transaction(|trans| {
            trans.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()));
        });

        state(&controller).recv_tunnels[&[1; 8]].memory.observe(0);

        controller.transaction(|trans| {
            trans.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()));
        });

        assert_eq!(
            state(&controller).recv_tunnels[&[1; 8]].memory.observe(0),
            PacketRecollection::Seen
        )
    }

    #[test]
    fn send_updates_preserve_state() {
        let mut router = Router::new([0; 8], vec![]);
        let (mut controller, _) = router.handles(0);

        controller.transaction(|trans| {
            trans.upsert_send_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()), vec![]);
        });

        state(&controller).send_tunnels[&[1; 8]]
            .next_sequence_number
            .store(1, Ordering::SeqCst);

        controller.transaction(|trans| {
            trans.upsert_send_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()), vec![])
        });

        assert_eq!(
            state(&controller).send_tunnels[&[1; 8]]
                .next_sequence_number
                .load(Ordering::SeqCst),
            1
        );
    }
}
