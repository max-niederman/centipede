use std::sync::{atomic::AtomicU64, Arc};

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

    /// Reconfigure the router by applying a function to the current configured state.
    fn reconfigure(&mut self, f: impl FnOnce(&ConfiguredRouter) -> ConfiguredRouter) {
        let prev = self.router.state.load();
        let next = f(prev.as_ref());

        self.router.state.store(Arc::new(next));
    }

    /// Reconfigure the router by cloning the current configured state and mutating it.
    fn reconfigure_mutate(&mut self, f: impl FnOnce(&mut ConfiguredRouter)) {
        self.reconfigure(|prev| {
            let mut next = prev.clone();
            f(&mut next);
            next
        })
    }

    /// Insert or update a receive tunnel.
    pub fn upsert_receive_tunnel(&mut self, sender_id: PeerId, cipher: ChaCha20Poly1305) {
        self.reconfigure_mutate(move |state| {
            if let Some(tunnel) = state.recv_tunnels.get_mut(&sender_id) {
                tunnel.cipher = cipher;
            } else {
                state.recv_tunnels.insert(
                    sender_id,
                    RecvTunnel {
                        cipher,
                        memory: Arc::new(PacketMemory::default()),
                    },
                );
            }
            increment_generation(state);
        });
    }

    /// Delete a receive tunnel.
    pub fn delete_receive_tunnel(&mut self, sender_id: PeerId) {
        self.reconfigure_mutate(move |state| {
            state.recv_tunnels.remove(&sender_id);
            increment_generation(state);
        });
    }

    /// Insert or update a send tunnel.
    pub fn upsert_send_tunnel(
        &mut self,
        receiver_id: PeerId,
        cipher: ChaCha20Poly1305,
        links: Vec<Link>,
    ) {
        self.reconfigure_mutate(move |state| {
            if let Some(tunnel) = state.send_tunnels.get_mut(&receiver_id) {
                tunnel.cipher = cipher;
                tunnel.links = links;
            } else {
                state.send_tunnels.insert(
                    receiver_id,
                    SendTunnel {
                        links,
                        cipher,
                        next_sequence_number: Arc::new(AtomicU64::new(0)),
                    },
                );
            }
            increment_generation(state);
        });
    }

    /// Delete a send tunnel.
    pub fn delete_send_tunnel(&mut self, receiver_id: PeerId) {
        self.reconfigure_mutate(move |state| {
            state.send_tunnels.remove(&receiver_id);
            increment_generation(state);
        });
    }
}

fn increment_generation(state: &mut ConfiguredRouter) {
    state.generation = state.generation.wrapping_add(1);
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

    fn state<'c>(controller: &Controller) -> Arc<ConfiguredRouter> {
        controller.router.state.load_full()
    }

    #[test]
    fn crud_receive_tunnel() {
        let mut router = Router::new([0; 8], vec![]);
        let (mut controller, _) = router.handles(0);

        controller.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()));
        controller.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()));

        assert!(state(&controller).recv_tunnels.contains_key(&[1; 8]));

        controller.delete_receive_tunnel([1; 8]);

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

        controller.upsert_send_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()), vec![link]);

        assert_eq!(state(&controller).send_tunnels[&[1; 8]].links, vec![link]);

        controller.upsert_send_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()), vec![]);

        assert_eq!(state(&controller).send_tunnels[&[1; 8]].links, vec![]);

        controller.delete_send_tunnel([1; 8]);

        assert!(!state(&controller).send_tunnels.contains_key(&[1; 8]));
    }

    #[test]
    fn receive_updates_preserve_state() {
        let mut router = Router::new([0; 8], vec![]);
        let (mut controller, _) = router.handles(0);

        controller.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()));

        state(&controller).recv_tunnels[&[1; 8]].memory.observe(0);

        controller.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()));

        assert_eq!(
            state(&controller).recv_tunnels[&[1; 8]].memory.observe(0),
            PacketRecollection::Seen
        )
    }

    #[test]
    fn send_updates_preserve_state() {
        let mut router = Router::new([0; 8], vec![]);
        let (mut controller, _) = router.handles(0);

        controller.upsert_send_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()), vec![]);

        state(&controller).send_tunnels[&[1; 8]]
            .next_sequence_number
            .store(1, Ordering::SeqCst);

        controller.upsert_send_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()), vec![]);

        assert_eq!(
            state(&controller).send_tunnels[&[1; 8]]
                .next_sequence_number
                .load(Ordering::SeqCst),
            1
        );
    }
}
