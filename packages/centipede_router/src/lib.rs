pub mod worker;

mod packet_memory;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use chacha20poly1305::ChaCha20Poly1305;
use packet_memory::PacketMemory;

/// The shared state of a Centipede tunnel router.
#[derive(Clone)]
pub struct Router {
    /// Our local peer identifier.
    local_id: PeerId,

    /// Local addresses on which to receive messages.
    recv_addrs: Vec<SocketAddr>,

    /// Set of receiving tunnels, by sender identifier.
    recv_tunnels: HashMap<PeerId, RecvTunnel>,

    /// Set of sending tunnels, by receiver identifier.
    send_tunnels: HashMap<PeerId, SendTunnel>,
}

/// The state of a receiving tunnel.
#[derive(Clone)]
struct RecvTunnel {
    /// Cipher with which to decrypt messages.
    cipher: ChaCha20Poly1305,

    /// Memory of received packets.
    memory: Arc<PacketMemory>,
}

/// The state of a sending tunnel.
#[derive(Clone)]
struct SendTunnel {
    /// Local addresses over which to send messages,
    /// along with an optional endpoint to send as the opposite endpoint.
    local_addrs: Vec<SocketAddr>,

    /// Cipher with which to encrypt messages, by sending endpoint.
    cipher: ChaCha20Poly1305,

    /// Addresses of the remote endpoints.
    remote_addrs: Vec<SocketAddr>,

    /// The next sequence number.
    next_sequence_number: Arc<AtomicU64>,
}

pub type PeerId = [u8; 8];

impl Router {
    /// Create a new router.
    pub fn new(peer_id: PeerId, recv_addrs: Vec<SocketAddr>) -> Self {
        Self {
            local_id: peer_id,
            recv_addrs,
            recv_tunnels: HashMap::new(),
            send_tunnels: HashMap::new(),
        }
    }

    /// Insert or update a receive tunnel.
    pub fn upsert_receive_tunnel(&mut self, sender_id: PeerId, cipher: ChaCha20Poly1305) {
        let mut cipher = Some(cipher);
        self.recv_tunnels
            .entry(sender_id)
            .and_modify(|tunnel| {
                tunnel.cipher = cipher.take().unwrap();
            })
            .or_insert_with(|| RecvTunnel {
                cipher: cipher.take().unwrap(),
                memory: Arc::new(PacketMemory::default()),
            });
    }

    /// Delete a receive tunnel.
    pub fn delete_receive_tunnel(&mut self, sender_id: PeerId) {
        self.recv_tunnels.remove(&sender_id);
    }

    /// Insert or update a send tunnel.
    pub fn upsert_send_tunnel(
        &mut self,
        receiver_id: PeerId,
        cipher: ChaCha20Poly1305,
        local_addrs: Vec<SocketAddr>,
        remote_addrs: Vec<SocketAddr>,
    ) {
        let mut cipher = Some(cipher);
        let mut local_addrs = Some(local_addrs);
        let mut remote_addrs = Some(remote_addrs);

        self.send_tunnels
            .entry(receiver_id)
            .and_modify(|tunnel| {
                tunnel.cipher = cipher.take().unwrap();
                tunnel.local_addrs = local_addrs.take().unwrap();
                tunnel.remote_addrs = remote_addrs.take().unwrap();
            })
            .or_insert_with(|| SendTunnel {
                local_addrs: local_addrs.take().unwrap(),
                cipher: cipher.take().unwrap(),
                remote_addrs: remote_addrs.take().unwrap(),
                next_sequence_number: Arc::new(AtomicU64::new(0)),
            });
    }

    /// Delete a send tunnel.
    pub fn delete_send_tunnel(&mut self, receiver_id: PeerId) {
        self.send_tunnels.remove(&receiver_id);
    }
}

#[cfg(test)]
mod control_tests {
    use std::sync::atomic::Ordering;

    use chacha20poly1305::KeyInit;

    use crate::packet_memory::PacketRecollection;

    use super::*;

    #[test]
    fn construct() {
        Router::new([0; 8], vec![]);
    }

    #[test]
    fn crud_receive_tunnel() {
        let mut router = Router::new([0; 8], vec![]);

        router.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()));
        router.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()));

        assert!(router.recv_tunnels.contains_key(&[1; 8]));

        router.delete_receive_tunnel([1; 8]);

        assert!(!router.recv_tunnels.contains_key(&[1; 8]));
    }

    #[test]
    fn crud_send_tunnel() {
        let mut router = Router::new([0; 8], vec![]);

        router.upsert_send_tunnel(
            [1; 8],
            ChaCha20Poly1305::new((&[0; 32]).into()),
            vec![SocketAddr::from(([0, 0, 0, 0], 0))],
            vec![],
        );

        assert_eq!(
            router.send_tunnels[&[1; 8]].local_addrs,
            vec![SocketAddr::from(([0, 0, 0, 0], 0))]
        );
        assert_eq!(router.send_tunnels[&[1; 8]].remote_addrs, vec![]);

        router.upsert_send_tunnel(
            [1; 8],
            ChaCha20Poly1305::new((&[1; 32]).into()),
            vec![SocketAddr::from(([0, 0, 0, 0], 0))],
            vec![SocketAddr::from(([0, 0, 0, 0], 1))],
        );

        assert_eq!(
            router.send_tunnels[&[1; 8]].local_addrs,
            vec![SocketAddr::from(([0, 0, 0, 0], 0))]
        );
        assert_eq!(
            router.send_tunnels[&[1; 8]].remote_addrs,
            vec![SocketAddr::from(([0, 0, 0, 0], 1))]
        );

        router.delete_send_tunnel([1; 8]);

        assert!(!router.send_tunnels.contains_key(&[1; 8]));
    }

    #[test]
    fn receive_updates_preserve_state() {
        let mut router = Router::new([0; 8], vec![]);

        router.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[0; 32]).into()));

        router.recv_tunnels[&[1; 8]].memory.observe(0);

        router.upsert_receive_tunnel([1; 8], ChaCha20Poly1305::new((&[1; 32]).into()));

        assert_eq!(
            router.recv_tunnels[&[1; 8]].memory.observe(0),
            PacketRecollection::Seen
        )
    }

    #[test]
    fn send_updates_preserve_state() {
        let mut router = Router::new([0; 8], vec![]);

        router.upsert_send_tunnel(
            [1; 8],
            ChaCha20Poly1305::new((&[0; 32]).into()),
            vec![SocketAddr::from(([0, 0, 0, 0], 0))],
            vec![],
        );

        router.send_tunnels[&[1; 8]]
            .next_sequence_number
            .store(1, Ordering::SeqCst);

        router.upsert_send_tunnel(
            [1; 8],
            ChaCha20Poly1305::new((&[1; 32]).into()),
            vec![SocketAddr::from(([0, 0, 0, 0], 0))],
            vec![],
        );

        assert_eq!(
            router.send_tunnels[&[1; 8]]
                .next_sequence_number
                .load(Ordering::SeqCst),
            1
        )
    }
}
