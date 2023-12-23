use centipede_proto::{
    marker::{auth, text},
    PacketMessage,
};
use chacha20poly1305::ChaCha20Poly1305;

use crate::{packet_memory::PacketRecollection, PeerId, Router};

use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
};

/// Handle an incoming packet message from the Centipede network.
pub fn handle_incoming<B>(
    router: &Router,
    message: PacketMessage<B, auth::Unknown, text::Ciphertext>,
) -> Option<ReceivePacket<B>>
where
    B: DerefMut<Target = [u8]>,
{
    let tunnel = router.recv_tunnels.get(&message.claimed_sender())?;
    let decrypted = message.decrypt_in_place(&tunnel.cipher).ok()?;

    match tunnel.memory.observe(decrypted.sequence_number()) {
        PacketRecollection::New => Some(ReceivePacket { decrypted }),
        PacketRecollection::Seen => None,
        PacketRecollection::Confusing => None,
    }
}

/// The obligation to
/// receive a packet from the Centipede network
/// and hand it off to the system's networking stack.
#[must_use]
pub struct ReceivePacket<B: Deref<Target = [u8]>> {
    /// The decrypted packet message.
    decrypted: PacketMessage<B, auth::Valid, text::Plaintext>,
}

impl<B: Deref<Target = [u8]>> ReceivePacket<B> {
    /// Get the decrypted packet data.
    pub fn packet(&self) -> &[u8] {
        self.decrypted.packet_plaintext()
    }
}

/// Handle an outgoing packet from the system's networking stack.
pub fn handle_outgoing<'r>(
    router: &'r Router,
    _packet: &'r [u8],
) -> impl Iterator<Item = SendPacket<'r>> + 'r {
    // TODO: route based on destination address

    router.send_tunnels.values().flat_map(move |tunnel| {
        tunnel.remote_addrs.iter().map(move |peer_addr| SendPacket {
            sender_id: &router.local_id,
            cipher: &tunnel.cipher,
            sequence_number: tunnel
                .next_sequence_number
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            peer_addr,
        })
    })
}

/// The obligation to
/// send a packet from the system's networking stack
/// to another peer on the Centipede network.
#[must_use]
pub struct SendPacket<'r> {
    /// The ID of the sending peer.
    pub sender_id: &'r PeerId,

    /// The cipher with which to encrypt the packet.
    pub cipher: &'r ChaCha20Poly1305,

    /// The sequence number of the packet.
    pub sequence_number: u64,

    /// The internet address of the peer.
    pub peer_addr: &'r SocketAddr,
}
