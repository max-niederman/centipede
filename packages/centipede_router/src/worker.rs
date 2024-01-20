use centipede_proto::{
    marker::{auth, text},
    PacketMessage,
};

use crate::{
    packet_memory::PacketRecollection, ConfiguredRouter, Link, PeerId, Router, SendTunnel,
};

use std::{
    collections::hash_map,
    iter, mem,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    pin::Pin,
    slice,
    sync::{atomic::Ordering, Arc},
};

/// A handle to the router for the use of a worker.
pub struct WorkerHandle<'r> {
    /// The underlying router.
    router: &'r Router,

    /// The last observed configuration generation, if any.
    last_config_generation: Option<u64>,
}

impl<'r> WorkerHandle<'r> {
    /// Create a new worker.
    pub(crate) fn new(router: &'r Router) -> Self {
        Self {
            router,
            last_config_generation: None,
        }
    }

    /// Check if the configuration has changed.
    pub fn check_config(&mut self) -> Option<ConfigChanged> {
        let config = self.router.state.load();

        if self.last_config_generation != Some(config.generation) {
            self.last_config_generation = Some(config.generation);
            Some(ConfigChanged {
                router_state: self.router.state.load(),
            })
        } else {
            None
        }
    }

    /// Handle an incoming packet message from the Centipede network.
    pub fn handle_incoming<B>(
        &mut self,
        message: PacketMessage<B, auth::Unknown, text::Ciphertext>,
    ) -> Option<ReceivePacket<B>>
    where
        B: DerefMut<Target = [u8]>,
    {
        let state = self.router.state.load();

        let tunnel = state.recv_tunnels.get(&message.claimed_sender())?;
        let decrypted = message.decrypt_in_place(&tunnel.cipher).ok()?;

        match tunnel.memory.observe(decrypted.sequence_number()) {
            PacketRecollection::New => Some(ReceivePacket { decrypted }),
            PacketRecollection::Seen => None,
            PacketRecollection::Confusing => None,
        }
    }

    /// Handle an outgoing packet from the system's networking stack.
    pub fn handle_outgoing<'p>(&mut self, packet: &'p [u8]) -> HandleOutgoing<'p> {
        HandleOutgoing::start(self.router, packet)
    }
}

/// Notification to the worker of a configuration change.
///
/// Note that this does not include the entire configuration,
/// and the [`WorkerHandle`] will still reflect changes made
/// after a notification but before the next.
pub struct ConfigChanged {
    router_state: arc_swap::Guard<Arc<ConfiguredRouter>>,
}

impl ConfigChanged {
    /// Addresses on which the worker should listen for incoming packets.
    /// 
    /// This iterator will not yield duplicates.
    pub fn recv_addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.router_state.recv_addrs.iter().copied()
    }

    /// Addresses from which the worker may be expected to send outgoing packets.
    /// 
    /// This iterator may yield duplicates.
    pub fn send_addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.router_state
            .send_tunnels
            .values()
            .flat_map(|tunnel| tunnel.links.iter().map(|link| link.local))
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

/// A coroutine yielding packets to send.
///
/// Once the `coroutines` feature is stable,
/// this will be replaced with a coroutine literal.
#[must_use = "outgoing packet coroutine must be resumed"]
pub struct HandleOutgoing<'p> {
    /// Plaintext of the outgoing packet being handled.
    packet_plaintext: &'p [u8],

    /// Iterator over the send tunnels.
    /// Peekable so we can access the current tunnel without consuming it.
    ///
    /// Note that the 'static lifetime here is a lie, and the iterator
    /// actually borrows from the router state.
    tunnels: iter::Peekable<hash_map::Values<'static, PeerId, SendTunnel>>,

    /// Iterator over the links of the current tunnel.
    ///
    /// Note that the 'static lifetime here is a lie, and the iterator
    /// actually borrows from the router state.
    remaining_links: slice::Iter<'static, Link>,

    /// Arc pointer owning the router state,
    /// preventing it from being dropped while this coroutine is running.
    ///
    /// Note that this must be after the iterators, so that they are dropped first.
    router_state: Pin<arc_swap::Guard<Arc<ConfiguredRouter>>>,
}

impl<'p> HandleOutgoing<'p> {
    /// Create a new coroutine yielding packets to send.
    fn start(router: &Router, packet: &'p [u8]) -> Self {
        let router_state = router.state.load();

        let mut tunnels = unsafe {
            // SAFETY: The iterator refers to the configured router,
            //         which lives as long as `Self`, and is never
            //         moved because it is behind a `Pin`.

            mem::transmute::<
                iter::Peekable<hash_map::Values<'_, PeerId, SendTunnel>>,
                iter::Peekable<hash_map::Values<'static, PeerId, SendTunnel>>,
            >(router_state.send_tunnels.values().peekable())
        };

        let remaining_links = tunnels
            .peek()
            .map(|tunnel| tunnel.links.iter())
            .unwrap_or_default();

        Self {
            packet_plaintext: packet,
            router_state: Pin::new(router_state),
            tunnels,
            remaining_links,
        }
    }

    /// Resume the coroutine, yielding the next packet to send.
    pub fn resume(&mut self, scratch: Vec<u8>) -> Option<SendPacket> {
        match self.remaining_links.next() {
            Some(&link) => {
                let tunnel = *self.tunnels.peek()?;

                let sequence_number = tunnel.next_sequence_number.fetch_add(1, Ordering::Relaxed);

                let mut message =
                    PacketMessage::new_in(sequence_number, self.router_state.local_id, scratch);
                message.overwrite_packet(self.packet_plaintext.iter().copied());
                let message = message.encrypt_in_place(&tunnel.cipher);

                Some(SendPacket { link, message })
            }
            None => {
                self.remaining_links = self.tunnels.peek()?.links.iter();
                self.tunnels.next().unwrap();
                None
            }
        }
    }
}

/// The obligation to
/// send a packet from the system's networking stack
/// to another peer on the Centipede network.
#[must_use = "send packet obligation must be fulfilled"]
pub struct SendPacket {
    /// The link to send the packet over.
    link: Link,

    /// The encrypted packet message to send.
    message: PacketMessage<Vec<u8>, auth::Valid, text::Ciphertext>,
}

impl SendPacket {
    /// Get the link to send the packet over.
    pub fn link(&self) -> Link {
        self.link
    }

    /// Get the packet message to send.
    pub fn message(&self) -> PacketMessage<&'_ [u8], auth::Valid, text::Ciphertext> {
        self.message.as_ref()
    }

    /// Fulfill the obligation to send the packet, getting back the scratch space.
    pub fn fulfill(self) -> Vec<u8> {
        self.message.to_buffer()
    }
}
