//! Pure state machine implementation of the Centipede control protocol.
//!
//! Performs no I/O, and is intended to be used as a building block for a real control daemon.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    mem,
    net::SocketAddr,
    ops::Deref,
    time::{Duration, SystemTime},
};

use centipede_proto::{
    control::{Content, Message},
    marker::auth,
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use rand::{CryptoRng, Rng};

/// A Centipede control daemon, implemented as a pure state machine.
pub struct Controller<R: Rng + CryptoRng> {
    /// Our private key.
    private_key: ed25519_dalek::SigningKey,

    /// A cryptographic random number generator to use for generating ephemeral keys.
    rng: R,

    /// Peer state, by public key.
    peers: HashMap<ed25519_dalek::VerifyingKey, PeerState>,

    /// Receive addresses mapped to the count of peers using them.
    recv_addrs: HashMap<SocketAddr, usize>,

    /// The current router configuration.
    router_config: centipede_router::Config,

    /// Whether the router configuration has changed since the last poll.
    router_config_changed: bool,

    /// Send queue for outgoing messages.
    send_queue: Vec<OutgoingMessage>,
}

/// The state of the controller w.r.t. a peer.
enum PeerState {
    /// We're listening for an incoming handshake.
    Listening {
        /// Addresses on which we're listening for incoming packets, and will advertise to the peer.
        local_addrs: HashSet<SocketAddr>,

        /// The maximum time we're willing to wait between the peer's heartbeats.
        rx_max_heartbeat_interval: Duration,
    },
    /// We've initiated a handshake and are waiting for a response.
    Initiating {
        /// The time at which we initiated the handshake.
        handshake_timestamp: SystemTime,

        /// The ephemeral key we used to initiate the handshake.
        ecdh_secret: x25519_dalek::EphemeralSecret,

        /// Addresses on which we're listening for incoming packets, and will advertise to the peer.
        local_addrs: HashSet<SocketAddr>,

        /// Addresses we've received heartbeats from, by the time they were last received.
        tx_remote_addrs: BTreeMap<SystemTime, HashSet<SocketAddr>>,

        /// The maximum time we're willing to wait between the peer's heartbeats.
        rx_max_heartbeat_interval: Duration,
    },
    /// We share a cipher with the peer and are exchanging heartbeats.
    Connected {
        /// The timestamp of the handshake that established the connection, **on the initiator's clock**.
        handshake_timestamp: SystemTime,

        /// The shared cipher.
        cipher: ChaCha20Poly1305,

        /// Addreses on which we're listening for incoming packets, and are sending heartbeats from.
        local_addrs: HashSet<SocketAddr>,

        /// Addresses on which we're listening for incoming packets, by the next time we should send a heartbeat.
        queued_heartbeats: BTreeMap<SystemTime, HashSet<SocketAddr>>,

        /// Addresses we've received heartbeats from, by the time they were last received.
        tx_remote_addrs: BTreeMap<SystemTime, HashSet<SocketAddr>>,

        /// The maximum time we're willing to wait between the peer's heartbeats.
        rx_max_heartbeat_interval: Duration,

        /// The target interval between our heartbeats.
        tx_heartbeat_interval: Duration,
    },
}

impl<R: Rng + CryptoRng> Controller<R> {
    /// Create a new, empty controller.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `private_key` - the private key of the local peer.
    /// * `rng` - a cryptographic random number generator to use for generating ephemeral keys.
    pub fn new(now: SystemTime, private_key: ed25519_dalek::SigningKey, rng: R) -> Self {
        Self {
            router_config: centipede_router::Config {
                local_id: public_key_to_peer_id(&private_key.verifying_key()),
                recv_addrs: HashSet::new(),
                recv_tunnels: HashMap::new(),
                send_tunnels: HashMap::new(),
            },
            router_config_changed: true,
            recv_addrs: HashMap::new(),
            peers: HashMap::new(),
            send_queue: Vec::new(),
            rng,
            private_key,
        }
    }

    // TODO: add settings for generating links to the remote addresses we get heartbeats from
    /// Register (or reregister) a peer and listen for incoming connections.
    ///
    /// Note that this will never initiate a handshake, even when doing so would be necessary to change the max heartbeat interval.
    /// For this reason, you should not reduce the max heartbeat interval for a connected peer, lest the peer be disconnected.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `public_key` - the public key of the peer.
    /// * `local_addrs` - addresses we'll tell the peer to send packets to.
    /// * `max_heartbeat_interval` - the maximum time we're willing to wait between the peer's heartbeats.
    pub fn listen(
        &mut self,
        now: SystemTime,
        public_key: ed25519_dalek::VerifyingKey,
        local_addrs: HashSet<SocketAddr>,
        max_heartbeat_interval: Duration,
    ) {
        // Add the addresses to the router config, and mark it as changed if necessary.
        // This must happen for any current state of the peer,
        // since we're going to need to listen on these addresses regardless.
        for &addr in &local_addrs {
            if self.router_config.recv_addrs.insert(addr) {
                self.router_config_changed = true;
            }
        }

        match self.peers.get_mut(&public_key) {
            Some(PeerState::Listening { .. }) | None => {
                self.peers.insert(
                    public_key,
                    PeerState::Listening {
                        local_addrs,
                        rx_max_heartbeat_interval: max_heartbeat_interval,
                    },
                );
            }
            Some(PeerState::Initiating {
                local_addrs: state_rx_local_addrs,
                ..
            }) => {
                *state_rx_local_addrs = local_addrs;
            }
            Some(PeerState::Connected {
                local_addrs: old_local_addrs,
                queued_heartbeats,
                ..
            }) => {
                for addr in local_addrs {
                    // Check if the address is new. I.e., if it's already queued for a heartbeat.
                    // Otherwise, we immediately queue a heartbeat for it.
                    if !old_local_addrs.insert(addr) {
                        queued_heartbeats.entry(now).or_default().insert(addr);
                    }
                }
            }
        }
    }

    /// Initiate a connection to a peer. Must be called after `listen`.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `public_key` - the public key of the peer.
    /// * `tx_remote_addrs` - addresses to try to send initiation messages to.
    pub fn initiate(
        &mut self,
        now: SystemTime,
        public_key: ed25519_dalek::VerifyingKey,
        tx_remote_addrs: Vec<SocketAddr>,
    ) {
        // Get the old state, ensuring that we know the peer.
        let old_state = self
            .peers
            .remove(&public_key)
            .expect("initiate must be called on a connected peer. call listen first");

        // Extract the local addresses and the max heartbeat interval from the old state.
        let (local_addrs, rx_max_heartbeat_interval) =
            old_state.forget_connection_and_destructure();

        let ecdh_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut self.rng);

        // Generate the initiate message.
        let message = Message::new(
            &self.private_key,
            public_key,
            Content::Initiate {
                handshake_timestamp: now,
                ecdh_public_key: (&ecdh_secret).into(),
                max_heartbeat_interval: rx_max_heartbeat_interval,
            },
        );
        for &local_addr in &local_addrs {
            for &remote_addr in &tx_remote_addrs {
                self.send_queue.push(OutgoingMessage {
                    from: local_addr,
                    to: remote_addr,
                    message: message.clone(),
                });
            }
        }

        // Insert the new state.
        self.peers.insert(
            public_key,
            PeerState::Initiating {
                handshake_timestamp: now,
                ecdh_secret,
                local_addrs,
                // We shouldn't start sending to the remote addresses until we've received a response.
                tx_remote_addrs: BTreeMap::new(),
                rx_max_heartbeat_interval,
            },
        );
    }

    /// Disconnect from a peer.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `public_key` - the public key of the peer.
    pub fn disconnect(&mut self, now: SystemTime, public_key: ed25519_dalek::VerifyingKey) {
        todo!()
    }

    /// Handle an incoming message, transitioning the state machine.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `message` - the incoming message.
    pub fn handle_incoming<B: Deref<Target = [u8]>>(
        &mut self,
        now: SystemTime,
        incoming: IncomingMessage<B>,
    ) {
        // First we make all the checks we can without verifying the message's signature.

        // Check that the message even claims to be addressed to us.
        if incoming.message.claimed_recipient() != &self.private_key.verifying_key() {
            return;
        }

        // Check that we know the peer.
        if !self.peers.contains_key(incoming.message.claimed_sender()) {
            return;
        }

        // Now we verify the message's signature, and return if it's invalid.
        let message = match incoming.message.authenticate() {
            Ok(message) => message,
            Err(_) => return,
        };

        // Note that, since we haven't returned, the claimed sender and recipient are now guaranteed to
        // be the actual sender and recipient and we know that the we are the actual recipient from the first guard.

        // Now we can proceed to handling the message.
        let new_state = match (
            self.peers.remove(message.sender()).unwrap(),
            message.content(),
        ) {
            // Receive an incoming initiate.
            (
                old_state,
                Content::Initiate {
                    handshake_timestamp,
                    ecdh_public_key: peer_ecdh_public_key,
                    max_heartbeat_interval: tx_max_heartbeat_interval,
                },
            ) if old_state.should_accept_incoming_initiate(*handshake_timestamp) => {
                // Since we want to accept the incoming initiate, we can forget the old state and extract the local addresses and the max heartbeat interval.
                let (local_addrs, rx_max_heartbeat_interval) =
                    old_state.forget_connection_and_destructure();

                // Generate our ephemeral keypair for the ECDH key exchange.
                let ecdh_secret_key = x25519_dalek::EphemeralSecret::random_from_rng(&mut self.rng);
                let ecdh_public_key = (&ecdh_secret_key).into();

                // Send the initiate acknowledgement.
                let response = Message::new(
                    &self.private_key,
                    *message.sender(),
                    Content::InitiateAcknowledge {
                        handshake_timestamp: *handshake_timestamp,
                        ecdh_public_key,
                        max_heartbeat_interval: rx_max_heartbeat_interval,
                    },
                );
                for &local_addr in local_addrs.iter() {
                    self.send_queue.push(OutgoingMessage {
                        from: local_addr,
                        to: incoming.from,
                        message: response.clone(),
                    });
                }

                // Generate the cipher using the shared secret of the ECDH key exchange.
                let cipher = ChaCha20Poly1305::new(&chacha20poly1305::Key::from(
                    ecdh_secret_key
                        .diffie_hellman(peer_ecdh_public_key)
                        .to_bytes(),
                ));

                // Initialize the receiving tunnel.
                self.router_config.recv_tunnels.insert(
                    public_key_to_peer_id(message.sender()),
                    centipede_router::config::RecvTunnel {
                        cipher: cipher.clone(),
                    },
                );
                self.router_config_changed = true;

                PeerState::Connected {
                    handshake_timestamp: *handshake_timestamp,
                    cipher,
                    // Create the heartbeat queue, with the initial heartbeats queued.
                    queued_heartbeats: [(now, local_addrs.clone())].into_iter().collect(),
                    local_addrs,
                    // We have not yet received any heartbeats, but we know that we can send to the iniating address.
                    tx_remote_addrs: [(now, [incoming.from].into_iter().collect())]
                        .into_iter()
                        .collect(),
                    // Use the max heartbeat interval from the `listen` call.
                    rx_max_heartbeat_interval,
                    // Aim to beat three times in each interval, in case packets are dropped, but
                    // don't beat more than once per second.
                    tx_heartbeat_interval: (*tx_max_heartbeat_interval / 4)
                        .min(Duration::from_secs(1)),
                }
            }
            (old_state, Content::Initiate { .. }) => {
                // We don't want to accept the incoming initiate, so we just put the old state back.
                old_state
            }

            // Receive an incoming initiate acknowledgement.
            (
                PeerState::Initiating {
                    handshake_timestamp,
                    ecdh_secret,
                    local_addrs,
                    mut tx_remote_addrs,
                    rx_max_heartbeat_interval,
                },
                Content::InitiateAcknowledge {
                    handshake_timestamp: peer_handshake_timestamp,
                    ecdh_public_key: peer_ecdh_public_key,
                    max_heartbeat_interval: tx_max_heartbeat_interval,
                },
            ) if handshake_timestamp == *peer_handshake_timestamp => {
                // Generate the cipher using the shared secret of the ECDH key exchange.
                let cipher = ChaCha20Poly1305::new(&chacha20poly1305::Key::from(
                    ecdh_secret.diffie_hellman(peer_ecdh_public_key).to_bytes(),
                ));

                // Initialize the receiving tunnel.
                self.router_config.recv_tunnels.insert(
                    public_key_to_peer_id(message.sender()),
                    centipede_router::config::RecvTunnel {
                        cipher: cipher.clone(),
                    },
                );
                self.router_config_changed = true;

                // The acknowledgement counts as a heartbeat, so we ensure its source is in the tx_remote_addrs.
                for addr_set in tx_remote_addrs.values_mut() {
                    addr_set.remove(&incoming.from);
                }
                tx_remote_addrs
                    .entry(now)
                    .or_default()
                    .insert(incoming.from);

                PeerState::Connected {
                    handshake_timestamp,
                    cipher,
                    // Create the heartbeat queue, with the initial heartbeats queued.
                    queued_heartbeats: [(now, local_addrs.clone())].into_iter().collect(),
                    local_addrs,
                    tx_remote_addrs,
                    rx_max_heartbeat_interval,
                    // Aim to beat three times in each interval, in case packets are dropped, but
                    // don't beat more than once per second.
                    tx_heartbeat_interval: (*tx_max_heartbeat_interval / 4)
                        .min(Duration::from_secs(1)),
                }
            }

            _ => todo!(),
        };
        self.peers.insert(*message.sender(), new_state);
    }

    /// Poll for events.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    pub fn poll(&mut self, now: SystemTime) -> Events {
        for (peer_key, peer_state) in self.peers.iter_mut() {
            // Send queued heartbeats.
            if let PeerState::Connected {
                tx_heartbeat_interval,
                queued_heartbeats,
                tx_remote_addrs,
                ..
            } = peer_state
            {
                let mut to_requeue = HashSet::new();

                while queued_heartbeats
                    .first_key_value()
                    .is_some_and(|(&t, _)| t <= now)
                {
                    let (_, addrs) = queued_heartbeats.pop_first().unwrap();

                    for &local_addr in &addrs {
                        for &remote_addr in tx_remote_addrs.values().flatten() {
                            self.send_queue.push(OutgoingMessage {
                                from: local_addr,
                                to: remote_addr,
                                message: Message::new(
                                    &self.private_key,
                                    *peer_key,
                                    Content::Heartbeat,
                                ),
                            });
                        }
                    }

                    to_requeue.extend(addrs);
                }

                // Queue the next set of heartbeats for all the addresses we sent heartbeats to.
                queued_heartbeats
                    .insert(now.checked_add(*tx_heartbeat_interval).unwrap(), to_requeue);
            }

            // expire old tx_remote_addrs
            if let PeerState::Initiating {
                tx_remote_addrs,
                rx_max_heartbeat_interval,
                ..
            }
            | PeerState::Connected {
                tx_remote_addrs,
                rx_max_heartbeat_interval,
                ..
            } = peer_state
            {
                while let Some(first_entry) = tx_remote_addrs.first_entry() {
                    if now.duration_since(*first_entry.key()).unwrap() >= *rx_max_heartbeat_interval
                    {
                        let to_remove = first_entry.remove();
                        for addr in to_remove {
                            let count = self.recv_addrs.get_mut(&addr).expect(
                                "tx_remote_addrs should only contain addresses in recv_addrs",
                            );

                            *count -= 1;
                            if *count == 0 {
                                self.recv_addrs.remove(&addr);

                                self.router_config.recv_addrs.remove(&addr);
                                self.router_config_changed = true;
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        Events {
            router_config: if self.router_config_changed {
                self.router_config_changed = false;
                Some(self.router_config.clone())
            } else {
                None
            },
            outgoing_messages: std::mem::take(&mut self.send_queue),
        }
    }
}

impl PeerState {
    /// Extract the local addresses and the max heartbeat interval from the state, forgetting the connection.
    fn forget_connection_and_destructure(self) -> (HashSet<SocketAddr>, Duration) {
        match self {
            PeerState::Listening {
                local_addrs,
                rx_max_heartbeat_interval,
            }
            | PeerState::Initiating {
                local_addrs,
                rx_max_heartbeat_interval,
                ..
            }
            | PeerState::Connected {
                local_addrs,
                rx_max_heartbeat_interval,
                ..
            } => (local_addrs, rx_max_heartbeat_interval),
        }
    }

    /// Returns `true` iff the current state should be superseded by accepting an incoming initiate with the given timestamp.
    fn should_accept_incoming_initiate(&self, timestamp: SystemTime) -> bool {
        match self {
            PeerState::Listening { .. } => true,
            PeerState::Initiating {
                handshake_timestamp,
                ..
            }
            | PeerState::Connected {
                handshake_timestamp,
                ..
            } => *handshake_timestamp < timestamp,
        }
    }
}

/// An incoming message, consisting of a message and the address it claims to be from.
#[derive(Debug)]
pub struct IncomingMessage<B: Deref<Target = [u8]>> {
    /// The address the message claims to be from.
    pub from: SocketAddr,

    /// The message.
    pub message: Message<B, auth::Unknown>,
}

/// An outgoing message, consisting of a message and how it should be sent.
#[derive(Debug)]
pub struct OutgoingMessage {
    /// The address the message should be sent from.
    pub from: SocketAddr,

    /// The address the message should be sent to.
    pub to: SocketAddr,

    /// The message.
    pub message: Message<Vec<u8>, auth::Valid>,
}

/// The result of polling the controller for events.
pub struct Events {
    /// A new router configuration.
    pub router_config: Option<centipede_router::Config>,

    /// Outgoing messages to send.
    pub outgoing_messages: Vec<OutgoingMessage>,
}

/// Convert a public key to a peer ID by taking its first 8 bytes.
fn public_key_to_peer_id(public_key: &ed25519_dalek::VerifyingKey) -> [u8; 8] {
    public_key.to_bytes()[..8].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use std::{iter, vec};

    use centipede_proto::control::Message;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;

    use super::*;

    /// Test that the state of a new controller is as expected.
    #[test]
    fn construction() {
        let rng = test_rng();

        for private_key in test_keys(rng.clone()) {
            for mut clock in test_clocks(rng.clone()) {
                println!("testing controller construction with clock = {clock:?} and pk = {private_key:?}");

                let mut controller = Controller::new(clock.now(), private_key.clone(), rng.clone());

                clock.increment(Duration::from_millis(1));

                let events = controller.poll(clock.now());

                let router_config = events
                    .router_config
                    .expect("controller should produce an initial router config");
                assert_eq!(
                    router_config.local_id,
                    public_key_to_peer_id(&private_key.verifying_key()),
                    "controller should start with a local ID from the top 8 bytes of the public key"
                );
                assert!(
                    router_config.recv_addrs.is_empty(),
                    "controller should start with no recv addrs"
                );
                assert!(
                    router_config.recv_tunnels.is_empty(),
                    "controller should start with no recv tunnels"
                );
                assert!(
                    router_config.send_tunnels.is_empty(),
                    "controller should start with no send tunnels"
                );

                assert!(
                    events.outgoing_messages.is_empty(),
                    "there should be no outgoing messages for a new controller"
                );
            }
        }
    }

    /// Tests the results of calling `listen`.
    #[test]
    fn listen() {
        let mut rng = rand_chacha::ChaChaRng::from_seed([172; 32]);

        let mut peer_key = ed25519_dalek::SigningKey::generate(&mut rng);

        for private_key in test_keys(rng.clone()) {
            for mut clock in test_clocks(rng.clone()) {
                println!("testing listen with clock = {clock:?} and pk = {private_key:?}");

                let mut controller = Controller::new(clock.now(), private_key.clone(), rng.clone());

                clock.increment(Duration::from_millis(1));

                let local_addr = SocketAddr::new([127, 0, 0, 1].into(), 1234);
                let remote_addr = SocketAddr::new([127, 0, 0, 2].into(), 45678);
                controller.listen(
                    clock.now(),
                    peer_key.verifying_key(),
                    [local_addr].into_iter().collect(),
                    Duration::from_secs(60),
                );

                clock.increment(Duration::from_millis(1));

                let events = controller.poll(clock.now());

                let router_config = events
                    .router_config
                    .expect("controller should produce a router config after listen");
                assert!(
                    router_config
                        .recv_addrs
                        .is_superset(&iter::once(local_addr).collect()),
                    "controller should have the recv addrs after listen"
                );
                assert!(
                    router_config.recv_tunnels.is_empty(),
                    "there can't be any recv tunnels immediately after an initial listen, since we have not yet performed the handshake"
                );
                assert!(
                    router_config.send_tunnels.is_empty(),
                    "there can't be any send tunnels immediately after an initial listen, since we have not yet performed the handshake"
                );

                assert!(
                    events.outgoing_messages.is_empty(),
                    "there should be no outgoing messages immediately after listen"
                );

                clock.increment(Duration::from_secs(10));

                let peer_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
                let handshake_timestamp = clock.now();
                controller.handle_incoming(
                    clock.now(),
                    IncomingMessage {
                        from: remote_addr,
                        message: Message::new(
                            &peer_key,
                            private_key.verifying_key(),
                            Content::Initiate {
                                handshake_timestamp,
                                ecdh_public_key: (&peer_secret).into(),
                                max_heartbeat_interval: Duration::from_secs(60),
                            },
                        )
                        .forget_auth(),
                    },
                );

                let events = controller.poll(clock.now());

                let router_config = events
                    .router_config
                    .expect("controller should produce a router config after listening for and receiving an incoming initiate");
                assert!(
                    router_config.recv_tunnels.get(&public_key_to_peer_id(&peer_key.verifying_key())).is_some(),
                    "controller should have a recv tunnel after listening for and receiving an incoming initiate"
                );
                assert!(
                    router_config
                        .send_tunnels
                        .get(&public_key_to_peer_id(&peer_key.verifying_key()))
                        .is_none(),
                    "controller cannot know where to send packets until receiving heartbeats"
                );

                let mut outgoing_msgs = events.outgoing_messages.into_iter();

                let response = outgoing_msgs
                    .next()
                    .expect("a listening controller should respond to handshakes immediately");
                assert_eq!(
                    response.from, local_addr,
                    "response must be from the local address"
                );
                assert_eq!(
                    response.to, remote_addr,
                    "response must be to the remote address"
                );
                assert_eq!(
                    response.message.sender(),
                    &private_key.verifying_key(),
                    "response should be from the local peer"
                );
                match response.message.content() {
                    Content::InitiateAcknowledge {
                        handshake_timestamp: timestamp,
                        ..
                    } => {
                        assert_eq!(
                            *timestamp, handshake_timestamp,
                            "initiate acknowledgement should echo the timestamp from the incoming initiate"
                        );
                    }
                    _ => panic!("controller should respond to an incoming initiate with an initiate acknowledgement"),
                }

                let heartbeat = outgoing_msgs.next().expect(
                    "a listening controller should send heartbeats immediately after the handshake",
                );
                assert_eq!(
                    heartbeat.message.sender(),
                    &private_key.verifying_key(),
                    "heartbeat should be from the local peer"
                );
                assert_eq!(
                    heartbeat.message.content(),
                    &Content::Heartbeat,
                    "second message from a listening controller should be the first heartbeat"
                );

                assert!(
                    outgoing_msgs.next().is_none(),
                    "there should be no more outgoing messages after the first heartbeat"
                );
            }
            peer_key = private_key;
        }
    }

    #[test]
    fn initiate() {
        let mut rng = rand_chacha::ChaChaRng::from_seed([172; 32]);

        let mut peer_key = ed25519_dalek::SigningKey::generate(&mut rng);

        for private_key in test_keys(rng.clone()) {
            for mut clock in test_clocks(rng.clone()) {
                for wait_to_initiate in [false, true] {
                    println!("testing initiate with clock = {clock:?}, pk = {private_key:?}, and wait_to_initiate = {wait_to_initiate}");

                    let mut controller =
                        Controller::new(clock.now(), private_key.clone(), rng.clone());

                    clock.increment(Duration::from_millis(1));

                    let local_addr = SocketAddr::new([127, 0, 0, 1].into(), 1234);
                    controller.listen(
                        clock.now(),
                        peer_key.verifying_key(),
                        [local_addr].into_iter().collect(),
                        Duration::from_secs(60),
                    );

                    // get the post-listen router config out of the way to test the effect of `initiate`
                    let _ = controller.poll(clock.now());

                    if wait_to_initiate {
                        clock.increment(Duration::from_secs(10));
                    }

                    let remote_addr = SocketAddr::new([127, 0, 0, 2].into(), 5678);
                    controller.initiate(clock.now(), peer_key.verifying_key(), vec![remote_addr]);

                    let mut events = controller.poll(clock.now());

                    assert!(
                        events.router_config.is_none(),
                        "handshake initiation should not change the router config immediately"
                    );

                    let handshake_timestamp = clock.now();
                    let initiate = events
                        .outgoing_messages
                        .pop()
                        .expect("initiating controller should send an initiate immediately");

                    assert_eq!(
                        initiate.from, local_addr,
                        "initiate must be from the local address"
                    );
                    assert_eq!(
                        initiate.to, remote_addr,
                        "initiate must be to the remote address"
                    );
                    assert_eq!(
                        initiate.message.sender(),
                        &private_key.verifying_key(),
                        "initiate should be from the local peer"
                    );
                    match initiate.message.content() {
                        Content::Initiate {
                            handshake_timestamp: timestamp,
                            ..
                        } => {
                            assert!(
                                *timestamp == handshake_timestamp,
                                "initiate should have the current timestamp"
                            );
                        }
                        _ => panic!("initiating controller should send an initiate immediately"),
                    }

                    assert!(
                        events.outgoing_messages.is_empty(),
                        "there should be no more outgoing messages after the first initiate"
                    );

                    clock.increment(Duration::from_millis(500));

                    controller.handle_incoming(
                        clock.now(),
                        IncomingMessage {
                            from: remote_addr,
                            message: Message::new(
                                &peer_key,
                                private_key.verifying_key(),
                                Content::InitiateAcknowledge {
                                    handshake_timestamp,
                                    ecdh_public_key:
                                        (&x25519_dalek::EphemeralSecret::random_from_rng(&mut rng))
                                            .into(),
                                    max_heartbeat_interval: Duration::from_secs(60),
                                },
                            )
                            .forget_auth(),
                        },
                    );

                    let mut events = controller.poll(clock.now());

                    let router_config = events.router_config.expect(
                        "controller should produce a router config after initiating and receiving an incoming initiate acknowledgement",
                    );
                    assert!(
                        router_config
                            .recv_tunnels
                            .get(&public_key_to_peer_id(&peer_key.verifying_key()))
                            .is_some(),
                        "controller should have a recv tunnel after initiating and receiving an incoming initiate acknowledgement"
                    );
                    assert!(
                        router_config
                            .send_tunnels
                            .get(&public_key_to_peer_id(&peer_key.verifying_key()))
                            .is_none(),
                        "controller cannot know where to send packets until receiving heartbeats"
                    );

                    let heartbeat = events.outgoing_messages.pop().expect(
                        "an initiating controller should send heartbeats immediately after the handshake",
                    );
                    assert_eq!(
                        heartbeat.message.sender(),
                        &private_key.verifying_key(),
                        "heartbeat should be from the local peer"
                    );
                    assert_eq!(
                        heartbeat.message.content(),
                        &Content::Heartbeat,
                        "second message from an initiating controller should be stamped with the current time"
                    );

                    assert!(
                        events.outgoing_messages.is_empty(),
                        "there should be no more outgoing messages after the first heartbeat"
                    );
                }
            }
            peer_key = private_key;
        }
    }

    // TODO: add tests for receiving heartbeats, disconnecting
    // TODO: add test using two controllers to test that they can communicate

    #[derive(Debug)]
    struct TestClock {
        now: SystemTime,
    }

    impl TestClock {
        fn now(&self) -> SystemTime {
            self.now
        }

        fn increment(&mut self, duration: Duration) {
            self.now += duration;
        }
    }

    fn test_clocks(mut rng: ChaChaRng) -> impl Iterator<Item = TestClock> {
        iter::once(Duration::ZERO)
            .chain(
                iter::repeat_with(move || {
                    Duration::from_secs(rng.gen_range(0..(100 * 365 * 24 * 60 * 60)))
                })
                .take(31),
            )
            .map(|dur| TestClock {
                now: SystemTime::UNIX_EPOCH + dur,
            })
    }

    fn test_keys(mut rng: ChaChaRng) -> impl Iterator<Item = ed25519_dalek::SigningKey> {
        iter::repeat_with(move || ed25519_dalek::SigningKey::generate(&mut rng)).take(32)
    }

    fn test_rng() -> rand_chacha::ChaChaRng {
        rand_chacha::ChaChaRng::from_seed([42; 32])
    }
}
