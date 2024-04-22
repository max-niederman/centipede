//! Pure state machine implementation of the Centipede control protocol.
//!
//! Performs no I/O, and is intended to be used as a building block for a real control daemon.

#![feature(btree_extract_if)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    ops::Deref,
    time::{Duration, SystemTime},
};

use base64::prelude::*;
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

        /// Addresses we've received messages from, by the time they were last received.
        remote_addrs: BTreeMap<SystemTime, HashSet<SocketAddr>>,

        /// The maximum time we're willing to wait between the peer's heartbeats.
        rx_max_heartbeat_interval: Duration,
    },
    /// We share a cipher with the peer and are exchanging heartbeats.
    Connected {
        /// The timestamp of the handshake that established the connection, **on the initiator's clock**.
        handshake_timestamp: SystemTime,

        /// Addreses on which we're listening for incoming packets, and are sending heartbeats from.
        local_addrs: HashSet<SocketAddr>,

        /// Addresses on which we're listening for incoming packets, by the next time we should send a heartbeat.
        queued_heartbeats: BTreeMap<SystemTime, HashSet<SocketAddr>>,

        /// Addresses we've received messages from, by the time they were last received.
        remote_addrs: BTreeMap<SystemTime, HashSet<SocketAddr>>,

        /// Remote addresses to which we have send tunnels.
        sending_to: HashSet<SocketAddr>,

        /// The maximum time we're willing to wait between the peer's heartbeats.
        rx_max_heartbeat_interval: Duration,

        /// The target interval between our heartbeats.
        tx_heartbeat_interval: Duration,
    },
}

impl<R: Rng + CryptoRng> Controller<R> {
    /// Create a new, empty controller and initial router config.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `private_key` - the private key of the local peer.
    /// * `rng` - a cryptographic random number generator to use for generating ephemeral keys.
    pub fn new(
        _now: SystemTime,
        private_key: ed25519_dalek::SigningKey,
        rng: R,
    ) -> (Self, centipede_router::Config) {
        let router_config = centipede_router::Config {
            local_id: public_key_to_peer_id(&private_key.verifying_key()),
            recv_addrs: HashSet::new(),
            recv_tunnels: HashMap::new(),
            send_tunnels: HashMap::new(),
        };

        (
            Self {
                router_config: router_config.clone(),
                router_config_changed: false,
                recv_addrs: HashMap::new(),
                peers: HashMap::new(),
                send_queue: Vec::new(),
                rng,
                private_key,
            },
            router_config,
        )
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
        log::debug!(
            "listening for incoming connections from `{}`",
            BASE64_STANDARD.encode(public_key)
        );

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
                local_addrs: state_local_addrs,
                queued_heartbeats,
                ..
            }) => {
                // Iterate over all the new addresses.
                for &addr in local_addrs.difference(state_local_addrs) {
                    // Queue a heartbeat for each new address.
                    queued_heartbeats.entry(now).or_default().insert(addr);
                }

                // Iterate over all the old addresses.
                for &addr in state_local_addrs.difference(&local_addrs) {
                    // Remove the address from the router config if it's no longer in use.
                    let count = self
                        .recv_addrs
                        .get_mut(&addr)
                        .expect("local_addrs should only contain addresses in recv_addrs");
                    *count -= 1;
                    if *count == 0 {
                        self.recv_addrs.remove(&addr);

                        self.router_config.recv_addrs.remove(&addr);
                        self.router_config_changed = true;
                    }

                    // Remove the addresses from the heartbeat queue.
                    queued_heartbeats.values_mut().for_each(|addrs| {
                        addrs.remove(&addr);
                    });

                    // Remove the address from the send tunnel.
                    self.router_config
                        .send_tunnels
                        .get_mut(&public_key_to_peer_id(&public_key))
                        .unwrap()
                        .links
                        .retain(|link| link.local != addr);
                    self.router_config_changed = true;
                }

                *state_local_addrs = local_addrs;
            }
        }
    }

    /// Initiate a connection to a peer. Must be called after `listen`.
    ///
    /// Note that this will not initiate a handshake if the peer is already connected.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `public_key` - the public key of the peer.
    /// * `remote_addrs` - addresses to try to send initiation messages to.
    pub fn initiate(
        &mut self,
        now: SystemTime,
        public_key: ed25519_dalek::VerifyingKey,
        remote_addrs: Vec<SocketAddr>,
    ) {
        log::debug!(
            "initiating connection to `{peer}` at {remote_addrs:?}",
            peer = BASE64_STANDARD.encode(public_key)
        );

        // Get the old state, ensuring that we know the peer.
        let old_state = self
            .peers
            .remove(&public_key)
            .expect("initiate must be called on a connected peer. call listen first");

        // Extract the local addresses and the max heartbeat interval from the old state.
        let (local_addrs, rx_max_heartbeat_interval) = match old_state {
            PeerState::Listening {
                local_addrs,
                rx_max_heartbeat_interval,
            }
            | PeerState::Initiating {
                local_addrs,
                rx_max_heartbeat_interval,
                ..
            } => (local_addrs, rx_max_heartbeat_interval),
            PeerState::Connected { .. } => return,
        };

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
            for &remote_addr in &remote_addrs {
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
                remote_addrs: BTreeMap::new(),
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
    pub fn disconnect(&mut self, _now: SystemTime, public_key: ed25519_dalek::VerifyingKey) {
        log::debug!("disconnecting from {public_key:?}");

        // Right now, we just clean up all references to the peer.
        // In the future, we might want to also send a disconnect message to the peer.

        // Remove the control state.
        let (local_addrs, _) = self
            .peers
            .remove(&public_key)
            .expect("cannot disconnect from an already disconnected peer")
            .forget_connection_and_destructure();

        // Remove the send tunnel.
        self.router_config
            .send_tunnels
            .remove(&public_key_to_peer_id(&public_key));

        // Remove the recieve tunnel.
        self.router_config
            .recv_tunnels
            .remove(&public_key_to_peer_id(&public_key));

        // Remove any receive addresses that are no longer in use.
        for addr in local_addrs {
            let count = self
                .recv_addrs
                .get_mut(&addr)
                .expect("local_addrs should only contain addresses in recv_addrs");

            *count -= 1;
            if *count == 0 {
                self.recv_addrs.remove(&addr);

                self.router_config.recv_addrs.remove(&addr);
                self.router_config_changed = true;
            }
        }
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
        log::trace!(
            "handling incoming message from remote addr {:?} with claimed content {:?}",
            incoming.from,
            incoming.message.claimed_content(),
        );

        // First we make all the checks we can without verifying the message's signature.

        // Check that the message even claims to be addressed to us.
        if incoming.message.claimed_recipient() != &self.private_key.verifying_key() {
            log::warn!("received message not addressed to us");
            return;
        }

        // Check that we know the peer.
        if !self.peers.contains_key(incoming.message.claimed_sender()) {
            log::warn!("received message from unknown peer");
            return;
        }

        // Now we verify the message's signature, and return if it's invalid.
        let message = match incoming.message.authenticate() {
            Ok(message) => message,
            Err(_) => {
                log::warn!("received message with invalid signature");
                return;
            }
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
                log::info!(
                    "accepting incoming handshake from `{peer}` at address {from} and time {time}",
                    peer = BASE64_STANDARD.encode(message.sender()),
                    from = incoming.from,
                    time = handshake_timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );

                // Since we want to accept the incoming initiate, we can forget the old state and extract the local addresses and the max heartbeat interval.
                let (local_addrs, rx_max_heartbeat_interval) =
                    old_state.forget_connection_and_destructure();

                // Generate our ephemeral keypair for the ECDH key exchange.
                let ecdh_secret_key = x25519_dalek::EphemeralSecret::random_from_rng(&mut self.rng);
                let ecdh_public_key = (&ecdh_secret_key).into();

                // Send the initiate acknowledgement.
                log::debug!(
                    "sending acknowledgements to `{peer}` from addresses {from:?}",
                    peer = BASE64_STANDARD.encode(message.sender()),
                    from = local_addrs
                );
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

                log::debug!(
                    "initializing send/receive tunnels to/from `{peer}`",
                    peer = BASE64_STANDARD.encode(message.sender())
                );

                // Initialize the receiving tunnel.
                // FIXME: reset packet memory
                self.router_config.recv_tunnels.insert(
                    public_key_to_peer_id(message.sender()),
                    centipede_router::config::RecvTunnel {
                        cipher: cipher.clone(),
                    },
                );
                self.router_config_changed = true;

                // Initialize the sending tunnel, but without any links yet.
                // We should only add links once we've received an initiate acknowledgement and know that the peer knows the cipher.
                self.router_config.send_tunnels.insert(
                    public_key_to_peer_id(message.sender()),
                    centipede_router::config::SendTunnel {
                        cipher: cipher.clone(),
                        links: HashSet::new(),
                    },
                );

                PeerState::Connected {
                    handshake_timestamp: *handshake_timestamp,
                    // Create the heartbeat queue, with the initial heartbeats queued.
                    queued_heartbeats: [(now, local_addrs.clone())].into_iter().collect(),
                    local_addrs,
                    // Because we received the initiate, we know the peer's address.
                    remote_addrs: [(now, [incoming.from].into_iter().collect())]
                        .into_iter()
                        .collect(),
                    // We have a send tunnel, but no links are associated with it yet.
                    sending_to: HashSet::new(),
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
                    mut remote_addrs,
                    rx_max_heartbeat_interval,
                },
                Content::InitiateAcknowledge {
                    handshake_timestamp: peer_handshake_timestamp,
                    ecdh_public_key: peer_ecdh_public_key,
                    max_heartbeat_interval: tx_max_heartbeat_interval,
                },
            ) if handshake_timestamp == *peer_handshake_timestamp => {
                log::info!(
                    "received initiation acknowledgement from `{peer}`",
                    peer = BASE64_STANDARD.encode(message.sender())
                );

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

                // Initialize sending tunnels to remote addresses.
                // Note that all of the remote addresses in `remote_addrs` actually sent heartbeats,
                // since any other message is either ignored or would have caused a state transition.
                let sending_to = remote_addrs
                    .values()
                    .flatten()
                    .copied()
                    .collect::<HashSet<_>>();
                self.router_config.send_tunnels.insert(
                    public_key_to_peer_id(message.sender()),
                    centipede_router::config::SendTunnel {
                        cipher: cipher.clone(),
                        links: local_addrs
                            .iter()
                            .copied()
                            .flat_map(|local| {
                                sending_to
                                    .iter()
                                    .copied()
                                    .map(move |remote| centipede_router::Link { local, remote })
                            })
                            .collect(),
                    },
                );
                self.router_config_changed = true;

                // The address that sent the initiate acknowledgement counts as a remote address.
                // However, we shouldn't send packets to it until we know that the peer knows the cipher.
                // Therefore, we don't add a link to the send tunnel yet.
                for addr_set in remote_addrs.values_mut() {
                    addr_set.remove(&incoming.from);
                }
                remote_addrs.entry(now).or_default().insert(incoming.from);

                PeerState::Connected {
                    handshake_timestamp,
                    // Create the heartbeat queue, with the initial heartbeats queued.
                    queued_heartbeats: [(now, local_addrs.clone())].into_iter().collect(),
                    local_addrs,
                    remote_addrs,
                    sending_to,
                    rx_max_heartbeat_interval,
                    // Aim to beat three times in each interval, in case packets are dropped, but
                    // don't beat more than once per second.
                    tx_heartbeat_interval: (*tx_max_heartbeat_interval / 4)
                        .min(Duration::from_secs(1)),
                }
            }
            (old_state, Content::InitiateAcknowledge { .. }) => {
                // We don't want to accept the incoming initiate acknowledgement, so we just put the old state back.
                old_state
            }

            (mut state, Content::Heartbeat) => {
                log::debug!(
                    "received heartbeat from `{peer}` at {time}",
                    peer = BASE64_STANDARD.encode(message.sender()),
                    time = now
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                );

                // Delay expiration of the remote address.
                if let PeerState::Connected { remote_addrs, .. }
                | PeerState::Initiating { remote_addrs, .. } = &mut state
                {
                    for addr_set in remote_addrs.values_mut() {
                        addr_set.remove(&incoming.from);
                    }
                    remote_addrs.entry(now).or_default().insert(incoming.from);
                }

                // If we are connected, add a send link if we don't have one yet.
                if let PeerState::Connected {
                    sending_to,
                    local_addrs,
                    ..
                } = &mut state
                {
                    if sending_to.insert(incoming.from) {
                        self.router_config
                            .send_tunnels
                            .get_mut(&public_key_to_peer_id(message.sender()))
                            .unwrap()
                            .links
                            .extend(local_addrs.iter().map(|&local| centipede_router::Link {
                                local,
                                remote: incoming.from,
                            }));
                        self.router_config_changed = true;
                    }
                }

                state
            }
        };

        self.peers.insert(*message.sender(), new_state);
    }

    /// Poll for events.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    #[must_use]
    pub fn poll(&mut self, now: SystemTime) -> Events {
        for (peer_key, peer_state) in self.peers.iter_mut() {
            // Send queued heartbeats.
            if let PeerState::Connected {
                tx_heartbeat_interval,
                queued_heartbeats,
                remote_addrs,
                ..
            } = peer_state
            {
                let mut to_requeue = HashSet::new();

                while queued_heartbeats
                    .first_key_value()
                    .is_some_and(|(&t, _)| t <= now)
                {
                    let (_, addrs) = queued_heartbeats.pop_first().unwrap();

                    let message = Message::new(&self.private_key, *peer_key, Content::Heartbeat);
                    for &local_addr in &addrs {
                        for &remote_addr in remote_addrs.values().flatten() {
                            self.send_queue.push(OutgoingMessage {
                                from: local_addr,
                                to: remote_addr,
                                message: message.clone(),
                            });
                        }
                    }

                    to_requeue.extend(addrs);
                }

                // Queue the next set of heartbeats for all the addresses we sent heartbeats to.
                queued_heartbeats
                    .insert(now.checked_add(*tx_heartbeat_interval).unwrap(), to_requeue);
            }

            // expire old remote_addrs
            if let PeerState::Initiating {
                remote_addrs,
                local_addrs,
                rx_max_heartbeat_interval,
                ..
            }
            | PeerState::Connected {
                remote_addrs,
                local_addrs,
                rx_max_heartbeat_interval,
                ..
            } = peer_state
            {
                let to_remove: HashSet<_> = remote_addrs
                    .extract_if(|t, _| *t + *rx_max_heartbeat_interval < now)
                    .flat_map(|(_, addrs)| addrs)
                    .collect();

                if !to_remove.is_empty() {
                    let send_tunnel = self
                        .router_config
                        .send_tunnels
                        .get_mut(&public_key_to_peer_id(peer_key))
                        .unwrap();

                    send_tunnel
                        .links
                        .retain(|link| !to_remove.contains(&link.remote));
                    self.router_config_changed = true;

                    if send_tunnel.links.is_empty() {
                        // If we have no more links, we should disconnect.
                        *peer_state = PeerState::Listening {
                            local_addrs: local_addrs.clone(),
                            rx_max_heartbeat_interval: *rx_max_heartbeat_interval,
                        };
                    }
                }
            }
        }

        if self.router_config_changed {
            log::trace!("poll resulted in router config change",);
        }
        if !self.send_queue.is_empty() {
            log::trace!("poll resulted in sending messages: {:#?}", self.send_queue);
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
