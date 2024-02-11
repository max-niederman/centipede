//! Pure state machine implementation of the Centipede control protocol.
//!
//! Performs no I/O, and is intended to be used as a building block for a real control daemon.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    ops::Add,
    time::{Duration, SystemTime},
};

use centipede_proto::{control::Message, marker::auth};
use chacha20poly1305::ChaCha20Poly1305;
use rand::CryptoRng;

/// A Centipede control daemon, implemented as a pure state machine.
pub struct Controller<R: CryptoRng> {
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
    send_queue: Vec<AddressedMessage>,
}

/// The state of the controller w.r.t. a peer.
enum PeerState {
    /// We're listening for an incoming handshake.
    Listening {
        /// Addresses on which we're listening for incoming packets, and will advertise to the peer.
        rx_local_addrs: Vec<SocketAddr>,

        /// The maximum time we're willing to wait between the peer's heartbeats.
        rx_max_heartbeat_interval: Duration,
    },
    /// We've initiated a handshake and are waiting for a response.
    Initiating {
        /// The time at which we initiated the handshake.
        timestamp: SystemTime,

        /// The ephemeral key we used to initiate the handshake.
        ecdh_secret: x25519_dalek::EphemeralSecret,

        /// Addresses we've received heartbeats from, by the time they were last received.
        tx_remote_addrs: BTreeMap<SystemTime, Vec<SocketAddr>>,

        /// The maximum time we're willing to wait between the peer's heartbeats.
        rx_max_heartbeat_interval: Duration,
    },
    /// We share a cipher with the peer and are exchanging heartbeats.
    Connected {
        /// The shared cipher.
        cipher: ChaCha20Poly1305,

        /// Addresses on which we're listening for incoming packets, by the last time we sent a heartbeat.
        rx_local_addrs: BTreeMap<SystemTime, Vec<SocketAddr>>,

        /// Addresses we've received heartbeats from, by the time they were last received.
        tx_remote_addrs: BTreeMap<SystemTime, Vec<SocketAddr>>,

        /// The maximum time we're willing to wait between the peer's heartbeats.
        rx_max_heartbeat_interval: Duration,

        /// The target interval between our heartbeats.
        tx_heartbeat_interval: Duration,

        /// The (peer clock) timestamp of the last heartbeat we received.
        rx_heartbeat_timestamp: u64,
    },
}

impl<R: CryptoRng> Controller<R> {
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
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `public_key` - the public key of the peer.
    /// * `rx_local_addrs` - addresses we'll tell the peer to send packets to.
    /// * `max_heartbeat_interval` - the maximum time we're willing to wait between the peer's heartbeats.
    pub fn listen(
        &mut self,
        now: SystemTime,
        public_key: ed25519_dalek::VerifyingKey,
        rx_local_addrs: Vec<SocketAddr>,
        max_heartbeat_interval: Duration,
    ) {
        todo!()
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
        todo!()
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
    pub fn handle_incoming(&mut self, now: SystemTime, message: AddressedMessage) {
        todo!()
    }

    /// Poll for events.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    pub fn poll(&mut self, now: SystemTime) -> Events {
        for peer in self.peers.values_mut() {
            // send heartbeats
            if let PeerState::Connected {
                tx_heartbeat_interval,
                tx_remote_addrs,
                ..
            } = peer
            {
                while let Some(first_entry) = tx_remote_addrs.first_entry() {
                    if now.duration_since(*first_entry.key()).unwrap() >= *tx_heartbeat_interval {
                        for local_addr in first_entry.remove() {
                            for &remote_addr in tx_remote_addrs.values().flatten() {
                                self.send_queue.push(AddressedMessage {
                                    from: local_addr,
                                    to: remote_addr,
                                    message: Message::new(
                                        &self.private_key,
                                        centipede_proto::control::Content::Heartbeat {
                                            timestamp: now
                                                .duration_since(SystemTime::UNIX_EPOCH)
                                                .unwrap(),
                                        },
                                    ),
                                });
                            }
                        }
                    } else {
                        break;
                    }
                }
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
            } = peer
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

/// A message with source and destination addresses.
pub struct AddressedMessage {
    /// The address from which to send the message.
    pub from: SocketAddr,
    /// The address to send the message to.
    pub to: SocketAddr,

    /// The message to send.
    pub message: Message<auth::Valid>,
}

/// The result of polling the controller for events.
pub struct Events {
    /// A new router configuration.
    pub router_config: Option<centipede_router::Config>,

    /// Outgoing messages to send.
    pub outgoing_messages: Vec<AddressedMessage>,
}

/// Convert a public key to a peer ID by taking its first 8 bytes.
fn public_key_to_peer_id(public_key: &ed25519_dalek::VerifyingKey) -> [u8; 8] {
    public_key.to_bytes()[..8].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use std::{iter, vec};

    use centipede_proto::control::{Content as MessageContent, Message};
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

        let mut peer_key = ed25519_dalek::SigningKey::generate(&mut rng).verifying_key();

        for private_key in test_keys(rng.clone()) {
            for mut clock in test_clocks(rng.clone()) {
                println!("testing listen with clock = {clock:?} and pk = {private_key:?}");

                let mut controller = Controller::new(clock.now(), private_key.clone(), rng.clone());

                clock.increment(Duration::from_millis(1));

                let local_addr = SocketAddr::new([127, 0, 0, 1].into(), 1234);
                let remote_addr = SocketAddr::new([127, 0, 0, 2].into(), 45678);
                controller.listen(
                    clock.now(),
                    peer_key,
                    vec![local_addr],
                    Duration::from_secs(60),
                );

                clock.increment(Duration::from_millis(1));

                let poll = controller.poll(clock.now());

                let router_config = poll
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
                    poll.outgoing_messages.is_empty(),
                    "there should be no outgoing messages immediately after listen"
                );

                clock.increment(Duration::from_secs(10));

                let peer_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
                let handshake_timestamp = clock.now_since_epoch();
                controller.handle_incoming(
                    clock.now(),
                    AddressedMessage {
                        from: remote_addr,
                        to: local_addr,
                        message: Message::new(
                            &private_key,
                            MessageContent::Initiate {
                                handshake_timestamp,
                                ecdh_public_key: (&peer_secret).into(),
                                max_heartbeat_interval: Duration::from_secs(60),
                            },
                        ),
                    },
                );

                let event = controller.poll(clock.now());

                let router_config = event
                    .router_config
                    .expect("controller should produce a router config after listening for and receiving an incoming initiate");
                assert!(
                    router_config.recv_tunnels.get(&public_key_to_peer_id(&peer_key)).is_some(),
                    "controller should have a recv tunnel after listening for and receiving an incoming initiate"
                );
                assert!(
                    router_config
                        .send_tunnels
                        .get(&public_key_to_peer_id(&peer_key))
                        .is_none(),
                    "controller cannot know where to send packets until receiving heartbeats"
                );

                let mut outgoing_msgs = poll.outgoing_messages.into_iter();

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
                    MessageContent::InitiateAcknowledge {
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
                    &MessageContent::Heartbeat {
                        timestamp: clock.now_since_epoch()
                    },
                    "second message from a listening controller should be the first heartbeat"
                );

                assert!(
                    outgoing_msgs.next().is_none(),
                    "there should be no more outgoing messages after the first heartbeat"
                );
            }
            peer_key = private_key.verifying_key();
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
                        vec![local_addr],
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

                    let handshake_timestamp = clock.now_since_epoch();
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
                        MessageContent::Initiate {
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
                        AddressedMessage {
                            from: remote_addr,
                            to: local_addr,
                            message: Message::new(
                                &peer_key,
                                MessageContent::InitiateAcknowledge {
                                    handshake_timestamp,
                                    ecdh_public_key:
                                        (&x25519_dalek::EphemeralSecret::random_from_rng(&mut rng))
                                            .into(),
                                    max_heartbeat_interval: Duration::from_secs(60),
                                },
                            ),
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
                        &MessageContent::Heartbeat { timestamp: clock.now_since_epoch() },
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

        fn now_since_epoch(&self) -> Duration {
            self.now.duration_since(SystemTime::UNIX_EPOCH).unwrap()
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
                .take(100),
            )
            .map(|dur| TestClock {
                now: SystemTime::UNIX_EPOCH + dur,
            })
    }

    fn test_keys(mut rng: ChaChaRng) -> impl Iterator<Item = ed25519_dalek::SigningKey> {
        iter::repeat_with(move || ed25519_dalek::SigningKey::generate(&mut rng)).take(100)
    }

    fn test_rng() -> rand_chacha::ChaChaRng {
        rand_chacha::ChaChaRng::from_seed([42; 32])
    }
}
