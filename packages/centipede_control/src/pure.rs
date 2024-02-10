//! Pure state machine implementation of the Centipede control protocol.
//!
//! Performs no I/O, and is intended to be used as a building block for a real control daemon.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use centipede_proto::{control::Message, marker::auth};
use chacha20poly1305::ChaCha20Poly1305;
use rand::CryptoRng;

/// A Centipede control daemon, implemented as a pure state machine.
pub struct Controller<R: CryptoRng> {
    /// Peer state, by public key.
    peers: HashMap<ed25519_dalek::VerifyingKey, PeerState>,

    /// Actions to be taken at some point in the future.
    timers: BTreeMap<SystemTime, TimerAction>,

    /// A cryptographic random number generator to use for generating ephemeral keys.
    rng: R,
}

/// The state of the controller w.r.t. a peer.
enum PeerState {}

/// An action to be taken when a timer expires.
enum TimerAction {}

impl<R: CryptoRng> Controller<R> {
    /// Create a new, empty controller.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `private_key` - the private key of the local peer.
    pub fn new(now: SystemTime, private_key: ed25519_dalek::SigningKey, csprng: R) -> Self {
        todo!()
    }

    /// Register a new peer and start listening for incoming connections.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `public_key` - the public key of the peer.
    /// * `recv_addrs` - addresses we'll tell the peer to send packets to.
    pub fn listen(
        &mut self,
        now: SystemTime,
        public_key: ed25519_dalek::VerifyingKey,
        recv_addrs: Vec<SocketAddr>,
    ) {
        todo!()
    }

    /// Initiate a connection to a peer. Must be called after `listen`.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    /// * `public_key` - the public key of the peer.
    /// * `known_addrs` - addresses to try to send initiation messages to.
    pub fn initiate(
        &mut self,
        now: SystemTime,
        public_key: ed25519_dalek::VerifyingKey,
        remote_addrs: Vec<SocketAddr>,
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
    pub fn handle_incoming(&mut self, now: SystemTime, message: Message<auth::Valid>) {
        todo!()
    }

    /// Poll for outgoing messages.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    pub fn poll_outgoing(&mut self, now: SystemTime) -> Poll<Message<auth::Valid>> {
        todo!()
    }

    /// Poll for new router configurations.
    ///
    /// # Arguments
    ///
    /// * `now` - the current time.
    pub fn poll_router_config(&mut self, now: SystemTime) -> Poll<centipede_router::Config> {
        todo!()
    }
}

/// The result of a polling operation.
/// Either a value, or a duration to wait before polling again,
/// assuming no other operations are performed in the meantime.
/// If the duration is `None`, the operation is complete and
/// will not need to be polled again, barring reconfiguration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll<T> {
    Ready(T),
    Pending(Option<Duration>),
}

impl<T> Poll<T> {
    pub fn ready(self) -> Option<T> {
        match self {
            Poll::Ready(value) => Some(value),
            Poll::Pending(_) => None,
        }
    }

    pub fn pending(self) -> Option<Duration> {
        match self {
            Poll::Ready(_) => None,
            Poll::Pending(duration) => duration,
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Poll::Ready(_))
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Poll::Pending(_))
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use centipede_proto::control::Content as MessageContent;
    use rand::{Rng, SeedableRng};
    use rand_chacha::{rand_core::CryptoRngCore, ChaChaRng};
    use x25519_dalek::x25519;

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

                let router_config = match controller.poll_router_config(clock.now()) {
                    Poll::Ready(config) => config,
                    Poll::Pending(_) => {
                        panic!("controller should produce an initial router config")
                    }
                };
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
                    controller.poll_outgoing(clock.now()).is_pending(),
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

                let recv_addrs = vec![SocketAddr::new([127, 0, 0, 1].into(), 1234)];
                controller.listen(clock.now(), peer_key, recv_addrs.clone());

                clock.increment(Duration::from_millis(1));

                let router_config = match controller.poll_router_config(clock.now()) {
                    Poll::Ready(config) => config,
                    Poll::Pending(_) => {
                        panic!("controller should produce a router config after listen")
                    }
                };
                assert!(
                    router_config
                        .recv_addrs
                        .is_superset(&recv_addrs.iter().cloned().collect()),
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
                    controller.poll_outgoing(clock.now()).is_pending(),
                    "there should be no outgoing messages immediately after listen"
                );

                clock.increment(Duration::from_secs(10));

                let peer_secret = x25519_dalek::EphemeralSecret::new(&mut rng);
                let handshake_timestamp = clock.now_since_epoch();
                controller.handle_incoming(
                    clock.now(),
                    make_message(
                        &private_key,
                        &MessageContent::Initiate {
                            timestamp: handshake_timestamp,
                            ecdh_public_key: (&peer_secret).into(),
                        },
                    ),
                );

                let router_config = match controller.poll_router_config(clock.now()) {
                    Poll::Ready(config) => config,
                    Poll::Pending(_) => {
                        panic!("controller should produce a router config after incoming initiate")
                    }
                };
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

                let response = match controller.poll_outgoing(clock.now()) {
                    Poll::Ready(message) => message,
                    Poll::Pending(_) => {
                        panic!("a listening controller should respond to handshakes immediately")
                    }
                };
                assert_eq!(
                    response.sender(),
                    &private_key.verifying_key(),
                    "response should be from the local peer"
                );
                match response.content() {
                    MessageContent::InitiateAcknowledge {
                        timestamp,
                        ecdh_public_key,
                    } => {
                        assert_eq!(
                            *timestamp, handshake_timestamp,
                            "initiate acknowledgement should echo the timestamp from the incoming initiate"
                        );
                    }
                    _ => panic!("controller should respond to an incoming initiate with an initiate acknowledgement"),
                }

                let heartbeat = match controller.poll_outgoing(clock.now()) {
                    Poll::Ready(message) => message,
                    Poll::Pending(_) => {
                        panic!("a listening controller should send heartbeats immediately after the handshake")
                    }
                };
                assert_eq!(
                    heartbeat.sender(),
                    &private_key.verifying_key(),
                    "heartbeat should be from the local peer"
                );
                assert_eq!(
                    heartbeat.content(),
                    &MessageContent::Heartbeat { sequence: 0 },
                    "second message from a listening controller should be the first heartbeat"
                );

                assert!(
                    controller.poll_outgoing(clock.now()).is_pending(),
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

                    let local_addrs = vec![SocketAddr::new([127, 0, 0, 1].into(), 1234)];
                    controller.listen(clock.now(), peer_key.verifying_key(), local_addrs.clone());

                    // get the post-listen router config out of the way to test the effect of `initiate`
                    assert!(controller.poll_router_config(clock.now).is_ready());

                    if wait_to_initiate {
                        clock.increment(Duration::from_secs(10));
                    }

                    let remote_addrs = vec![SocketAddr::new([127, 0, 0, 2].into(), 5678)];
                    controller.initiate(
                        clock.now(),
                        peer_key.verifying_key(),
                        remote_addrs.clone(),
                    );

                    assert!(
                        controller.poll_router_config(clock.now()).is_pending(),
                        "handshake initiation should not change the router config immediately"
                    );

                    let handshake_timestamp = clock.now_since_epoch();
                    let initiate = match controller.poll_outgoing(clock.now()) {
                        Poll::Ready(message) => message,
                        Poll::Pending(_) => {
                            panic!("initiating controller should send an initiate immediately")
                        }
                    };
                    assert_eq!(
                        initiate.sender(),
                        &private_key.verifying_key(),
                        "initiate should be from the local peer"
                    );
                    match initiate.content() {
                        MessageContent::Initiate {
                            timestamp,
                            ecdh_public_key,
                        } => {
                            assert!(
                                *timestamp == handshake_timestamp,
                                "initiate should have the current timestamp"
                            );
                        }
                        _ => panic!("initiating controller should send an initiate immediately"),
                    }

                    clock.increment(Duration::from_millis(500));

                    controller.handle_incoming(
                        clock.now(),
                        make_message(
                            &peer_key,
                            &MessageContent::InitiateAcknowledge {
                                timestamp: handshake_timestamp,
                                ecdh_public_key: (&x25519_dalek::EphemeralSecret::new(&mut rng))
                                    .into(),
                            },
                        ),
                    );

                    let router_config = match controller.poll_router_config(clock.now()) {
                        Poll::Ready(config) => config,
                        Poll::Pending(_) => {
                            panic!("controller should produce a router config after incoming initiate acknowledgement")
                        }
                    };
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

                    let heartbeat = match controller.poll_outgoing(clock.now()) {
                        Poll::Ready(message) => message,
                        Poll::Pending(_) => {
                            panic!("an initiating controller should send heartbeats immediately after the handshake")
                        }
                    };
                    assert_eq!(
                        heartbeat.sender(),
                        &private_key.verifying_key(),
                        "heartbeat should be from the local peer"
                    );
                    assert_eq!(
                        heartbeat.content(),
                        &MessageContent::Heartbeat { sequence: 0 },
                        "second message from an initiating controller should be the first heartbeat"
                    );

                    assert!(
                        controller.poll_outgoing(clock.now()).is_pending(),
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
            .chain(iter::repeat_with(move || {
                Duration::from_secs(rng.gen_range(0..(100 * 365 * 24 * 60 * 60)))
            }))
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

    fn make_message(
        private_key: &ed25519_dalek::SigningKey,
        content: &MessageContent,
    ) -> Message<auth::Valid> {
        Message::parse_and_validate(&Message::serialize(private_key, content)).unwrap()
    }

    fn public_key_to_peer_id(public_key: &ed25519_dalek::VerifyingKey) -> [u8; 8] {
        public_key.to_bytes()[..8].try_into().unwrap()
    }
}
